"""Backfill DEX-derived IOCs for samples parsed before two extractor changes:

  * the domain regex gained ".pl", so a bare Polish C2 host (a banker phishing
    mBank/Pekao as "mbank-weryfikacja.pl") now becomes a domain IOC instead of
    surviving only inside a full URL;
  * the overlay/injection target list (dex.targeted_packages) is now persisted
    as the ioc_type "targeted_app" - the single best indicator of a banker's
    target country, which until now lived only in results.json and was
    overwritten every run.

Rows already in the database were parsed by the old code and carry neither. This
script re-fetches each sample from MWDB, re-runs the manifest + DEX analysis in
memory, and inserts the MISSING "domain" and "targeted_app" rows. Existing IOCs
are left untouched: only (type, value) pairs not already present for a sample are
added, so a sample re-parsed to the same domains gains nothing.

The sample never touches the disk: on Windows, Defender flags saved malware and
then blocks reopening the file. Parsing runs from memory, in a child process
under a timeout.

Speed: each sample is one MWDB download (network I/O) plus one isolated parse
that does the manifest AND the DEX analysis in a single child process - one
androguard import instead of two. A thread pool overlaps the downloads and the
subprocess waits across --workers samples at once; all database writes stay on
the main thread, so SQLite is only ever touched by one thread.

Usage:
    python backfill_dex_iocs.py                       # preview, downloads nothing
    python backfill_dex_iocs.py --apply               # fetch and backfill
    python backfill_dex_iocs.py --apply --workers 8   # more parallelism
    python backfill_dex_iocs.py --apply --limit 20    # only 20 samples (a test)

The script is resumable: every processed sample is recorded in a progress table,
so a later run continues where the last one stopped. An interrupted run keeps
everything it committed; in-flight samples are simply redone next time.
"""
import hashlib
import os
import shutil
import sqlite3
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from isolation import run_isolated
from manifest_parser import parse_apk_bytes
from dex_analyzer import analyze_dex_bytes
from threat_db import _normalize_ioc
from mwdb_client import get_client

DB = os.path.join("output", "threat_intel.db")

# Which IOC kinds this backfill is responsible for. Deliberately narrow: the two
# features that changed. Re-inserting urls/ips the old parse already captured
# would be churn with no new information.
_BACKFILL_TYPES = ("domain", "targeted_app")

_DEFAULT_WORKERS = 6

# Per-sample parse budget. A handful of samples (big obfuscated VPN apps with
# huge native libs - the org.newvpn cluster) never parse inside any sane limit;
# at 120s a worker gives up fast enough to stay useful, and such a sample is
# recorded done-with-error so the backfill terminates instead of re-downloading
# and re-timing-out it on every run.
_PARSE_TIMEOUT = 120


def _now():
    return datetime.now(timezone.utc).isoformat()


# ── The work done per sample, off the main thread ─────────────────────────────

def _parse_and_analyze(apk_bytes: bytes) -> dict:
    """Manifest + DEX in ONE child process (run under run_isolated).

    Doing both here, rather than in two separate isolated calls, halves the
    per-sample cost: androguard is imported once, not twice, and only one
    subprocess is spawned. targeted_packages needs the manifest's permissions
    and own_package, so the manifest is parsed first.

    Returns only the two fields this backfill cares about, as plain lists so the
    result pickles cleanly back from the child.
    """
    manifest = parse_apk_bytes(apk_bytes)
    own_pkg = manifest.get("package") or ""
    perms = tuple(manifest.get("permissions") or ())
    dex = analyze_dex_bytes(apk_bytes, own_pkg, perms)
    return {
        "domains": dex.get("domains", []) or [],
        "targeted": dex.get("targeted_packages", []) or [],
        "error": dex.get("error"),
    }


_thread_local = threading.local()


def _client():
    """One MWDB client per worker thread - requests sessions are not meant to be
    shared across threads, and a thread pool would otherwise race on one."""
    c = getattr(_thread_local, "mwdb", None)
    if c is None:
        c = _thread_local.mwdb = get_client()
    return c


def _fetch_and_parse(sha256: str):
    """Download one sample and re-derive its domains + target list, in memory.

    Runs on a worker thread. Returns (sha256, result_dict, None) or, on failure,
    (sha256, None, error_message). No database access here - the main thread
    owns the connection.
    """
    try:
        data = _client().query_file(sha256).download()
        if hashlib.sha256(data).hexdigest() != sha256:
            return sha256, None, "downloaded file has a mismatched SHA-256"
        res = run_isolated(_parse_and_analyze, (data,), timeout=_PARSE_TIMEOUT)
        if res.get("error"):
            return sha256, None, str(res["error"])
        return sha256, res, None
    except Exception as e:  # download / isolation / parse failure for this one
        return sha256, None, str(e)


# ── Database side, main thread only ───────────────────────────────────────────

def backup_database():
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    target = f"{DB}.bak-{stamp}"
    shutil.copy2(DB, target)
    return target


def ensure_progress_table(conn):
    """A sample is 'done' once it appears here, whether or not it yielded new
    IOCs - otherwise a clean sample would be re-downloaded on every run. A
    sample that could not be parsed is recorded too, with the reason in `error`,
    so it is attempted once and never again."""
    conn.execute(
        "CREATE TABLE IF NOT EXISTS dex_backfill_done ("
        "sha256 TEXT PRIMARY KEY, done_at TEXT, error TEXT)"
    )
    # Legacy table from an earlier run had no error column.
    try:
        conn.execute("ALTER TABLE dex_backfill_done ADD COLUMN error TEXT")
    except sqlite3.OperationalError:
        pass  # column already there
    conn.commit()


def pending_samples(conn, limit=None):
    conn.row_factory = sqlite3.Row
    sql = ("SELECT s.sha256, s.package, s.filename FROM samples s "
           "WHERE s.sha256 NOT IN (SELECT sha256 FROM dex_backfill_done) "
           "ORDER BY s.first_seen DESC")
    if limit:
        sql += f" LIMIT {int(limit)}"
    rows = conn.execute(sql).fetchall()
    return [dict(r) for r in rows]


def existing_iocs(conn, sha256):
    """The (ioc_type, value) pairs already on record for a sample, so the
    backfill never duplicates a row."""
    return {
        (r[0], r[1])
        for r in conn.execute(
            "SELECT ioc_type, value FROM iocs WHERE sha256=? AND ioc_type IN (?, ?)",
            (sha256, *_BACKFILL_TYPES),
        )
    }


def _store(conn, sha256, res):
    """Insert the missing domain / targeted_app rows for one sample and mark it
    done. Returns (new_domains, new_pl_domains, new_targets)."""
    have = existing_iocs(conn, sha256)
    now = _now()
    new_rows, n_pl = [], 0
    for dom in res["domains"]:
        value = _normalize_ioc("domain", dom)
        if ("domain", value) not in have:
            new_rows.append(("domain", value))
            have.add(("domain", value))
            if value.endswith(".pl"):
                n_pl += 1
    for pkg in res["targeted"]:
        value = _normalize_ioc("targeted_app", pkg)
        if ("targeted_app", value) not in have:
            new_rows.append(("targeted_app", value))
            have.add(("targeted_app", value))

    for ioc_type, value in new_rows:
        conn.execute(
            "INSERT INTO iocs (sha256, ioc_type, value, first_seen) VALUES (?, ?, ?, ?)",
            (sha256, ioc_type, value, now),
        )
    conn.execute(
        "INSERT OR REPLACE INTO dex_backfill_done (sha256, done_at, error) "
        "VALUES (?, ?, NULL)",
        (sha256, now),
    )
    conn.commit()
    n_dom = sum(1 for t, _ in new_rows if t == "domain")
    n_tgt = sum(1 for t, _ in new_rows if t == "targeted_app")
    return n_dom, n_pl, n_tgt


def _mark_error(conn, sha256, err):
    """Record a sample we could not parse as done, with the reason, so it is
    tried once and not re-downloaded on every later run."""
    conn.execute(
        "INSERT OR REPLACE INTO dex_backfill_done (sha256, done_at, error) "
        "VALUES (?, ?, ?)",
        (sha256, _now(), err[:200]),
    )
    conn.commit()


def main():
    apply_ = "--apply" in sys.argv
    limit = None
    if "--limit" in sys.argv:
        limit = int(sys.argv[sys.argv.index("--limit") + 1])
    workers = _DEFAULT_WORKERS
    if "--workers" in sys.argv:
        workers = max(1, int(sys.argv[sys.argv.index("--workers") + 1]))

    conn = sqlite3.connect(DB)
    ensure_progress_table(conn)
    targets = pending_samples(conn, limit)

    print("MODE:", "APPLY" if apply_ else "PREVIEW (nothing will be downloaded)")
    print(f"Samples not yet backfilled: {len(targets)}")
    print()

    if not apply_:
        for r in targets[:10]:
            print("   %s  %s" % (r["sha256"][:16], r["package"] or "(no package)"))
        if len(targets) > 10:
            print(f"   ... and {len(targets) - 10} more")
        print()
        print("Every sample is downloaded from MWDB, so this takes a while.")
        print(f"Run with --apply to execute (default {_DEFAULT_WORKERS} parallel workers).")
        conn.close()
        return

    if not targets:
        print("Nothing to backfill.")
        conn.close()
        return

    conn.close()  # reopen after the backup so the file is quiescent when copied
    print("Database backup:", backup_database())
    print(f"Workers: {workers}")
    print()

    conn = sqlite3.connect(DB)
    labels = {r["sha256"]: (r["package"] or r["filename"] or r["sha256"][:16])
              for r in targets}
    total = len(targets)
    stats = {"samples": 0, "domains": 0, "pl_domains": 0, "targets": 0,
             "with_new": 0, "error": 0}
    i = 0
    pool = ThreadPoolExecutor(max_workers=workers)
    try:
        futures = {pool.submit(_fetch_and_parse, r["sha256"]): r["sha256"]
                   for r in targets}
        for fut in as_completed(futures):
            i += 1
            sha256, res, err = fut.result()
            label = labels.get(sha256, sha256[:16])[:34]
            if err:
                stats["error"] += 1
                _mark_error(conn, sha256, err)  # done-with-error: never retried
                print("  [%d/%d] %-34s ERROR: %s" % (i, total, label, err[:60]))
                continue
            n_dom, n_pl, n_tgt = _store(conn, sha256, res)
            stats["samples"] += 1
            stats["domains"] += n_dom
            stats["pl_domains"] += n_pl
            stats["targets"] += n_tgt
            note = ""
            if n_dom or n_tgt:
                stats["with_new"] += 1
                parts = []
                if n_dom:
                    parts.append(f"+{n_dom} domain" + (f" ({n_pl} .pl)" if n_pl else ""))
                if n_tgt:
                    parts.append(f"+{n_tgt} targeted_app")
                note = "  " + ", ".join(parts)
            print("  [%d/%d] %-34s%s" % (i, total, label, note))
    except KeyboardInterrupt:
        print()
        print("Interrupted. Everything stored so far is committed - just run it again.")
        pool.shutdown(wait=False, cancel_futures=True)
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
        conn.close()

    print()
    print("Summary:")
    print("   samples processed     %d" % stats["samples"])
    print("   samples gaining IOCs   %d" % stats["with_new"])
    print("   new domain rows       %d  (of which .pl: %d)" % (stats["domains"], stats["pl_domains"]))
    print("   new targeted_app rows %d" % stats["targets"])
    if stats["error"]:
        print("   errors                %d" % stats["error"])


if __name__ == "__main__":
    main()
