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

Usage:
    python backfill_dex_iocs.py                      # preview, downloads nothing
    python backfill_dex_iocs.py --apply              # fetch and backfill
    python backfill_dex_iocs.py --apply --limit 20   # only 20 samples (a test run)

The script is resumable: every processed sample is recorded in a progress table,
so a later run continues where the last one stopped. An interrupted run keeps
everything it committed.
"""
import hashlib
import os
import shutil
import sqlite3
import sys
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


def _now():
    return datetime.now(timezone.utc).isoformat()


def backup_database():
    """Copy the database next to itself with a timestamp, return the new name."""
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    target = f"{DB}.bak-{stamp}"
    shutil.copy2(DB, target)
    return target


def ensure_progress_table(conn):
    """A sample is 'done' once it appears here, whether or not it yielded new
    IOCs - otherwise a clean sample would be re-downloaded on every run."""
    conn.execute(
        "CREATE TABLE IF NOT EXISTS dex_backfill_done ("
        "sha256 TEXT PRIMARY KEY, done_at TEXT)"
    )
    conn.commit()


def pending_samples(conn, limit=None):
    """Samples not yet processed by this backfill, newest first."""
    conn.row_factory = sqlite3.Row
    sql = ("SELECT s.sha256, s.package, s.filename FROM samples s "
           "WHERE s.sha256 NOT IN (SELECT sha256 FROM dex_backfill_done) "
           "ORDER BY s.first_seen DESC")
    if limit:
        sql += f" LIMIT {int(limit)}"
    rows = conn.execute(sql).fetchall()
    return [dict(r) for r in rows]


def reparse_sample(mwdb, sha256):
    """Fetch one sample and re-derive its domains + target list, in memory.

    Returns (domains, targeted_packages). Raises on download or hash mismatch;
    a parse that fails inside the isolated child is reported by the caller.
    """
    data = mwdb.query_file(sha256).download()
    if hashlib.sha256(data).hexdigest() != sha256:
        raise ValueError("downloaded file has a mismatched SHA-256")

    # targeted_packages is gated on the manifest's permissions, and own_package
    # keeps a sample off its own target list, so the manifest is parsed first.
    manifest = run_isolated(parse_apk_bytes, (data,), timeout=90)
    own_pkg = manifest.get("package") or ""
    perms = tuple(manifest.get("permissions") or ())

    dex = run_isolated(analyze_dex_bytes, (data, own_pkg, tuple(perms)), timeout=120)
    if dex.get("error"):
        raise ValueError(dex["error"])
    return dex.get("domains", []) or [], dex.get("targeted_packages", []) or []


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


def main():
    apply_ = "--apply" in sys.argv
    limit = None
    if "--limit" in sys.argv:
        limit = int(sys.argv[sys.argv.index("--limit") + 1])

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
        print("Run with --apply to execute.")
        conn.close()
        return

    if not targets:
        print("Nothing to backfill.")
        conn.close()
        return

    conn.close()  # reopen after the backup so the file is quiescent when copied
    print("Database backup:", backup_database())
    print()

    mwdb = get_client()
    conn = sqlite3.connect(DB)

    stats = {"samples": 0, "domains": 0, "pl_domains": 0, "targets": 0,
             "with_new": 0, "error": 0}
    try:
        for i, r in enumerate(targets, 1):
            sha256 = r["sha256"]
            label = r["package"] or r["filename"] or sha256[:16]
            try:
                domains, targeted = reparse_sample(mwdb, sha256)
            except Exception as e:
                stats["error"] += 1
                print("  [%d/%d] %-34s ERROR: %s" % (i, len(targets), label[:34], str(e)[:60]))
                continue

            have = existing_iocs(conn, sha256)
            now = _now()
            new_rows, n_pl = [], 0
            for dom in domains:
                value = _normalize_ioc("domain", dom)
                if ("domain", value) not in have:
                    new_rows.append(("domain", value))
                    have.add(("domain", value))
                    if value.endswith(".pl"):
                        n_pl += 1
            for pkg in targeted:
                value = _normalize_ioc("targeted_app", pkg)
                if ("targeted_app", value) not in have:
                    new_rows.append(("targeted_app", value))
                    have.add(("targeted_app", value))

            for ioc_type, value in new_rows:
                conn.execute(
                    "INSERT INTO iocs (sha256, ioc_type, value, first_seen) "
                    "VALUES (?, ?, ?, ?)",
                    (sha256, ioc_type, value, now),
                )
            conn.execute(
                "INSERT OR REPLACE INTO dex_backfill_done (sha256, done_at) VALUES (?, ?)",
                (sha256, now),
            )
            conn.commit()

            n_dom = sum(1 for t, _ in new_rows if t == "domain")
            n_tgt = sum(1 for t, _ in new_rows if t == "targeted_app")
            stats["samples"] += 1
            stats["domains"] += n_dom
            stats["pl_domains"] += n_pl
            stats["targets"] += n_tgt
            if new_rows:
                stats["with_new"] += 1
            note = ""
            if n_dom or n_tgt:
                parts = []
                if n_dom:
                    parts.append(f"+{n_dom} domain" + (f" ({n_pl} .pl)" if n_pl else ""))
                if n_tgt:
                    parts.append(f"+{n_tgt} targeted_app")
                note = "  " + ", ".join(parts)
            print("  [%d/%d] %-34s%s" % (i, len(targets), label[:34], note))
    except KeyboardInterrupt:
        print()
        print("Interrupted. Everything done so far is committed - just run it again.")
    finally:
        conn.close()

    print()
    print("Summary:")
    print("   samples processed   %d" % stats["samples"])
    print("   samples gaining IOCs %d" % stats["with_new"])
    print("   new domain rows     %d  (of which .pl: %d)" % (stats["domains"], stats["pl_domains"]))
    print("   new targeted_app rows %d" % stats["targets"])
    if stats["error"]:
        print("   errors              %d" % stats["error"])


if __name__ == "__main__":
    main()
