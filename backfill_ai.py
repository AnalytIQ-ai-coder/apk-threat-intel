"""Fill in the AI risk ratings that were never produced.

Why there are holes: assess_risk talks to a local Ollama instance. When Ollama
is not running the call raises, the pipeline stores {"error": ...}, threat_db
writes NULL into ai_risk and the run carries on - the right behaviour for a
single sample, but it means a run started before Ollama was up finishes with no
ratings at all. In output/threat_intel.db the gaps come in whole days
(2026-09-08: 0 of 64 rated, 2026-09-13: 0 of 20, 2026-09-15: 0 of 20) and add
up to 1038 non-split samples with no rating, 277 of them at VT >= 5.

Scope: only rows with split_name = '' - samples that went through split
detection and are not splits. Rows with split_name IS NULL were never checked
and may well be config splits; rating those would recreate exactly the "RISK:
low, no permissions" fabrication that backfill_splits.py exists to undo. Run
backfill_splits.py --apply first if you want those rows in scope too.

Samples are taken worst-first (highest VirusTotal detection count), so an
interrupted run has already done the ones worth having.

One difference from the live path: VirusTotal is not re-queried. The detection
count comes from the database, but the threat label was never stored, so the
model sees "35/74 detected, threat label: none" where a live run would have
shown "trojan.spynote". Ratings produced here are, if anything, conservative.

Usage:
    python backfill_ai.py                       # preview, downloads nothing
    python backfill_ai.py --apply               # fetch, rate and store
    python backfill_ai.py --apply --limit 20    # a test run
    python backfill_ai.py --apply --min-vt 5    # only samples VT >= 5

Resumable: a sample is only written once a rating comes back, so a run that
dies halfway - or any failure caused by Ollama going away again - leaves the
row untouched and the next run picks it up.
"""
import hashlib
import os
import shutil
import sqlite3
import sys
from datetime import datetime

import requests

from ai_analyzer import OLLAMA_URL, MODEL, assess_risk
from dex_analyzer import analyze_dex_bytes
from isolation import run_isolated
from manifest_parser import parse_apk_bytes, split_has_no_code
from mwdb_client import get_client
import threat_db

DB = os.path.join("output", "threat_intel.db")


def backup_database():
    """Copy the database next to itself with a timestamp, return the new name."""
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    target = f"{DB}.bak-{stamp}"
    shutil.copy2(DB, target)
    return target


def ollama_is_ready():
    """Check the model is actually served before downloading a single sample.

    Ollama being absent is the whole reason these gaps exist, so it is worth
    one HTTP call up front rather than finding out 300 downloads in.
    """
    tags_url = OLLAMA_URL.replace("/api/generate", "/api/tags")
    try:
        response = requests.get(tags_url, timeout=10)
        response.raise_for_status()
    except requests.RequestException as e:
        return False, f"Ollama unreachable at {tags_url}: {e}"

    names = [m.get("name", "") for m in response.json().get("models", [])]
    if MODEL not in names:
        return False, (f"Ollama is up but {MODEL} is not among its models: "
                       f"{', '.join(names) or '(none)'}")
    return True, f"Ollama ready, {MODEL} available"


def candidates(limit=None, min_vt=0):
    """Unrated samples that are known not to be splits, worst first."""
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    sql = ("SELECT sha256, package, app_name, filename, vt_malicious, vt_total, first_seen "
           "FROM samples "
           "WHERE (ai_risk IS NULL OR ai_risk='') AND split_name='' "
           "  AND COALESCE(vt_malicious, 0) >= ? "
           "ORDER BY COALESCE(vt_malicious, 0) DESC, first_seen DESC")
    if limit:
        sql += f" LIMIT {int(limit)}"
    rows = conn.execute(sql, (int(min_vt),)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def count_never_split_checked():
    """Unrated rows backfill_splits.py has not reached yet - out of scope here."""
    conn = sqlite3.connect(DB)
    n = conn.execute("SELECT COUNT(*) FROM samples "
                     "WHERE (ai_risk IS NULL OR ai_risk='') AND split_name IS NULL").fetchone()[0]
    conn.close()
    return n


def rebuild_sample(mwdb, row):
    """Fetch a sample and rebuild the fields assess_risk reads.

    The APK never touches the disk. Both parsers run in a child process under a
    deadline, the same way the live pipeline isolates them: hostile input can
    hang androguard or exhaust memory, and one bad sample must not take the
    whole backfill down with it.
    """
    sha256 = row["sha256"]
    apk_bytes = mwdb.query_file(sha256).download()
    if hashlib.sha256(apk_bytes).hexdigest() != sha256:
        raise ValueError("downloaded file has a mismatched SHA-256")

    parsed = run_isolated(parse_apk_bytes, (apk_bytes,), timeout=90)
    permissions = parsed.get("permissions") or []
    parsed["dex"] = run_isolated(
        analyze_dex_bytes,
        (apk_bytes, parsed.get("package") or "", tuple(permissions)),
        timeout=120,
    )
    parsed["sha256"] = sha256
    # From the database, not from VirusTotal: re-querying a thousand samples
    # would burn days of the free 500/day quota to add nothing the model
    # actually weighs. The threat label was never stored, so it stays absent.
    parsed["vt"] = {"malicious": row["vt_malicious"], "total": row["vt_total"]}
    return parsed


def _arg_value(flag, default=None):
    if flag in sys.argv:
        return int(sys.argv[sys.argv.index(flag) + 1])
    return default


def preview(targets, never_checked):
    for r in targets[:15]:
        print("   %s  %-38s %-22s %s/%s" % (
            r["sha256"][:16],
            (r["package"] or "(no package)")[:38],
            (r["app_name"] or "")[:22],
            r["vt_malicious"] if r["vt_malicious"] is not None else "-",
            r["vt_total"] if r["vt_total"] is not None else "-"))
    if len(targets) > 15:
        print(f"   ... and {len(targets) - 15} more")
    print()
    ready, message = ollama_is_ready()
    print(("   " if ready else "   ! ") + message)
    print()
    print("Every sample is downloaded from MWDB and re-analysed, so this takes a while.")
    print("Run with --apply to execute.")


def main():
    apply_ = "--apply" in sys.argv
    limit = _arg_value("--limit")
    min_vt = _arg_value("--min-vt", 0)

    threat_db.init_db()

    targets = candidates(limit, min_vt)
    never_checked = count_never_split_checked()

    print("MODE:", "APPLY" if apply_ else "PREVIEW (nothing will be downloaded)")
    print(f"Samples with no AI rating, confirmed not to be splits: {len(targets)}")
    flagged = [r for r in targets if (r["vt_malicious"] or 0) >= 5]
    print(f"   of which VirusTotal already calls malicious (>= 5 engines): {len(flagged)}")
    if never_checked:
        print(f"   ({never_checked} further unrated rows were never split-checked and are left")
        print("    alone - run backfill_splits.py --apply to bring them into scope)")
    print()

    if not apply_:
        preview(targets, never_checked)
        return

    if not targets:
        print("Nothing to backfill.")
        return

    ready, message = ollama_is_ready()
    print(message)
    if not ready:
        print("Aborting before downloading anything - fix Ollama and run again.")
        sys.exit(1)

    print("Database backup:", backup_database())
    print()

    mwdb = get_client()
    conn = sqlite3.connect(DB)

    stats = {"rated": 0, "turned_out_to_be_split": 0, "ai_failed": 0, "error": 0}
    by_risk = {}
    try:
        for i, r in enumerate(targets, 1):
            sha256 = r["sha256"]
            label = (r["package"] or r["filename"] or sha256[:16])[:36]
            vt = "%s/%s" % (r["vt_malicious"] if r["vt_malicious"] is not None else "-",
                            r["vt_total"] if r["vt_total"] is not None else "-")
            prefix = "  [%d/%d] %-36s %-7s" % (i, len(targets), label, vt)

            try:
                data = rebuild_sample(mwdb, r)
            except Exception as e:
                stats["error"] += 1
                print(f"{prefix} ERROR: {str(e)[:45]}")
                continue

            # split_name said this is not a split, but that column can predate
            # the current detection. Trust the parse we just did over the flag.
            if split_has_no_code(data):
                name = (data.get("split") or {}).get("name") or ""
                conn.execute("UPDATE samples SET split_name=? WHERE sha256=?", (name, sha256))
                conn.commit()
                stats["turned_out_to_be_split"] += 1
                print(f"{prefix} split {name} - not rated")
                continue

            ai = assess_risk(data)
            risk = ai.get("risk")
            if ai.get("error") or not risk or risk == "unknown":
                # Leave the row untouched so a later run retries it. This is
                # the case that produced the gaps in the first place, and
                # writing "unknown" would hide it instead of fixing it.
                stats["ai_failed"] += 1
                reason = ai.get("error") or "unparsable reply"
                print(f"{prefix} AI failed: {str(reason)[:45]}")
                continue

            conn.execute("UPDATE samples SET ai_risk=? WHERE sha256=?", (risk, sha256))
            conn.commit()
            stats["rated"] += 1
            by_risk[risk] = by_risk.get(risk, 0) + 1
            print(f"{prefix} {risk.upper():<8} {ai.get('reason', '')[:60]}")
    except KeyboardInterrupt:
        print()
        print("Interrupted. Everything done so far is committed - just run it again.")
    finally:
        conn.close()

    print()
    print("Summary:")
    for key, value in stats.items():
        if value:
            print("   %-24s %d" % (key, value))
    for risk in ("critical", "high", "medium", "low"):
        if by_risk.get(risk):
            print("   rated %-18s %d" % (risk, by_risk[risk]))
    if stats["ai_failed"]:
        print()
        print("   Rows the model could not rate were left NULL on purpose - run again.")


if __name__ == "__main__":
    main()
