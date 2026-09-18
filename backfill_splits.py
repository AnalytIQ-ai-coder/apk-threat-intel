"""Work out retroactively which stored samples are App Bundle splits.

The problem this fixes: an AAB install is base.apk plus a set of splits
(config.arm64_v8a, config.xxhdpi, config.pl...). A config split is not an
application - no label, no permissions, no minSdk and usually no code. Dropped
into the pipeline as a standalone sample it looked like an app that "requests
no permissions", and the model was handed a prompt of empty fields and duly
answered "RISK: low, no permissions". In output/threat_intel.db 164 rows carry
a 'low' rating produced exactly that way. That is a false negative conjured out
of nothing, not an assessment of a sample.

manifest_parser.detect_split now catches this as samples arrive. This script
fills in the rows written before it did.

Scope: only samples with no app label (app_name empty). A full APK with a label
is not a config split - a split has nothing to label - so there is no point
downloading 1245 files to confirm it.

Usage:
    python backfill_splits.py                      # preview, downloads nothing
    python backfill_splits.py --apply              # fetch and backfill
    python backfill_splits.py --apply --limit 20   # only 20 samples (a test run)

The script is resumable: it takes rows with split_name IS NULL and marks every
sample it checks (either the split name or an empty string), so a later run
continues where the last one stopped.
"""
import hashlib
import os
import shutil
import sqlite3
import sys
from datetime import datetime

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


def candidates(limit=None):
    """Samples never checked and carrying no label - the ones that could be splits."""
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    sql = ("SELECT sha256, package, filename, ai_risk FROM samples "
           "WHERE split_name IS NULL AND (app_name IS NULL OR app_name='') "
           "ORDER BY first_seen DESC")
    if limit:
        sql += f" LIMIT {int(limit)}"
    rows = conn.execute(sql).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def split_for_sample(mwdb, sha256):
    """Fetch a sample and return (split description or None, whether to skip AI).

    The sample never touches the disk: on Windows, Defender flags saved malware
    and blocks reopening the file. Parsing runs from memory, in a child process
    under a timeout, exactly as backfill_certs.py does it.
    """
    data = mwdb.query_file(sha256).download()
    if hashlib.sha256(data).hexdigest() != sha256:
        raise ValueError("downloaded file has a mismatched SHA-256")
    parsed = run_isolated(parse_apk_bytes, (data,), timeout=90)
    return parsed.get("split"), split_has_no_code(parsed)


def main():
    apply_ = "--apply" in sys.argv
    limit = None
    if "--limit" in sys.argv:
        limit = int(sys.argv[sys.argv.index("--limit") + 1])

    # The split_name column may not exist yet - the migration lives in init_db.
    threat_db.init_db()

    targets = candidates(limit)
    print("MODE:", "APPLY" if apply_ else "PREVIEW (nothing will be downloaded)")
    print(f"Samples to check: {len(targets)}")
    fabricated = [r for r in targets if r["ai_risk"]]
    print(f"   of which carry an AI rating that may be conjured from empty data: {len(fabricated)}")
    print()

    if not apply_:
        for r in targets[:10]:
            print("   %s  %-40s ai_risk=%s" % (
                r["sha256"][:16], (r["package"] or "(no package)")[:40], r["ai_risk"]))
        if len(targets) > 10:
            print(f"   ... and {len(targets) - 10} more")
        print()
        print("Every sample is downloaded from MWDB, so this takes a while.")
        print("Run with --apply to execute.")
        return

    if not targets:
        print("Nothing to backfill.")
        return

    print("Database backup:", backup_database())
    print()

    mwdb = get_client()
    conn = sqlite3.connect(DB)

    stats = {"split_without_code": 0, "split_with_code": 0, "full_apk": 0,
             "rating_cleared": 0, "error": 0}
    try:
        for i, r in enumerate(targets, 1):
            sha256 = r["sha256"]
            label = (r["package"] or r["filename"] or sha256[:16])[:38]
            try:
                split, no_code = split_for_sample(mwdb, sha256)
            except Exception as e:
                stats["error"] += 1
                print("  [%d/%d] %-38s ERROR: %s" % (i, len(targets), label, str(e)[:50]))
                continue

            name = (split or {}).get("name") or ""

            if not split:
                stats["full_apk"] += 1
                conn.execute("UPDATE samples SET split_name='' WHERE sha256=?", (sha256,))
                conn.commit()
                print("  [%d/%d] %-38s full APK" % (i, len(targets), label))
                continue

            # An AI rating for a split with no code describes an empty prompt
            # rather than the sample, so we clear it instead of letting it drag
            # the picture down when browsing the database. A "feature" split
            # keeps its rating: it has its own code, so the model had something
            # to work with.
            clear_rating = no_code and r["ai_risk"]
            if clear_rating:
                conn.execute("UPDATE samples SET split_name=?, ai_risk=NULL WHERE sha256=?",
                             (name, sha256))
                stats["rating_cleared"] += 1
            else:
                conn.execute("UPDATE samples SET split_name=? WHERE sha256=?", (name, sha256))
            conn.commit()

            stats["split_without_code" if no_code else "split_with_code"] += 1
            print("  [%d/%d] %-38s split %-20s %s%s" % (
                i, len(targets), label, name,
                "without code" if no_code else "with code",
                "  (cleared ai_risk=%s)" % r["ai_risk"] if clear_rating else ""))
    except KeyboardInterrupt:
        print()
        print("Interrupted. Everything done so far is committed - just run it again.")
    finally:
        conn.close()

    print()
    print("Summary:")
    for key, value in stats.items():
        if value:
            print("   %-20s %d" % (key, value))


if __name__ == "__main__":
    main()
