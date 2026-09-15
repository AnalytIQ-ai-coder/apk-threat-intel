"""Backfill missing certificates for samples stored before v2/v3 signature
support existed (see cert_analyzer.extract_cert_der).

The old code only read the JAR signature (v1), so APKs built for SDK 30+ landed
in the database with cert_sha1 = NULL and could not be clustered by signature.
This script re-fetches those samples from MWDB, extracts the certificate alone
and fills the gap. Nothing is written to disk.

Usage:
    python backfill_certs.py                      # preview, downloads nothing
    python backfill_certs.py --apply              # fetch and backfill
    python backfill_certs.py --apply --limit 20   # only 20 samples (a test run)

The script is resumable: it only picks rows with cert_sha1 IS NULL, so a later
run continues where the last one stopped.
"""
import hashlib
import os
import shutil
import sqlite3
import sys
from datetime import datetime

from isolation import run_isolated
from manifest_parser import parse_apk_bytes
from mwdb_client import get_client

DB = os.path.join("output", "threat_intel.db")


def backup_database():
    """Copy the database next to itself with a timestamp, return the new name."""
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    target = f"{DB}.bak-{stamp}"
    shutil.copy2(DB, target)
    return target


def samples_without_cert(limit=None):
    """Rows that never got a certificate, newest first."""
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    sql = ("SELECT sha256, package, filename FROM samples "
           "WHERE cert_sha1 IS NULL ORDER BY first_seen DESC")
    if limit:
        sql += f" LIMIT {int(limit)}"
    rows = conn.execute(sql).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def cert_for_sample(mwdb, sha256):
    """Fetch one sample and extract its certificate. Returns the cert dict or None.

    The sample never touches the disk: on Windows, Defender flags saved malware
    and blocks reopening the file (which surfaces as "[Errno 22] Invalid
    argument"). Parsing runs from memory, in a child process under a timeout.
    """
    data = mwdb.query_file(sha256).download()
    if hashlib.sha256(data).hexdigest() != sha256:
        raise ValueError("downloaded file has a mismatched SHA-256")
    parsed = run_isolated(parse_apk_bytes, (data,), timeout=90)
    return parsed.get("cert")


def main():
    apply_ = "--apply" in sys.argv
    limit = None
    if "--limit" in sys.argv:
        limit = int(sys.argv[sys.argv.index("--limit") + 1])

    targets = samples_without_cert(limit)
    print("MODE:", "APPLY" if apply_ else "PREVIEW (nothing will be downloaded)")
    print(f"Samples without a certificate: {len(targets)}")
    print()

    if not apply_:
        for r in targets[:10]:
            print("   %s  %s" % (r["sha256"][:16], r["package"] or "(no package)"))
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

    stats = {"v1": 0, "v2": 0, "v3": 0, "no_signature": 0, "error": 0}
    try:
        for i, r in enumerate(targets, 1):
            sha256 = r["sha256"]
            label = r["package"] or r["filename"] or sha256[:16]
            try:
                cert = cert_for_sample(mwdb, sha256)
            except Exception as e:
                stats["error"] += 1
                print("  [%d/%d] %-34s ERROR: %s" % (i, len(targets), label[:34], str(e)[:60]))
                continue

            if not cert or cert.get("error") or not cert.get("sha1"):
                stats["no_signature"] += 1
                reason = (cert or {}).get("error", "no certificate data")
                print("  [%d/%d] %-34s no certificate (%s)" % (
                    i, len(targets), label[:34], reason[:40]))
                continue

            scheme = cert.get("signature_scheme") or "?"
            stats[scheme] = stats.get(scheme, 0) + 1
            conn.execute(
                "UPDATE samples SET cert_sha1=?, cert_subject=? WHERE sha256=?",
                (cert["sha1"], cert.get("subject"), sha256),
            )
            conn.commit()
            print("  [%d/%d] %-34s %s  scheme %s" % (
                i, len(targets), label[:34], cert["sha1"][:16], scheme))
    except KeyboardInterrupt:
        print()
        print("Interrupted. Everything done so far is committed - just run it again.")
    finally:
        conn.close()

    print()
    print("Summary:")
    for key, value in stats.items():
        if value:
            print("   %-14s %d" % (key, value))


if __name__ == "__main__":
    main()
