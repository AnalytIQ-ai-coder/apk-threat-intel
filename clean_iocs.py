"""One-off cleanup of IOCs stored before wallet validation existed.

Drops BTC/TRON addresses that fail Base58Check/bech32 (the regex used to catch
32-character hashes and Java class names) and trims control characters from the
remaining values. Long URLs are left alone - those are often genuine.

Usage:
    python clean_iocs.py            # preview, writes nothing
    python clean_iocs.py --apply    # apply the changes (after a backup)
"""
import json
import os
import shutil
import sqlite3
import sys
from datetime import datetime

from dex_analyzer import (_domain_is_ioc, _is_plausible_ip,
                          _is_public_resolver, _drop_sequential_ips)
from ioc_extractor import (_GITHUB_RAW_RE, _is_valid_btc, _is_valid_tron,
                           _is_standard_telegram_link)

DB = os.path.join("output", "threat_intel.db")
WALLET_VALIDATORS = {"wallet_btc": _is_valid_btc, "wallet_tron": _is_valid_tron}


def strip_control_chars(text):
    """Drop anything unprintable; plain spaces survive."""
    return "".join(ch for ch in text if ch.isprintable() or ch in " ")


def backup(path):
    """Copy path next to itself with a timestamp suffix, return the new name."""
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    target = f"{path}.bak-{stamp}"
    shutil.copy2(path, target)
    return target


def junk_rows(c):
    """Return (ids_to_delete, reason_counts) using the same rules as the pipeline.

    This reproduces the filters from ioc_extractor/dex_analyzer exactly, so the
    database ends up agreeing with what a run today would produce.
    """
    ids, reasons = [], {}

    def mark(row_id, reason):
        ids.append(row_id)
        reasons[reason] = reasons.get(reason, 0) + 1

    for ioc_type, valid in WALLET_VALIDATORS.items():
        for r in c.execute("SELECT id, value FROM iocs WHERE ioc_type=?", (ioc_type,)):
            if not valid(r["value"]):
                mark(r["id"], "wallets without a valid checksum")

    for r in c.execute("SELECT id, value FROM iocs WHERE ioc_type='contact_telegram'"):
        if _is_standard_telegram_link(r["value"]):
            mark(r["id"], "standard Telegram deep links")

    for r in c.execute("SELECT id, value FROM iocs WHERE ioc_type='deaddrop_github'"):
        if not _GITHUB_RAW_RE.findall(r["value"]):
            mark(r["id"], "/blob/ links to library repositories")

    # The production rule _is_plausible_ip goes first: it removes X.509 OID
    # fragments (2.5.4.3 = commonName, 2.5.29.15 = keyUsage and friends) that
    # reached the database before it existed. Only the survivors are then put
    # through the sequential heuristic.
    per_sample = {}
    for r in c.execute("SELECT id, sha256, value FROM iocs WHERE ioc_type='ip'"):
        if not _is_plausible_ip(r["value"]):
            mark(r["id"], "OID fragments / subnet masks")
            continue
        if _is_public_resolver(r["value"]):
            mark(r["id"], "public DNS resolvers")
            continue
        per_sample.setdefault(r["sha256"], []).append((r["id"], r["value"]))

    for rows in per_sample.values():
        keep = _drop_sequential_ips({v for _, v in rows})
        for row_id, value in rows:
            if value not in keep:
                mark(row_id, "sequential pseudo-IPs (version numbers)")

    # Domains: _DOMAIN_RE only sees the tail of a string ending in something
    # TLD-shaped, so the database collected Java class names
    # ("StreamBitmapDecoder.com"), GLSL swizzles from shaders ("fragColor.xyz"),
    # package tails ("org.openjsse.net") and documentation placeholders
    # ("www.example.com").
    for r in c.execute("SELECT id, value FROM iocs WHERE ioc_type='domain'"):
        if not _domain_is_ioc(r["value"]):
            mark(r["id"], "code identifiers posing as domains")

    return ids, reasons


def clean_database(apply_):
    """Clean the IOC table. Returns values that vanish from the database entirely."""
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    to_delete, reasons = junk_rows(c)

    to_fix = []
    for r in c.execute("SELECT id, value FROM iocs"):
        cleaned = strip_control_chars(r["value"])
        if cleaned != r["value"]:
            to_fix.append((r["id"], cleaned))

    for reason, count in sorted(reasons.items(), key=lambda kv: -kv[1]):
        print(f"  {reason:.<42} {count}")
    print(f"  {'values with control characters':.<42} {len(to_fix)} (to be trimmed)")

    # IOCs disappearing from the database completely. Only these get pulled
    # from the exports, so we never delete a value that is genuine in some
    # other sample.
    vanishing = set()
    if to_delete:
        placeholders = ",".join("?" * len(to_delete))
        candidates = {r["value"] for r in
                      c.execute(f"SELECT value FROM iocs WHERE id IN ({placeholders})", to_delete)}
        for value in candidates:
            remaining = c.execute(
                f"SELECT COUNT(*) FROM iocs WHERE value=? AND id NOT IN ({placeholders})",
                [value] + to_delete).fetchone()[0]
            if remaining == 0:
                vanishing.add(value)

    # --- domain case normalisation ---
    # The equivalent of threat_db._normalize_ioc for rows written earlier. DNS
    # is case-insensitive, so "LITEAPKS.COM", "Liteapks.com" and "liteapks.com"
    # are one host sitting in the database as three rows that never correlate.
    already_queued = {i for i, _ in to_fix}
    being_deleted = set(to_delete)
    lowercased = []
    for r in c.execute("SELECT id, value FROM iocs WHERE ioc_type='domain'"):
        if r["id"] in already_queued or r["id"] in being_deleted:
            continue
        lower = strip_control_chars(r["value"]).lower()
        if lower != r["value"]:
            lowercased.append((r["id"], lower))
    to_fix.extend(lowercased)

    # After lowercasing, some rows become duplicates within the same sample.
    # Keep the oldest (lowest id). These go in their own list and NOT into
    # to_delete: the value itself is not leaving the database, only its
    # spelling changes, so it must not be cut from the exports.
    seen, duplicates_after_normalising = set(), []
    for r in c.execute("SELECT id, sha256, value FROM iocs WHERE ioc_type='domain' ORDER BY id"):
        key = (r["sha256"], strip_control_chars(r["value"]).lower())
        if key in seen:
            duplicates_after_normalising.append(r["id"])
        else:
            seen.add(key)

    removed = set(to_delete) | set(duplicates_after_normalising)
    to_fix = [(i, v) for i, v in to_fix if i not in removed]
    print(f"  {'domains to lowercase':.<42} {len(lowercased)}")
    print(f"  {'duplicates after normalisation':.<42} {len(duplicates_after_normalising)}")

    if apply_ and (to_delete or to_fix or duplicates_after_normalising):
        c.executemany("DELETE FROM iocs WHERE id=?",
                      [(i,) for i in list(to_delete) + duplicates_after_normalising])
        c.executemany("UPDATE iocs SET value=? WHERE id=?",
                      [(v, i) for i, v in to_fix])
        conn.commit()
        conn.execute("VACUUM")
    conn.close()
    return vanishing


def clean_csv(path, apply_):
    """Apply the same filters to the exported iocs.csv."""
    if not os.path.exists(path):
        return 0
    import csv
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.reader(f))
    header, data = rows[0], rows[1:]

    # The CSV carries a sha256 column, so sequential IPs are grouped per sample
    # here exactly as they are in the database and at runtime.
    ips_per_sample = {}
    for row in data:
        if row[2] == "ip" and not _is_public_resolver(row[3]):
            ips_per_sample.setdefault(row[0], set()).add(row[3])
    ips_kept = {sha: _drop_sequential_ips(v) for sha, v in ips_per_sample.items()}

    keep = []
    for row in data:
        sha, ioc_type, value = row[0], row[2], row[3]
        valid = WALLET_VALIDATORS.get(ioc_type)
        if valid and not valid(value.lstrip("'")):
            continue
        if ioc_type == "contact_telegram" and _is_standard_telegram_link(value):
            continue
        if ioc_type == "deaddrop_github" and not _GITHUB_RAW_RE.findall(value):
            continue
        if ioc_type == "ip" and (_is_public_resolver(value)
                                 or value not in ips_kept.get(sha, set())):
            continue
        row[3] = strip_control_chars(value)
        keep.append(row)

    dropped = len(data) - len(keep)
    print(f"  {path}: {dropped} rows to remove (out of {len(data)})")
    if apply_ and dropped:
        with open(path, "w", newline="", encoding="utf-8") as f:
            wr = csv.writer(f)
            wr.writerow(header)
            wr.writerows(keep)
    return dropped


def clean_misp(path, apply_, vanishing=()):
    """Clean the MISP event export.

    A MISP event does not tie an attribute back to a sample, so sequential IPs
    cannot be grouped per sample here. We only remove values that left the
    database COMPLETELY - otherwise we would delete an IOC that is genuine in
    some other sample.
    """
    if not os.path.exists(path):
        return 0
    with open(path, encoding="utf-8") as f:
        event = json.load(f)
    attrs = event["Event"]["Attribute"]

    keep = []
    for a in attrs:
        value = a.get("value", "")
        if a.get("type") == "btc" and not _is_valid_btc(value):
            continue
        if value in vanishing:
            continue
        a["value"] = strip_control_chars(value)
        keep.append(a)

    dropped = len(attrs) - len(keep)
    print(f"  {path}: {dropped} attributes to remove (out of {len(attrs)})")
    if apply_ and dropped:
        event["Event"]["Attribute"] = keep
        with open(path, "w", encoding="utf-8") as f:
            json.dump(event, f, indent=2, ensure_ascii=False)
    return dropped


def main():
    apply_ = "--apply" in sys.argv
    print("MODE:", "APPLY" if apply_ else "PREVIEW (nothing will be changed)")
    print()

    targets = [DB,
               os.path.join("output", "iocs.csv"),
               os.path.join("output", "misp_event.json")]
    if apply_:
        print("Backups:")
        for path in targets:
            if os.path.exists(path):
                print("  ", backup(path))
        print()

    print("Threat-intel database:")
    vanishing = clean_database(apply_)
    print()
    print("Exports:")
    clean_csv(os.path.join("output", "iocs.csv"), apply_)
    clean_misp(os.path.join("output", "misp_event.json"), apply_, vanishing)
    print()
    print("Done." if apply_ else "Run with --apply to execute.")


if __name__ == "__main__":
    main()
