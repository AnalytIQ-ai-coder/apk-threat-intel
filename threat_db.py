"""SQLite history of samples and IOCs.

Lets us answer "have we seen this C2 before" or "how many samples share this
certificate" without grepping through output/results.json from every previous
run.
"""
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

DB_PATH = os.path.join("output", "threat_intel.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    sha256 TEXT PRIMARY KEY,
    filename TEXT,
    package TEXT,
    app_name TEXT,
    cert_sha1 TEXT,
    cert_subject TEXT,
    vt_malicious INTEGER,
    vt_total INTEGER,
    malware_families TEXT,
    ai_risk TEXT,
    first_seen TEXT,
    upload_time TEXT,
    duplicate_count INTEGER DEFAULT 0,
    -- App Bundle split name, e.g. "config.arm64_v8a". Separates a sample that
    -- has no permissions because it is only a container for libraries or
    -- resources from one that genuinely asks for nothing.
    -- Three states, deliberately distinct:
    --   'config.xxx' -- a split,
    --   ''           -- checked, it is a full APK,
    --   NULL         -- NOT CHECKED (row predates this column).
    -- That is how backfill_splits.py knows what is left to do, and why it can
    -- be interrupted and resumed.
    split_name TEXT
);

CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256 TEXT NOT NULL,
    ioc_type TEXT NOT NULL,   -- url, ip, domain, btc, eth, tron, telegram,
                              -- whatsapp, discord_webhook, github_deaddrop,
                              -- firebase_rtdb, pages_dev, workers_dev, bitbucket
    value TEXT NOT NULL,
    first_seen TEXT,
    FOREIGN KEY (sha256) REFERENCES samples(sha256)
);

CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(ioc_type);
CREATE INDEX IF NOT EXISTS idx_samples_cert ON samples(cert_sha1);
"""


@contextmanager
def _connect():
    os.makedirs("output", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    """Create the schema, and migrate databases made before later columns."""
    with _connect() as conn:
        conn.executescript(_SCHEMA)
        for ddl in (
            "ALTER TABLE samples ADD COLUMN duplicate_count INTEGER DEFAULT 0",
            "ALTER TABLE samples ADD COLUMN split_name TEXT",
        ):
            try:
                conn.execute(ddl)
            except sqlite3.OperationalError:
                pass  # column already there


# The public AOSP test keys (testkey/platform/shared/media) ship with the
# Android source. Everyone who repackages an APK signs with them, from modders
# to malware authors, so a shared signature does not mean a shared operator.
# Correlating on them linked a modded Unity game to a banking trojan.
# Note: the Android Studio debug keystore ("CN=Android Debug") is generated per
# machine, so sharing one IS a signal and it is deliberately absent from here.
_NON_IDENTIFYING_CERT_SUBJECTS = ("android@android.com",)


def cert_identifies_author(cert: dict) -> bool:
    """Is this certificate worth correlating samples on?"""
    subject = (cert.get("subject") or "").lower()
    return not any(m in subject for m in _NON_IDENTIFYING_CERT_SUBJECTS)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_ioc(ioc_type: str, value: str) -> str:
    """Lowercase domains. Domains only.

    DNS is case-insensitive, so "LITEAPKS.COM", "Liteapks.com" and
    "liteapks.com" are one host. Without this they sit in the database as three
    separate rows that never correlate: the reuse query compares values with
    "=", which is case-sensitive in SQLite, so the same domain in different
    samples produced no link at all.

    What must NOT be touched here:
      * url         - path and query are case-sensitive, "/AbC" is not "/abc";
      * wallet_eth  - the capitalisation carries the EIP-55 checksum;
      * wallet_btc / wallet_tron - Base58Check will not survive the change;
      * contacts (telegram, discord) - handles are displayed verbatim.

    The "a capital letter means this came from an identifier" signal is not
    lost: _domain_is_ioc settles that before anything reaches the database.
    """
    if ioc_type == "domain":
        return value.lower()
    return value


def store_sample(data: dict, iocs: dict) -> dict:
    """Store a sample and its IOCs. Returns which of those we had seen before."""
    init_db()
    sha256 = data.get("sha256", "")
    if not sha256:
        return {"correlations": []}

    cert = data.get("cert") or {}
    dex = data.get("dex") or {}
    ai = data.get("ai") or {}
    vt = data.get("vt") or {}

    now = _now()
    correlations = []

    with _connect() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO samples
               (sha256, filename, package, app_name, cert_sha1, cert_subject,
                vt_malicious, vt_total, malware_families, ai_risk, first_seen, upload_time,
                split_name)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                       COALESCE((SELECT first_seen FROM samples WHERE sha256=?), ?), ?, ?)""",
            (
                sha256,
                data.get("filename"),
                data.get("package"),
                data.get("app_name"),
                cert.get("sha1"),
                cert.get("subject"),
                vt.get("malicious"),
                vt.get("total"),
                ",".join(dex.get("malware_frameworks", []) or []),
                ai.get("risk"),
                sha256, now,
                data.get("upload_time"),
                # Empty string, not NULL: this sample went through split
                # detection and is not one. NULL is reserved for rows that were
                # never checked.
                (data.get("split") or {}).get("name") or "",
            ),
        )

        # Certificate reuse: the same signature on many samples means one
        # operator, but only for certificates that identify anyone at all.
        if cert.get("sha1") and cert_identifies_author(cert):
            rows = conn.execute(
                "SELECT sha256, filename FROM samples WHERE cert_sha1=? AND sha256<>?",
                (cert["sha1"], sha256),
            ).fetchall()
            if rows:
                correlations.append({
                    "type": "shared_certificate",
                    "value": cert["sha1"],
                    "seen_in": [dict(r) for r in rows],
                })

        # Flatten every IOC value into (type, value) pairs to insert and correlate.
        flat = []
        for url in dex.get("urls", []) or []:
            flat.append(("url", url))
        for ip in dex.get("ips", []) or []:
            flat.append(("ip", ip))
        for dom in dex.get("domains", []) or []:
            flat.append(("domain", dom))

        if iocs and not iocs.get("error"):
            for kind, values in iocs.get("wallets", {}).items():
                for v in values:
                    flat.append((f"wallet_{kind}", v))
            for kind, values in iocs.get("operator_contacts", {}).items():
                for v in values:
                    flat.append((f"contact_{kind}", v))
            for v in iocs.get("discord_webhooks", []):
                flat.append(("discord_webhook", v))
            for kind, values in iocs.get("dead_drops", {}).items():
                for v in values:
                    flat.append((f"deaddrop_{kind}", v))

        for ioc_type, value in flat:
            value = _normalize_ioc(ioc_type, value)
            existing = conn.execute(
                "SELECT DISTINCT s.sha256, s.filename FROM iocs i "
                "JOIN samples s ON s.sha256 = i.sha256 "
                "WHERE i.value=? AND i.sha256<>?",
                (value, sha256),
            ).fetchall()
            if existing:
                correlations.append({
                    "type": "reused_ioc",
                    "ioc_type": ioc_type,
                    "value": value,
                    "seen_in": [dict(r) for r in existing],
                })
            conn.execute(
                "INSERT INTO iocs (sha256, ioc_type, value, first_seen) VALUES (?, ?, ?, ?)",
                (sha256, ioc_type, value, now),
            )

    return {"correlations": correlations}


def top_reused_iocs(limit: int = 20) -> list[dict]:
    """IOCs seen across the most distinct samples - the best abuse-report candidates."""
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            """SELECT ioc_type, value, COUNT(DISTINCT sha256) AS sample_count
               FROM iocs GROUP BY ioc_type, value
               HAVING sample_count > 1
               ORDER BY sample_count DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


def stats() -> dict:
    """Headline counts for the end-of-run summary."""
    init_db()
    with _connect() as conn:
        n_samples = conn.execute("SELECT COUNT(*) FROM samples").fetchone()[0]
        n_iocs = conn.execute("SELECT COUNT(DISTINCT value) FROM iocs").fetchone()[0]
        n_certs = conn.execute(
            "SELECT COUNT(DISTINCT cert_sha1) FROM samples WHERE cert_sha1 IS NOT NULL"
        ).fetchone()[0]
        n_dupes = conn.execute(
            "SELECT COALESCE(SUM(duplicate_count), 0) FROM samples"
        ).fetchone()[0]
        return {
            "samples": n_samples, "unique_iocs": n_iocs,
            "unique_certs": n_certs, "duplicates_skipped": n_dupes,
        }


def get_sample(sha256: str) -> dict | None:
    """Fetch a stored sample by hash - used to dedupe before the full analysis."""
    init_db()
    with _connect() as conn:
        row = conn.execute("SELECT * FROM samples WHERE sha256=?", (sha256,)).fetchone()
        return dict(row) if row else None


def mark_duplicate(sha256: str, filename: str) -> None:
    """Record that a known sample showed up again under a different filename.

    Cheaper than repeating the full VT/MobSF/AI pass for bytes we already have.
    """
    init_db()
    with _connect() as conn:
        conn.execute(
            "UPDATE samples SET duplicate_count = COALESCE(duplicate_count, 0) + 1 WHERE sha256=?",
            (sha256,),
        )


def recent_samples(limit: int = 50) -> list[dict]:
    """Most recently seen samples, newest first."""
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM samples ORDER BY first_seen DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_iocs_for_sample(sha256: str) -> list[dict]:
    """Every IOC recorded for one sample."""
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            "SELECT ioc_type, value, first_seen FROM iocs WHERE sha256=? ORDER BY ioc_type",
            (sha256,),
        ).fetchall()
        return [dict(r) for r in rows]


def search_ioc(term: str, limit: int = 50) -> list[dict]:
    """Substring search over IOC values, returning the samples they appeared in."""
    init_db()
    # % and _ in the user's term are LIKE wildcards. Left alone, a search for
    # 100_200 also matches 100x200. We escape with '!' rather than backslash to
    # avoid doubling escapes through the SQL string.
    escaped = term.replace('!', '!!').replace('%', '!%').replace('_', '!_')
    with _connect() as conn:
        rows = conn.execute(
            """SELECT i.ioc_type, i.value, s.sha256, s.filename, s.package
               FROM iocs i JOIN samples s ON s.sha256 = i.sha256
               WHERE i.value LIKE ? ESCAPE '!'
               ORDER BY i.value LIMIT ?""",
            (f"%{escaped}%", limit),
        ).fetchall()
        return [dict(r) for r in rows]
