"""SQLite z historią próbek/IOC — pozwala odpowiedzieć na pytania w stylu
"czy ten C2 już widzieliśmy" albo "ile próbek dzieli ten certyfikat"
bez przeszukiwania ręcznie output/results.json z poprzednich uruchomień.
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
    duplicate_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256 TEXT NOT NULL,
    ioc_type TEXT NOT NULL,   -- url, ip, domain, btc, eth, tron, telegram,
                              -- whatsapp, discord_webhook, github_deaddrop,
                              -- firebase_rtdb, pages_dev
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
    with _connect() as conn:
        conn.executescript(_SCHEMA)
        # migracja dla baz utworzonych przed dodaniem duplicate_count
        try:
            conn.execute("ALTER TABLE samples ADD COLUMN duplicate_count INTEGER DEFAULT 0")
        except sqlite3.OperationalError:
            pass


# Publiczne klucze testowe AOSP (testkey/platform/shared/media) sa dolaczone do
# zrodel Androida. Podpisuje nimi kazdy, kto przepakowuje APK — od modderow po
# autorow malware — wiec wspolny podpis nie oznacza wspolnego operatora.
# Korelacja po nich laczyla np. zmodowana gre Unity z trojanem bankowym.
# Uwaga: debug keystore Android Studio ("CN=Android Debug") jest generowany per
# maszyna, wiec jego wspoldzielenie JEST sygnalem i celowo go tu nie ma.
_CERT_SUBJECT_NIEIDENTYFIKUJACE = ("android@android.com",)


def cert_identyfikuje_autora(cert: dict) -> bool:
    """Czy po tym certyfikacie warto korelowac probki."""
    subject = (cert.get("subject") or "").lower()
    return not any(m in subject for m in _CERT_SUBJECT_NIEIDENTYFIKUJACE)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def store_sample(data: dict, iocs: dict) -> dict:
    """Zapisuje próbkę + jej IOC. Zwraca korelacje: co z tych IOC już widzieliśmy."""
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
                vt_malicious, vt_total, malware_families, ai_risk, first_seen, upload_time)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                       COALESCE((SELECT first_seen FROM samples WHERE sha256=?), ?), ?)""",
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
            ),
        )

        # cert reuse — ten sam podpis na wielu próbkach = jeden operator,
        # ale tylko dla certow, ktore w ogole identyfikuja autora
        if cert.get("sha1") and cert_identyfikuje_autora(cert):
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

        # zbierz wszystkie wartości IOC do wstawienia + korelacji
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
    """IOC widziane w największej liczbie różnych próbek — najlepsi kandydaci do zgłoszenia."""
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
    """Zwraca zapisaną próbkę po hashu — używane do dedupu przed pełną analizą."""
    init_db()
    with _connect() as conn:
        row = conn.execute("SELECT * FROM samples WHERE sha256=?", (sha256,)).fetchone()
        return dict(row) if row else None


def mark_duplicate(sha256: str, filename: str) -> None:
    """Odnotowuje, że dana próbka pojawiła się ponownie pod inną nazwą pliku,
    bez powtarzania pełnej analizy (VT/MobSF/AI)."""
    init_db()
    with _connect() as conn:
        conn.execute(
            "UPDATE samples SET duplicate_count = COALESCE(duplicate_count, 0) + 1 WHERE sha256=?",
            (sha256,),
        )


def recent_samples(limit: int = 50) -> list[dict]:
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM samples ORDER BY first_seen DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_iocs_for_sample(sha256: str) -> list[dict]:
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            "SELECT ioc_type, value, first_seen FROM iocs WHERE sha256=? ORDER BY ioc_type",
            (sha256,),
        ).fetchall()
        return [dict(r) for r in rows]


def search_ioc(term: str, limit: int = 50) -> list[dict]:
    """Szuka IOC po fragmencie wartości i zwraca próbki, w których wystąpił."""
    init_db()
    # % i _ w zapytaniu uzytkownika sa wildcardami LIKE - bez neutralizacji
    # szukanie 100_200 trafia takze w 100x200. Jako znak ucieczki bierzemy '!',
    # zeby nie mnozyc odwrotnych ukosnikow w SQL-u.
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
