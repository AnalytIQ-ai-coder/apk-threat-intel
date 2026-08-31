"""Uzupelnia brakujace certyfikaty dla probek zapisanych przed dodaniem
obslugi schematow podpisu v2/v3 (patrz cert_analyzer._pobierz_cert_der).

Stary kod czytal wylacznie podpis JAR (v1), wiec APK budowane pod SDK 30+
trafialy do bazy z cert_sha1 = NULL i nie dawaly sie klastrowac po podpisie.
Skrypt pobiera te probki ponownie z MWDB, wyciaga sam certyfikat i uzupelnia
baze. Pliki sa kasowane natychmiast po sparsowaniu.

Uzycie:
    python backfill_certs.py                 # podglad, nic nie pobiera
    python backfill_certs.py --apply         # pobiera i uzupelnia
    python backfill_certs.py --apply --limit 20   # tylko 20 probek (test)

Skrypt jest wznawialny: bierze wylacznie wiersze z cert_sha1 IS NULL, wiec
kolejne uruchomienie kontynuuje od miejsca przerwania.
"""
import hashlib
import os
import shutil
import sqlite3
import sys
import traceback
from datetime import datetime

from isolation import run_isolated
from manifest_parser import parse_apk_bytes
from mwdb_client import get_client

DB = os.path.join("output", "threat_intel.db")


def kopia_bazy():
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    cel = f"{DB}.bak-{stamp}"
    shutil.copy2(DB, cel)
    return cel


def brakujace(limit=None):
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    sql = "SELECT sha256, package, filename FROM samples WHERE cert_sha1 IS NULL ORDER BY first_seen DESC"
    if limit:
        sql += f" LIMIT {int(limit)}"
    rows = conn.execute(sql).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def cert_dla_probki(mwdb, sha256):
    """Pobiera probke i wyciaga certyfikat. Zwraca dict cert albo None.

    Probka NIE trafia na dysk: pod Windowsem Defender flaguje zapisane malware
    i blokuje ponowne otwarcie pliku (widoczne jako "[Errno 22] Invalid
    argument"). Parsowanie idzie z pamieci, w osobnym procesie z limitem czasu.
    """
    dane = mwdb.query_file(sha256).download()
    if hashlib.sha256(dane).hexdigest() != sha256:
        raise ValueError("pobrany plik ma niezgodny SHA-256")
    wynik = run_isolated(parse_apk_bytes, (dane,), timeout=90)
    return wynik.get("cert")


def main():
    apply_ = "--apply" in sys.argv
    limit = None
    if "--limit" in sys.argv:
        limit = int(sys.argv[sys.argv.index("--limit") + 1])

    cele = brakujace(limit)
    print("TRYB:", "ZAPIS" if apply_ else "PODGLAD (nic nie zostanie pobrane)")
    print(f"Probek bez certyfikatu do przetworzenia: {len(cele)}")
    print()

    if not apply_:
        for r in cele[:10]:
            print("   %s  %s" % (r["sha256"][:16], r["package"] or "(brak pakietu)"))
        if len(cele) > 10:
            print(f"   ... i {len(cele) - 10} wiecej")
        print()
        print("Kazda probka jest pobierana z MWDB (to moze potrwac).")
        print("Uruchom z --apply, zeby wykonac.")
        return

    if not cele:
        print("Nie ma czego uzupelniac.")
        return

    print("Kopia zapasowa bazy:", kopia_bazy())
    print()

    mwdb = get_client()
    conn = sqlite3.connect(DB)

    statystyki = {"v1": 0, "v2": 0, "v3": 0, "brak_podpisu": 0, "blad": 0}
    try:
        for i, r in enumerate(cele, 1):
            sha256 = r["sha256"]
            etykieta = r["package"] or r["filename"] or sha256[:16]
            try:
                cert = cert_dla_probki(mwdb, sha256)
            except Exception as e:
                statystyki["blad"] += 1
                print("  [%d/%d] %-34s BLAD: %s" % (i, len(cele), etykieta[:34], str(e)[:60]))
                continue

            if not cert or cert.get("error") or not cert.get("sha1"):
                statystyki["brak_podpisu"] += 1
                powod = (cert or {}).get("error", "brak danych certyfikatu")
                print("  [%d/%d] %-34s bez certyfikatu (%s)" % (i, len(cele), etykieta[:34], powod[:40]))
                continue

            schemat = cert.get("signature_scheme") or "?"
            statystyki[schemat] = statystyki.get(schemat, 0) + 1
            conn.execute(
                "UPDATE samples SET cert_sha1=?, cert_subject=? WHERE sha256=?",
                (cert["sha1"], cert.get("subject"), sha256),
            )
            conn.commit()
            print("  [%d/%d] %-34s %s  schemat %s" % (
                i, len(cele), etykieta[:34], cert["sha1"][:16], schemat))
    except KeyboardInterrupt:
        print()
        print("Przerwano. Wyniki dotad zapisane sa juz w bazie — mozna uruchomic ponownie.")
    finally:
        conn.close()

    print()
    print("Podsumowanie:")
    for k, v in statystyki.items():
        if v:
            print("   %-14s %d" % (k, v))


if __name__ == "__main__":
    main()
