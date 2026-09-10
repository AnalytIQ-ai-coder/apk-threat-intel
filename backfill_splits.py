"""Rozpoznaje wstecz, ktore probki w bazie sa splitami z App Bundle.

Problem, ktory to naprawia: instalacja z AAB to base.apk plus zestaw splitow
(config.arm64_v8a, config.xxhdpi, config.pl...). Split konfiguracyjny nie jest
aplikacja — nie ma etykiety, uprawnien, minSdk ani zwykle kodu. Wrzucony do
pipeline'u jako samodzielna probka wygladal jak aplikacja "nieproszaca o zadne
uprawnienia", a model dostawal prompt z samymi pustymi polami i odpowiadal
"RISK: low, brak uprawnien". W output/threat_intel.db 164 wiersze maja ocene
'low' powstala dokladnie w ten sposob. To falszywy negatyw wygenerowany
z niczego, nie ocena probki.

Od teraz manifest_parser.wykryj_split rozpoznaje to na biezaco. Ten skrypt
uzupelnia wiersze zapisane wczesniej.

Zakres: wylacznie probki bez nazwy aplikacji (app_name pusty). Pelne APK z
etykieta splitem konfiguracyjnym nie jest — split nie ma czego etykietowac —
wiec nie ma sensu pobierac 1245 plikow, zeby to potwierdzic.

Uzycie:
    python backfill_splits.py                    # podglad, nic nie pobiera
    python backfill_splits.py --apply            # pobiera i uzupelnia
    python backfill_splits.py --apply --limit 20 # tylko 20 probek (test)

Skrypt jest wznawialny: bierze wiersze ze split_name IS NULL, a kazda
sprawdzona probke oznacza (nazwa splitu albo pusty napis), wiec kolejne
uruchomienie kontynuuje od miejsca przerwania.
"""
import hashlib
import os
import shutil
import sqlite3
import sys
from datetime import datetime

from isolation import run_isolated
from manifest_parser import parse_apk_bytes, split_bez_kodu
from mwdb_client import get_client
import threat_db

DB = os.path.join("output", "threat_intel.db")


def kopia_bazy():
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    cel = f"{DB}.bak-{stamp}"
    shutil.copy2(DB, cel)
    return cel


def kandydaci(limit=None):
    """Probki niesprawdzone i bez etykiety — czyli te, ktore moga byc splitem."""
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


def split_dla_probki(mwdb, sha256):
    """Pobiera probke i zwraca (opis splitu albo None, czy pominac AI).

    Probka NIE trafia na dysk: pod Windowsem Defender flaguje zapisane malware
    i blokuje ponowne otwarcie pliku. Parsowanie idzie z pamieci, w osobnym
    procesie z limitem czasu — tak samo jak w backfill_certs.py.
    """
    dane = mwdb.query_file(sha256).download()
    if hashlib.sha256(dane).hexdigest() != sha256:
        raise ValueError("pobrany plik ma niezgodny SHA-256")
    wynik = run_isolated(parse_apk_bytes, (dane,), timeout=90)
    return wynik.get("split"), split_bez_kodu(wynik)


def main():
    apply_ = "--apply" in sys.argv
    limit = None
    if "--limit" in sys.argv:
        limit = int(sys.argv[sys.argv.index("--limit") + 1])

    # Kolumna split_name mogla jeszcze nie powstac — migracja siedzi w init_db.
    threat_db.init_db()

    cele = kandydaci(limit)
    print("TRYB:", "ZAPIS" if apply_ else "PODGLAD (nic nie zostanie pobrane)")
    print(f"Probek do sprawdzenia: {len(cele)}")
    zmyslone = [r for r in cele if r["ai_risk"]]
    print(f"   w tym z ocena AI, ktora moze byc zmyslona z pustych danych: {len(zmyslone)}")
    print()

    if not apply_:
        for r in cele[:10]:
            print("   %s  %-40s ai_risk=%s" % (
                r["sha256"][:16], (r["package"] or "(brak pakietu)")[:40], r["ai_risk"]))
        if len(cele) > 10:
            print(f"   ... i {len(cele) - 10} wiecej")
        print()
        print("Kazda probka jest pobierana z MWDB (to potrwa).")
        print("Uruchom z --apply, zeby wykonac.")
        return

    if not cele:
        print("Nie ma czego uzupelniac.")
        return

    print("Kopia zapasowa bazy:", kopia_bazy())
    print()

    mwdb = get_client()
    conn = sqlite3.connect(DB)

    stat = {"split_bez_kodu": 0, "split_z_kodem": 0, "pelne_apk": 0,
            "ocena_wyczyszczona": 0, "blad": 0}
    try:
        for i, r in enumerate(cele, 1):
            sha256 = r["sha256"]
            etykieta = (r["package"] or r["filename"] or sha256[:16])[:38]
            try:
                split, bez_kodu = split_dla_probki(mwdb, sha256)
            except Exception as e:
                stat["blad"] += 1
                print("  [%d/%d] %-38s BLAD: %s" % (i, len(cele), etykieta, str(e)[:50]))
                continue

            nazwa = (split or {}).get("nazwa") or ""

            if not split:
                stat["pelne_apk"] += 1
                conn.execute("UPDATE samples SET split_name='' WHERE sha256=?", (sha256,))
                conn.commit()
                print("  [%d/%d] %-38s pelne APK" % (i, len(cele), etykieta))
                continue

            # Ocena AI dla splitu bez kodu opisuje pusty prompt, nie probke —
            # kasujemy ja, zeby nie zaniżala obrazu przy przegladaniu bazy.
            # Splitowi typu "feature" oceny nie ruszamy: ma wlasny kod, wiec
            # model mial na czym pracowac.
            czysc = bez_kodu and r["ai_risk"]
            if czysc:
                conn.execute("UPDATE samples SET split_name=?, ai_risk=NULL WHERE sha256=?",
                             (nazwa, sha256))
                stat["ocena_wyczyszczona"] += 1
            else:
                conn.execute("UPDATE samples SET split_name=? WHERE sha256=?", (nazwa, sha256))
            conn.commit()

            stat["split_bez_kodu" if bez_kodu else "split_z_kodem"] += 1
            print("  [%d/%d] %-38s split %-20s %s%s" % (
                i, len(cele), etykieta, nazwa,
                "bez kodu" if bez_kodu else "z kodem",
                "  (skasowano ai_risk=%s)" % r["ai_risk"] if czysc else ""))
    except KeyboardInterrupt:
        print()
        print("Przerwano. Wyniki dotad sa juz zapisane — mozna uruchomic ponownie.")
    finally:
        conn.close()

    print()
    print("Podsumowanie:")
    for k, v in stat.items():
        if v:
            print("   %-20s %d" % (k, v))


if __name__ == "__main__":
    main()
