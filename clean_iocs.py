"""Jednorazowe czyszczenie IOC zapisanych przed dodaniem walidacji portfeli.

Usuwa adresy BTC/TRON, ktore nie przechodza Base58Check/bech32 (regex lapal
32-znakowe hashe i nazwy klas Javy), oraz obcina znaki sterujace w pozostalych
wartosciach. Nie rusza dlugich URL-i — te bywaja prawdziwe.

Uzycie:
    python clean_iocs.py            # podglad, nic nie zapisuje
    python clean_iocs.py --apply    # wykonuje zmiany (po kopii zapasowej)
"""
import json
import os
import shutil
import sqlite3
import sys
from datetime import datetime

from dex_analyzer import (_domena_jest_iocem, _is_plausible_ip,
                          _jest_publicznym_resolwerem, _odsiej_sekwencyjne_ip)
from ioc_extractor import _GITHUB_RAW_RE, _is_valid_btc, _is_valid_tron, _telegram_standardowy

DB = os.path.join("output", "threat_intel.db")
WALIDATORY = {"wallet_btc": _is_valid_btc, "wallet_tron": _is_valid_tron}


def bez_znakow_sterujacych(text):
    return "".join(ch for ch in text if ch.isprintable() or ch in " ")


def kopia(sciezka):
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    cel = f"{sciezka}.bak-{stamp}"
    shutil.copy2(sciezka, cel)
    return cel


def zbedne_wpisy(c):
    """Zwraca (ids_do_usuniecia, powody) wg tych samych regul co pipeline.

    Reprodukujemy dokladnie logike filtrow z ioc_extractor/dex_analyzer, zeby
    baza zgadzala sie z tym, co wyprodukowalby dzisiejszy run.
    """
    ids, powody = [], {}

    def dodaj(rid, powod):
        ids.append(rid)
        powody[powod] = powody.get(powod, 0) + 1

    for typ, valid in WALIDATORY.items():
        for r in c.execute("SELECT id, value FROM iocs WHERE ioc_type=?", (typ,)):
            if not valid(r["value"]):
                dodaj(r["id"], "portfele bez sumy kontrolnej")

    for r in c.execute("SELECT id, value FROM iocs WHERE ioc_type='contact_telegram'"):
        if _telegram_standardowy(r["value"]):
            dodaj(r["id"], "standardowe deep-linki Telegrama")

    for r in c.execute("SELECT id, value FROM iocs WHERE ioc_type='deaddrop_github'"):
        if not _GITHUB_RAW_RE.findall(r["value"]):
            dodaj(r["id"], "linki /blob/ do repozytoriow bibliotek")

    # Najpierw regula produkcyjna _is_plausible_ip: odsiewa fragmenty OID-ow
    # z X.509 (2.5.4.3 = commonName, 2.5.29.15 = keyUsage itd.), ktore trafily
    # do bazy przed jej dodaniem. Dopiero reszte oceniamy heurystyka sekwencyjna.
    per_probka = {}
    for r in c.execute("SELECT id, sha256, value FROM iocs WHERE ioc_type='ip'"):
        if not _is_plausible_ip(r["value"]):
            dodaj(r["id"], "fragmenty OID / maski podsieci")
            continue
        if _jest_publicznym_resolwerem(r["value"]):
            dodaj(r["id"], "publiczne resolwery DNS")
            continue
        per_probka.setdefault(r["sha256"], []).append((r["id"], r["value"]))
    for wpisy in per_probka.values():
        zostaja = _odsiej_sekwencyjne_ip({v for _, v in wpisy})
        for rid, wartosc in wpisy:
            if wartosc not in zostaja:
                dodaj(rid, "sekwencyjne pseudo-IP (numery wersji)")

    # Domeny: _DOMAIN_RE widzi tylko ogon stringa zakonczony czyms, co wyglada
    # na TLD, wiec do bazy trafily nazwy klas Javy ("StreamBitmapDecoder.com"),
    # swizzle GLSL z shaderow ("fragColor.xyz"), ogony pakietow
    # ("org.openjsse.net") i placeholdery z dokumentacji ("www.example.com").
    for r in c.execute("SELECT id, value FROM iocs WHERE ioc_type='domain'"):
        if not _domena_jest_iocem(r["value"]):
            dodaj(r["id"], "identyfikatory z kodu udajace domeny")

    return ids, powody


def czysc_baze(apply_):
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    do_usuniecia, powody = zbedne_wpisy(c)

    do_poprawy = []
    for r in c.execute("SELECT id, value FROM iocs"):
        czyste = bez_znakow_sterujacych(r["value"])
        if czyste != r["value"]:
            do_poprawy.append((r["id"], czyste))

    for powod, ile in sorted(powody.items(), key=lambda kv: -kv[1]):
        print(f"  {powod:.<42} {ile}")
    print(f"  {'wartosci ze znakami sterujacymi':.<42} {len(do_poprawy)} (do obciecia)")

    # IOC znikajace z bazy calkowicie — tylko te usuwamy z eksportow, zeby nie
    # skasowac wartosci, ktora w innej probce jest prawdziwa.
    znikajace = set()
    if do_usuniecia:
        pyt = ",".join("?" * len(do_usuniecia))
        kandydaci = {r["value"] for r in
                     c.execute(f"SELECT value FROM iocs WHERE id IN ({pyt})", do_usuniecia)}
        for w in kandydaci:
            pozostale = c.execute(
                f"SELECT COUNT(*) FROM iocs WHERE value=? AND id NOT IN ({pyt})",
                [w] + do_usuniecia).fetchone()[0]
            if pozostale == 0:
                znikajace.add(w)

    # --- normalizacja wielkosci liter w domenach ---
    # Odpowiednik _normalizuj_ioc z threat_db dla wierszy zapisanych wczesniej.
    # DNS nie rozroznia wielkosci liter, wiec "LITEAPKS.COM", "Liteapks.com"
    # i "liteapks.com" to jeden host lezacy w bazie jako trzy wiersze, ktore
    # nigdy sie ze soba nie skoreluja.
    juz_poprawiane = {i for i, _ in do_poprawy}
    pomijane = set(do_usuniecia)
    na_male_litery = []
    for r in c.execute("SELECT id, value FROM iocs WHERE ioc_type='domain'"):
        if r["id"] in juz_poprawiane or r["id"] in pomijane:
            continue
        mala = bez_znakow_sterujacych(r["value"]).lower()
        if mala != r["value"]:
            na_male_litery.append((r["id"], mala))
    do_poprawy.extend(na_male_litery)

    # Po sprowadzeniu do malych liter czesc wierszy staje sie duplikatami
    # w obrebie tej samej probki. Zostawiamy najstarszy (najnizsze id).
    # Te ida osobna lista, a NIE do do_usuniecia: wartosc nie znika z bazy,
    # tylko zmienia zapis, wiec nie wolno jej wycinac z eksportow.
    widziane, duplikaty_po_normalizacji = set(), []
    for r in c.execute("SELECT id, sha256, value FROM iocs WHERE ioc_type='domain' ORDER BY id"):
        klucz = (r["sha256"], bez_znakow_sterujacych(r["value"]).lower())
        if klucz in widziane:
            duplikaty_po_normalizacji.append(r["id"])
        else:
            widziane.add(klucz)
    skasowane = set(do_usuniecia) | set(duplikaty_po_normalizacji)
    do_poprawy = [(i, v) for i, v in do_poprawy if i not in skasowane]
    print(f"  {'domeny do sprowadzenia na male litery':.<42} {len(na_male_litery)}")
    print(f"  {'duplikaty po normalizacji':.<42} {len(duplikaty_po_normalizacji)}")

    if apply_ and (do_usuniecia or do_poprawy or duplikaty_po_normalizacji):
        c.executemany("DELETE FROM iocs WHERE id=?",
                      [(i,) for i in list(do_usuniecia) + duplikaty_po_normalizacji])
        c.executemany("UPDATE iocs SET value=? WHERE id=?",
                      [(v, i) for i, v in do_poprawy])
        conn.commit()
        conn.execute("VACUUM")
    conn.close()
    return znikajace


def czysc_csv(sciezka, apply_):
    if not os.path.exists(sciezka):
        return 0
    import csv
    with open(sciezka, newline="", encoding="utf-8") as f:
        wiersze = list(csv.reader(f))
    naglowek, dane = wiersze[0], wiersze[1:]

    # CSV ma kolumne sha256, wiec sekwencyjne IP grupujemy per probka —
    # dokladnie tak jak w bazie i w runtime.
    ip_per_probka = {}
    for w in dane:
        if w[2] == "ip" and not _jest_publicznym_resolwerem(w[3]):
            ip_per_probka.setdefault(w[0], set()).add(w[3])
    ip_zostaja = {sha: _odsiej_sekwencyjne_ip(v) for sha, v in ip_per_probka.items()}

    zostaje = []
    for w in dane:
        sha, typ, wartosc = w[0], w[2], w[3]
        valid = WALIDATORY.get(typ)
        if valid and not valid(wartosc.lstrip("'")):
            continue
        if typ == "contact_telegram" and _telegram_standardowy(wartosc):
            continue
        if typ == "deaddrop_github" and not _GITHUB_RAW_RE.findall(wartosc):
            continue
        if typ == "ip" and (_jest_publicznym_resolwerem(wartosc)
                            or wartosc not in ip_zostaja.get(sha, set())):
            continue
        w[3] = bez_znakow_sterujacych(wartosc)
        zostaje.append(w)

    usuniete = len(dane) - len(zostaje)
    print(f"  {sciezka}: {usuniete} wierszy do usuniecia (z {len(dane)})")
    if apply_ and usuniete:
        with open(sciezka, "w", newline="", encoding="utf-8") as f:
            wr = csv.writer(f)
            wr.writerow(naglowek)
            wr.writerows(zostaje)
    return usuniete


def czysc_misp(sciezka, apply_, znikajace=()):
    """MISP event nie wiaze atrybutu z probka, wiec sekwencyjnych IP nie da sie
    tu grupowac per probka. Usuwamy wylacznie wartosci, ktore znikly z bazy
    CALKOWICIE — inaczej skasowalibysmy IOC prawdziwy w innej probce.
    """
    if not os.path.exists(sciezka):
        return 0
    with open(sciezka, encoding="utf-8") as f:
        event = json.load(f)
    attrs = event["Event"]["Attribute"]

    zostaje = []
    for a in attrs:
        wartosc = a.get("value", "")
        if a.get("type") == "btc" and not _is_valid_btc(wartosc):
            continue
        if wartosc in znikajace:
            continue
        a["value"] = bez_znakow_sterujacych(wartosc)
        zostaje.append(a)

    usuniete = len(attrs) - len(zostaje)
    print(f"  {sciezka}: {usuniete} atrybutow do usuniecia (z {len(attrs)})")
    if apply_ and usuniete:
        event["Event"]["Attribute"] = zostaje
        with open(sciezka, "w", encoding="utf-8") as f:
            json.dump(event, f, indent=2, ensure_ascii=False)
    return usuniete


def main():
    apply_ = "--apply" in sys.argv
    print("TRYB:", "ZAPIS" if apply_ else "PODGLAD (nic nie zostanie zmienione)")
    print()

    cele = [DB, os.path.join("output", "iocs.csv"), os.path.join("output", "misp_event.json")]
    if apply_:
        print("Kopie zapasowe:")
        for sciezka in cele:
            if os.path.exists(sciezka):
                print("  ", kopia(sciezka))
        print()

    print("Baza threat-intel:")
    znikajace = czysc_baze(apply_)
    print()
    print("Eksporty:")
    czysc_csv(os.path.join("output", "iocs.csv"), apply_)
    czysc_misp(os.path.join("output", "misp_event.json"), apply_, znikajace)
    print()
    print("Gotowe." if apply_ else "Uruchom z --apply, zeby wykonac.")


if __name__ == "__main__":
    main()
