"""Testy warstwy YARA: czy regula w ogole moze trafic w prawdziwy APK.

Uruchomienie: python tests/test_yara.py   (nie wymaga pytest)

Powod istnienia tego pliku: przez caly czas dzialania pipeline'u YARA nie
zwrocila ANI JEDNEGO trafienia (38/38 probek z pustym yara_matches przy
13 zaladowanych regulach). Przyczyna nie byla w regulach, tylko w tym, ze
skanowany byl surowy plik APK, czyli ZIP z DEFLATE'owanymi wpisami — stringi
z classes.dex byly dla YARY niewidoczne. Ponizsze testy pilnuja, zeby ten
tryb awarii nie wrocil po cichu.
"""
import os
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import yara_scanner  # noqa: E402

# Fragment string poola DEX-a probki ghy.ikx.rentaapps (C2 + nazwa pakietu
# w formie, w jakiej wystepuje w DEX, czyli ze slashami) oraz etykieta z zasobow.
DEX_KAMPANII = (
    b"\x00" * 64
    + b"Lghy/ikx/rentaapps/MainActivity;"
    + b"http://bsqzx.xyz/"
    + b"Lcom/launcher/mango/LauncherProvider;"
    + b"\x00" * 64
)
ARSC_KAMPANII = b"\x00" * 32 + b"System_Upgrade" + b"\x00" * 32


def _zbuduj_apk(katalog, nazwa, kompresja):
    p = os.path.join(katalog, nazwa)
    with zipfile.ZipFile(p, "w", kompresja) as z:
        z.writestr("classes.dex", DEX_KAMPANII)
        z.writestr("resources.arsc", ARSC_KAMPANII)
        z.writestr("AndroidManifest.xml", b"ghy.ikx.rentaapps")
        z.writestr("lib/arm64-v8a/libearth.so", os.urandom(2048))
    return p


def test_regula_trafia_w_skompresowany_apk():
    # Wlasciwy test: tak wyglada prawdziwy APK. Przed poprawka skanera
    # to dopasowanie NIE zachodzilo.
    with tempfile.TemporaryDirectory() as d:
        p = _zbuduj_apk(d, "kampania.apk", zipfile.ZIP_DEFLATED)
        reguly = [m["rule"] for m in yara_scanner.scan(p)]
        assert "Rentaapps_C2_bsqzx" in reguly, reguly


def test_regula_trafia_takze_gdy_wpisy_sa_nieskompresowane():
    with tempfile.TemporaryDirectory() as d:
        p = _zbuduj_apk(d, "stored.apk", zipfile.ZIP_STORED)
        reguly = [m["rule"] for m in yara_scanner.scan(p)]
        assert "Rentaapps_C2_bsqzx" in reguly, reguly


def test_czysty_apk_nie_wywoluje_trafienia():
    # Kontrprzyklad: sam fakt, ze skanujemy odkompresowana zawartosc, nie moze
    # produkowac trafien na dowolnej aplikacji.
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "czysty.apk")
        with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("classes.dex", b"Landroidx/core/app/NotificationCompat;" * 40)
            z.writestr("resources.arsc", b"Moja Aplikacja")
        assert yara_scanner.scan(p) == []


def test_builder_bez_c2_lapie_rotacje_domeny():
    # Druga regula ma zlapac kolejna fale, gdy operator zmieni domene C2.
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "nowa_fala.apk")
        with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("classes.dex", b"Lghy/zzz/rentaapps/X;http://inna-domena.top/"
                                      b"Lcom/launcher/mango/LauncherProvider;")
            z.writestr("resources.arsc", ARSC_KAMPANII)
        reguly = [m["rule"] for m in yara_scanner.scan(p)]
        assert "Rentaapps_Builder_Nowa_Domena" in reguly, reguly


def test_klucz_testowy_aosp_nie_jest_kotwica():
    # Klucz 27196E386B875E76 maja tez cztery niepowiazane rodziny w naszej
    # bazie (5 z 18 probek). Regula nie moze sie o niego opierac — sprawdzamy,
    # ze w pliku regul nie ma odcisku ani modulu tego klucza.
    p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "yara_rules", "bsqzx_rentaapps.yar")
    with open(p, encoding="utf-8") as f:
        tresc = f.read()
    # Wlasciwy niezmiennik: w pliku nie ma ZADNEJ kotwicy na bajtach klucza,
    # czyli zadnego stringa heksowego { .. }. Sam odcisk SHA-1 w komentarzu
    # i w meta jest w porzadku — to dokumentacja, nie warunek dopasowania.
    import re
    assert "$modulus" not in tresc
    assert not re.search(r"=\s*\{[0-9a-fA-F\s]+\}", tresc), "kotwica heksowa w regule"


def test_zaden_plik_regul_sie_nie_wysypal():
    # Jeden niereferencowany string potrafil wczesniej wylaczyc CALY zestaw.
    assert yara_scanner.bledne_pliki_regul() == []


# ── Klaster "APK Signer / Earth" ─────────────────────────────────────────────
# Bajty ponizej sa WYCIETE z prawdziwej probki b46b27b8 (MAX_VIDE0), a nie
# wymyslone: fragment DER podmiotu certyfikatu i jego okres waznosci.
# Zapisane szesnastkowo celowo — literal bajtowy z sekwencjami ucieczki juz raz
# w tym repo wpisal do pliku prawdziwy bajt NUL i zepsul modul.
EARTH_DN = bytes.fromhex("040b0c054561727468311330110603550403" "0c0a41504b205369676e6572")
EARTH_WAZNOSC = bytes.fromhex(
    "301e170d3139303930333233303332345a170d3439313032353233303332345a")

# Uprawnienia o nazwach zaczynajacych sie od cyfry, tak jak w probce.
# Pula stringow AXML jest UTF-16, stad kodowanie — regula uzywa "wide".
MANIFEST_EARTH = (
    bytes(16)
    + "android.permission.1TKPV12F".encode("utf-16-le")
    + bytes(8)
    + "android.permission.4Q83E7I3WD".encode("utf-16-le")
    + bytes(16)
)


def _zbuduj_apk_earth(katalog, nazwa, cert=True, wabiki=True, perm_od_cyfry=True):
    p = os.path.join(katalog, nazwa)
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("classes.dex", bytes(256))
        z.writestr("resources.arsc", bytes(256))
        z.writestr("AndroidManifest.xml",
                   MANIFEST_EARTH if perm_od_cyfry else bytes(64))
        if cert:
            # STORED, bo w prawdziwym APK blok podpisu lezy poza wpisami ZIP
            # i jest nieskompresowany — regula szuka go w surowych bajtach.
            info = zipfile.ZipInfo("META-INF/CERT.RSA")
            info.compress_type = zipfile.ZIP_STORED
            z.writestr(info, bytes(32) + EARTH_DN + EARTH_WAZNOSC + bytes(32))
        if wabiki:
            # Zarezerwowane nazwy APK uzyte jako katalogi. Kazda nazwa wpisu
            # trafia do pliku dwa razy (naglowek lokalny + centralny katalog).
            for i in range(6):
                z.writestr(f"classes.dex/wabik{i}.jpg", b"x")
                z.writestr(f"AndroidManifest.xml/wabik{i}.png", b"x")
    return p


def test_earth_wabiki_zip_trafia_w_prawdziwy_uklad():
    with tempfile.TemporaryDirectory() as d:
        p = _zbuduj_apk_earth(d, "earth.apk")
        reguly = [m["rule"] for m in yara_scanner.scan(p)]
        assert "Earth_Signer_Wabiki_ZIP" in reguly, reguly


def test_earth_hunting_nie_dubluje_reguly_glownej():
    # Ta sama pulapka, ktora w bsqzx_rentaapps.yar sprawila, ze druga regula
    # nigdy by nie strzelila — tylko odwrotnie. Probka z pelnym odciskiem
    # buildera ma trafiac WYLACZNIE w regule glowna, zeby trafienie w hunting
    # zawsze znaczylo "ten sam klucz, ale inny build".
    with tempfile.TemporaryDirectory() as d:
        p = _zbuduj_apk_earth(d, "earth.apk")
        reguly = [m["rule"] for m in yara_scanner.scan(p)]
        assert "Earth_Signer_Klucz_Hunting" not in reguly, reguly


def test_earth_sam_klucz_lapie_inny_build():
    # Odpowiednik probki Rasmlar5: ten sam certyfikat, zaden marker buildera.
    with tempfile.TemporaryDirectory() as d:
        p = _zbuduj_apk_earth(d, "inny.apk", wabiki=False, perm_od_cyfry=False)
        reguly = [m["rule"] for m in yara_scanner.scan(p)]
        assert "Earth_Signer_Klucz_Hunting" in reguly, reguly
        assert "Earth_Signer_Wabiki_ZIP" not in reguly, reguly


def test_uprawnienia_od_cyfry_lapane_w_osobnej_regule():
    # Pilnuje trzech rzeczy naraz: modyfikatora "wide", tego ze skaner
    # naprawde rozpakowuje AndroidManifest.xml, oraz PODZIALU NA REGULY.
    #
    # Ten test powstal z bledu: pierwsza wersja earth_signer.yar wymagala
    # w jednym warunku certyfikatu (widocznego tylko w przebiegu po surowych
    # bajtach) I uprawnien (widocznych tylko w przebiegu po rozpakowanej
    # zawartosci). Taka galaz nie moze strzelic nigdy. Marker manifestu musi
    # wiec stac w regule, ktora nie odwoluje sie do niczego z surowych bajtow.
    with tempfile.TemporaryDirectory() as d:
        p = _zbuduj_apk_earth(d, "perm.apk", wabiki=False)
        reguly = [m["rule"] for m in yara_scanner.scan(p)]
        assert "APK_Uprawnienia_O_Nazwach_Od_Cyfry" in reguly, reguly


def test_wabiki_bez_klucza_nie_sa_przypisywane_do_earth():
    # Kontrprzyklad: sama technika nie moze przypisywac probki do klastra.
    with tempfile.TemporaryDirectory() as d:
        p = _zbuduj_apk_earth(d, "obcy.apk", cert=False)
        reguly = [m["rule"] for m in yara_scanner.scan(p)]
        assert "APK_Zarezerwowane_Nazwy_Jako_Katalogi" in reguly, reguly
        assert "Earth_Signer_Wabiki_ZIP" not in reguly, reguly
        assert "Earth_Signer_Klucz_Hunting" not in reguly, reguly


def test_czysty_apk_nie_trafia_regul_earth():
    with tempfile.TemporaryDirectory() as d:
        p = _zbuduj_apk_earth(d, "czysty.apk", cert=False, wabiki=False,
                              perm_od_cyfry=False)
        reguly = [m["rule"] for m in yara_scanner.scan(p)]
        assert not reguly, reguly


if __name__ == "__main__":
    testy = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_")]
    bledy = 0
    for nazwa, fn in testy:
        try:
            fn()
            print(f"  OK    {nazwa}")
        except AssertionError as e:
            bledy += 1
            print(f"  BLAD  {nazwa}: {e}")
    print(f"\n{len(testy) - bledy}/{len(testy)} przeszlo")
    sys.exit(1 if bledy else 0)
