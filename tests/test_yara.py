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
