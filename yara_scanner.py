"""Skanowanie próbek regułami YARA z yara_rules/. Rozpoznaje rodziny/kampanie,
które ręcznie zidentyfikowaliśmy w poprzednich raportach (patrz custom_families.yar),
zamiast polegać wyłącznie na klasyfikacji MobSF.

Jeśli pakiet `yara-python` nie jest zainstalowany, moduł działa jako no-op
(zwraca listę pustą) — nie blokuje reszty pipeline'u.
"""
import os
import zipfile

RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "yara_rules")

try:
    import yara
    _YARA_AVAILABLE = True
except ImportError:
    _YARA_AVAILABLE = False

_compiled = None
# Pliki, ktorych nie udalo sie skompilowac — do wgladu dla wywolujacego.
_bledne_pliki = []


def _compile_rules():
    """Kompiluje reguly plik po pliku, pomijajac te z bledem skladni.

    Wczesniej wszystkie pliki szly do jednego yara.compile(), wiec literowka
    w jednej regule wywracala CALY zestaw — scan() zwracal po cichu pusta liste
    i detekcja YARA znikala niezauwazona. Teraz zepsuty plik kosztuje wylacznie
    siebie, a informacja o tym jest glosna.
    """
    global _compiled, _bledne_pliki
    if _compiled is not None:
        return _compiled
    if not _YARA_AVAILABLE or not os.path.isdir(RULES_DIR):
        _compiled = False
        return _compiled

    nazwy = sorted(n for n in os.listdir(RULES_DIR) if n.endswith((".yar", ".yara")))
    if not nazwy:
        print("[yara_scanner] UWAGA: brak plikow regul w %s" % RULES_DIR)
        _compiled = False
        return _compiled

    dobre, _bledne_pliki = {}, []
    for nazwa in nazwy:
        sciezka = os.path.join(RULES_DIR, nazwa)
        try:
            yara.compile(filepath=sciezka)          # walidacja pojedynczego pliku
            dobre[nazwa] = sciezka
        except Exception as e:
            _bledne_pliki.append((nazwa, str(e)))
            print("[yara_scanner] !!! POMINIETO regule %s — blad skladni: %s" % (nazwa, e))

    if not dobre:
        print("[yara_scanner] !!! ZADNA regula sie nie skompilowala — detekcja YARA WYLACZONA")
        _compiled = False
        return _compiled

    try:
        _compiled = yara.compile(filepaths=dobre)
    except Exception as e:                          # nie powinno wystapic po walidacji
        print("[yara_scanner] !!! blad laczenia regul: %s — detekcja YARA WYLACZONA" % e)
        _compiled = False
        return _compiled

    ile_regul = sum(1 for _ in _compiled)
    print("[yara_scanner] zaladowano %d regul z %d plikow%s" % (
        ile_regul, len(dobre),
        (" (POMINIETO %d zepsutych)" % len(_bledne_pliki)) if _bledne_pliki else ""))
    return _compiled


def bledne_pliki_regul():
    """Lista (nazwa, blad) plikow pominietych przy ostatniej kompilacji."""
    _compile_rules()
    return list(_bledne_pliki)


# APK to ZIP, a jego wpisy sa DEFLATE'owane. YARA dostajaca sciezke pliku widzi
# skompresowane bajty, wiec ZADEN string z classes.dex nie moze sie dopasowac —
# potwierdzone eksperymentem (ten sam marker: wpis STORED trafia, DEFLATE nie)
# i danymi z produkcji: 38/38 probek mialo puste yara_matches przy 13 zaladowanych
# regulach. Dlatego oprocz surowego pliku skanujemy tez odkompresowana zawartosc.
#
# Surowego pliku NIE zastepujemy: blok podpisu v2/v3 lezy poza wpisami ZIP-a,
# nieskompresowany, i to na nim dzialaja reguly na modul RSA z campaign_certs.yar.
_MAX_WPIS_BYTES = 64 * 1024 * 1024
_MAX_LACZNIE_BYTES = 256 * 1024 * 1024

# Wpisy niosace stringi, na ktorych opieraja sie reguly: kod (dex), manifest,
# zasoby (etykieta aplikacji), payloady w assets/ i biblioteki natywne.
_ROZSZERZENIA_DO_SKANU = (".dex", ".arsc", ".so")
_NAZWY_DO_SKANU = ("androidmanifest.xml",)
_PREFIKSY_DO_SKANU = ("assets/",)


def _wpis_do_skanu(nazwa: str) -> bool:
    n = nazwa.lower()
    return (n.endswith(_ROZSZERZENIA_DO_SKANU)
            or n.rsplit("/", 1)[-1] in _NAZWY_DO_SKANU
            or n.startswith(_PREFIKSY_DO_SKANU))


def _odkompresowana_zawartosc(apk_path: str) -> bytes:
    """Skleja odkompresowane wpisy APK w jeden bufor do skanowania.

    Limity sa takie same jak w dex_analyzer i z tego samego powodu: deklarowany
    file_size w spreparowanym archiwum potrafi klamac, wiec cap egzekwujemy
    takze przy samym odczycie. Blad pojedynczego wpisu pomijamy — lepiej
    przeskanowac czesc niz nic.
    """
    kawalki, razem = [], 0
    try:
        with zipfile.ZipFile(apk_path) as z:
            for info in z.infolist():
                if info.is_dir() or not _wpis_do_skanu(info.filename):
                    continue
                if info.file_size > _MAX_WPIS_BYTES:
                    continue
                zostalo = _MAX_LACZNIE_BYTES - razem
                if zostalo <= 0:
                    break
                try:
                    with z.open(info) as fh:
                        dane = fh.read(min(_MAX_WPIS_BYTES, zostalo) + 1)
                except Exception as e:
                    # Wpis, ktorego zipfile nie potrafi rozpakowac. Android bywa
                    # znacznie bardziej pobłażliwy i takie APK instaluje, wiec to
                    # nie jest "plik uszkodzony" — to technika anty-analityczna,
                    # i to skuteczna: KAZDA regula opierajaca sie na stringach
                    # z tego wpisu cicho nie strzeli.
                    #
                    # Dwa potwierdzone warianty z probek w bazie:
                    #   * metoda kompresji spoza standardu (dozwolone 0, 8, 9, 12, 14)
                    #     — probka Venom, AndroidManifest.xml z metoda 17180 w katalogu
                    #     centralnym i 32040 w naglowku lokalnym (NotImplementedError),
                    #   * ustawiony bit 0 flag ogolnych, czyli "wpis zaszyfrowany"
                    #     — klaster tiktok18/MetaMask, gdzie w jednej probce oznaczono
                    #     tak classes.dex i AndroidManifest.xml, a w drugiej WSZYSTKIE
                    #     wpisy, przez co bufor zawartosci byl calkowicie pusty
                    #     (RuntimeError "File is encrypted").
                    # Szczegoly w yara_rules/venom_tools.yar i metamask_loader.yar.
                    #
                    # Lapiemy szeroko (Exception), bo lista trikow nie jest zamknieta,
                    # a kazdy z nich objawia sie tak samo: cisza nie do odroznienia od
                    # braku dopasowania. Samych bajtow nie doklejamy — przebieg po
                    # surowym pliku i tak je widzi, wiec zysku by nie bylo, a szum
                    # moglby dac falszywki.
                    print("[yara_scanner] UWAGA: %s nie do rozpakowania (%s, metoda %d,"
                          " flagi 0x%04x) — pominiety w przebiegu po zawartosci, reguly"
                          " oparte na jego stringach NIE zadzialaja na tej probce"
                          % (info.filename, type(e).__name__, info.compress_type,
                             info.flag_bits))
                    continue
                if len(dane) > zostalo:
                    break
                kawalki.append(dane)
                razem += len(dane)
    except Exception:
        return b""
    return bytes([0]).join(kawalki)


def scan(apk_path: str) -> list[dict]:
    """Zwraca listę {rule, family, description} dla dopasowanych reguł custom YARA."""
    rules = _compile_rules()
    if not rules:
        return []

    try:
        matches = list(rules.match(apk_path))     # surowe bajty: blok podpisu v2/v3
    except Exception as e:
        print(f"[yara_scanner] Błąd skanowania {apk_path}: {e}")
        return []

    dane = _odkompresowana_zawartosc(apk_path)
    if dane:
        try:
            matches += list(rules.match(data=dane))
        except Exception as e:
            print(f"[yara_scanner] Błąd skanowania zawartości {apk_path}: {e}")

    results, widziane = [], set()
    for m in matches:
        if m.rule in widziane:      # ta sama regula z obu przebiegow
            continue
        widziane.add(m.rule)
        results.append({
            "rule": m.rule,
            "family": m.meta.get("family", m.rule),
            "description": m.meta.get("description", ""),
        })
    return results


def available() -> bool:
    return _YARA_AVAILABLE


def scan_isolated(apk_path: str, timeout: int = 60) -> list[dict]:
    """scan() uruchomione w osobnym procesie z twardym limitem czasu.

    libyara to kod natywny (C) parsujacy plik kontrolowany przez atakujacego —
    blad w nim nie konczy sie wyjatkiem Pythona, tylko naruszeniem pamieci albo
    zapetleniem. Osobny proces sprawia, ze najgorszym przypadkiem jest utrata
    wynikow YARA dla jednej probki.
    """
    from isolation import run_isolated, IsolationTimeout, IsolationError
    try:
        return run_isolated(scan, (apk_path,), timeout=timeout)
    except IsolationTimeout as e:
        print(f"[yara_scanner] skanowanie przerwane: {e}")
        return []
    except IsolationError as e:
        print(f"[yara_scanner] blad: {str(e).splitlines()[-1]}")
        return []
