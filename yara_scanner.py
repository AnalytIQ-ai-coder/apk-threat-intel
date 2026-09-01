"""Skanowanie próbek regułami YARA z yara_rules/. Rozpoznaje rodziny/kampanie,
które ręcznie zidentyfikowaliśmy w poprzednich raportach (patrz custom_families.yar),
zamiast polegać wyłącznie na klasyfikacji MobSF.

Jeśli pakiet `yara-python` nie jest zainstalowany, moduł działa jako no-op
(zwraca listę pustą) — nie blokuje reszty pipeline'u.
"""
import os

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


def scan(apk_path: str) -> list[dict]:
    """Zwraca listę {rule, family, description} dla dopasowanych reguł custom YARA."""
    rules = _compile_rules()
    if not rules:
        return []

    try:
        matches = rules.match(apk_path)
    except Exception as e:
        print(f"[yara_scanner] Błąd skanowania {apk_path}: {e}")
        return []

    results = []
    for m in matches:
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
