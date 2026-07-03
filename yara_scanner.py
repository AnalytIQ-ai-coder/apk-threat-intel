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


def _compile_rules():
    global _compiled
    if _compiled is not None:
        return _compiled
    if not _YARA_AVAILABLE or not os.path.isdir(RULES_DIR):
        _compiled = False
        return _compiled

    filepaths = {}
    for name in os.listdir(RULES_DIR):
        if name.endswith((".yar", ".yara")):
            filepaths[name] = os.path.join(RULES_DIR, name)

    if not filepaths:
        _compiled = False
        return _compiled

    try:
        _compiled = yara.compile(filepaths=filepaths)
    except yara.SyntaxError as e:
        print(f"[yara_scanner] Błąd kompilacji reguł: {e}")
        _compiled = False
    return _compiled


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
