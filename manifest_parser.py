import json
import os
import shutil
import subprocess
import tempfile
# defusedxml zamiast xml.etree: to drugie jest wg dokumentacji Pythona
# podatne na billion laughs i quadratic blowup, a parsujemy tu manifest
# odkodowany ze zlosliwej probki.
import defusedxml.ElementTree as ET
import zipfile

from loguru import logger
# Wyciszamy tu, a nie tylko w analyzer.py: ten modul biegnie takze w
# procesach potomnych run_isolated, ktore nie importuja analyzer.py.
logger.disable("androguard")

from androguard.core.apk import APK
from cert_analyzer import analyze_cert
from isolation import run_isolated, IsolationTimeout, IsolationError

_APKTOOL_JAR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools", "apktool.jar")
_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
_MAX_INNER_APK_BYTES = 512 * 1024 * 1024


def _read_apk_bytes_from_xapk(xapk_path: str) -> bytes:
    with zipfile.ZipFile(xapk_path, "r") as z:
        names = z.namelist()

        package = None
        if "manifest.json" in names:
            with z.open("manifest.json") as f:
                meta = json.load(f)
                package = meta.get("package_name")

        root_apks = [n for n in names if n.endswith(".apk") and "/" not in n]
        all_apks = [n for n in names if n.endswith(".apk")]
        apk_candidates = root_apks if root_apks else all_apks

        if not apk_candidates:
            raise ValueError("No .apk found inside XAPK archive")

        if package:
            preferred = [n for n in apk_candidates if package in n]
            if preferred:
                apk_candidates = preferred

        # XAPK to niezaufany ZIP — wpis moze rozpakowac sie do gigabajtow.
        info = z.getinfo(apk_candidates[0])
        if info.file_size > _MAX_INNER_APK_BYTES:
            raise ValueError(f"APK w XAPK ma {info.file_size} B — powyzej limitu")
        with z.open(info) as f:
            data = f.read(_MAX_INNER_APK_BYTES + 1)
        if len(data) > _MAX_INNER_APK_BYTES:
            raise ValueError("APK w XAPK przekroczyl limit przy odczycie")
        return data


def _safe(fn, default=None):
    try:
        return fn()
    except (KeyError, Exception):
        return default


_AUTOSTART_ACTIONS = {
    "android.intent.action.BOOT_COMPLETED",
    "android.intent.action.LOCKED_BOOT_COMPLETED",
    "android.intent.action.MY_PACKAGE_REPLACED",
    "android.intent.action.PACKAGE_REPLACED",
    "android.intent.action.ACTION_POWER_CONNECTED",
}

_SUSPICIOUS_ACTIONS = {
    "android.provider.Telephony.SMS_RECEIVED",
    "android.telephony.action.CARRIER_CONFIG_CHANGED",
    "android.intent.action.PACKAGE_ADDED",
    "android.intent.action.PACKAGE_INSTALL",
    "android.net.conn.CONNECTIVITY_CHANGE",
    "android.intent.action.USER_PRESENT",
    "android.intent.action.SCREEN_ON",
}


def _parse_intent_filters(apk: APK) -> dict:
    autostart = []
    suspicious = []
    try:
        for activity_or_receiver in list(_safe(apk.get_receivers, [])) + list(_safe(apk.get_services, [])):
            filters = _safe(lambda: apk.get_intent_filters("receiver", activity_or_receiver), {})
            if not filters:
                continue
            for actions in filters.get("action", []):
                if actions in _AUTOSTART_ACTIONS:
                    autostart.append(actions)
                if actions in _SUSPICIOUS_ACTIONS:
                    suspicious.append(actions)
    except Exception:
        pass

    # Also scan raw manifest XML for actions
    try:
        manifest_xml = apk.get_android_manifest_xml()
        xml_str = str(manifest_xml) if manifest_xml is not None else ""
        for action in _AUTOSTART_ACTIONS:
            if action in xml_str and action not in autostart:
                autostart.append(action)
        for action in _SUSPICIOUS_ACTIONS:
            if action in xml_str and action not in suspicious:
                suspicious.append(action)
    except Exception:
        pass

    return {"autostart": sorted(set(autostart)), "suspicious_actions": sorted(set(suspicious))}


def _atrybut(root, nazwa: str) -> str:
    """Czyta atrybut korzenia manifestu, z przestrzenia nazw androida i bez niej.

    "split" i "package" sa w AndroidManifest.xml atrybutami bez prefiksu, ale
    "isFeatureSplit" juz z prefiksem. Zamiast pamietac, ktory jest ktory,
    sprawdzamy obie formy.
    """
    if root is None:
        return ""
    return (root.get(nazwa) or root.get(f"{_ANDROID_NS}{nazwa}") or "").strip()


def wykryj_split(root) -> dict | None:
    """Rozpoznaje, czy manifest opisuje SPLIT z App Bundle, czy pelne APK.

    Po co: instalacja z AAB sklada sie z base.apk plus zestawu splitow
    (config.arm64_v8a, config.xxhdpi, config.pl...). Split konfiguracyjny NIE
    JEST aplikacja — nie ma etykiety, uprawnien, minSdk ani zwykle kodu, bo to
    kontener na biblioteki natywne albo zasoby dla jednej ABI/gestosci/jezyka.
    Wrzucony do pipeline'u jako samodzielna probka wyglada jak aplikacja, ktora
    "nie prosi o zadne uprawnienia", i dokladnie tak byl opisywany: model
    dostawal pusty zestaw faktow i zwracal RISK: low z uzasadnieniem "brak
    uprawnien". To nie jest ocena, tylko artefakt.

    Rozpoznanie jest jednoznaczne i nie wymaga heurystyk: korzen <manifest>
    splitu ma atrybut split="...", ktorego pelne APK nie ma w ogole.
    Zmierzone na probkach z bazy:
      ch.publisheria.bring          split="config.arm64_v8a"  splitTypes="base__abi"
      com.hankuper.promoter.market  split="config.tr" / "config.ja" / "config.pt"
      com.anbui.cqcm.app            split="config.arm64_v8a"
      xyz.nextalone.nagram (pelne)  brak atrybutu split
      ghy.gss.rentaapps    (pelne)  brak atrybutu split

    Zwraca None dla pelnego APK (i dla base.apk, ktory tez nie ma tego
    atrybutu), albo opis splitu.
    """
    nazwa = _atrybut(root, "split")
    if not nazwa:
        return None

    feature = _atrybut(root, "isFeatureSplit").lower() in ("true", "1")
    if feature:
        rodzaj = "feature"
    elif nazwa.startswith("config."):
        rodzaj = "config"
    else:
        rodzaj = "nieznany"

    return {
        "nazwa": nazwa,
        "rodzaj": rodzaj,
        "typy": _atrybut(root, "splitTypes"),
        # Wypelniane przez wywolujacego, ktory widzi liste plikow.
        "ma_dex": None,
    }


def split_bez_kodu(data: dict) -> bool:
    """Czy to split z AAB, ktory nie niesie wlasnego kodu.

    Dla takiej probki nie ma czego oceniac: nie ma uprawnien, komponentow ani
    DEX-a, wiec kazda "ocena ryzyka" opisuje pusty zestaw faktow, a nie probke.
    Split typu "feature" jest wyjatkiem — ma wlasny kod i przechodzi normalna
    sciezke analizy.
    """
    split = data.get("split")
    if not split:
        return False
    if split.get("rodzaj") == "feature":
        return False
    ma_dex = split.get("ma_dex")
    if ma_dex is None:
        # Fallback apktool nie widzi listy plikow. Opieramy sie wtedy na
        # konwencji nazewniczej, ktora dla splitow konfiguracyjnych jest
        # ustalona przez samo narzedzie budujace bundle.
        return split.get("rodzaj") == "config"
    return not ma_dex


def _parse_apk_obj(apk: APK) -> dict:
    intent_filters = _parse_intent_filters(apk)
    declared_perms = _safe(apk.get_declared_permissions, [])
    providers = _safe(apk.get_providers, [])

    split = wykryj_split(_safe(apk.get_android_manifest_xml))
    if split is not None:
        # O tym, czy split niesie kod, rozstrzyga obecnosc DEX-a, a nie nazwa.
        # Split typu "feature" kod ma i zasluguje na pelna analize; splity
        # konfiguracyjne go nie maja. Sprawdzenie faktu jest pewniejsze niz
        # wnioskowanie z prefiksu "config.", ktory jest tylko konwencja.
        pliki = _safe(apk.get_files, []) or []
        split["ma_dex"] = any(str(n).lower().endswith(".dex") for n in pliki)

    return {
        "split": split,
        "package": _safe(apk.get_package),
        "app_name": _safe(apk.get_app_name),
        "version_name": _safe(apk.get_androidversion_name),
        "version_code": _safe(apk.get_androidversion_code),
        "min_sdk": _safe(apk.get_min_sdk_version),
        "target_sdk": _safe(apk.get_target_sdk_version),
        "permissions": sorted(_safe(apk.get_permissions, [])),
        "declared_permissions": list(declared_perms) if declared_perms else [],
        "activities": list(_safe(apk.get_activities, [])),
        "services": list(_safe(apk.get_services, [])),
        "receivers": list(_safe(apk.get_receivers, [])),
        "providers": list(providers) if providers else [],
        "autostart_actions": intent_filters["autostart"],
        "suspicious_actions": intent_filters["suspicious_actions"],
        "is_multidex": _safe(apk.is_multidex, False),
        "cert": analyze_cert(apk),
    }


def _parse_raw(apk_path: str) -> APK:
    """Fallback: wczytaj bajty i parsuj z raw=True.

    Omija błąd apkInspector [Errno 22] na Windows oraz radzi sobie z APK
    o nietypowym/uszkodzonym nagłówku ZIP (np. Triada), których
    APK(path) nie potrafi otworzyć.
    """
    with open(apk_path, "rb") as f:
        return APK(f.read(), raw=True)


def parse_apk_bytes(apk_bytes: bytes) -> dict:
    """Parsuje APK prosto z pamieci, bez zapisu na dysk.

    Zapisanie probki na dysk pod Windowsem sprawia, ze Defender ja flaguje
    i blokuje ponowne otwarcie — Python zglasza to jako mylace
    "[Errno 22] Invalid argument" przy open(). Analiza w pamieci omija
    skanowanie plikowe w calosci i jest przy okazji szybsza.
    """
    return _parse_apk_obj(APK(apk_bytes, raw=True))


def parse_apk_apktool(apk_path: str, timeout: int = 120) -> dict:
    """Fallback: dekoduj manifest apktoolem gdy androguard się wiesza.

    apktool używa innego dekodera AXML, odpornego na część technik anty-analizy
    (AXML bombing). Zwraca częściowe dane (bez certyfikatu — apktool nie parsuje
    podpisu). Wymaga tools/apktool.jar oraz Javy w PATH.
    """
    if not os.path.exists(_APKTOOL_JAR):
        raise ValueError("Brak tools/apktool.jar — nie mogę użyć fallbacku")

    out_dir = tempfile.mkdtemp(prefix="apktool_")
    try:
        # -s: pomiń dekompilację DEX (szybciej), -f: nadpisz, --no-res też można,
        # ale potrzebujemy AndroidManifest.xml, więc zostawiamy zasoby.
        subprocess.run(
            ["java", "-jar", _APKTOOL_JAR, "d", "-s", "-f", "-o", out_dir, apk_path],
            capture_output=True, timeout=timeout, check=True,
        )
        manifest_path = os.path.join(out_dir, "AndroidManifest.xml")
        if not os.path.exists(manifest_path):
            raise ValueError("apktool nie wygenerował AndroidManifest.xml")
        return _parse_manifest_xml(manifest_path)
    except subprocess.TimeoutExpired:
        raise ValueError(f"apktool timeout po {timeout}s")
    except subprocess.CalledProcessError as e:
        raise ValueError(f"apktool błąd: {e.stderr.decode(errors='ignore')[:200]}")
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)


def _parse_manifest_xml(manifest_path: str) -> dict:
    """Wyciąga dane z odkodowanego (plaintext) AndroidManifest.xml apktoola."""
    tree = ET.parse(manifest_path)
    root = tree.getroot()

    split = wykryj_split(root)
    if split is not None:
        # Tu nie widzimy listy plikow (apktool rozpakowal tylko manifest),
        # wiec zostawiamy None zamiast zgadywac.
        split["ma_dex"] = None

    def _name(el):
        return el.get(f"{_ANDROID_NS}name")

    app = root.find("application")
    activities, services, receivers, providers = [], [], [], []
    autostart, suspicious = [], []
    if app is not None:
        activities = [_name(e) for e in app.findall("activity") if _name(e)]
        services = [_name(e) for e in app.findall("service") if _name(e)]
        receivers = [_name(e) for e in app.findall("receiver") if _name(e)]
        providers = [_name(e) for e in app.findall("provider") if _name(e)]
        for rec in app.findall("receiver"):
            for action in rec.iter("action"):
                a = _name(action) or ""
                if "BOOT_COMPLETED" in a or "MY_PACKAGE_REPLACED" in a or "QUICKBOOT" in a:
                    autostart.append(a)
                if "SMS_RECEIVED" in a or "USER_PRESENT" in a or "CONNECTIVITY_CHANGE" in a:
                    suspicious.append(a)

    perms = sorted({_name(e) for e in root.findall("uses-permission") if _name(e)})
    declared = [_name(e) for e in root.findall("permission") if _name(e)]

    return {
        "split": split,
        "package": root.get("package"),
        "app_name": None,  # apktool nie rozwiązuje etykiety z zasobów w trybie -s
        "version_name": root.get(f"{_ANDROID_NS}versionName"),
        "version_code": root.get(f"{_ANDROID_NS}versionCode"),
        "min_sdk": None,
        "target_sdk": None,
        "permissions": perms,
        "declared_permissions": declared,
        "activities": activities,
        "services": services,
        "receivers": receivers,
        "providers": providers,
        "autostart_actions": sorted(set(autostart)),
        "suspicious_actions": sorted(set(suspicious)),
        "is_multidex": False,
        "cert": None,
        "parsed_via": "apktool-fallback",
    }


def parse_apk_timeout(apk_path: str, timeout: int = 90) -> dict:
    """Parsuj APK w osobnym procesie z twardym limitem czasu.

    Chroni przed spreparowanym AndroidManifest.xml (AXML bombing), ktory
    zawiesza parser androguarda w nieskonczonosc jako technika anty-analizy.
    Po przekroczeniu limitu proces jest ubijany i probujemy fallbacku apktool.
    """
    try:
        return run_isolated(parse_apk, (apk_path,), timeout=timeout)
    except IsolationTimeout:
        print(f"  [~] androguard timeout po {timeout}s - probuje fallback apktool...")
        return parse_apk_apktool(apk_path)
    except IsolationError as e:
        raise ValueError(str(e).splitlines()[-1])


def parse_apk(apk_path: str) -> dict:
    try:
        if apk_path.lower().endswith(".xapk"):
            data = _read_apk_bytes_from_xapk(apk_path)
            apk = APK(data, raw=True)
        else:
            try:
                apk = APK(apk_path)
            except Exception:
                # Fallback dla APK, których apkInspector nie potrafi otworzyć
                apk = _parse_raw(apk_path)
        return _parse_apk_obj(apk)
    except Exception as e:
        raise ValueError(f"Failed to parse '{apk_path}': {e}")
