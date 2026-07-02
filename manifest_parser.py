import json
import os
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import zipfile
import multiprocessing as mp

from androguard.core.apk import APK
from cert_analyzer import analyze_cert

_APKTOOL_JAR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools", "apktool.jar")
_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


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

        with z.open(apk_candidates[0]) as f:
            return f.read()


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


def _parse_apk_obj(apk: APK) -> dict:
    intent_filters = _parse_intent_filters(apk)
    declared_perms = _safe(apk.get_declared_permissions, [])
    providers = _safe(apk.get_providers, [])

    return {
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


def _parse_worker(apk_path: str, q) -> None:
    try:
        q.put(("ok", parse_apk(apk_path)))
    except Exception as e:
        q.put(("err", str(e)))


def parse_apk_timeout(apk_path: str, timeout: int = 90) -> dict:
    """Parsuj APK w osobnym procesie z twardym limitem czasu.

    Chroni przed spreparowanym AndroidManifest.xml (AXML bombing), który
    zawiesza parser androguarda w nieskończoność jako technika anty-analizy.
    Po przekroczeniu limitu proces jest ubijany i zgłaszany jest wyjątek.
    """
    ctx = mp.get_context("spawn")
    q = ctx.Queue()
    p = ctx.Process(target=_parse_worker, args=(apk_path, q), daemon=True)
    p.start()
    p.join(timeout)

    if p.is_alive():
        p.terminate()
        p.join()
        print(f"  [~] androguard timeout po {timeout}s — próbuję fallback apktool...")
        return parse_apk_apktool(apk_path)
    if q.empty():
        raise ValueError("Proces parsujący zakończył się bez wyniku")

    status, payload = q.get()
    if status == "err":
        raise ValueError(payload)
    return payload


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
