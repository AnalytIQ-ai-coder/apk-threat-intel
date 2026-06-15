import json
import zipfile

from androguard.core.apk import APK
from cert_analyzer import analyze_cert


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
        xml_str = str(manifest_xml) if manifest_xml else ""
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


def parse_apk(apk_path: str) -> dict:
    try:
        if apk_path.lower().endswith(".xapk"):
            data = _read_apk_bytes_from_xapk(apk_path)
            apk = APK(data, raw=True)
        else:
            apk = APK(apk_path)
        return _parse_apk_obj(apk)
    except Exception as e:
        raise ValueError(f"Failed to parse '{apk_path}': {e}")
