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


def _parse_apk_obj(apk: APK) -> dict:
    return {
        "package": apk.get_package(),
        "app_name": apk.get_app_name(),
        "version_name": apk.get_androidversion_name(),
        "version_code": apk.get_androidversion_code(),
        "min_sdk": apk.get_min_sdk_version(),
        "target_sdk": apk.get_target_sdk_version(),
        "permissions": sorted(apk.get_permissions()),
        "activities": list(apk.get_activities()),
        "services": list(apk.get_services()),
        "receivers": list(apk.get_receivers()),
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
