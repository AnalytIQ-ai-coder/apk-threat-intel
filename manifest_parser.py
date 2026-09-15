"""AndroidManifest parsing, with fallbacks for samples that fight back.

Three paths, in order of preference: androguard on the file, androguard on raw
bytes, and apktool as a last resort. Malware routinely ships manifests that are
valid enough for Android and hostile enough to stall a parser, so every entry
point here is either isolated, time-boxed, or both.
"""
import json
import os
import shutil
import subprocess
import tempfile
import zipfile

# defusedxml rather than xml.etree: the standard parser is documented as
# vulnerable to billion laughs and quadratic blowup, and what we feed it is a
# manifest decoded out of a malicious sample.
import defusedxml.ElementTree as ET

from loguru import logger

# Muted here and not only in analyzer.py: this module also runs inside the
# run_isolated child processes, which never import analyzer.py.
logger.disable("androguard")

from androguard.core.apk import APK  # noqa: E402
from cert_analyzer import analyze_cert  # noqa: E402
from isolation import run_isolated, IsolationTimeout, IsolationError  # noqa: E402

_APKTOOL_JAR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools", "apktool.jar")
_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
_MAX_INNER_APK_BYTES = 512 * 1024 * 1024


def _read_apk_bytes_from_xapk(xapk_path: str) -> bytes:
    """Pull the main APK out of an XAPK bundle."""
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

        # An XAPK is an untrusted ZIP: one entry can expand into gigabytes.
        info = z.getinfo(apk_candidates[0])
        if info.file_size > _MAX_INNER_APK_BYTES:
            raise ValueError(f"APK inside XAPK is {info.file_size} B, over the limit")
        with z.open(info) as f:
            data = f.read(_MAX_INNER_APK_BYTES + 1)
        if len(data) > _MAX_INNER_APK_BYTES:
            raise ValueError("APK inside XAPK ran past the limit while reading")
        return data


def _safe(fn, default=None):
    """Call fn() and fall back to default on any failure.

    androguard raises a wide and undocumented range of exceptions on damaged
    input, and one missing manifest field should not cost us the whole sample.
    """
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
    """Collect autostart and otherwise interesting broadcast actions."""
    autostart = []
    suspicious = []
    try:
        for component in list(_safe(apk.get_receivers, [])) + list(_safe(apk.get_services, [])):
            filters = _safe(lambda: apk.get_intent_filters("receiver", component), {})
            if not filters:
                continue
            for action in filters.get("action", []):
                if action in _AUTOSTART_ACTIONS:
                    autostart.append(action)
                if action in _SUSPICIOUS_ACTIONS:
                    suspicious.append(action)
    except Exception:
        pass

    # Second pass over the raw manifest XML: the intent-filter API misses
    # actions on components androguard failed to enumerate.
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


def _manifest_attr(root, name: str) -> str:
    """Read a root-element attribute, with and without the android namespace.

    In AndroidManifest.xml "split" and "package" carry no prefix, but
    "isFeatureSplit" does. Rather than remember which is which, try both.
    """
    if root is None:
        return ""
    return (root.get(name) or root.get(f"{_ANDROID_NS}{name}") or "").strip()


def detect_split(root) -> dict | None:
    """Tell an App Bundle split apart from a full APK.

    Why this matters: an AAB install is base.apk plus a set of splits
    (config.arm64_v8a, config.xxhdpi, config.pl...). A config split is NOT an
    application - no label, no permissions, no minSdk and usually no code,
    because it is a container for native libraries or resources for a single
    ABI, density or language. Dropped into the pipeline as a standalone sample
    it looks like an app that "requests no permissions", and that is exactly
    how it used to get described: the model received an empty set of facts and
    answered RISK: low, reasoning "no permissions". That is an artefact of the
    empty prompt, not an assessment of anything.

    Detection needs no heuristics. A split's <manifest> root carries a
    split="..." attribute that a full APK does not have at all. Measured
    against samples in the database:

        ch.publisheria.bring          split="config.arm64_v8a"  splitTypes="base__abi"
        com.hankuper.promoter.market  split="config.tr" / "config.ja" / "config.pt"
        com.anbui.cqcm.app            split="config.arm64_v8a"
        xyz.nextalone.nagram (full)   no split attribute
        ghy.gss.rentaapps    (full)   no split attribute

    Returns None for a full APK - and for base.apk, which has no such
    attribute either - or a description of the split.
    """
    name = _manifest_attr(root, "split")
    if not name:
        return None

    if _manifest_attr(root, "isFeatureSplit").lower() in ("true", "1"):
        kind = "feature"
    elif name.startswith("config."):
        kind = "config"
    else:
        kind = "unknown"

    return {
        "name": name,
        "kind": kind,
        "types": _manifest_attr(root, "splitTypes"),
        # Filled in by the caller, who can see the file listing.
        "has_dex": None,
    }


def split_has_no_code(data: dict) -> bool:
    """Is this an App Bundle split that carries no code of its own?

    There is nothing to assess in one: no permissions, no components, no DEX,
    so any "risk rating" describes an empty set of facts rather than a sample.
    A "feature" split is the exception - it has its own code and goes through
    the normal path.
    """
    split = data.get("split")
    if not split:
        return False
    if split.get("kind") == "feature":
        return False

    has_dex = split.get("has_dex")
    if has_dex is None:
        # The apktool fallback never sees the file listing. Fall back to the
        # naming convention, which for config splits is fixed by the bundle
        # tool itself rather than chosen by the author.
        return split.get("kind") == "config"
    return not has_dex


def _parse_apk_obj(apk: APK) -> dict:
    """Flatten a parsed APK into the dict the rest of the pipeline expects."""
    intent_filters = _parse_intent_filters(apk)
    declared_perms = _safe(apk.get_declared_permissions, [])
    providers = _safe(apk.get_providers, [])

    split = detect_split(_safe(apk.get_android_manifest_xml))
    if split is not None:
        # Whether a split carries code is settled by the presence of a DEX, not
        # by its name. Feature splits do have code and deserve full analysis;
        # config splits do not. Checking the fact beats inferring from the
        # "config." prefix, which is only a convention.
        files = _safe(apk.get_files, []) or []
        split["has_dex"] = any(str(n).lower().endswith(".dex") for n in files)

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
    """Fallback: read the bytes and parse with raw=True.

    Sidesteps the apkInspector [Errno 22] on Windows and copes with APKs whose
    ZIP header is unusual or damaged (Triada, for one) that APK(path) refuses
    to open at all.
    """
    with open(apk_path, "rb") as f:
        return APK(f.read(), raw=True)


def parse_apk_bytes(apk_bytes: bytes) -> dict:
    """Parse an APK straight from memory, never touching the disk.

    Writing a sample to disk on Windows gets it flagged by Defender, which then
    blocks reopening the file - Python surfaces that as a misleading
    "[Errno 22] Invalid argument" from open(). Working in memory skips file
    scanning entirely and is faster into the bargain.
    """
    return _parse_apk_obj(APK(apk_bytes, raw=True))


def parse_apk_apktool(apk_path: str, timeout: int = 120) -> dict:
    """Fallback: decode the manifest with apktool when androguard hangs.

    apktool uses a different AXML decoder, one that shrugs off some
    anti-analysis tricks (AXML bombing). Returns partial data - no certificate,
    because apktool does not parse the signature. Needs tools/apktool.jar and
    a java on PATH.
    """
    if not os.path.exists(_APKTOOL_JAR):
        raise ValueError("tools/apktool.jar is missing, cannot use the fallback")

    out_dir = tempfile.mkdtemp(prefix="apktool_")
    try:
        # -s skips DEX decompilation, which is most of the runtime; -f
        # overwrites. --no-res would be faster still, but the manifest needs
        # the resource table, so resources stay.
        subprocess.run(
            ["java", "-jar", _APKTOOL_JAR, "d", "-s", "-f", "-o", out_dir, apk_path],
            capture_output=True, timeout=timeout, check=True,
        )
        manifest_path = os.path.join(out_dir, "AndroidManifest.xml")
        if not os.path.exists(manifest_path):
            raise ValueError("apktool produced no AndroidManifest.xml")
        return _parse_manifest_xml(manifest_path)
    except subprocess.TimeoutExpired:
        raise ValueError(f"apktool timed out after {timeout}s")
    except subprocess.CalledProcessError as e:
        raise ValueError(f"apktool failed: {e.stderr.decode(errors='ignore')[:200]}")
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)


def _parse_manifest_xml(manifest_path: str) -> dict:
    """Read apktool's decoded plaintext AndroidManifest.xml."""
    tree = ET.parse(manifest_path)
    root = tree.getroot()

    split = detect_split(root)
    if split is not None:
        # No file listing here (apktool only unpacked the manifest), so leave
        # this unknown rather than guess.
        split["has_dex"] = None

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
        "app_name": None,  # apktool -s does not resolve the label from resources
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
    """Parse an APK in a child process under a hard deadline.

    Guards against a crafted AndroidManifest.xml (AXML bombing) that hangs
    androguard's parser forever as an anti-analysis technique. Past the
    deadline the process is killed and we try the apktool fallback.
    """
    try:
        return run_isolated(parse_apk, (apk_path,), timeout=timeout)
    except IsolationTimeout:
        print(f"  [~] androguard timed out after {timeout}s, trying apktool fallback...")
        return parse_apk_apktool(apk_path)
    except IsolationError as e:
        raise ValueError(str(e).splitlines()[-1])


def parse_apk(apk_path: str) -> dict:
    """Parse an APK or XAPK from disk."""
    try:
        if apk_path.lower().endswith(".xapk"):
            data = _read_apk_bytes_from_xapk(apk_path)
            apk = APK(data, raw=True)
        else:
            try:
                apk = APK(apk_path)
            except Exception:
                # Fallback for APKs that apkInspector cannot open.
                apk = _parse_raw(apk_path)
        return _parse_apk_obj(apk)
    except Exception as e:
        raise ValueError(f"Failed to parse '{apk_path}': {e}")
