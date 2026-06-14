import math
import re
import zipfile
from io import BytesIO

from androguard.core.dex import DEX

# ── URL / IP / domain patterns ────────────────────────────────────────────────
_URL_RE = re.compile(r'https?://[^\s\'"<>]{6,}', re.IGNORECASE)
_IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b')
_DOMAIN_RE = re.compile(
    r'\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|tk|top|xyz|info|biz|co|app|dev)\b',
    re.IGNORECASE,
)
_PKG_RE = re.compile(r'\b([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){2,})\b')

_DOMAIN_WHITELIST = {
    "schemas.android.com", "www.w3.org", "play.google.com",
    "developer.android.com", "goo.gl", "firebase.google.com",
    "googleapis.com", "google.com", "facebook.com", "amazon.com",
    "crashlytics.com", "appsflyer.com", "adjust.com",
}

# ── Dangerous API signatures ──────────────────────────────────────────────────
_DANGEROUS_APIS = {
    "Device fingerprinting": [
        "getDeviceId", "getSubscriberId", "getSimSerialNumber",
        "getImei", "getImsi", "getLine1Number",
    ],
    "SMS abuse": [
        "sendTextMessage", "sendMultipartTextMessage",
        "onReceive.*SMS", "SMS_RECEIVED",
    ],
    "Accessibility abuse": [
        "AccessibilityService", "onAccessibilityEvent",
        "performGlobalAction", "findAccessibilityNodeInfosByText",
    ],
    "Device admin": [
        "DeviceAdminReceiver", "DevicePolicyManager",
        "lockNow", "wipeData", "resetPassword",
    ],
    "Account theft": [
        "getAccounts", "AccountManager", "getAuthToken",
    ],
    "Camera/Mic recording": [
        "MediaRecorder", "AudioRecord", "takePicture",
    ],
    "Encryption/hiding": [
        "AES", "DESede", "Cipher.getInstance", "SecretKeySpec",
    ],
    "Overlay attack": [
        "TYPE_APPLICATION_OVERLAY", "TYPE_SYSTEM_ALERT",
        "SYSTEM_ALERT_WINDOW", "drawOverApps",
    ],
    "Root/Privilege escalation": [
        "su\\b", "/system/bin/su", "Runtime.exec", "ProcessBuilder",
    ],
    "Reflection/obfuscation": [
        "getDeclaredMethod", "invoke\\(", "Class.forName",
        "DexClassLoader", "PathClassLoader",
    ],
}


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((f / n) * math.log2(f / n) for f in freq if f > 0)


def _is_whitelisted(value: str) -> bool:
    return any(w in value for w in _DOMAIN_WHITELIST)


def _extract_dex_strings(apk_bytes: bytes) -> list[str]:
    strings = []
    try:
        with zipfile.ZipFile(BytesIO(apk_bytes)) as z:
            for name in z.namelist():
                if re.match(r'classes\d*\.dex', name):
                    try:
                        dex = DEX(z.read(name))
                        strings.extend(str(s) for s in dex.get_strings())
                    except Exception:
                        continue
    except Exception:
        pass
    return strings


def _analyze_entropy_and_libs(apk_bytes: bytes) -> dict:
    native_libs = []
    high_entropy_files = []

    try:
        with zipfile.ZipFile(BytesIO(apk_bytes)) as z:
            for info in z.infolist():
                name = info.filename

                # Native libraries
                if name.startswith("lib/") and name.endswith(".so"):
                    parts = name.split("/")
                    arch = parts[1] if len(parts) >= 3 else "unknown"
                    lib_name = parts[-1]
                    native_libs.append({"name": lib_name, "arch": arch})

                # Entropy on interesting files
                if info.file_size > 1024 and any(name.endswith(ext)
                        for ext in (".dex", ".so", ".jar", ".bin", ".dat")):
                    try:
                        data = z.read(name)
                        entropy = _shannon_entropy(data)
                        if entropy > 7.0:
                            high_entropy_files.append({
                                "file": name,
                                "entropy": round(entropy, 3),
                                "size": info.file_size,
                            })
                    except Exception:
                        continue
    except Exception:
        pass

    return {"native_libs": native_libs, "high_entropy_files": high_entropy_files}


def _find_dangerous_apis(strings: list[str]) -> dict:
    found = {}
    all_text = "\n".join(strings)
    for category, patterns in _DANGEROUS_APIS.items():
        matches = []
        for p in patterns:
            if re.search(p, all_text):
                matches.append(p.replace("\\b", "").replace("\\(", "()"))
        if matches:
            found[category] = matches
    return found


def _find_targeted_packages(strings: list[str], own_package: str = "") -> list[str]:
    candidates = set()
    banking_keywords = {
        "bank", "sber", "tinkoff", "alfa", "vtb", "gazprom", "finam",
        "raif", "otp", "unicredit", "modul", "oneme", "wildberries",
        "pay", "wallet", "fintech", "crypto", "btc", "cash",
    }
    for s in strings:
        for m in _PKG_RE.findall(s):
            if m == own_package:
                continue
            if len(m) < 10 or m.startswith("android.") or m.startswith("java."):
                continue
            lower = m.lower()
            if any(kw in lower for kw in banking_keywords):
                candidates.add(m)
    return sorted(candidates)


def analyze_dex(apk_path: str, own_package: str = "") -> dict:
    try:
        with open(apk_path, "rb") as f:
            apk_bytes = f.read()
    except Exception as e:
        return {"error": str(e)}

    strings = _extract_dex_strings(apk_bytes)
    infra = _analyze_entropy_and_libs(apk_bytes)

    urls, ips, domains = set(), set(), set()
    for s in strings:
        for m in _URL_RE.findall(s):
            if not _is_whitelisted(m):
                urls.add(m)
        for m in _IP_RE.findall(s):
            if not any(m.startswith(p) for p in ("127.", "0.", "192.168.", "10.", "172.")):
                ips.add(m)
        for m in _DOMAIN_RE.findall(s):
            if not _is_whitelisted(m):
                domains.add(m)

    return {
        "urls": sorted(urls),
        "ips": sorted(ips),
        "domains": sorted(domains),
        "native_libs": infra["native_libs"],
        "high_entropy_files": infra["high_entropy_files"],
        "dangerous_apis": _find_dangerous_apis(strings),
        "targeted_packages": _find_targeted_packages(strings, own_package),
        "dex_string_count": len(strings),
    }
