import base64
import math
import re
import zipfile
from io import BytesIO

from loguru import logger

# Muted here and not only in analyzer.py: this module also runs inside the
# run_isolated child processes, which never import analyzer.py.
logger.disable("androguard")

from androguard.core.dex import DEX

# ── URL / IP / domain patterns ────────────────────────────────────────────────
_URL_RE = re.compile(r'https?://[^\s\'"<>]{6,}', re.IGNORECASE)
_IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b')
_DOMAIN_RE = re.compile(
    r'\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|tk|top|xyz|info|biz|co|dev)\b',
    re.IGNORECASE,
)
_PKG_RE = re.compile(r'\b([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){2,})\b')

_DOMAIN_WHITELIST = {
    "schemas.android.com", "www.w3.org", "play.google.com",
    "developer.android.com", "goo.gl", "firebase.google.com",
    "googleapis.com", "google.com", "facebook.com", "amazon.com",
    "crashlytics.com", "appsflyer.com", "adjust.com",
}

# Android/Java package name prefixes that look like domains but aren't
_JAVA_PACKAGE_PREFIXES = (
    "android.", "com.android.", "com.google.android.", "dalvik.",
    "java.", "javax.", "kotlin.", "kotlinx.", "androidx.",
    "org.apache.", "org.json.", "org.xml.", "org.w3c.",
    "sun.", "libcore.", "okhttp3.", "retrofit2.",
)

# Exact false-positive "domains" that are actually Kotlin/Java identifiers
# (e.g. kotlinx.coroutines.Dispatchers.IO gets chopped down to "Dispatchers.IO"
# by the domain regex, since it only sees the tail with a valid-looking TLD)
_DOMAIN_FALSE_POSITIVES = {"dispatchers.io"}

# The TLD tokens from _DOMAIN_RE. A package name is reversed DNS, so its TLD
# sits at the FRONT ("com.chrome.dev", "org.openjsse.net") while a real domain
# ends with one. That single criterion drops package tails without a blocklist.
_TLD_TOKENS = frozenset({
    "com", "net", "org", "io", "ru", "cn", "tk", "top", "xyz",
    "info", "biz", "co", "dev",
})

# The subset used to spot reversed DNS from the FIRST label. Deliberately
# without "dev", "info" and "co": those are common subdomain names
# (dev.tapjoy.com, info.startappservice.com, co.uk), so the full set threw away
# real hosts along with the package names.
_TLDS_STARTING_A_PACKAGE = frozenset({
    "com", "net", "org", "io", "ru", "cn", "tk", "top", "xyz", "biz",
})

# These TLDs collide with code identifiers more often than any others:
# geometry and CSS (rect.top, window.top, a.style.top) plus logging
# (console.info, Log.INFO). Of 36 ".top" domains in the database four are real,
# and of 63 ".info" domains about five are. They can NOT be dropped wholesale -
# poker-rooms.top and cln9vhvfo2.top are live C2 - so instead we raise the bar
# for them inside _domain_is_ioc.
_TLDS_COLLIDING_WITH_CODE = frozenset({"top", "info", "xyz", "io", "tk"})

# Property and object names that ".top" or ".info" tends to follow in code.
# Checked against EVERY label, because the pattern nests
# ("a.style.top", "Log.private.info", "feature.screen.info").
_PROPERTIES_POSING_AS_HOSTS = frozenset({
    # object properties and logging: rect.top, window.top, console.info
    "style", "window", "console", "log", "screen", "feature",
    "document", "parent", "rect", "layout", "bounds",
    # shader vector names - a ".xyz" swizzle follows these
    "color", "position", "normal", "tangent", "texel", "vertex",
    "hsl", "hsv", "fragcolor", "light", "dir", "pos", "vec",
})

# Placeholders from documentation and tutorials. Matched EXACTLY, not by
# substring: "dynamicdns.park-your-domain.com" is a real dyn-DNS provider and
# happens to contain "domain.com".
_PLACEHOLDER_DOMAINS = frozenset({
    "example.com", "www.example.com", "example.org", "www.example.org",
    "example.net", "www.example.net", "domain.com", "www.domain.com",
    "mydomain.com", "yourdomain.com", "test.com", "www.test.com",
    "simple.com", "www.xxxyyyxxx.com",
})

# First two octets of well-known ASN.1/X.509 OID roots (RSADSI, X.500 attrs/
# extensions, OIW, Certicom, TeleTrust, NIST algorithm IDs, ...). DEX string
# pools embed these from crypto libs (BouncyCastle etc). A long OID like
# "2.16.840.1.101.3.4.1.9.16" gets sliced into many overlapping 4-number
# windows by the plain IPv4 regex, each of which looks like a valid IP.
_OID_FIRST_OCTETS = {"0", "1", "2", "3", "4", "5", "7"}

# Specific observed OID fragments whose first octet looks like a normal public
# IP block but is actually part of a longer ASN.1 arc chain (e.g. NIST/PKCS
# algorithm OIDs 2.16.840.1.101.3.4.x sliced into "101.3.4.x" windows).
_OID_FRAGMENT_PREFIXES = ("61.1.1.", "101.3.4.", "223.101.")

# Addresses reserved for documentation: RFC 5737 (TEST-NET-1/2/3) plus
# 123.45.67.89, the canonical "example IP" from tutorials, hard-coded into the
# UI of server apps (Servers Ultimate displays it as a template).
_DOC_IP_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.")
_DOC_IPS_EXACT = frozenset({"123.45.67.89"})

# Four-part SDK version numbers ("6.4.2.1", "9.14.12.0") are indistinguishable
# from an IP address to the regex alone. A single ibisPaint X sample produced
# ten of them at once. The difference is statistical: an address whose four
# octets are ALL small covers 0.02% of the address space, yet of 127 addresses
# in the database 26 meet that condition and every one is a version number.
# Many end in ".0", so even read as addresses they would be network addresses
# rather than hosts.
#
# The threshold of 30 rather than, say, 255 comes from measuring the database.
# One extra condition: an address carrying a port always survives, because a
# port means network context rather than a library version.
_MAX_VERSION_OCTET = 30

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
    # NFC relay: the victim taps a physical payment card against the phone, the
    # malware reads the APDU responses and forwards them to the attacker's
    # device, which emulates that card at a terminal. IsoDep on its own is
    # legitimate (wallets, document readers) - it is READING plus EMULATION in
    # one sample that has no consumer use. The YARA rule draws that line.
    "NFC / payment cards": [
        "IsoDep", "transceive", "NfcAdapter", "enableReaderMode",
        "HostApduService", "processCommandApdu", "2PAY.SYS.DDF01",
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


# ── Guard rails for reading the archive ──────────────────────────────────────
# An APK is an untrusted ZIP: an entry of a few kB can expand into gigabytes
# (zip bomb). We never read an entry without checking file_size first.
_MAX_ENTRY_BYTES = 64 * 1024 * 1024
_MAX_B64_INPUT = 8192

# Magic bytes of formats that get embedded as Base64 and are not text.
_BINARY_MAGIC = (b"\x89PNG", b"PK\x03\x04", b"dex\n", b"GIF8", b"\x1f\x8b\x08\x00")


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((f / n) * math.log2(f / n) for f in freq if f > 0)


def _is_whitelisted(value: str) -> bool:
    if any(w in value for w in _DOMAIN_WHITELIST):
        return True
    lower = value.lower()
    if lower in _DOMAIN_FALSE_POSITIVES:
        return True
    return any(lower.startswith(p) for p in _JAVA_PACKAGE_PREFIXES)


# An identifier segment: what can sit right next to a match when the regex
# landed in the middle of a longer dotted name.
_IDENTIFIER_SEGMENT_RE = re.compile(r"[A-Za-z0-9_]+")


def _is_identifier_fragment(context: str, start: int, end: int) -> bool:
    """Is this match a slice of a longer dotted name rather than a host?

    Measured across five real APKs: this is where most of the false positives
    come from, and they cannot be filtered by looking at the matched value
    alone. "camerax.core.io" comes from "camerax.core.io.ioExecutor",
    "client.dev" from the Firebase flag "..._stitching_token.client.dev",
    "br.com" from "br.com.eventim.mobile.app.Android", and "rx2.io" from the
    RxJava property "rx2.io-priority".
    """
    # TAIL of a longer name. The condition on the character BEFORE the dot
    # matters and cannot be dropped: a dot in front of the match is not enough
    # on its own. The regex only fails to reach left when the previous label
    # holds a character outside [a-z0-9-]. If that character is a letter, digit
    # or underscore we have an identifier ("..._token.client.dev", or two
    # string-pool entries glued together: "h3_tun.rs" + "cdnjs.cloudflare.com").
    # If it is punctuation, this is a real host with a truncated prefix -
    # "*.cloudflareclient.com", "<gateway_unique_id>.cloudflare-gateway.com" -
    # and discarding it would be a loss. Without this condition the filter ate
    # four genuine Cloudflare hosts in a single sample.
    if start >= 2 and context[start - 1] == "." and (
        context[start - 2].isalnum() or context[start - 2] == "_"
    ):
        return True

    after = context[end:]
    # HEAD of a longer name: another segment follows the supposed TLD.
    if after[:1] == ".":
        m = _IDENTIFIER_SEGMENT_RE.match(after[1:])
        # The 3-character threshold protects domains with a two-part TLD: for
        # "example.com.br" the regex returns "example.com", and a trailing
        # ".br" must not be what decides this is an identifier.
        if m and len(m.group()) >= 3:
            return True
    # A hyphen after the TLD shows up in system properties ("rx2.io-priority",
    # "rx2.io-keep-alive-time"). Narrowed to a purely alphabetic segment,
    # because "index.crates.io-6f17d22bba15001f" is a Cargo registry path in
    # which index.crates.io is a real host.
    if after[:1] == "-":
        m = _IDENTIFIER_SEGMENT_RE.match(after[1:])
        if m and len(m.group()) >= 3 and m.group().isalpha():
            return True

    return False


def _domain_is_ioc(value: str, context: str = "", start: int = 0,
                   end: int = 0) -> bool:
    """Is this _DOMAIN_RE match really a host, or an identifier from the code?

    The regex only ever sees the tail of a string ending in something that
    looks like a TLD, so it just as happily catches Java class names
    ("BitmapEncoder.com"), GLSL swizzles from Flutter shaders
    ("lightDirAndSpotCutoff.xyz") and package tails ("org.openjsse.net").

    For domains ONLY. It is wrong for URLs: "https://CaptchaKey.com" is a real
    address despite the capitals in the host name.
    """
    if _is_whitelisted(value):
        return False

    if value.lower() in _PLACEHOLDER_DOMAINS:
        return False

    # Context is only supplied when extracting from a DEX. clean_iocs.py calls
    # this on finished values out of the database, where there is no context
    # left, and then this test is simply skipped.
    if context and _is_identifier_fragment(context, start, end):
        return False

    labels = value.split(".")

    # A version number posing as a host: "1.3.17.dev", "2.6.8.dev". At least
    # TWO numeric labels before the TLD are required - with one, the rule would
    # take 10010.com and 10086.cn, real Chinese carrier domains.
    if len(labels) >= 3 and all(e.isdigit() for e in labels[:-1]):
        return False

    if labels[0].lower() in _TLDS_STARTING_A_PACKAGE:
        return False  # reversed DNS -> package name, not a host

    # A long camelCase name is a Java class, not a host. The 18-character
    # threshold is not decoration: without it the rule ate HappyMod.com,
    # LEEAPK.COM, JesusFreke.com and YTPL.net - real pirated-APK sites, which
    # are valuable distribution IOCs. Short camelCase stays: a few false
    # positives (CenterCrop.com) are cheaper than losing real hosts.
    if len(labels[0]) > 18 and re.search("[a-z0-9][A-Z]", labels[0]):
        return False

    # GLSL swizzle: ".xyz" is a TLD, so vector component access in libflutter
    # shaders ("a.xyz", "b.xyz") looks like a domain. Narrowed to a
    # single-character label, because "g.co", "x.com" and "a.applovin.com" are
    # real domains and must not be lost.
    if len(labels) == 2 and len(labels[0]) == 1 and labels[1].lower() == "xyz":
        return False

    if labels[-1].lower() in _TLDS_COLLIDING_WITH_CODE:
        # DNS is written in lower case; ".Top" or ".INFO" is a code constant.
        if not labels[-1].islower():
            return False
        # A capital in the label before the TLD: "Rect.top", "SystemUiOverlay.top".
        if any(c.isupper() for c in labels[-2]):
            return False
        # Short purely alphabetic labels are minified variable names
        # ("a.top", "s.INFO", "a.j.top"). The "letters only" part matters:
        # without it the rule took www.6b.top and tws.6b.top, a short but
        # genuine domain.
        if len(labels[-2]) <= 2 and labels[-2].isalpha():
            return False
        # DELIBERATELY not rejecting a single-character FIRST label. It was
        # tempting for "x.print.processor.info", but measuring the database
        # showed the cost: s.presage.io, s.cloud.ogury.io and
        # s.qa.cloud.ogury.io are real hosts of the Ogury ad network. Short
        # subdomains (s., a., d., g.co) are everywhere at CDNs - that is the
        # third time this same rule tried to take real data.
        if any(e.lower() in _PROPERTIES_POSING_AS_HOSTS for e in labels[:-1]):
            return False

    return True


def _is_plausible_ip(value: str) -> bool:
    """Is this an address that makes sense as an IOC?

    Filters out four classes of junk that a four-number regex picks up
    alongside real addresses:
      * X.509 OID fragments (2.5.4.3 = commonName, 2.5.29.15 = keyUsage) - long
        ASN.1 arcs slice into overlapping windows that look like IPs,
      * version numbers with a leading zero in an octet ("6.14.0.04"),
      * network and broadcast addresses plus reserved ranges,
      * private and link-local ranges - including 169.254.169.254, the cloud
        metadata endpoint, which is not attacker infrastructure.
    """
    host = _normalize_ip(value)
    octets = host.split(".")
    if len(octets) != 4:
        return False

    for o in octets:
        if not o.isdigit() or int(o) > 255:
            return False
        if len(o) > 1 and o.startswith("0"):
            return False  # "04" is version notation, not an octet

    if octets[0] in _OID_FIRST_OCTETS:
        return False
    if host.startswith(_OID_FRAGMENT_PREFIXES):
        return False
    if host.startswith(_DOC_IP_PREFIXES) or host in _DOC_IPS_EXACT:
        return False

    has_port = ":" in value.replace("[b64] ", "")
    all_octets_equal = len(set(octets)) == 1   # 8.8.8.8, 1.1.1.1, 9.9.9.9
    if (not has_port and not all_octets_equal
            and all(int(o) <= _MAX_VERSION_OCTET for o in octets)):
        return False    # a version number, not an address

    a, b = int(octets[0]), int(octets[1])
    if octets[2:] == ["0", "0"]:
        return False                      # network address (x.y.0.0), not a host
    if a in (0, 10, 127):
        return False                      # this-network, private, loopback
    if a == 172 and 16 <= b <= 31:
        return False                      # private 172.16/12, not all of 172.x
    if a == 192 and b == 168:
        return False
    if a == 169 and b == 254:
        return False                      # link-local plus cloud metadata
    if a >= 224:
        return False                      # multicast, reserved, broadcast
    return True


def _read_capped(z: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int = _MAX_ENTRY_BYTES):
    """Read one archive entry under a hard size limit.

    A crafted APK can understate file_size, so the limit is enforced at read
    time as well. Returns None when the entry runs over, and the caller simply
    skips it.
    """
    if info.file_size > limit:
        return None
    try:
        with z.open(info) as fh:
            data = fh.read(limit + 1)
    except Exception:
        return None
    if len(data) > limit:
        return None
    return data


def _extract_dex_strings(apk_bytes: bytes) -> list[str]:
    strings = []
    try:
        with zipfile.ZipFile(BytesIO(apk_bytes)) as z:
            for info in z.infolist():
                if re.match(r'classes\d*\.dex', info.filename):
                    data = _read_capped(z, info)
                    if data is None:
                        continue
                    try:
                        dex = DEX(data)
                        strings.extend(str(s) for s in dex.get_strings())
                    except Exception:
                        continue
    except Exception:
        pass
    return strings


# Minimum run of printable bytes we count as a string inside a .so, same idea
# as the `strings` tool. Anything shorter is mostly noise.
_NATIVE_STR_RE = re.compile(rb"[\x20-\x7e]{6,}")
_MAX_NATIVE_STRINGS = 200000


# Public DNS resolvers. Apps hit these routinely (DoH, connectivity checks,
# HTTPDNS), so as IOCs they are pure noise - 8.8.8.8 alone used to correlate a
# dozen unrelated samples with each other.
_PUBLIC_RESOLVERS = {
    "8.8.8.8", "8.8.4.4",                                  # Google
    "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3",  # Cloudflare
    "9.9.9.9", "9.9.9.10", "9.9.9.11", "149.112.112.112",  # Quad9
    "208.67.222.222", "208.67.220.220", "208.67.222.123", "208.67.220.123",  # OpenDNS
    "94.140.14.14", "94.140.15.15", "94.140.14.15", "94.140.15.16",  # AdGuard
    "64.6.64.6", "64.6.65.6",                              # Verisign
    "84.200.69.80", "84.200.70.40",                        # DNS.WATCH
    "8.26.56.26", "8.20.247.20",                           # Comodo
    "77.88.8.8", "77.88.8.1", "77.88.8.88", "77.88.8.2",   # Yandex
    "223.5.5.5", "223.6.6.6",                              # AliDNS
    "114.114.114.114", "114.114.115.115",                  # 114DNS
    "180.76.76.76",                                        # Baidu
    "1.2.4.8", "210.2.4.8",                                # CNNIC
    "194.242.2.2",                                         # Mullvad
}

# HTTPDNS services use whole pools rather than single addresses.
_RESOLVER_PREFIXES = ("119.29.29.", "119.28.28.", "45.90.28.", "45.90.30.")


def _normalize_ip(value: str) -> str:
    """Strip the [b64] marker and any port, leaving the bare address."""
    return value.replace("[b64] ", "").split(":", 1)[0].strip()


def _is_public_resolver(value: str) -> bool:
    host = _normalize_ip(value)
    return host in _PUBLIC_RESOLVERS or host.startswith(_RESOLVER_PREFIXES)


def _drop_sequential_ips(ips: set) -> set:
    """Remove "addresses" that are really version numbers.

    A run like 80.5.1.1 ... 80.5.1.10 inside one sample is library versioning,
    not infrastructure. Real C2 does not show up as several consecutive
    addresses differing only in the last octet.
    """
    groups = {}
    for ip in ips:
        prefix = _normalize_ip(ip).rsplit(".", 1)[0]
        groups.setdefault(prefix, []).append(ip)
    return {ip for members in groups.values() if len(members) < 3 for ip in members}


def _extract_native_strings(apk_bytes: bytes) -> list[str]:
    """Pull printable strings out of the native libraries (lib/**/*.so).

    Well-written malware keeps its C2 address in native code, not in the DEX.
    One libbot.so sample (VT 28/75) yielded zero IOCs because we only ever read
    classes*.dex - the better hidden the payload, the less we extracted.
    """
    strings = []
    try:
        with zipfile.ZipFile(BytesIO(apk_bytes)) as z:
            for info in z.infolist():
                name = info.filename
                if not (name.startswith("lib/") and name.endswith(".so")):
                    continue
                data = _read_capped(z, info)
                if data is None:
                    continue
                for m in _NATIVE_STR_RE.finditer(data):
                    strings.append(m.group().decode("ascii", errors="ignore"))
                    if len(strings) >= _MAX_NATIVE_STRINGS:
                        return strings
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
                    data = _read_capped(z, info)
                    if data is None:
                        continue
                    try:
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


# ── Known malware frameworks / SDKs ──────────────────────────────────────────
# Markers come in two classes, because a bare `"octo" in text` produced false
# positives wholesale: "october" and "doctor" contain "octo", "supermacro"
# contains "ermac", "alienate" contains "alien". A Unity game with ad SDKs has
# tens of thousands of string-pool entries, so a hit was all but guaranteed.
#
#   strong - an artefact specific to the family (package prefix, unique
#            string). A hit stands on its own.
#   weak   - the family name alone, which can be an ordinary word. Requires a
#            word-boundary match AND a permission confirming a banker profile.
_MALWARE_FRAMEWORKS = {
    "Cerberus": {"strong": ["com.pns.", "cerbero"], "weak": ["cerberus"]},
    "Anubis":   {"strong": ["com.google.anubis"],   "weak": ["anubis"]},
    "SpyNote":  {"strong": ["com.craxsrat", "spynote"], "weak": []},
    "Hydra":    {"strong": ["com.hydra"],           "weak": ["hydra"]},
    "BankBot":  {"strong": ["bankbot", "com.android.protect"], "weak": []},
    "Alien":    {"strong": ["com.alien"],           "weak": ["alien"]},
    "Gustuff":  {"strong": ["gustuff"],             "weak": []},
    "Sharkbot": {"strong": ["sharkbot", "com.sharkbot"], "weak": []},
    "Ermac":    {"strong": [],                      "weak": ["ermac"]},
    "Octo":     {"strong": ["com.octo"],            "weak": ["octo"]},
    "Hook":     {"strong": ["hookbot", "com.hook"], "weak": []},
    "Mamont":   {"strong": ["pwtrick"],             "weak": ["mamont"]},
}

# Permissions without which an Android banking trojan cannot work. They act as
# confirmation for the weak markers. SYSTEM_ALERT_WINDOW and FOREGROUND_SERVICE
# are deliberately absent: both are common in games and ad SDKs.
_CONFIRMING_PERMISSIONS = (
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.REQUEST_INSTALL_PACKAGES",
)


# ── Suspicious class name patterns ────────────────────────────────────────────
_SUSPICIOUS_CLASS_PATTERNS = [
    re.compile(r'com\.[a-z]{6,12}\.[a-z]{6,12}$'),   # random-looking package
]

_KNOWN_PACKER_CLASSES = [
    "com.stub", "com.shell", "com.secshell", "com.qihoo",
    "com.tencent.StubShell", "com.wrapper", "lanchon.dexpatcher",
    "com.bangcle", "com.ieee", "com.protect",
]


def _detect_malware_frameworks(strings: list[str], permissions=()) -> list[str]:
    """Identify malware families from artefacts in the DEX string pool.

    permissions comes from the manifest and confirms the weak markers; without
    one, a weak hint is dropped so we do not label games as bankers.
    """
    all_text = chr(10).join(strings).lower()
    # Weak markers are matched against whole words, not substrings: "october"
    # and "doctor" contain "octo", but split into words they no longer match.
    words = set(re.split("[^a-z0-9]+", all_text))
    has_confirmation = any(p in set(permissions or ()) for p in _CONFIRMING_PERMISSIONS)

    found = []
    for name, markers in _MALWARE_FRAMEWORKS.items():
        if any(kw in all_text for kw in markers["strong"]):
            found.append(name)
            continue
        if not has_confirmation:
            continue
        if any(kw in words for kw in markers["weak"]):
            found.append(name)
    return found


def _detect_packers(strings: list[str]) -> list[str]:
    all_text = "\n".join(strings)
    found = []
    for packer in _KNOWN_PACKER_CLASSES:
        if packer in all_text:
            found.append(packer)
    return found


def _find_hidden_dex(apk_bytes: bytes) -> list[dict]:
    """Find DEX files disguised as other file types in assets/."""
    hidden = []
    DEX_MAGIC = b"dex\n"
    try:
        with zipfile.ZipFile(BytesIO(apk_bytes)) as z:
            for info in z.infolist():
                name = info.filename
                if re.match(r'classes\d*\.dex', name):
                    continue
                if any(name.endswith(ext) for ext in (".dex", ".apk", ".jar")):
                    continue
                # Four magic bytes are enough; no reason to unpack the rest.
                try:
                    with z.open(info) as fh:
                        magic = fh.read(4)
                except Exception:
                    continue
                if magic == DEX_MAGIC:
                    hidden.append({"file": name, "size": info.file_size})
    except Exception:
        pass
    return hidden


def _decode_base64_strings(strings: list[str]) -> list[str]:
    """Decode suspicious Base64 strings; URLs and IPs are the valuable part.

    Returns matched IOCs only, never the whole decoded blob: apps often keep
    icons and resources as Base64, and random PNG/ZIP bytes hit the IP regex
    almost every time.
    """
    found = set()
    b64_re = re.compile(r'^[A-Za-z0-9+/]{20,}={0,2}$')
    for s in strings:
        s = s.strip()
        if not b64_re.match(s) or len(s) > _MAX_B64_INPUT:
            continue
        try:
            raw = base64.b64decode(s, validate=True)
        except Exception:
            continue
        if raw[:4] in _BINARY_MAGIC or raw[:3] == b"\xff\xd8\xff":  # PNG/ZIP/DEX/GZIP, JPEG
            continue

        text = raw.decode("utf-8", errors="ignore")
        if not text:
            continue
        printable = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
        if printable / len(text) < 0.9:  # binary, not text
            continue

        found.update(_URL_RE.findall(text))
        found.update(m for m in _IP_RE.findall(text) if _is_plausible_ip(m))
    return sorted(found)[:20]


# A list of banking packages only means something if the sample can do
# anything with it: draw a phishing overlay, read the UI through Accessibility
# or intercept an SMS code. Without that it is just an app-category table - the
# Niagara launcher picked up 31 "targets" this way (ING, PayPal, Samsung Pay).
# REQUEST_INSTALL_PACKAGES is deliberately absent: every browser declares it.
_APP_ATTACK_PERMISSIONS = (
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.SYSTEM_ALERT_WINDOW",
)


_TARGET_KEYWORDS = (
    "bank", "sber", "tinkoff", "alfa", "vtb", "gazprom", "finam",
    "raif", "otp", "unicredit", "modul", "oneme", "wildberries",
    "pay", "wallet", "fintech", "crypto", "btc", "cash",
)

# Library packages that contain the keywords but are not attack targets:
# javax.crypto and org.bouncycastle.crypto landed on the "targets" list for
# every app that uses encryption, which is to say nearly every app.
_LIBRARY_PACKAGES = _JAVA_PACKAGE_PREFIXES + (
    "javax.", "org.bouncycastle.", "org.spongycastle.", "com.google.",
    "io.reactivex.", "com.squareup.", "org.codehaus.", "org.jetbrains.",
    "com.sun.", "gnu.", "kawa.", "com.facebook.", "org.slf4j.",
)

# Segments that start with a keyword but are ordinary words from the code:
# "module" starts with "modul" (Modulbank), "payload" starts with "pay".
_NON_TARGET_SEGMENTS = frozenset({
    "module", "modules", "modular", "payload", "payloads",
})


def _find_targeted_packages(strings: list[str], own_package: str = "",
                            permissions=()) -> list[str]:
    if not any(p in set(permissions or ()) for p in _APP_ATTACK_PERMISSIONS):
        return []  # no way to attack another app, so this is not a target list

    candidates = set()
    for s in strings:
        for m in _PKG_RE.findall(s):
            if m == own_package or len(m) < 10:
                continue
            lower = m.lower()
            if lower.startswith(_LIBRARY_PACKAGES):
                continue

            segments = re.split("[._]", lower)
            # "www.paypal.com" is a domain, not a package - _PKG_RE cannot tell
            # them apart. In reversed DNS the TLD leads, never trails.
            if segments[-1] in _TLD_TOKENS:
                continue

            # Match the START of a segment rather than any substring of the
            # whole name: "sberbankmobile" should start with "sber", but
            # "kawa.standard.module_name" must not pass for Modulbank.
            for seg in segments:
                if seg in _NON_TARGET_SEGMENTS:
                    continue
                if any(seg.startswith(kw) for kw in _TARGET_KEYWORDS):
                    candidates.add(m)
                    break
    return sorted(candidates)


def analyze_dex(apk_path: str, own_package: str = "", permissions=()) -> dict:
    """analyze_dex_bytes for a file on disk - what the live pipeline calls."""
    try:
        with open(apk_path, "rb") as f:
            apk_bytes = f.read()
    except Exception as e:
        return {"error": str(e)}
    return analyze_dex_bytes(apk_bytes, own_package, permissions)


def analyze_dex_bytes(apk_bytes: bytes, own_package: str = "", permissions=()) -> dict:
    """The analysis itself, over bytes already in memory.

    Split out from analyze_dex so backfill_ai.py can run it on a sample pulled
    straight from MWDB without writing the APK to disk first - on Windows
    Defender flags saved malware and then blocks reopening the file.
    """
    strings = _extract_dex_strings(apk_bytes)
    infra = _analyze_entropy_and_libs(apk_bytes)
    # Strings from .so go through the same regexes: C2 hidden in native code
    # never used to reach the results at all.
    native = _extract_native_strings(apk_bytes)

    urls, ips, domains = set(), set(), set()
    for s in strings + native:
        for m in _URL_RE.findall(s):
            if not _is_whitelisted(m):
                urls.add(m)
        for m in _IP_RE.findall(s):
            if _is_plausible_ip(m):
                ips.add(m)
        for m in _DOMAIN_RE.finditer(s):
            if _domain_is_ioc(m.group(), s, m.start(), m.end()):
                domains.add(m.group())

    decoded_b64 = _decode_base64_strings(strings)
    for text in decoded_b64:
        for m in _URL_RE.findall(text):
            urls.add(f"[b64] {m}")
        for m in _IP_RE.findall(text):
            if _is_plausible_ip(m):
                ips.add(f"[b64] {m}")

    ips = {ip for ip in ips if not _is_public_resolver(ip)}
    ips = _drop_sequential_ips(ips)

    return {
        "urls": sorted(urls),
        "ips": sorted(ips),
        "domains": sorted(domains),
        "native_libs": infra["native_libs"],
        "high_entropy_files": infra["high_entropy_files"],
        "dangerous_apis": _find_dangerous_apis(strings),
        "targeted_packages": _find_targeted_packages(strings, own_package, permissions),
        "malware_frameworks": _detect_malware_frameworks(strings, permissions),
        "packers": _detect_packers(strings),
        "hidden_dex": _find_hidden_dex(apk_bytes),
        "decoded_b64_iocs": decoded_b64,
        "dex_string_count": len(strings),
        "native_string_count": len(native),
    }


def analyze_dex_isolated(apk_path: str, own_package: str = "", permissions=(),
                         timeout: int = 120) -> dict:
    """analyze_dex in a child process under a hard deadline.

    Parsing a DEX carries the same risk as parsing a manifest: hostile input
    can hang androguard or exhaust memory. A failure does not end the run - the
    sample loses its DEX section and the rest (VT, MobSF, manifest) survives.
    """
    from isolation import run_isolated, IsolationTimeout, IsolationError
    try:
        return run_isolated(analyze_dex, (apk_path, own_package, tuple(permissions or ())), timeout=timeout)
    except IsolationTimeout as e:
        return {"error": f"DEX analysis aborted: {e}"}
    except IsolationError as e:
        return {"error": f"DEX analysis failed: {str(e).splitlines()[-1]}"}
