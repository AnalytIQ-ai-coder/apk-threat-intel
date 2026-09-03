import base64
import math
import re
import zipfile
from io import BytesIO

from loguru import logger
# Wyciszamy tu, a nie tylko w analyzer.py: ten modul biegnie takze w
# procesach potomnych run_isolated, ktore nie importuja analyzer.py.
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

# Tokeny TLD z _DOMAIN_RE. Nazwa pakietu to odwrocony DNS, wiec TLD stoi w niej
# na POCZATKU ("com.chrome.dev", "org.openjsse.net"), a w prawdziwej domenie
# na koncu. To jedno kryterium odsiewa ogony pakietow bez listy wyjatkow.
_TLD_TOKENY = frozenset({
    "com", "net", "org", "io", "ru", "cn", "tk", "top", "xyz",
    "info", "biz", "co", "dev",
})

# Podzbior uzywany do rozpoznawania odwroconego DNS po PIERWSZEJ etykiecie.
# Swiadomie bez "dev", "info" i "co" — to popularne nazwy subdomen
# (dev.tapjoy.com, info.startappservice.com, co.uk), wiec pelny zestaw
# odsiewal prawdziwe hosty razem z nazwami pakietow.
_TLD_NA_POCZATKU_PAKIETU = frozenset({
    "com", "net", "org", "io", "ru", "cn", "tk", "top", "xyz", "biz",
})

# Placeholdery z dokumentacji i tutoriali. Dopasowanie DOKLADNE, nie po
# podciagu: "dynamicdns.park-your-domain.com" to prawdziwy dostawca dyn-DNS,
# a zawiera w sobie "domain.com".
# Te TLD koliduja z identyfikatorami z kodu czesciej niz jakiekolwiek inne:
# geometria i CSS (rect.top, window.top, a.style.top) oraz logowanie
# (console.info, Log.INFO). W bazie na 36 domen ".top" prawdziwe sa cztery,
# a na 63 domeny ".info" okolo pieciu. NIE mozna ich wyciac hurtem —
# poker-rooms.top i cln9vhvfo2.top to realne C2 — wiec zamiast tego podnosimy
# dla nich prog wiarygodnosci w _domena_jest_iocem.
_TLD_KOLIDUJACE_Z_KODEM = frozenset({"top", "info", "xyz", "io", "tk"})

# Nazwy wlasciwosci i obiektow, po ktorych czesto nastepuje ".top" albo ".info"
# w kodzie. Sprawdzane w KAZDEJ etykiecie, bo wzorzec bywa zagniezdzony
# ("a.style.top", "Log.private.info", "feature.screen.info").
_WLASCIWOSCI_UDAJACE_HOST = frozenset({
    # wlasciwosci obiektow i logowanie: rect.top, window.top, console.info
    "style", "window", "console", "log", "screen", "feature",
    "document", "parent", "rect", "layout", "bounds",
    # nazwy wektorow w shaderach — po nich nastepuje swizzle ".xyz"
    "color", "position", "normal", "tangent", "texel", "vertex",
    "hsl", "hsv", "fragcolor", "light", "dir", "pos", "vec",
})

_DOMENY_PLACEHOLDER = frozenset({
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

# Adresy zarezerwowane dla dokumentacji: RFC 5737 (TEST-NET-1/2/3) plus
# 123.45.67.89 — kanoniczne "przykladowe IP" z tutoriali, wpisane na sztywno
# w UI aplikacji serwerowych (Servers Ultimate pokazywal je jako wzorzec).
_IP_DOKUMENTACYJNE = ("192.0.2.", "198.51.100.", "203.0.113.")
_IP_DOKUMENTACYJNE_DOKLADNE = frozenset({"123.45.67.89"})

# Numery wersji SDK zapisane czterema czlonami ("6.4.2.1", "9.14.12.0") sa
# nieodroznialne od adresu IP dla samego regexa. Jedna probka ibisPaint X dala
# ich dziesiec naraz. Roznica jest statystyczna: adres, ktorego WSZYSTKIE cztery
# oktety sa male, to 0,02% przestrzeni adresowej, a wsrod 127 adresow w bazie
# 26 spelnia ten warunek i kazdy z nich jest numerem wersji. Wiele konczy sie
# na ".0", wiec nawet jako adresy bylyby adresami sieci, nie hostow.
#
# Prog 30 zamiast np. 255 wybrany po pomiarze na bazie. Warunek dodatkowy:
# adres z numerem portu zostaje zawsze — port oznacza kontekst sieciowy,
# a nie wersje biblioteki.
_MAX_OKTET_WERSJI = 30

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
    # Przekaznik NFC: ofiara przyklada fizyczna karte platnicza do telefonu,
    # malware odczytuje odpowiedzi APDU i przekazuje je na urzadzenie atakujacego,
    # ktore emuluje ta karte przy terminalu. Sam IsoDep bywa legalny (portfele,
    # czytniki dokumentow) — dopiero ODCZYT plus EMULACJA w jednej probce nie ma
    # zastosowania w aplikacji konsumenckiej. Rozroznienie robi regula YARA.
    "NFC / karty platnicze": [
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


# ── Limity ochronne przy czytaniu archiwum ───────────────────────────────────
# APK jest niezaufanym ZIP-em: wpis ważący kilka kB potrafi rozpakować się do
# gigabajtów (zip bomba). Nigdy nie czytamy wpisu bez sprawdzenia file_size.
_MAX_ENTRY_BYTES = 64 * 1024 * 1024
_MAX_B64_INPUT = 8192

# Magic bytes formatów, które bywają osadzane jako Base64 i nie są tekstem.
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


def _domena_jest_iocem(value: str) -> bool:
    """Czy dopasowanie _DOMAIN_RE to faktycznie host, a nie identyfikator z kodu.

    Regex widzi wylacznie ogon stringa zakonczony czyms, co wyglada na TLD,
    wiec rownie chetnie lapie nazwy klas Javy ("BitmapEncoder.com"), swizzle
    GLSL z shaderow Fluttera ("lightDirAndSpotCutoff.xyz") i ogony pakietow
    ("org.openjsse.net").

    Uzywane WYLACZNIE dla domen. Do URL-i sie nie nadaje: "https://CaptchaKey.com"
    to prawdziwy adres mimo wielkich liter w nazwie hosta.
    """
    if _is_whitelisted(value):
        return False

    if value.lower() in _DOMENY_PLACEHOLDER:
        return False

    etykiety = value.split(".")

    if etykiety[0].lower() in _TLD_NA_POCZATKU_PAKIETU:
        return False  # odwrocony DNS -> nazwa pakietu, nie host

    # Dluga nazwa w camelCase to klasa Javy, nie host. Prog 18 znakow nie jest
    # ozdobnikiem: bez niego regula zjadala HappyMod.com, LEEAPK.COM,
    # JesusFreke.com i YTPL.net, czyli prawdziwe serwisy z pirackimi APK, ktore
    # sa wartosciowym IOC dystrybucji. Krotkie camelCase zostaje — kilka
    # falszywek (CenterCrop.com) jest tansze niz utrata realnych hostow.
    if len(etykiety[0]) > 18 and re.search("[a-z0-9][A-Z]", etykiety[0]):
        return False

    # Swizzle GLSL: ".xyz" jest TLD, wiec dostep do skladowych wektora w
    # shaderach libflutter ("a.xyz", "b.xyz") udaje domene. Zawezone do
    # jednoznakowej etykiety, bo "g.co", "x.com" i "a.applovin.com" sa
    # prawdziwymi domenami i nie wolno ich zgubic.
    if len(etykiety) == 2 and len(etykiety[0]) == 1 and etykiety[1].lower() == "xyz":
        return False

    if etykiety[-1].lower() in _TLD_KOLIDUJACE_Z_KODEM:
        # DNS zapisuje sie malymi literami; ".Top" albo ".INFO" to stala w kodzie.
        if not etykiety[-1].islower():
            return False
        # Wielka litera w etykiecie przed TLD: "Rect.top", "SystemUiOverlay.top".
        if any(z.isupper() for z in etykiety[-2]):
            return False
        # Krotkie etykiety czysto literowe to nazwy zmiennych po minifikacji
        # ("a.top", "s.INFO", "a.j.top"). Warunek "tylko litery" jest istotny:
        # bez niego regula zabierala www.6b.top i tws.6b.top, czyli krotka,
        # ale prawdziwa domene.
        if len(etykiety[-2]) <= 2 and etykiety[-2].isalpha():
            return False
        # SWIADOMIE nie odrzucamy jednoznakowej PIERWSZEJ etykiety. Kusilo,
        # zeby tak zrobic dla "x.print.processor.info", ale pomiar na bazie
        # pokazal koszt: s.presage.io, s.cloud.ogury.io i s.qa.cloud.ogury.io
        # to prawdziwe hosty sieci reklamowej Ogury. Krotkie subdomeny
        # (s., a., d., g.co) sa u CDN-ow powszechne — to juz trzeci raz, gdy
        # ta sama regula probowala zabrac realne dane.
        if any(e.lower() in _WLASCIWOSCI_UDAJACE_HOST for e in etykiety[:-1]):
            return False

    return True


def _is_plausible_ip(value: str) -> bool:
    """Czy to adres, ktory ma sens jako IOC.

    Odsiewa cztery klasy smieci, ktore regex na cztery liczby lapie razem
    z prawdziwymi adresami:
      * fragmenty OID-ow z X.509 (2.5.4.3 = commonName, 2.5.29.15 = keyUsage) —
        dlugie luki ASN.1 tna sie na nakladajace okna wygladajace jak IP,
      * numery wersji z wiodacym zerem w oktecie ("6.14.0.04"),
      * adresy sieci (x.0.0.0), rozgloszeniowy i zakresy zarezerwowane,
      * zakresy prywatne i link-local — w tym 169.254.169.254, czyli endpoint
        metadanych chmury, ktory nie jest infrastruktura atakujacego.
    """
    host = _normalizuj_ip(value)
    oktety = host.split(".")
    if len(oktety) != 4:
        return False

    for o in oktety:
        if not o.isdigit() or int(o) > 255:
            return False
        if len(o) > 1 and o.startswith("0"):
            return False  # "04" to zapis wersji, nie oktetu

    if oktety[0] in _OID_FIRST_OCTETS:
        return False
    if host.startswith(_OID_FRAGMENT_PREFIXES):
        return False
    if host.startswith(_IP_DOKUMENTACYJNE) or host in _IP_DOKUMENTACYJNE_DOKLADNE:
        return False
    ma_port = ":" in value.replace("[b64] ", "")
    wszystkie_rowne = len(set(oktety)) == 1   # 8.8.8.8, 1.1.1.1, 9.9.9.9
    if (not ma_port and not wszystkie_rowne
            and all(int(o) <= _MAX_OKTET_WERSJI for o in oktety)):
        return False    # numer wersji, nie adres

    a, b = int(oktety[0]), int(oktety[1])
    if oktety[2:] == ["0", "0"]:
        return False                      # adres sieci (x.y.0.0), nie hosta
    if a in (0, 10, 127):
        return False                      # this-network, prywatna, loopback
    if a == 172 and 16 <= b <= 31:
        return False                      # prywatna 172.16/12 (a nie cale 172.x)
    if a == 192 and b == 168:
        return False
    if a == 169 and b == 254:
        return False                      # link-local + metadane chmury
    if a >= 224:
        return False                      # multicast, zarezerwowane, rozgloszeniowy
    return True


def _read_capped(z: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int = _MAX_ENTRY_BYTES):
    """Czyta wpis z archiwum z twardym limitem rozmiaru.

    Deklarowany file_size potrafi być zaniżony przez spreparowany APK, więc
    limit egzekwujemy również przy samym odczycie. Zwraca None, gdy wpis
    przekracza limit — wtedy po prostu go pomijamy.
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


# Minimalna dlugosc sekwencji drukowalnych bajtow uznawanej za string w .so —
# jak w narzedziu `strings`. Krotsze daja glownie szum.
_NATIVE_STR_RE = re.compile(rb"[\x20-\x7e]{6,}")
_MAX_NATIVE_STRINGS = 200000


# Publiczne resolwery DNS. Aplikacje odwoluja sie do nich rutynowo (DoH,
# sprawdzanie lacznosci, HTTPDNS), wiec jako IOC sa czystym szumem — 8.8.8.8
# potrafilo skorelowac ze soba kilkanascie niepowiazanych probek.
_PUBLICZNE_RESOLWERY = {
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

# Uslugi HTTPDNS uzywaja calych pul zamiast pojedynczych adresow.
_PREFIKSY_RESOLWEROW = ("119.29.29.", "119.28.28.", "45.90.28.", "45.90.30.")


def _normalizuj_ip(value: str) -> str:
    """Zdejmuje znacznik [b64] i numer portu, zostawiajac sam adres."""
    return value.replace("[b64] ", "").split(":", 1)[0].strip()


def _jest_publicznym_resolwerem(value: str) -> bool:
    host = _normalizuj_ip(value)
    return host in _PUBLICZNE_RESOLWERY or host.startswith(_PREFIKSY_RESOLWEROW)


def _odsiej_sekwencyjne_ip(ips: set) -> set:
    """Usuwa "adresy" bedace w rzeczywistosci numerami wersji.

    Ciag w rodzaju 80.5.1.1 ... 80.5.1.10 w jednej probce to wersjonowanie
    biblioteki, nie infrastruktura. Prawdziwe C2 nie wystepuje jako kilka
    kolejnych adresow roznacych sie wylacznie ostatnim oktetem.
    """
    grupy = {}
    for ip in ips:
        prefiks = _normalizuj_ip(ip).rsplit(".", 1)[0]
        grupy.setdefault(prefiks, []).append(ip)
    return {ip for czlonkowie in grupy.values() if len(czlonkowie) < 3 for ip in czlonkowie}


def _extract_native_strings(apk_bytes: bytes) -> list[str]:
    """Wyciaga drukowalne stringi z bibliotek natywnych (lib/**/*.so).

    Dobrze napisane malware trzyma adres C2 w kodzie natywnym, nie w DEX-ie.
    Probka z libbot.so (VT 28/75) dala zero IOC, bo czytalismy wylacznie
    classes*.dex — im lepiej ukryty payload, tym mniej wyciagalismy.
    """
    strings = []
    try:
        with zipfile.ZipFile(BytesIO(apk_bytes)) as z:
            for info in z.infolist():
                nazwa = info.filename
                if not (nazwa.startswith("lib/") and nazwa.endswith(".so")):
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
# Wskazniki dzielimy na dwie klasy, bo samo "octo" in text dawalo fałszywki na
# potege: slowa "october" i "doctor" zawieraja "octo", "supermacro" zawiera
# "ermac", "alienate" zawiera "alien". W grze Unity z SDK reklamowymi string
# pool ma dziesiatki tysiecy wpisow, wiec trafienie bylo praktycznie pewne.
#
#   strong — artefakt specyficzny dla rodziny (prefiks pakietu, unikalny string).
#            Trafienie wystarcza samo w sobie.
#   weak   — sama nazwa rodziny, bywajaca zwyklym slowem. Wymaga dopasowania do
#            granic slowa ORAZ uprawnienia potwierdzajacego profil bankera.
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

# Uprawnienia, bez ktorych android'owy trojan bankowy nie zadziala. Sluza jako
# potwierdzenie dla slabych wskaznikow. Swiadomie NIE ma tu SYSTEM_ALERT_WINDOW
# ani FOREGROUND_SERVICE — te sa powszechne w grach i SDK reklamowych.
_PERMISJE_POTWIERDZAJACE = (
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
    """Rozpoznaje rodziny malware po artefaktach w string poolu DEX.

    permissions pochodzi z manifestu i potwierdza slabe wskazniki - bez niego
    slaba przeslanka jest odrzucana, zeby nie etykietowac gier jako bankerow.
    """
    all_text = chr(10).join(strings).lower()
    # Slabe wskazniki dopasowujemy do calych slow, nie do podciagow: "october"
    # i "doctor" zawieraja "octo", ale rozbite na slowa juz nie pasuja.
    slowa = set(re.split("[^a-z0-9]+", all_text))
    ma_potwierdzenie = any(p in set(permissions or ()) for p in _PERMISJE_POTWIERDZAJACE)

    found = []
    for name, wskazniki in _MALWARE_FRAMEWORKS.items():
        if any(kw in all_text for kw in wskazniki["strong"]):
            found.append(name)
            continue
        if not ma_potwierdzenie:
            continue
        if any(kw in slowa for kw in wskazniki["weak"]):
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
                # Wystarczą 4 bajty magic — nie ma powodu rozpakowywać całości.
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
    """Try to decode suspicious Base64 strings — URLs and IPs are most valuable.

    Zwraca wyłącznie dopasowane IOC, nigdy całego zdekodowanego bloba: apki
    często trzymają ikony/zasoby jako Base64, a losowe bajty PNG/ZIP trafiają
    w regex na IP praktycznie zawsze.
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
        if printable / len(text) < 0.9:  # to nie jest tekst, tylko binarka
            continue

        found.update(_URL_RE.findall(text))
        found.update(m for m in _IP_RE.findall(text) if _is_plausible_ip(m))
    return sorted(found)[:20]


# Lista pakietow bankowych ma znaczenie tylko wtedy, gdy probka moze cokolwiek
# z nia zrobic: nalozyc okno phishingowe, odczytac UI przez Accessibility albo
# przechwycic SMS z kodem. Bez tego jest to zwykla tablica kategorii aplikacji —
# launcher Niagara dostal przez to liste 31 "celow" (ING, PayPal, Samsung Pay).
# Swiadomie NIE ma tu REQUEST_INSTALL_PACKAGES: kazda przegladarka je deklaruje.
_PERMISJE_ATAKU_NA_APLIKACJE = (
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.SYSTEM_ALERT_WINDOW",
)


_SLOWA_KLUCZE_CELOW = (
    "bank", "sber", "tinkoff", "alfa", "vtb", "gazprom", "finam",
    "raif", "otp", "unicredit", "modul", "oneme", "wildberries",
    "pay", "wallet", "fintech", "crypto", "btc", "cash",
)

# Pakiety bibliotek, ktore zawieraja slowa-klucze, ale nie sa celem ataku:
# javax.crypto i org.bouncycastle.crypto trafialy na liste "celow" w kazdej
# aplikacji uzywajacej szyfrowania, czyli praktycznie w kazdej.
_PAKIETY_BIBLIOTEK = _JAVA_PACKAGE_PREFIXES + (
    "javax.", "org.bouncycastle.", "org.spongycastle.", "com.google.",
    "io.reactivex.", "com.squareup.", "org.codehaus.", "org.jetbrains.",
    "com.sun.", "gnu.", "kawa.", "com.facebook.", "org.slf4j.",
)

# Segmenty, ktore zaczynaja sie od slowa-klucza, ale sa zwyklymi slowami z kodu.
# "module" zaczyna sie od "modul" (Modulbank), "payload" od "pay".
_SEGMENTY_NIE_CEL = frozenset({
    "module", "modules", "modular", "payload", "payloads",
})


def _find_targeted_packages(strings: list[str], own_package: str = "",
                            permissions=()) -> list[str]:
    if not any(p in set(permissions or ()) for p in _PERMISJE_ATAKU_NA_APLIKACJE):
        return []  # brak zdolnosci ataku na inna aplikacje -> to nie lista celow

    candidates = set()
    for s in strings:
        for m in _PKG_RE.findall(s):
            if m == own_package or len(m) < 10:
                continue
            lower = m.lower()
            if lower.startswith(_PAKIETY_BIBLIOTEK):
                continue

            segmenty = re.split("[._]", lower)
            # "www.paypal.com" to domena, nie pakiet — _PKG_RE nie widzi roznicy.
            # W odwroconym DNS TLD stoi na poczatku, nigdy na koncu.
            if segmenty[-1] in _TLD_TOKENY:
                continue

            # Dopasowanie do POCZATKU segmentu zamiast do dowolnego podciagu
            # calej nazwy: "sberbankmobile" ma zaczynac sie od "sber", ale
            # "kawa.standard.module_name" nie ma uchodzic za Modulbank.
            for seg in segmenty:
                if seg in _SEGMENTY_NIE_CEL:
                    continue
                if any(seg.startswith(kw) for kw in _SLOWA_KLUCZE_CELOW):
                    candidates.add(m)
                    break
    return sorted(candidates)


def analyze_dex(apk_path: str, own_package: str = "", permissions=()) -> dict:
    try:
        with open(apk_path, "rb") as f:
            apk_bytes = f.read()
    except Exception as e:
        return {"error": str(e)}

    strings = _extract_dex_strings(apk_bytes)
    infra = _analyze_entropy_and_libs(apk_bytes)
    # Stringi z .so ida przez te same regexy — C2 ukryte w kodzie natywnym
    # nigdy wczesniej nie trafialo do wynikow.
    native = _extract_native_strings(apk_bytes)

    urls, ips, domains = set(), set(), set()
    for s in strings + native:
        for m in _URL_RE.findall(s):
            if not _is_whitelisted(m):
                urls.add(m)
        for m in _IP_RE.findall(s):
            if _is_plausible_ip(m):
                ips.add(m)
        for m in _DOMAIN_RE.findall(s):
            if _domena_jest_iocem(m):
                domains.add(m)

    decoded_b64 = _decode_base64_strings(strings)
    for text in decoded_b64:
        for m in _URL_RE.findall(text):
            urls.add(f"[b64] {m}")
        for m in _IP_RE.findall(text):
            if _is_plausible_ip(m):
                ips.add(f"[b64] {m}")

    ips = {ip for ip in ips if not _jest_publicznym_resolwerem(ip)}
    ips = _odsiej_sekwencyjne_ip(ips)

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
    """analyze_dex uruchomione w osobnym procesie z twardym limitem czasu.

    Parsowanie DEX-a to ta sama klasa ryzyka co parsowanie manifestu: wrogie
    wejscie moze zawiesic androguarda albo wyczerpac pamiec. Blad nie przerywa
    runu — probka traci sekcje DEX, reszta analizy (VT, MobSF, manifest) zostaje.
    """
    from isolation import run_isolated, IsolationTimeout, IsolationError
    try:
        return run_isolated(analyze_dex, (apk_path, own_package, tuple(permissions or ())), timeout=timeout)
    except IsolationTimeout as e:
        return {"error": f"analiza DEX przerwana: {e}"}
    except IsolationError as e:
        return {"error": f"analiza DEX nie powiodla sie: {str(e).splitlines()[-1]}"}
