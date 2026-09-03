"""Ekstrakcja IOC wykraczających poza to, co łapie dex_analyzer.

Skupia się na tym, co ręcznie wyłuskiwaliśmy z raportów: portfele krypto
(cel clipperów), kontakty operatorów (Telegram/WhatsApp), webhooki Discord
(kanały eksfiltracji) i "dead-dropy" hostowane na GitHub/Firebase/Pages,
z których malware pobiera świeży adres C2.
"""
import hashlib
import re

# Ta sama, zabezpieczona przed zip bombą ekstrakcja co w analizie DEX —
# nie duplikujemy jej tutaj drugi raz.
from dex_analyzer import _extract_dex_strings, _extract_native_strings

_BTC_RE = re.compile(r'\b(?:bc1[a-z0-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b')
_ETH_RE = re.compile(r'\b0x[a-fA-F0-9]{40}\b')
_TRON_RE = re.compile(r'\bT[A-Za-z1-9]{33}\b')

_TELEGRAM_RE = re.compile(r't\.me/[A-Za-z0-9_]{4,32}')
_WHATSAPP_RE = re.compile(r'wa\.me/\+?\d{7,15}')
_DISCORD_WEBHOOK_RE = re.compile(
    r'discord(?:app)?\.com/api/webhooks/\d{15,25}/[A-Za-z0-9_\-]{50,90}'
)

# "Dead-drop" resolvery — malware pobiera stamtąd aktualny adres C2, więc
# host sam w sobie jest IOC nadającym się do zgłoszenia (np. GitHub abuse).
# Dead-drop to zasob, ktory malware POBIERA: raw.githubusercontent.com albo
# github.com/.../raw/... . Sciezka /blob/ to podglad w przegladarce (HTML),
# wiec lapala wylacznie linki z komunikatow bledow bibliotek (gson, FastAdapter).
_GITHUB_RAW_RE = re.compile(
    r"(?:raw\.githubusercontent\.com/[A-Za-z0-9_.-]{1,39}/[A-Za-z0-9_.-]{1,100}/"
    r"|github\.com/[A-Za-z0-9_.-]{1,39}/[A-Za-z0-9_.-]{1,100}/raw/)"
    r"[A-Za-z0-9/._~:?#@!$&()*+,;=%-]{1,200}"
)
_FIREBASE_RTDB_RE = re.compile(r'[a-z0-9\-]{3,50}-default-rtdb\.firebaseio\.com')
_PAGES_DEV_RE = re.compile(r'[a-z0-9\-]{3,50}\.pages\.dev')
# Cloudflare Workers to ta sama klasa darmowej infrastruktury przekazujacej co
# Pages: konto zaklada sie w minute, subdomena jest za darmo, a ruch wychodzi
# z adresow Cloudflare. W bazie mielismy 9 takich hostow (m.in.
# sync.softwaremirror.workers.dev z probki wykrytej przez 30/75 silnikow)
# i zaden nie byl klasyfikowany jako dead-drop.
# Adres ma postac [<worker>.]<konto>.workers.dev — pierwszy czlon bywa pominiety.
_WORKERS_DEV_RE = re.compile(
    r"(?:[a-z0-9\-]{1,63}\.)?[a-z0-9\-]{3,50}\.workers\.dev"
)

_WALLET_BLACKLIST_SUBSTR = (
    "1111111111", "0000000000",
)


# Standardowe deep-linki obecne w KAZDYM kliencie Telegrama i jego forkach.
# Bez tego kazdy fork trafial do bazy z kilkunastoma "kontaktami operatora",
# ktore sa zwyklymi elementami interfejsu aplikacji.
_TELEGRAM_STANDARDOWE = {
    "botfather", "addstickers", "addemoji", "addstyle", "addtheme", "addlist",
    "joinchat", "proxy", "socks", "spambot", "premiumbot", "giftcode",
    "stickers", "boost", "call", "folder", "nasettings", "share", "setlanguage",
    "confirmphone", "login", "invoice", "contact", "wallet", "premium",
}


def _telegram_standardowy(link: str) -> bool:
    return link.split("/", 1)[-1].lower() in _TELEGRAM_STANDARDOWE


def _looks_like_junk_wallet(addr: str) -> bool:
    return any(sub in addr for sub in _WALLET_BLACKLIST_SUBSTR)


# ── Walidacja adresów portfeli ────────────────────────────────────────────────
# Sam regex łapie stanowczo za dużo: 32-znakowy hash hex zaczynający się od "1"
# albo "3" (np. MD5 zapisany w string poolu) pasuje do wzorca adresu legacy,
# bo alfabet Base58 pokrywa się z hex poza znakami 0/O/I/l. Bez weryfikacji
# sumy kontrolnej takie śmieci trafiały do iocs.csv i zgłoszeń abuse.

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}


def _b58check_decode(addr: str) -> bytes | None:
    """Dekoduje Base58Check i sprawdza sumę kontrolną.

    Zwraca payload (bajt wersji + 20-bajtowy hash) albo None, jeśli adres jest
    nieprawidłowy. Checksum to pierwsze 4 bajty sha256(sha256(payload)), więc
    szansa przypadkowego trafienia to ~1/2^32.
    """
    num = 0
    for ch in addr:
        idx = _B58_INDEX.get(ch)
        if idx is None:
            return None
        num = num * 58 + idx

    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    leading_zeros = len(addr) - len(addr.lstrip("1"))  # wiodące "1" to bajty 0x00
    raw = bytes(leading_zeros) + body  # wiodace 1 -> bajty 0x00

    if len(raw) != 25:
        return None
    payload, checksum = raw[:21], raw[21:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != checksum:
        return None
    return payload


# ── bech32 / bech32m (BIP-173 / BIP-350) ─────────────────────────────────────
_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_CONST = 1           # segwit v0
_BECH32M_CONST = 0x2BC830A3  # segwit v1+ (taproot)


def _bech32_polymod(values) -> int:
    generator = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i, g in enumerate(generator):
            if (top >> i) & 1:
                chk ^= g
    return chk


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _is_valid_btc_bech32(addr: str) -> bool:
    """Adresy segwit (bc1...) — bech32 dla v0, bech32m dla v1+ (taproot)."""
    a = addr.lower()
    if not a.startswith("bc1") or not (14 <= len(a) <= 74):
        return False
    data = []
    for c in a[3:]:
        idx = _BECH32_CHARSET.find(c)
        if idx < 0:
            return False
        data.append(idx)
    if len(data) < 6:
        return False

    const = _bech32_polymod(_bech32_hrp_expand("bc") + data)
    witver = data[0]
    if witver == 0:
        return const == _BECH32_CONST
    if 1 <= witver <= 16:
        return const == _BECH32M_CONST
    return False


def _is_valid_btc(addr: str) -> bool:
    if addr.startswith("bc1"):
        return _is_valid_btc_bech32(addr)
    payload = _b58check_decode(addr)
    return payload is not None and payload[0] in (0x00, 0x05)  # P2PKH / P2SH


def _is_valid_tron(addr: str) -> bool:
    """TRON używa tego samego Base58Check, z bajtem wersji 0x41."""
    payload = _b58check_decode(addr)
    return payload is not None and payload[0] == 0x41


def extract_iocs(apk_path: str) -> dict:
    """Zwraca portfele krypto, kontakty operatorów i dead-dropy znalezione w DEX."""
    try:
        with open(apk_path, "rb") as f:
            apk_bytes = f.read()
    except Exception as e:
        return {"error": str(e)}

    strings = _extract_dex_strings(apk_bytes) + _extract_native_strings(apk_bytes)
    text = "\n".join(strings)

    btc = {m for m in _BTC_RE.findall(text) if _is_valid_btc(m)}
    tron = {m for m in _TRON_RE.findall(text) if _is_valid_tron(m)}
    # ETH nie ma obowiązkowej sumy kontrolnej (EIP-55 działa tylko dla adresów
    # pisanych mieszaną wielkością liter), więc zostaje filtr na oczywiste atrapy.
    eth = {m for m in _ETH_RE.findall(text) if not _looks_like_junk_wallet(m)}

    telegram = {m for m in _TELEGRAM_RE.findall(text) if not _telegram_standardowy(m)}
    whatsapp = {m for m in _WHATSAPP_RE.findall(text)}
    discord_webhooks = {m for m in _DISCORD_WEBHOOK_RE.findall(text)}

    github_deaddrops = {m for m in _GITHUB_RAW_RE.findall(text)}
    firebase_rtdb = {m for m in _FIREBASE_RTDB_RE.findall(text)}
    pages_dev = {m for m in _PAGES_DEV_RE.findall(text)}
    workers_dev = {m for m in _WORKERS_DEV_RE.findall(text)}

    return {
        "wallets": {
            "btc": sorted(btc),
            "eth": sorted(eth),
            "tron": sorted(tron),
        },
        "operator_contacts": {
            "telegram": sorted(telegram),
            "whatsapp": sorted(whatsapp),
        },
        "discord_webhooks": sorted(discord_webhooks),
        "dead_drops": {
            "github": sorted(github_deaddrops),
            "firebase_rtdb": sorted(firebase_rtdb),
            "pages_dev": sorted(pages_dev),
            "workers_dev": sorted(workers_dev),
        },
    }


def has_any_ioc(iocs: dict) -> bool:
    if iocs.get("error"):
        return False
    if any(iocs["wallets"].values()):
        return True
    if any(iocs["operator_contacts"].values()):
        return True
    if iocs["discord_webhooks"]:
        return True
    if any(iocs["dead_drops"].values()):
        return True
    return False


def extract_iocs_isolated(apk_path: str, timeout: int = 90) -> dict:
    """extract_iocs uruchomione w osobnym procesie — patrz analyze_dex_isolated."""
    from isolation import run_isolated, IsolationTimeout, IsolationError
    try:
        return run_isolated(extract_iocs, (apk_path,), timeout=timeout)
    except IsolationTimeout as e:
        return {"error": f"ekstrakcja IOC przerwana: {e}"}
    except IsolationError as e:
        return {"error": f"ekstrakcja IOC nie powiodla sie: {str(e).splitlines()[-1]}"}
