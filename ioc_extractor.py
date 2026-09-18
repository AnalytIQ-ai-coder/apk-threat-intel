"""IOC extraction beyond what dex_analyzer already catches.

Focused on what we used to dig out of reports by hand: crypto wallets (what
clippers go after), operator contacts (Telegram/WhatsApp), Discord webhooks
(exfiltration channels) and "dead drops" hosted on GitHub/Firebase/Pages, from
which malware fetches a fresh C2 address.
"""
import hashlib
import re

# Same zip-bomb-guarded extraction as the DEX analysis uses; no reason to have
# a second copy of it here.
from dex_analyzer import _extract_dex_strings, _extract_native_strings

_BTC_RE = re.compile(r'\b(?:bc1[a-z0-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b')
_ETH_RE = re.compile(r'\b0x[a-fA-F0-9]{40}\b')
_TRON_RE = re.compile(r'\bT[A-Za-z1-9]{33}\b')

_TELEGRAM_RE = re.compile(r't\.me/[A-Za-z0-9_]{4,32}')
_WHATSAPP_RE = re.compile(r'wa\.me/\+?\d{7,15}')
_DISCORD_WEBHOOK_RE = re.compile(
    r'discord(?:app)?\.com/api/webhooks/\d{15,25}/[A-Za-z0-9_\-]{50,90}'
)

# Dead-drop resolvers: malware fetches its current C2 address from these, so
# the host is itself a reportable IOC (GitHub abuse, for instance).
# A dead drop is a resource malware DOWNLOADS: raw.githubusercontent.com or
# github.com/.../raw/... . A /blob/ path is the browser preview (HTML), so it
# only ever matched links from library error messages (gson, FastAdapter).
_GITHUB_RAW_RE = re.compile(
    r"(?:raw\.githubusercontent\.com/[A-Za-z0-9_.-]{1,39}/[A-Za-z0-9_.-]{1,100}/"
    r"|github\.com/[A-Za-z0-9_.-]{1,39}/[A-Za-z0-9_.-]{1,100}/raw/)"
    r"[A-Za-z0-9/._~:?#@!$&()*+,;=%-]{1,200}"
)
# Bitbucket works exactly like GitHub here: public repo, free account, and a
# file under /raw/ served as plain content. The com.co.xb (NewPay) and
# com.safe.xp (XPay) samples keep their current C2 domain list there
# (bitbucket.org/xpay2050/xinbipay/raw/main/domain.json), with a backup on
# object storage. This used to land in the database as an ordinary URL.
#
# Requiring "/raw/" does the same job as excluding "/blob/" does for GitHub:
# without it the rule would take bitbucket.org/loganchien/clang and .../llvm,
# which are LLVM toolchain source links out of library messages. Measured over
# 12697 unique IOCs: 2 hits, both real, zero false positives.
#
# The /downloads/ form (release file hosting) is deliberately NOT covered - we
# have no sample using it, and adding it unmeasured would risk false positives
# from legitimate library links.
_BITBUCKET_RAW_RE = re.compile(
    r"(?:bitbucket\.org/[A-Za-z0-9_.-]{1,62}/[A-Za-z0-9_.-]{1,62}/raw/"
    # Bitbucket's equivalent of raw.githubusercontent.com. Added by analogy
    # with the GitHub rule rather than from measurement - this path has no use
    # other than fetching a file's raw content.
    r"|api\.bitbucket\.org/2\.0/repositories/[A-Za-z0-9_.-]{1,62}/[A-Za-z0-9_.-]{1,62}/src/)"
    r"[A-Za-z0-9/._~:?#@!$&()*+,;=%-]{1,200}"
)
_FIREBASE_RTDB_RE = re.compile(r'[a-z0-9\-]{3,50}-default-rtdb\.firebaseio\.com')
_PAGES_DEV_RE = re.compile(r'[a-z0-9\-]{3,50}\.pages\.dev')
# Cloudflare Workers is the same class of free relay infrastructure as Pages:
# an account takes a minute to open, the subdomain is free, and traffic leaves
# from Cloudflare addresses. The database held 9 such hosts (among them
# sync.softwaremirror.workers.dev, from a sample 30 of 75 engines flagged) and
# not one was classified as a dead drop.
# The form is [<worker>.]<account>.workers.dev; the first part is optional.
_WORKERS_DEV_RE = re.compile(
    r"(?:[a-z0-9\-]{1,63}\.)?[a-z0-9\-]{3,50}\.workers\.dev"
)

_WALLET_BLACKLIST_SUBSTR = (
    "1111111111", "0000000000",
)


# Standard deep links present in EVERY Telegram client and its forks. Without
# this, each fork landed in the database with a dozen "operator contacts" that
# are really just parts of the app's own UI.
_TELEGRAM_STANDARD_LINKS = {
    "botfather", "addstickers", "addemoji", "addstyle", "addtheme", "addlist",
    "joinchat", "proxy", "socks", "spambot", "premiumbot", "giftcode",
    "stickers", "boost", "call", "folder", "nasettings", "share", "setlanguage",
    "confirmphone", "login", "invoice", "contact", "wallet", "premium",
}


def _is_standard_telegram_link(link: str) -> bool:
    """Is this a built-in Telegram deep link rather than an operator contact?"""
    return link.split("/", 1)[-1].lower() in _TELEGRAM_STANDARD_LINKS


def _looks_like_junk_wallet(addr: str) -> bool:
    return any(sub in addr for sub in _WALLET_BLACKLIST_SUBSTR)


# ── Wallet address validation ────────────────────────────────────────────────
# The regex alone catches far too much: a 32-character hex hash starting with
# "1" or "3" (an MD5 sitting in the string pool, say) fits the legacy address
# pattern, because the Base58 alphabet overlaps hex everywhere except 0/O/I/l.
# Without a checksum check that junk ended up in iocs.csv and in abuse reports.

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}


def _b58check_decode(addr: str) -> bytes | None:
    """Decode Base58Check and verify the checksum.

    Returns the payload (version byte plus 20-byte hash), or None if the
    address is invalid. The checksum is the first 4 bytes of
    sha256(sha256(payload)), so a chance hit runs at about 1 in 2^32.
    """
    num = 0
    for ch in addr:
        idx = _B58_INDEX.get(ch)
        if idx is None:
            return None
        num = num * 58 + idx

    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    leading_zeros = len(addr) - len(addr.lstrip("1"))  # leading "1"s are 0x00 bytes
    raw = bytes(leading_zeros) + body

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
    """Segwit addresses (bc1...): bech32 for v0, bech32m for v1+ (taproot)."""
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
    """TRON uses the same Base58Check, with version byte 0x41."""
    payload = _b58check_decode(addr)
    return payload is not None and payload[0] == 0x41


def extract_iocs(apk_path: str) -> dict:
    """Return crypto wallets, operator contacts and dead drops found in the DEX."""
    try:
        with open(apk_path, "rb") as f:
            apk_bytes = f.read()
    except Exception as e:
        return {"error": str(e)}

    strings = _extract_dex_strings(apk_bytes) + _extract_native_strings(apk_bytes)
    text = "\n".join(strings)

    btc = {m for m in _BTC_RE.findall(text) if _is_valid_btc(m)}
    tron = {m for m in _TRON_RE.findall(text) if _is_valid_tron(m)}
    # ETH has no mandatory checksum (EIP-55 only applies to mixed-case
    # addresses), so all that is left is a filter for obvious placeholders.
    eth = {m for m in _ETH_RE.findall(text) if not _looks_like_junk_wallet(m)}

    telegram = {m for m in _TELEGRAM_RE.findall(text) if not _is_standard_telegram_link(m)}
    whatsapp = {m for m in _WHATSAPP_RE.findall(text)}
    discord_webhooks = {m for m in _DISCORD_WEBHOOK_RE.findall(text)}

    github_deaddrops = {m for m in _GITHUB_RAW_RE.findall(text)}
    bitbucket_deaddrops = {m for m in _BITBUCKET_RAW_RE.findall(text)}
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
            "bitbucket": sorted(bitbucket_deaddrops),
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
    """extract_iocs in a child process - see analyze_dex_isolated."""
    from isolation import run_isolated, IsolationTimeout, IsolationError
    try:
        return run_isolated(extract_iocs, (apk_path,), timeout=timeout)
    except IsolationTimeout as e:
        return {"error": f"IOC extraction aborted: {e}"}
    except IsolationError as e:
        return {"error": f"IOC extraction failed: {str(e).splitlines()[-1]}"}
