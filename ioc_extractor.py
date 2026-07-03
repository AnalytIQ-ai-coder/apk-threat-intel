"""Ekstrakcja IOC wykraczających poza to, co łapie dex_analyzer.

Skupia się na tym, co ręcznie wyłuskiwaliśmy z raportów: portfele krypto
(cel clipperów), kontakty operatorów (Telegram/WhatsApp), webhooki Discord
(kanały eksfiltracji) i "dead-dropy" hostowane na GitHub/Firebase/Pages,
z których malware pobiera świeży adres C2.
"""
import re
import zipfile
from io import BytesIO

from androguard.core.dex import DEX

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
_GITHUB_RAW_RE = re.compile(
    r'github(?:usercontent)?\.com/[A-Za-z0-9_\-]{1,39}/[A-Za-z0-9_\-.]{1,100}(?:/raw/|/blob/)[^\s\'"<>]{1,200}'
)
_FIREBASE_RTDB_RE = re.compile(r'[a-z0-9\-]{3,50}-default-rtdb\.firebaseio\.com')
_PAGES_DEV_RE = re.compile(r'[a-z0-9\-]{3,50}\.pages\.dev')

# Fałszywe znaczące symbole często obecne w placeholderach/testach —
# odsiewamy je, żeby nie zaśmiecać wyników.
_WALLET_BLACKLIST_SUBSTR = (
    "1111111111", "0000000000",
)


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


def _looks_like_junk_wallet(addr: str) -> bool:
    return any(sub in addr for sub in _WALLET_BLACKLIST_SUBSTR)


def extract_iocs(apk_path: str) -> dict:
    """Zwraca portfele krypto, kontakty operatorów i dead-dropy znalezione w DEX."""
    try:
        with open(apk_path, "rb") as f:
            apk_bytes = f.read()
    except Exception as e:
        return {"error": str(e)}

    strings = _extract_dex_strings(apk_bytes)
    text = "\n".join(strings)

    btc = {m for m in _BTC_RE.findall(text) if not _looks_like_junk_wallet(m)}
    eth = {m for m in _ETH_RE.findall(text) if not _looks_like_junk_wallet(m)}
    tron = {m for m in _TRON_RE.findall(text) if not _looks_like_junk_wallet(m)}

    telegram = {m for m in _TELEGRAM_RE.findall(text)}
    whatsapp = {m for m in _WHATSAPP_RE.findall(text)}
    discord_webhooks = {m for m in _DISCORD_WEBHOOK_RE.findall(text)}

    github_deaddrops = {m for m in _GITHUB_RAW_RE.findall(text)}
    firebase_rtdb = {m for m in _FIREBASE_RTDB_RE.findall(text)}
    pages_dev = {m for m in _PAGES_DEV_RE.findall(text)}

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
