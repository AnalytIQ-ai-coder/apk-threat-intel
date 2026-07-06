import requests

from config import ABUSECH_API_KEY

_TIMEOUT = 15
_HEADERS = {"Auth-Key": ABUSECH_API_KEY} if ABUSECH_API_KEY else {}

_MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
_THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
_URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/url/"


def check_malwarebazaar(sha256: str) -> dict:
    
    try:
        r = requests.post(
            _MALWAREBAZAAR_URL, data={"query": "get_info", "hash": sha256},
            headers=_HEADERS, timeout=_TIMEOUT,
        )
        j = r.json()
        if j.get("query_status") == "ok" and j.get("data"):
            info = j["data"][0]
            return {
                "known": True,
                "signature": info.get("signature"),
                "tags": info.get("tags") or [],
                "first_seen": info.get("first_seen"),
                "link": f"https://bazaar.abuse.ch/sample/{sha256}/",
            }
        return {"known": False}
    except Exception as e:
        return {"error": str(e)}


def check_threatfox_ioc(value: str) -> dict:
    try:
        r = requests.post(
            _THREATFOX_URL, json={"query": "search_ioc", "search_term": value},
            headers=_HEADERS, timeout=_TIMEOUT,
        )
        j = r.json()
        if j.get("query_status") == "ok" and j.get("data"):
            hits = j["data"]
            return {
                "known": True,
                "hits": [
                    {
                        "malware": h.get("malware_printable"),
                        "threat_type": h.get("threat_type"),
                        "confidence": h.get("confidence_level"),
                    }
                    for h in hits[:3]
                ],
            }
        return {"known": False}
    except Exception as e:
        return {"error": str(e)}


def check_urlhaus(url: str) -> dict:
    try:
        r = requests.post(_URLHAUS_URL, data={"url": url}, headers=_HEADERS, timeout=_TIMEOUT)
        j = r.json()
        if j.get("query_status") == "ok":
            return {
                "known": True,
                "status": j.get("url_status"),
                "threat": j.get("threat"),
                "tags": j.get("tags") or [],
            }
        return {"known": False}
    except Exception as e:
        return {"error": str(e)}


def enrich(data: dict, iocs: dict) -> dict:

    result = {"malwarebazaar": None, "threatfox_hits": [], "urlhaus_hits": []}

    sha256 = data.get("sha256")
    if sha256:
        result["malwarebazaar"] = check_malwarebazaar(sha256)

    dex = data.get("dex") or {}
    ioc_candidates = list((dex.get("ips") or [])[:5]) + list((dex.get("domains") or [])[:5])
    if iocs and not iocs.get("error"):
        ioc_candidates += list(iocs.get("dead_drops", {}).get("github", []))[:3]

    for candidate in ioc_candidates:
        tf = check_threatfox_ioc(candidate)
        if tf.get("known"):
            result["threatfox_hits"].append({"ioc": candidate, **tf})

    for url in (dex.get("urls") or [])[:5]:
        uh = check_urlhaus(url)
        if uh.get("known"):
            result["urlhaus_hits"].append({"url": url, **uh})

    return result
