import requests
from config import VT_API_KEY


def check_sha256(sha256: str) -> dict:
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        resp = requests.get(url, headers=headers, timeout=15)
    except requests.RequestException as e:
        return {"error": str(e)}

    if resp.status_code == 404:
        return {"not_found": True}
    if resp.status_code != 200:
        return {"error": f"HTTP {resp.status_code}"}

    stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values())

    popular_threat = (
        resp.json()["data"]["attributes"]
        .get("popular_threat_classification", {})
        .get("suggested_threat_label", None)
    )

    return {
        "malicious": malicious,
        "suspicious": suspicious,
        "total": total,
        "threat_label": popular_threat,
        "link": f"https://www.virustotal.com/gui/file/{sha256}",
    }
