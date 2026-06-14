import time

import requests

from config import VT_API_KEY

_BASE = "https://www.virustotal.com/api/v3"


def _parse_stats(data: dict) -> dict:
    attrs = data["data"]["attributes"]
    stats = attrs["last_analysis_stats"]
    sha256 = attrs.get("sha256", "")
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "total": sum(stats.values()),
        "threat_label": (
            attrs.get("popular_threat_classification", {})
            .get("suggested_threat_label")
        ),
        "link": f"https://www.virustotal.com/gui/file/{sha256}",
    }


def check_sha256(sha256: str) -> dict:
    headers = {"x-apikey": VT_API_KEY}
    try:
        resp = requests.get(f"{_BASE}/files/{sha256}", headers=headers, timeout=15)
    except requests.RequestException as e:
        return {"error": str(e)}

    if resp.status_code == 404:
        return {"not_found": True}
    if resp.status_code != 200:
        return {"error": f"HTTP {resp.status_code}"}

    return _parse_stats(resp.json())


def upload_file(apk_path: str, sha256: str) -> dict:
    """Upload APK to VT and poll for analysis results. Only called when hash not found."""
    headers = {"x-apikey": VT_API_KEY}
    filename = apk_path.replace("\\", "/").split("/")[-1]

    try:
        with open(apk_path, "rb") as f:
            resp = requests.post(
                f"{_BASE}/files",
                headers=headers,
                files={"file": (filename, f, "application/octet-stream")},
                timeout=120,
            )
    except requests.RequestException as e:
        return {"error": f"Upload failed: {e}"}

    if resp.status_code not in (200, 201):
        return {"error": f"Upload HTTP {resp.status_code}"}

    analysis_id = resp.json().get("data", {}).get("id")
    if not analysis_id:
        return {"error": "No analysis ID returned from VT upload"}

    # Poll for results — VT typically finishes in 30–90 seconds
    for _ in range(12):
        time.sleep(15)
        try:
            poll = requests.get(f"{_BASE}/analyses/{analysis_id}", headers=headers, timeout=15)
        except requests.RequestException as e:
            return {"error": f"Poll failed: {e}"}

        if poll.status_code != 200:
            continue

        status = poll.json().get("data", {}).get("attributes", {}).get("status")
        if status == "completed":
            return check_sha256(sha256)

    return {"error": "VT analysis timed out after polling"}
