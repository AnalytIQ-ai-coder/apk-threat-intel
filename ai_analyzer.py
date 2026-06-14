import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "qwen2.5:14b"


def assess_risk(data: dict) -> dict:
    sha256 = data.get("sha256", "unknown")
    package = data.get("package", "unknown")
    app_name = data.get("app_name", "unknown")
    version = data.get("version_name", "unknown")
    min_sdk = data.get("min_sdk", "unknown")
    target_sdk = data.get("target_sdk", "unknown")
    permissions = data.get("permissions", [])
    vt = data.get("vt", {})

    if vt.get("not_found"):
        vt_info = "Not found in VirusTotal database"
    elif vt.get("error"):
        vt_info = f"VirusTotal error: {vt['error']}"
    else:
        m, t = vt.get("malicious", 0), vt.get("total", 0)
        label = vt.get("threat_label") or "none"
        vt_info = f"{m}/{t} antivirus engines detected as malicious, threat label: {label}"

    prompt = f"""You are a mobile malware analyst. Analyze this Android APK and assess whether it is malicious or suspicious.

Package name: {package}
App name: {app_name}
Version: {version}
Min SDK: {min_sdk} / Target SDK: {target_sdk}
SHA256: {sha256}
VirusTotal: {vt_info}
Permissions ({len(permissions)}):
{chr(10).join(f"  - {p}" for p in permissions) if permissions else "  none"}

Respond in this exact format:
RISK: <low|medium|high|critical>
REASON: <2-3 sentences explaining your assessment>"""

    try:
        resp = requests.post(
            OLLAMA_URL,
            json={"model": MODEL, "prompt": prompt, "stream": False},
            timeout=60,
        )
        resp.raise_for_status()
        text = resp.json().get("response", "").strip()
        return _parse_response(text)
    except requests.RequestException as e:
        return {"error": str(e)}


def _parse_response(text: str) -> dict:
    risk = "unknown"
    reason = text

    for line in text.splitlines():
        if line.startswith("RISK:"):
            risk = line.split(":", 1)[1].strip().lower()
        elif line.startswith("REASON:"):
            reason = line.split(":", 1)[1].strip()

    return {"risk": risk, "reason": reason}
