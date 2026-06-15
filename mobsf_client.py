"""
MobSF REST API client.

Static analysis: always available when MobSF is running.
Dynamic analysis: requires an Android emulator (AVD) connected to MobSF.

MobSF setup:
    docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf

API key: visible in MobSF web UI at http://localhost:8000 (top right corner).
"""

import time

import requests

from config import MOBSF_URL, MOBSF_API_KEY

_HEADERS = {"Authorization": MOBSF_API_KEY} if MOBSF_API_KEY else {}


def _post(endpoint: str, **kwargs) -> dict:
    try:
        resp = requests.post(
            f"{MOBSF_URL}/api/v1/{endpoint}",
            headers=_HEADERS,
            timeout=120,
            **kwargs,
        )
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        return {"error": str(e)}


def _get(endpoint: str, params: dict = None) -> dict:
    try:
        resp = requests.get(
            f"{MOBSF_URL}/api/v1/{endpoint}",
            headers=_HEADERS,
            params=params or {},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        return {"error": str(e)}


def upload_and_scan(apk_path: str) -> dict:
    """Upload APK to MobSF and run static analysis. Returns file hash used for further calls."""
    filename = apk_path.replace("\\", "/").split("/")[-1]
    try:
        with open(apk_path, "rb") as f:
            result = _post("upload", files={"file": (filename, f, "application/octet-stream")})
    except Exception as e:
        return {"error": str(e)}

    if result.get("error"):
        return result

    file_hash = result.get("hash")
    if not file_hash:
        return {"error": "No hash returned from MobSF upload"}

    scan = _post("scan", data={"hash": file_hash, "scan_type": "apk", "file_name": filename})
    if scan.get("error"):
        return {"error": scan["error"], "hash": file_hash}

    return {"hash": file_hash}


def get_static_report(file_hash: str) -> dict:
    """Fetch MobSF static analysis report and extract key findings."""
    report = _post("report_json", data={"hash": file_hash})
    if report.get("error"):
        return report

    findings = {
        "mobsf_score": report.get("appsec", {}).get("security_score"),
        "trackers": [t["name"] for t in report.get("trackers", {}).get("trackers", [])],
        "network_security": report.get("network_security", {}).get("network_findings", []),
        "certificate_analysis": report.get("certificate_analysis", {}).get("certificate_findings", []),
        "manifest_analysis": [
            f"{i.get('rule', '')} — {i.get('title', '')}"
            for i in report.get("manifest_analysis", {}).get("manifest_findings", [])
            if i.get("severity") in ("high", "warning")
        ],
        "code_analysis": {
            sev: [f"{v.get('metadata', {}).get('filename', '')} — {k}" for k, v in findings.items()]
            for sev, findings in report.get("code_analysis", {}).get("findings", {}).items()
            if sev in ("high",)
        },
        "permissions": {
            "dangerous": [
                p for p, info in report.get("permissions", {}).items()
                if isinstance(info, dict) and info.get("status") == "dangerous"
            ]
        },
    }
    return findings


def start_dynamic(file_hash: str) -> dict:
    """Start dynamic analysis. Requires Android emulator connected to MobSF."""
    return _post("dynamic/start_analysis", data={"hash": file_hash})


def stop_dynamic(file_hash: str) -> dict:
    return _post("dynamic/stop_analysis", data={"hash": file_hash})


def get_dynamic_report(file_hash: str) -> dict:
    """Fetch dynamic analysis report and extract key findings."""
    report = _post("dynamic/report_json", data={"hash": file_hash})
    if report.get("error"):
        return report

    return {
        "network_calls": [
            {"url": c.get("url"), "method": c.get("method"), "data": c.get("data")}
            for c in report.get("network", [])
            if c.get("url")
        ][:20],
        "api_calls": report.get("apicalls", [])[:30],
        "files_accessed": report.get("files", [])[:20],
        "crypto_operations": report.get("crypto", [])[:10],
        "sms_sent": report.get("sms", []),
        "clipboard_access": report.get("clipboard", []),
        "screenshots": len(report.get("screenshots", [])),
    }


def analyze(apk_path: str, dynamic: bool = False) -> dict:
    """
    Full MobSF analysis pipeline.
    dynamic=True requires Android emulator running in MobSF.
    """
    if not MOBSF_API_KEY or not MOBSF_URL:
        return {"error": "MobSF not configured (MOBSF_URL / MOBSF_API_KEY missing)"}

    upload = upload_and_scan(apk_path)
    if upload.get("error"):
        return upload

    file_hash = upload["hash"]
    result = {"hash": file_hash, "static": get_static_report(file_hash)}

    if dynamic:
        start = start_dynamic(file_hash)
        if start.get("error"):
            result["dynamic"] = {"error": start["error"]}
        else:
            # Wait for dynamic analysis to collect data (~60s is typical minimum)
            print("[dim][~] MobSF dynamic analysis running (60s)...[/dim]")
            time.sleep(60)
            stop_dynamic(file_hash)
            result["dynamic"] = get_dynamic_report(file_hash)

    return result
