"""Export a run's results into formats that are ready to use elsewhere.

CSV (for Excel or a SIEM), a MISP event JSON (for import) and ready-written
abuse reports for the hosts that come up most (GitHub, Discord, Firebase).
"""
import csv
import json
import os
from datetime import datetime, timezone

OUTPUT_DIR = "output"


# CSV values come from the samples themselves (package names, URLs out of the
# DEX). Spreadsheets treat a cell starting with =, +, -, @, TAB or CR as a
# formula, so opening the report in Excel would execute code from the malware
# we just analysed.
_CSV_INJECTION_PREFIXES = ("=", "+", "-", "@", chr(9), chr(13))


def csv_safe(value):
    """Defuse formulas in a CSV cell (CWE-1236)."""
    if value is None:
        return ""
    text = str(value)
    if text.startswith(_CSV_INJECTION_PREFIXES):
        return "'" + text
    return text


def _host_of(value: str) -> str:
    """Strip scheme and path, leaving the bare host."""
    v = value.split("://", 1)[-1]
    return v.split("/", 1)[0]


def export_csv(results: list[dict], path: str = None) -> str:
    """A flat list of IOCs across every sample in this run, one row per IOC."""
    path = path or os.path.join(OUTPUT_DIR, "iocs.csv")
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    rows = []
    for data in results:
        sha256 = data.get("sha256", "")
        package = data.get("package", "")
        dex = data.get("dex") or {}
        iocs = data.get("iocs") or {}

        for url in dex.get("urls", []) or []:
            rows.append((sha256, package, "url", url))
        for ip in dex.get("ips", []) or []:
            rows.append((sha256, package, "ip", ip))
        for dom in dex.get("domains", []) or []:
            rows.append((sha256, package, "domain", dom))

        if iocs and not iocs.get("error"):
            for kind, values in iocs.get("wallets", {}).items():
                for v in values:
                    rows.append((sha256, package, f"wallet_{kind}", v))
            for kind, values in iocs.get("operator_contacts", {}).items():
                for v in values:
                    rows.append((sha256, package, f"contact_{kind}", v))
            for v in iocs.get("discord_webhooks", []):
                rows.append((sha256, package, "discord_webhook", v))
            for kind, values in iocs.get("dead_drops", {}).items():
                for v in values:
                    rows.append((sha256, package, f"deaddrop_{kind}", v))

    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["sha256", "package", "ioc_type", "value"])
        w.writerows([[csv_safe(c) for c in row] for row in rows])

    return path


def export_misp_event(results: list[dict], path: str = None) -> str:
    """A simplified event in MISP import format, with no pymisp dependency."""
    path = path or os.path.join(OUTPUT_DIR, "misp_event.json")
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    attributes = []
    for data in results:
        sha256 = data.get("sha256", "")
        if sha256:
            attributes.append({"type": "sha256", "value": sha256, "category": "Payload delivery"})

        dex = data.get("dex") or {}
        for url in dex.get("urls", []) or []:
            attributes.append({"type": "url", "value": url, "category": "Network activity"})
        for ip in dex.get("ips", []) or []:
            attributes.append({"type": "ip-dst", "value": ip, "category": "Network activity"})
        for dom in dex.get("domains", []) or []:
            attributes.append({"type": "domain", "value": dom, "category": "Network activity"})

        iocs = data.get("iocs") or {}
        if iocs and not iocs.get("error"):
            for v in iocs.get("wallets", {}).get("btc", []):
                attributes.append({"type": "btc", "value": v, "category": "Financial fraud"})
            for v in iocs.get("wallets", {}).get("eth", []):
                attributes.append({"type": "text", "value": v, "category": "Financial fraud",
                                    "comment": "ETH wallet"})
            for v in iocs.get("discord_webhooks", []):
                attributes.append({"type": "url", "value": f"https://{v}",
                                    "category": "Network activity", "comment": "Discord exfil webhook"})

    event = {
        "Event": {
            "info": f"APK threat-intel batch - {datetime.now(timezone.utc).strftime('%Y-%m-%d')}",
            "threat_level_id": "2",
            "analysis": "1",
            "distribution": "0",
            "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "Attribute": attributes,
        }
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(event, f, indent=2, ensure_ascii=False)

    return path


# Hosts we can write a ready-made abuse report for
_ABUSE_TEMPLATES = {
    "github.com": (
        "GitHub repo hosting a dead-drop / C2 resolver for Android malware",
        "This GitHub repository is being used as a dead-drop resolver by Android "
        "banking malware. The app fetches the current C2 address from this repo/raw "
        "file at runtime.",
    ),
    "discord.com": (
        "Discord webhook used as malware data-exfiltration endpoint",
        "This Discord webhook is hardcoded in Android malware samples and used to "
        "exfiltrate stolen victim data (SMS, contacts, device info).",
    ),
    "firebaseio.com": (
        "Firebase Realtime Database abused as malware C2",
        "This Firebase RTDB project is used as a C2 / data-exfiltration channel by "
        "Android banking malware.",
    ),
    "pages.dev": (
        "Cloudflare Pages site used as malware C2 resolver",
        "This Cloudflare Pages deployment is used by Android malware to resolve the "
        "current C2 address at runtime.",
    ),
}


def generate_abuse_reports(results: list[dict]) -> list[dict]:
    """Group dead drops and webhooks by host and write the report for each.

    Each report lists the hashes of the samples abusing that resource. Returns
    a list of {resource, title, body}.
    """
    by_host: dict[str, dict] = {}

    for data in results:
        sha256 = data.get("sha256", "")
        package = data.get("package", "")
        iocs = data.get("iocs") or {}
        if not iocs or iocs.get("error"):
            continue

        candidates = []
        candidates += iocs.get("discord_webhooks", [])
        candidates += iocs.get("dead_drops", {}).get("github", [])
        candidates += iocs.get("dead_drops", {}).get("bitbucket", [])
        candidates += iocs.get("dead_drops", {}).get("firebase_rtdb", [])
        candidates += iocs.get("dead_drops", {}).get("pages_dev", [])
        candidates += iocs.get("dead_drops", {}).get("workers_dev", [])

        for value in candidates:
            host = _host_of(value)
            template_key = next((k for k in _ABUSE_TEMPLATES if k in host), None)
            if not template_key:
                continue
            entry = by_host.setdefault(value, {"host": host, "template": template_key, "samples": []})
            entry["samples"].append({"sha256": sha256, "package": package})

    reports = []
    for value, entry in by_host.items():
        title, intro = _ABUSE_TEMPLATES[entry["template"]]
        sample_lines = "\n".join(
            f"- {s['sha256']} ({s['package']})" for s in entry["samples"]
        )
        body = (
            f"{intro}\n\n"
            f"Abused resource: {value}\n\n"
            f"Malware samples observed using this resource (SHA-256, verifiable on VirusTotal):\n"
            f"{sample_lines}\n\n"
            f"Please review and take appropriate action (disable/delete)."
        )
        reports.append({"resource": value, "title": title, "body": body})

    return reports


def export_abuse_reports(results: list[dict], path: str = None) -> str:
    """Write the generated abuse reports to a plain text file."""
    path = path or os.path.join(OUTPUT_DIR, "abuse_reports.txt")
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    reports = generate_abuse_reports(results)

    with open(path, "w", encoding="utf-8") as f:
        if not reports:
            f.write("No resources in this run qualify for an automatic abuse report.\n")
        for r in reports:
            f.write(f"{'=' * 70}\n{r['title']}\n{'=' * 70}\n{r['body']}\n\n\n")

    return path
