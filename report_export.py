"""Eksport wyników runu do formatów gotowych do dalszego użycia:
CSV (do Excela/SIEM), MISP-owy event JSON (do importu) oraz gotowe
teksty zgłoszeń nadużyć dla popularnych hostów (GitHub, Discord, Firebase).
"""
import csv
import json
import os
from datetime import datetime, timezone

OUTPUT_DIR = "output"


# Wartosci w CSV pochodza z probek (nazwa pakietu, URL-e z DEX). Arkusze
# traktuja komorke zaczynajaca sie od =, +, -, @, TAB lub CR jako formule,
# wiec otwarcie raportu w Excelu wykonywaloby kod z analizowanego malware.
_CSV_INJECTION_PREFIXES = ("=", "+", "-", "@", chr(9), chr(13))


def csv_safe(value):
    """Neutralizuje formuly w komorce CSV (CWE-1236)."""
    if value is None:
        return ""
    text = str(value)
    if text.startswith(_CSV_INJECTION_PREFIXES):
        return "'" + text
    return text


def _host_of(value: str) -> str:
    v = value.split("://", 1)[-1]
    return v.split("/", 1)[0]


def export_csv(results: list[dict], path: str = None) -> str:
    """Płaska lista IOC ze wszystkich próbek w bieżącym runie — jeden wiersz na IOC."""
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
    """Uproszczony event w formacie zgodnym z importem MISP (bez zależności od pymisp)."""
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
            "info": f"APK threat-intel batch — {datetime.now(timezone.utc).strftime('%Y-%m-%d')}",
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


# Hosty, dla których generujemy gotowy tekst zgłoszenia z komendy "abuse report"
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
    """Grupuje dead-dropy/webhooki po hoście i generuje gotowy tekst zgłoszenia
    z listą hashy próbek, które go nadużywają. Zwraca listę {host, title, body}.
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
        candidates += iocs.get("dead_drops", {}).get("firebase_rtdb", [])
        candidates += iocs.get("dead_drops", {}).get("pages_dev", [])

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
    path = path or os.path.join(OUTPUT_DIR, "abuse_reports.txt")
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    reports = generate_abuse_reports(results)

    with open(path, "w", encoding="utf-8") as f:
        if not reports:
            f.write("Brak zasobów nadających się do automatycznego zgłoszenia w tym runie.\n")
        for r in reports:
            f.write(f"{'=' * 70}\n{r['title']}\n{'=' * 70}\n{r['body']}\n\n\n")

    return path
