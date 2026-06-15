import csv
import io
import smtplib
from email.message import EmailMessage

from config import EMAIL_SENDER, EMAIL_PASSWORD, EMAIL_RECIPIENT


def _build_body(results: list[dict]) -> str:
    lines = [f"Przeanalizowano {len(results)} plik(ów) APK.\n"]
    for r in results:
        vt = r.get("vt") or {}
        ai = r.get("ai") or {}
        cert = r.get("cert") or {}
        dex = r.get("dex") or {}

        lines.append(f"{'=' * 60}")
        lines.append(f"Pakiet  : {r.get('package') or 'N/A'}")
        lines.append(f"Nazwa   : {r.get('app_name') or 'N/A'}")
        lines.append(f"Wersja  : {r.get('version_name')} ({r.get('version_code')})")
        lines.append(f"SHA256  : {r.get('sha256') or 'N/A'}")

        # AI risk
        if ai.get("risk"):
            lines.append(f"AI Risk : {ai['risk'].upper()} — {ai.get('reason', '')}")

        # VirusTotal
        if vt.get("not_found"):
            lines.append("VT      : Not found")
        elif vt.get("error"):
            lines.append(f"VT      : Error — {vt['error']}")
        elif vt.get("total"):
            label = f" [{vt['threat_label']}]" if vt.get("threat_label") else ""
            lines.append(f"VT      : {vt['malicious']}/{vt['total']}{label}  {vt.get('link', '')}")

        # Certificate
        if cert and not cert.get("error"):
            self_signed = "YES" if cert.get("self_signed") else "NO"
            lines.append(f"Cert    : Self-signed: {self_signed} | SHA1: {cert.get('sha1', 'N/A')}")

        # DEX highlights
        targeted = dex.get("targeted_packages", [])
        if targeted:
            lines.append(f"Targeted apps ({len(targeted)}): {', '.join(targeted[:5])}")
        dangerous = dex.get("dangerous_apis", {})
        if dangerous:
            lines.append(f"Dangerous APIs: {', '.join(dangerous.keys())}")

        perms = r.get("permissions", [])
        lines.append(f"Uprawnienia ({len(perms)}): {', '.join(perms[:5])}")
        lines.append("")
    return "\n".join(lines)


def _build_csv(results: list[dict]) -> bytes:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "sha256", "package", "app_name", "version_name", "version_code",
        "min_sdk", "target_sdk", "is_multidex", "permissions",
        "declared_permissions", "providers", "autostart_actions", "suspicious_actions",
        "vt_detections", "vt_total", "vt_label", "vt_link",
        "ai_risk", "ai_reason",
        "cert_self_signed", "cert_sha1", "cert_expired",
        "malware_frameworks", "packers", "hidden_dex",
        "targeted_apps_count", "targeted_apps",
        "dangerous_apis",
        "urls", "ips", "decoded_b64_iocs",
        "high_entropy_files",
        "mobsf_score", "mobsf_trackers", "mobsf_manifest_issues",
        "mobsf_network_calls", "mobsf_sms_sent",
    ])
    for r in results:
        vt = r.get("vt") or {}
        ai = r.get("ai") or {}
        cert = r.get("cert") or {}
        dex = r.get("dex") or {}
        mobsf = r.get("mobsf") or {}
        mobsf_static = mobsf.get("static") or {}
        mobsf_dynamic = mobsf.get("dynamic") or {}

        writer.writerow([
            r.get("sha256"),
            r.get("package"),
            r.get("app_name"),
            r.get("version_name"),
            r.get("version_code"),
            r.get("min_sdk"),
            r.get("target_sdk"),
            r.get("is_multidex", ""),
            "; ".join(r.get("permissions", [])),
            "; ".join(r.get("declared_permissions", [])),
            "; ".join(r.get("providers", [])),
            "; ".join(r.get("autostart_actions", [])),
            "; ".join(r.get("suspicious_actions", [])),
            vt.get("malicious", ""),
            vt.get("total", ""),
            vt.get("threat_label", ""),
            vt.get("link", ""),
            ai.get("risk", ""),
            ai.get("reason", ""),
            cert.get("self_signed", ""),
            cert.get("sha1", ""),
            cert.get("expired", ""),
            "; ".join(dex.get("malware_frameworks", [])),
            "; ".join(dex.get("packers", [])),
            "; ".join(h["file"] for h in dex.get("hidden_dex", [])),
            len(dex.get("targeted_packages", [])),
            "; ".join(dex.get("targeted_packages", [])),
            "; ".join(dex.get("dangerous_apis", {}).keys()),
            "; ".join(dex.get("urls", [])),
            "; ".join(dex.get("ips", [])),
            "; ".join(dex.get("decoded_b64_iocs", [])),
            "; ".join(e["file"] for e in dex.get("high_entropy_files", [])),
            mobsf_static.get("mobsf_score", ""),
            "; ".join(mobsf_static.get("trackers", [])),
            "; ".join(mobsf_static.get("manifest_analysis", [])[:5]),
            "; ".join(f"{c['method']} {c['url']}" for c in mobsf_dynamic.get("network_calls", [])[:5]),
            "; ".join(str(s) for s in mobsf_dynamic.get("sms_sent", [])),
        ])
    return buf.getvalue().encode("utf-8")


def send_report(results: list[dict]):
    msg = EmailMessage()
    msg["Subject"] = f"MWDB APK Report — {len(results)} aplikacji"
    msg["From"] = EMAIL_SENDER
    msg["To"] = EMAIL_RECIPIENT
    msg.set_content(_build_body(results))

    csv_data = _build_csv(results)
    msg.add_attachment(csv_data, maintype="text", subtype="csv", filename="results.csv")

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(EMAIL_SENDER, EMAIL_PASSWORD)
        smtp.send_message(msg)
