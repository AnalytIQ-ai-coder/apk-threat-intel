import csv
import io
import smtplib
from email.message import EmailMessage

from config import EMAIL_SENDER, EMAIL_PASSWORD, EMAIL_RECIPIENT


def _build_body(results: list[dict]) -> str:
    lines = [f"Przeanalizowano {len(results)} plik(ów) APK.\n"]
    for r in results:
        lines.append(f"{'=' * 60}")
        lines.append(f"Pakiet  : {r.get('package') or 'N/A'}")
        lines.append(f"Nazwa   : {r.get('app_name') or 'N/A'}")
        lines.append(f"Wersja  : {r.get('version_name')} ({r.get('version_code')})")
        lines.append(f"SHA256  : {r.get('sha256') or 'N/A'}")
        perms = r.get("permissions", [])
        lines.append(f"Uprawnienia ({len(perms)}):")
        for p in perms:
            lines.append(f"  - {p}")
        lines.append("")
    return "\n".join(lines)


def _build_csv(results: list[dict]) -> bytes:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["sha256", "package", "app_name", "version_name", "version_code",
                     "min_sdk", "target_sdk", "permissions"])
    for r in results:
        writer.writerow([
            r.get("sha256"),
            r.get("package"),
            r.get("app_name"),
            r.get("version_name"),
            r.get("version_code"),
            r.get("min_sdk"),
            r.get("target_sdk"),
            "; ".join(r.get("permissions", [])),
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
