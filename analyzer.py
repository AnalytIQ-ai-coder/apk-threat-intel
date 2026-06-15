import json
import os
import traceback
from datetime import datetime, timezone

from loguru import logger
logger.disable("androguard")

from rich import print
from rich.table import Table
from rich import console as rich_console

os.makedirs("output", exist_ok=True)

from mwdb_client import get_client
from downloader import save_apk
from manifest_parser import parse_apk
from mailer import send_report
from state import load_last_run, save_last_run
from vt_client import check_sha256, upload_file
from ai_analyzer import assess_risk
from dex_analyzer import analyze_dex
from config import VT_API_KEY

console = rich_console.Console()


def get_since(last_run: datetime | None) -> datetime:
    if last_run is None:
        now = datetime.now(timezone.utc)
        return now.replace(hour=0, minute=0, second=0, microsecond=0)
    return last_run


def filter_new(files: list, since: datetime) -> list:
    new = []
    for obj in files:
        upload_time = getattr(obj, "upload_time", None)
        if upload_time is None:
            continue
        # mwdblib zwraca upload_time jako datetime (może być naive lub aware)
        if upload_time.tzinfo is None:
            upload_time = upload_time.replace(tzinfo=timezone.utc)
        if upload_time >= since:
            new.append(obj)
    return new


def print_result(data: dict):
    table = Table(title=f"[bold]{data.get('package', 'unknown')}[/bold]", show_lines=True)
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")

    table.add_row("Package", data.get("package") or "N/A")
    table.add_row("App name", data.get("app_name") or "N/A")
    table.add_row("Version", f"{data.get('version_name')} ({data.get('version_code')})")
    table.add_row("Min SDK", str(data.get("min_sdk") or "N/A"))
    table.add_row("Target SDK", str(data.get("target_sdk") or "N/A"))
    table.add_row("SHA256", data.get("sha256") or "N/A")
    table.add_row("Upload time", data.get("upload_time") or "N/A")

    # Certificate
    cert = data.get("cert")
    if cert and not cert.get("error"):
        self_signed = "[red]YES[/red]" if cert.get("self_signed") else "[green]NO[/green]"
        expired = " [red](EXPIRED)[/red]" if cert.get("expired") else ""
        cert_str = (
            f"Self-signed: {self_signed}{expired}\n"
            f"Subject: {cert.get('subject', 'N/A')}\n"
            f"Valid: {cert.get('valid_from', '')[:10]} → {cert.get('valid_to', '')[:10]}\n"
            f"SHA1: {cert.get('sha1', 'N/A')}"
        )
        table.add_row("Certificate", cert_str)

    # AI
    ai = data.get("ai")
    if ai:
        if ai.get("error"):
            ai_str = f"[red]Error: {ai['error']}[/red]"
        else:
            risk = ai.get("risk", "unknown")
            reason = ai.get("reason", "")
            color = {"low": "green", "medium": "yellow", "high": "red", "critical": "bold red"}.get(risk, "white")
            ai_str = f"[{color}]{risk.upper()}[/{color}]\n{reason}"
        table.add_row("AI Risk", ai_str)

    # VirusTotal
    vt = data.get("vt")
    if vt:
        if vt.get("not_found"):
            vt_str = "Not found in VT"
        elif vt.get("error"):
            vt_str = f"Error: {vt['error']}"
        else:
            m, t = vt["malicious"], vt["total"]
            label = f"  [{vt['threat_label']}]" if vt.get("threat_label") else ""
            color = "red" if m > 0 else "green"
            vt_str = f"[{color}]{m}/{t} engines{label}[/{color}]\n{vt['link']}"
        table.add_row("VirusTotal", vt_str)

    # Manifest extras
    if data.get("autostart_actions"):
        table.add_row("[red]Autostart[/red]", "\n".join(data["autostart_actions"]))
    if data.get("suspicious_actions"):
        table.add_row("[yellow]Suspicious actions[/yellow]", "\n".join(data["suspicious_actions"]))
    if data.get("declared_permissions"):
        table.add_row("Declared permissions", "\n".join(data["declared_permissions"]))
    if data.get("providers"):
        table.add_row("Content providers", "\n".join(data["providers"]))
    if data.get("is_multidex"):
        table.add_row("[yellow]MultiDex[/yellow]", "YES")

    # DEX analysis
    dex = data.get("dex")
    if dex and not dex.get("error"):
        if dex.get("malware_frameworks"):
            table.add_row("[bold red]Malware family[/bold red]", ", ".join(dex["malware_frameworks"]))
        if dex.get("packers"):
            table.add_row("[red]Packers detected[/red]", "\n".join(dex["packers"]))
        if dex.get("hidden_dex"):
            hidden_str = "\n".join(f"{h['file']} ({h['size']} B)" for h in dex["hidden_dex"])
            table.add_row("[bold red]Hidden DEX[/bold red]", hidden_str)
        if dex.get("urls"):
            table.add_row("URLs in DEX", "\n".join(dex["urls"]))
        if dex.get("ips"):
            table.add_row("IPs in DEX", "\n".join(dex["ips"]))
        if dex.get("decoded_b64_iocs"):
            table.add_row("[yellow]Decoded Base64 IOCs[/yellow]", "\n".join(dex["decoded_b64_iocs"]))
        if dex.get("domains"):
            table.add_row("Domains in DEX", "\n".join(dex["domains"]))
        if dex.get("targeted_packages"):
            table.add_row("[red]Targeted apps[/red]", "\n".join(dex["targeted_packages"]))
        if dex.get("dangerous_apis"):
            apis_str = "\n".join(
                f"[red]{cat}[/red]: {', '.join(methods)}"
                for cat, methods in dex["dangerous_apis"].items()
            )
            table.add_row("Dangerous APIs", apis_str)
        if dex.get("native_libs"):
            libs_str = "\n".join(f"{l['name']} ({l['arch']})" for l in dex["native_libs"])
            table.add_row("Native libs", libs_str)
        if dex.get("high_entropy_files"):
            entropy_str = "\n".join(
                f"{e['file']} — entropy {e['entropy']}"
                for e in dex["high_entropy_files"]
            )
            table.add_row("[red]High entropy files[/red]", entropy_str)

    permissions = data.get("permissions", [])
    table.add_row("Permissions", "\n".join(permissions) if permissions else "none")

    console.print(table)


def main():
    run_start = datetime.now(timezone.utc)

    last_run = load_last_run()
    since = get_since(last_run)

    if last_run is None:
        print(f"[yellow][*] First run — fetching APKs uploaded today (since {since.strftime('%Y-%m-%d %H:%M UTC')})[/yellow]")
    else:
        print(f"[yellow][*] Fetching APKs uploaded since last run ({since.strftime('%Y-%m-%d %H:%M UTC')})[/yellow]")

    mwdb = get_client()

    since_str = since.strftime("%Y-%m-%d %H:%M")
    query = f'tag:*apk AND upload_time:["{since_str}" TO *]'
    print(f"[dim]Query: {query}[/dim]")
    files = list(mwdb.search_files(query))

    if not files:
        print("[yellow][!] No new APKs found since last run.[/yellow]")
        save_last_run(run_start)
        return

    print(f"[green][+] Found {len(files)} new file(s)[/green]")

    results = []

    for obj in files:
        sha256 = getattr(obj, "sha256", "?")
        filename = getattr(obj, "name", "") or ""

        if not filename.lower().endswith(".apk") or filename.lower().endswith(".xapk"):
            print(f"\n[dim][~] Skipping {filename} (not .apk)[/dim]")
            continue

        print(f"\n[bold blue][~] Processing {filename} ({sha256[:16]}...)[/bold blue]")

        apk_path = None
        try:
            apk_path = save_apk(obj)
            data = parse_apk(apk_path)

            data["sha256"] = sha256
            data["filename"] = filename
            upload_time = getattr(obj, "upload_time", None)
            data["upload_time"] = upload_time.isoformat() if upload_time else None

            data["dex"] = analyze_dex(apk_path, own_package=data.get("package", ""))

            if VT_API_KEY:
                vt = check_sha256(sha256)
                if vt.get("not_found") and apk_path and os.path.exists(apk_path):
                    print(f"[dim][~] Hash not in VT — uploading file for analysis...[/dim]")
                    vt = upload_file(apk_path, sha256)
                data["vt"] = vt

            print(f"[dim][~] Asking AI...[/dim]")
            data["ai"] = assess_risk(data)

            print_result(data)
            results.append(data)

        except Exception as e:
            print(f"[red][!] Error processing {sha256[:16]}: {e}[/red]")
            traceback.print_exc()

        finally:
            if apk_path and os.path.exists(apk_path):
                os.remove(apk_path)

    output_path = "output/results.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print(f"\n[bold green][+] Done. {len(results)}/{len(files)} processed. Results saved to {output_path}[/bold green]")

    save_last_run(run_start)
    print(f"[dim]State saved — next run will fetch APKs uploaded after {run_start.strftime('%Y-%m-%d %H:%M UTC')}[/dim]")

    if results:
        try:
            print("[blue][~] Sending email report...[/blue]")
            send_report(results)
            print("[bold green][+] Email sent successfully.[/bold green]")
        except Exception as e:
            print(f"[red][!] Failed to send email: {e}[/red]")


if __name__ == "__main__":
    main()
