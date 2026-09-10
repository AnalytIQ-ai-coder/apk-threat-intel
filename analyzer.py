import json
import os
import sys
import traceback
from datetime import datetime, timezone

# Nazwy aplikacji w probkach bywaja pisane homoglifami (cyrylica, cherokee).
# Jesli konsola ma kodowanie inne niz UTF-8, samo wypisanie takiej nazwy
# przerywa caly run UnicodeEncodeError - wymuszamy UTF-8 z podmiana znakow.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from loguru import logger
logger.disable("androguard")

from rich import print
from rich.markup import escape
from rich.markup import render as render_markup
from rich.table import Table
from rich import console as rich_console

os.makedirs("output", exist_ok=True)

from mwdb_client import get_client
from downloader import save_apk
from manifest_parser import parse_apk_timeout, split_bez_kodu
from mailer import send_report
from state import load_last_run, save_last_run
from vt_client import check_sha256, upload_file
from ai_analyzer import assess_risk
from dex_analyzer import analyze_dex_isolated
from mobsf_client import analyze as mobsf_analyze
from config import VT_API_KEY, MOBSF_API_KEY, MOBSF_DYNAMIC, ENRICHMENT_ENABLED
from ioc_extractor import extract_iocs_isolated
import threat_db
import yara_scanner
import report_export
import enrichment

console = rich_console.Console()

# Komórki tabeli zawierają dane pochodzące wprost z analizowanej próbki (stringi
# z DEX, nazwy plików w archiwum). Surowe bajty w terminalu to nie tylko brzydki
# wydruk — mogą nieść sekwencje sterujące ANSI/OSC. Dlatego każda komórka jest
# czyszczona ze znaków sterujących i przycinana do rozsądnej długości.
_MAX_CELL_CHARS = 2000


def _sanitize_cell(value):
    if value is None:
        return None
    if not isinstance(value, str):
        value = str(value)

    cleaned = "".join(c for c in value if c.isprintable() or c in "\n\t")

    truncated_by = 0
    if len(cleaned) > _MAX_CELL_CHARS:
        truncated_by = len(cleaned) - _MAX_CELL_CHARS
        cleaned = cleaned[:_MAX_CELL_CHARS]

    # Dane z próbki mogą przypadkiem (lub celowo) zawierać coś, co rich weźmie
    # za znacznik — wtedy render rzuca wyjątkiem i psuje cały run.
    try:
        render_markup(cleaned)
    except Exception:
        cleaned = escape(cleaned)

    if truncated_by:
        cleaned += f"\n[dim]… obcięto {truncated_by} znaków[/dim]"
    return cleaned


def _sanitize_plain(value: str, limit: int = 256) -> str:
    """Dla wartości, które nigdy nie powinny nieść znaczników rich
    (np. nazwa pliku z MWDB) — czyścimy i escapujemy bezwarunkowo."""
    if not isinstance(value, str):
        value = str(value)
    cleaned = "".join(c for c in value if c.isprintable())
    if len(cleaned) > limit:
        cleaned = cleaned[:limit] + "…"
    return escape(cleaned)


class SafeTable(Table):
    """Table sanityzująca każdą komórkę — patrz _sanitize_cell."""

    def add_row(self, *renderables, **kwargs):
        return super().add_row(*(_sanitize_cell(r) for r in renderables), **kwargs)


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
    table = SafeTable(title=f"[bold]{escape(str(data.get('package') or 'unknown'))}[/bold]", show_lines=True)
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")

    # Nazwa pakietu i aplikacji bywaja celowo spreparowane (homoglify, znaki
    # zero-width), wiec escapujemy je bezwarunkowo - nic nie moze zniknac.
    table.add_row("Package", _sanitize_plain(data.get("package") or "N/A"))
    table.add_row("App name", _sanitize_plain(data.get("app_name") or "N/A"))

    # Split z App Bundle to nie aplikacja, tylko jej kawalek. Mowimy o tym od
    # razu pod nazwa, zeby puste "Permissions: none" nizej nie bylo czytane
    # jako "ta aplikacja nic nie chce".
    split = data.get("split")
    if split:
        opis = f"{split['nazwa']} (rodzaj: {split['rodzaj']}"
        if split.get("ma_dex") is not None:
            opis += ", z kodem" if split["ma_dex"] else ", bez kodu"
        opis += ")"
        table.add_row("[bold yellow]Split z AAB[/bold yellow]", opis)
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
        schemat = cert.get("signature_scheme")
        schemat_str = f"  [dim](schemat {schemat})[/dim]" if schemat else ""
        cert_str = (
            f"Self-signed: {self_signed}{expired}{schemat_str}\n"
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

    # MobSF
    mobsf = data.get("mobsf")
    if mobsf and not mobsf.get("error"):
        static = mobsf.get("static", {})
        if static.get("mobsf_score") is not None:
            score = static["mobsf_score"]
            color = "green" if score >= 70 else "yellow" if score >= 40 else "red"
            table.add_row("MobSF Score", f"[{color}]{score}/100[/{color}]")
        if static.get("trackers"):
            table.add_row("[yellow]Trackers[/yellow]", ", ".join(static["trackers"]))
        if static.get("manifest_analysis"):
            table.add_row("[red]Manifest issues[/red]", "\n".join(static["manifest_analysis"][:5]))
        if static.get("permissions", {}).get("dangerous"):
            table.add_row("Dangerous perms", "\n".join(static["permissions"]["dangerous"][:10]))
        dynamic = mobsf.get("dynamic", {})
        if dynamic and not dynamic.get("error"):
            if dynamic.get("network_calls"):
                net_str = "\n".join(f"{c['method']} {c['url']}" for c in dynamic["network_calls"][:5])
                table.add_row("[red]Network calls[/red]", net_str)
            if dynamic.get("sms_sent"):
                table.add_row("[bold red]SMS sent[/bold red]", "\n".join(str(s) for s in dynamic["sms_sent"]))
            if dynamic.get("files_accessed"):
                table.add_row("Files accessed", "\n".join(dynamic["files_accessed"][:5]))
            if dynamic.get("crypto_operations"):
                table.add_row("Crypto ops", "\n".join(str(c) for c in dynamic["crypto_operations"][:5]))

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

    # YARA — rodziny/kampanie rozpoznane po własnych regułach
    yara_matches = data.get("yara_matches") or []
    if yara_matches:
        yara_str = "\n".join(f"[bold red]{m['family']}[/bold red] — {m['description']}" for m in yara_matches)
        table.add_row("[bold red]YARA match[/bold red]", yara_str)

    # IOC — portfele, kontakty operatorów, dead-dropy
    iocs = data.get("iocs") or {}
    if iocs and not iocs.get("error"):
        wallets = iocs.get("wallets", {})
        wallet_lines = [f"{k.upper()}: {v}" for k, values in wallets.items() for v in values]
        if wallet_lines:
            table.add_row("[bold red]Crypto wallets[/bold red]", "\n".join(wallet_lines))

        contacts = iocs.get("operator_contacts", {})
        contact_lines = [v for values in contacts.values() for v in values]
        if contact_lines:
            table.add_row("[yellow]Operator contacts[/yellow]", "\n".join(contact_lines))

        if iocs.get("discord_webhooks"):
            table.add_row("[bold red]Discord webhooks[/bold red]", "\n".join(iocs["discord_webhooks"]))

        dead_drops = iocs.get("dead_drops", {})
        drop_lines = [v for values in dead_drops.values() for v in values]
        if drop_lines:
            table.add_row("[red]Dead-drop resolvers[/red]", "\n".join(drop_lines))

    # Wzbogacanie zewnętrzne — abuse.ch (ThreatFox/URLhaus/MalwareBazaar)
    enrich = data.get("enrichment") or {}
    mb = enrich.get("malwarebazaar") or {}
    if mb.get("known"):
        table.add_row(
            "[bold red]MalwareBazaar[/bold red]",
            f"znany jako: {mb.get('signature') or 'brak sygnatury'}\n{mb.get('link', '')}",
        )
    if enrich.get("threatfox_hits"):
        tf_lines = [
            f"{h['ioc']} — {', '.join(x.get('malware') or '?' for x in h.get('hits', []))}"
            for h in enrich["threatfox_hits"]
        ]
        table.add_row("[bold red]ThreatFox[/bold red]", "\n".join(tf_lines))
    if enrich.get("urlhaus_hits"):
        uh_lines = [f"{h['url']} — {h.get('threat', '?')} ({h.get('status', '?')})" for h in enrich["urlhaus_hits"]]
        table.add_row("[bold red]URLhaus[/bold red]", "\n".join(uh_lines))

    # Korelacje — ten sam cert/IOC widziany w poprzednich runach
    correlations = data.get("correlations") or []
    if correlations:
        corr_lines = []
        for c in correlations[:5]:
            names = ", ".join(s.get("filename", s.get("sha256", "")[:12]) for s in c.get("seen_in", [])[:3])
            if c["type"] == "shared_certificate":
                corr_lines.append(f"Cert {c['value'][:16]}... też w: {names}")
            else:
                corr_lines.append(f"{c['ioc_type']} '{c['value'][:40]}' też w: {names}")
        table.add_row("[bold yellow]Znane z wcześniejszych runów[/bold yellow]", "\n".join(corr_lines))

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
    query = f'(tag:*apk OR tag:"runnable:android:apk") AND upload_time:["{since_str}" TO *]'
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
        # Nazwa nadana przez wrzucającego próbkę — trafia do print() i do bazy,
        # więc czyścimy ją ze znaków sterujących i znaczników rich.
        filename = _sanitize_plain(getattr(obj, "name", "") or "")

        # Próbki z tagiem runnable:android:apk często mają nazwę = sha256 bez rozszerzenia,
        # więc nie można polegać wyłącznie na nazwie pliku
        tags = list(getattr(obj, "tags", None) or [])
        looks_like_apk = filename.lower().endswith(".apk") or "runnable:android:apk" in tags
        if filename.lower().endswith(".xapk") or not looks_like_apk:
            print(f"\n[dim][~] Skipping {filename} (not .apk)[/dim]")
            continue

        existing = threat_db.get_sample(sha256) if sha256 != "?" else None
        if existing:
            threat_db.mark_duplicate(sha256, filename)
            print(
                f"\n[dim][~] Skipping {filename} ({sha256[:16]}...) — duplikat próbki "
                f"już przeanalizowanej jako {existing.get('filename')}[/dim]"
            )
            continue

        print(f"\n[bold blue][~] Processing {filename} ({sha256[:16]}...)[/bold blue]")

        apk_path = None
        try:
            apk_path = save_apk(obj)
            data = parse_apk_timeout(apk_path, timeout=90)

            data["sha256"] = sha256
            data["filename"] = filename
            upload_time = getattr(obj, "upload_time", None)
            data["upload_time"] = upload_time.isoformat() if upload_time else None

            data["dex"] = analyze_dex_isolated(
                apk_path,
                own_package=data.get("package", ""),
                permissions=data.get("permissions", []),
            )
            data["iocs"] = extract_iocs_isolated(apk_path)
            data["yara_matches"] = yara_scanner.scan_isolated(apk_path)

            if VT_API_KEY:
                vt = check_sha256(sha256)
                if vt.get("not_found") and apk_path and os.path.exists(apk_path):
                    print(f"[dim][~] Hash not in VT — uploading file for analysis...[/dim]")
                    vt = upload_file(apk_path, sha256)
                data["vt"] = vt

            if MOBSF_API_KEY:
                print(f"[dim][~] MobSF analysis...[/dim]")
                data["mobsf"] = mobsf_analyze(apk_path, dynamic=MOBSF_DYNAMIC)

            if split_bez_kodu(data):
                # Splitu konfiguracyjnego nie ma po co wysylac do modelu: nie ma
                # uprawnien, komponentow ani DEX-a, wiec prompt skladalby sie
                # z samych pustych pol. Model odpowiadal na to "RISK: low,
                # brak uprawnien" i taka ocena szla do bazy — 164 wiersze w
                # output/threat_intel.db powstaly wlasnie tak. To falszywy
                # negatyw wygenerowany z niczego, a nie ocena probki.
                powod = "split %s bez kodu — nie ma czego oceniac" % data["split"]["nazwa"]
                print(f"[dim][~] Pomijam AI: {powod}[/dim]")
                data["ai"] = {"skipped": powod}
            else:
                print(f"[dim][~] Asking AI...[/dim]")
                data["ai"] = assess_risk(data)

            if ENRICHMENT_ENABLED:
                print(f"[dim][~] Sprawdzam IOC w ThreatFox/URLhaus/MalwareBazaar...[/dim]")
                data["enrichment"] = enrichment.enrich(data, data.get("iocs") or {})

            correlation = threat_db.store_sample(data, data.get("iocs") or {})
            data["correlations"] = correlation.get("correlations", [])

            print_result(data)
            results.append(data)

        except Exception as e:
            print(f"[red][!] Error processing {sha256[:16]}:[/red] {escape(str(e))}")
            traceback.print_exc()

        finally:
            if apk_path and os.path.exists(apk_path):
                os.remove(apk_path)

    output_path = "output/results.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print(f"\n[bold green][+] Done. {len(results)}/{len(files)} processed. Results saved to {output_path}[/bold green]")

    if results:
        csv_path = report_export.export_csv(results)
        misp_path = report_export.export_misp_event(results)
        abuse_path = report_export.export_abuse_reports(results)
        print(f"[dim][~] Exports: {csv_path}, {misp_path}, {abuse_path}[/dim]")

        db_stats = threat_db.stats()
        print(
            f"[dim][~] Baza threat-intel: {db_stats['samples']} próbek, "
            f"{db_stats['unique_iocs']} unikalnych IOC, {db_stats['unique_certs']} certów, "
            f"{db_stats['duplicates_skipped']} duplikatów pominiętych łącznie[/dim]"
        )

        reused = threat_db.top_reused_iocs(limit=5)
        if reused:
            print("[yellow][~] Najczęściej powtarzające się IOC w historii:[/yellow]")
            for r in reused:
                print(f"    [{r['ioc_type']}] {r['value'][:60]} — {r['sample_count']} próbek")

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
