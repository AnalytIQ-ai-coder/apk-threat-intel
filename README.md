# apk-threat-intel

Automated Android APK threat analysis pipeline. Downloads samples from [MWDB (CERT Polska)](https://mwdb.cert.pl), performs static analysis, checks VirusTotal, runs local AI risk assessment, and sends an email report.

## What it does

For each new APK sample:

1. **Downloads** from MWDB (incremental — only new samples since last run)
2. **Parses AndroidManifest.xml** — package, permissions, activities, services, receivers, content providers, intent filters (autostart/suspicious actions), declared permissions, MultiDex detection
3. **Analyzes DEX bytecode** — URLs, IPs, domains, targeted app package names, dangerous API categories, Shannon entropy, native libs, malware framework fingerprints (Mamont, Cerberus, Anubis, etc.), packer detection, hidden DEX files, Base64-encoded IOCs
4. **Checks certificate** — self-signed detection, expiry, subject, SHA1 fingerprint
5. **Checks VirusTotal** — SHA256 lookup first; uploads file and polls for results if hash is unknown
6. **MobSF static analysis** — security score, trackers, manifest issues, dangerous permissions (optional, requires Docker)
7. **MobSF dynamic analysis** — network calls, SMS sent, files accessed, crypto operations (optional, requires Android emulator)
8. **AI risk assessment** — local Ollama model rates risk as low/medium/high/critical with reasoning (no data sent externally)
9. **YARA scan** — custom rules for campaigns identified in previous runs (fake MetaMask/Ermac/Octo, RU bankers, USDT clippers, etc.), see `yara_rules/`
10. **IOC extraction** — crypto wallets (BTC/ETH/TRON), operator contacts (Telegram/WhatsApp), Discord exfil webhooks, dead-drop C2 resolvers (GitHub, Firebase RTDB, Cloudflare Pages)
11. **External enrichment** — checks sample hash and extracted IOCs against abuse.ch (MalwareBazaar, ThreatFox, URLhaus) to see if they're already publicly known
12. **App Bundle split detection** — a `config.*` split is not an application (no label, no permissions, usually no code), so it is flagged as such and skipped for AI rating instead of being described as an app that "requests no permissions"
13. **Deduplication** — skips full re-analysis (VT/MobSF/AI/apktool) for samples already seen under a different filename
14. **Threat-intel database** — every sample and IOC is stored in `output/threat_intel.db` (SQLite), with correlation across runs (shared signing certificate, reused IOC)
15. **Exports** — CSV, MISP-compatible event JSON, and ready-to-send abuse report text per run
16. **Sends email report** — HTML body summary + CSV attachment with 35+ fields per sample
17. **Deletes downloaded files** — even on error

## Example output

```
┏━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Field                ┃ Value                                                     ┃
┡━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Package              │ ru.aj7ees.es788                                           │
│ App name             │ Max_video                                                 │
│ Certificate          │ Self-signed: YES (Android Debug Key)                     │
│ AI Risk              │ CRITICAL — trojan.mamont/pwtrick, banking overlay         │
│ VirusTotal           │ 13/75 engines                                             │
│ MobSF Score          │ 49/100                                                    │
│ Manifest issues      │ clear_text_traffic, exported unprotected service          │
│ Autostart            │ BOOT_COMPLETED, LOCKED_BOOT_COMPLETED                    │
│ Suspicious actions   │ SMS_RECEIVED, SCREEN_ON, CONNECTIVITY_CHANGE             │
│ Malware family       │ Mamont                                                    │
│ Targeted apps        │ ru.alfabank.mobile.android (+ 29 more Russian banks)     │
│ Dangerous APIs       │ SMS abuse: sendTextMessage                                │
│                      │ Account theft: AccountManager, getAuthToken               │
│                      │ Root: su, Encryption: AES                                 │
│ Dangerous perms      │ RECEIVE_SMS, SEND_SMS, READ_SMS, CALL_PHONE              │
└━━━━━━━━━━━━━━━━━━━━━━┴━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┘
```

## Requirements

- Python 3.10+
- [Ollama](https://ollama.com) with `qwen2.5:14b` model
- MWDB account — [mwdb.cert.pl](https://mwdb.cert.pl)
- VirusTotal account — [virustotal.com](https://www.virustotal.com) (free tier: 500 req/day)
- Gmail account with App Password
- **Optional:** [Docker](https://www.docker.com) for MobSF static analysis
- **Optional:** Android emulator (Android Studio AVD or Genymotion) for MobSF dynamic analysis

## Installation

**1. Clone**
```bash
git clone https://github.com/your-username/apk-threat-intel.git
cd apk-threat-intel
```

**2. Virtual environment**
```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux/macOS
source .venv/bin/activate
```

**3. Dependencies**
```bash
pip install -r requirements.txt
```

**4. Configure**
```bash
cp .env.example .env
# edit .env and fill in your keys
```

**5. Ollama + model**

Download Ollama from [ollama.com](https://ollama.com), then:
```bash
ollama pull qwen2.5:14b
```

## Configuration

| Variable | Description |
|----------|-------------|
| `MWDB_API_KEY` | API key from mwdb.cert.pl → account settings |
| `MWDB_URL` | MWDB API URL (default: `https://mwdb.cert.pl/api/`) |
| `EMAIL_SENDER` | Gmail address for sending reports |
| `EMAIL_PASSWORD` | Gmail App Password — [generate here](https://myaccount.google.com/apppasswords) |
| `EMAIL_RECIPIENT` | Recipient email address |
| `VT_API_KEY` | VirusTotal API key (free account) |
| `MOBSF_URL` | MobSF URL (default: `http://localhost:8000`) |
| `MOBSF_API_KEY` | MobSF REST API key — visible in MobSF web UI top-right corner |
| `MOBSF_DYNAMIC` | Set to `true` to enable dynamic analysis (requires Android emulator) |
| `ABUSECH_API_KEY` | Optional Auth-Key for abuse.ch (MalwareBazaar/ThreatFox/URLhaus) — works without one at a lower rate limit |
| `ENRICHMENT_ENABLED` | Set to `false` to skip abuse.ch lookups (default: `true`) |

> **Never commit `.env`** — it is in `.gitignore`.

## Usage

```bash
python analyzer.py
```

- **First run** — fetches all APKs uploaded today
- **Next runs** — fetches only APKs uploaded since last run
- State saved in `output/state.json`
- Results also saved to `output/results.json`, `output/threat_intel.db`, `output/iocs.csv`, `output/misp_event.json`, `output/abuse_reports.txt`

### Dashboard

Browse the accumulated threat-intel database (samples, IOC correlations, search) in a browser:

```bash
python dashboard.py
```

Opens at http://localhost:5001 — overview stats, recent samples, most-reused IOCs across runs, sample detail view, and an IOC search box.

## Project structure

```
├── analyzer.py          # Main entry point
├── mwdb_client.py       # MWDB API client
├── downloader.py        # APK download
├── manifest_parser.py   # AndroidManifest.xml parser, intent filters, split detection
├── cert_analyzer.py     # Certificate analysis (v1/v2/v3 signature schemes)
├── dex_analyzer.py      # DEX analysis (URLs, APIs, entropy, malware frameworks, hidden DEX)
├── vt_client.py         # VirusTotal lookup + file upload fallback
├── mobsf_client.py      # MobSF static/dynamic analysis (optional)
├── ai_analyzer.py       # Local AI risk assessment via Ollama
├── ioc_extractor.py     # Crypto wallets, operator contacts, dead-drop resolvers
├── yara_scanner.py      # Custom YARA rule matching
├── yara_rules/          # Rules for campaigns identified in previous runs
├── enrichment.py        # abuse.ch lookups (MalwareBazaar/ThreatFox/URLhaus)
├── threat_db.py         # SQLite threat-intel store + cross-run correlation
├── report_export.py     # CSV / MISP event JSON / abuse report exports
├── dashboard.py         # Flask web UI over threat_intel.db
├── mailer.py            # Email report with CSV
├── isolation.py         # Runs parsers for untrusted files in a child process
├── state.py             # Last run timestamp
├── config.py            # Config loader (.env)
├── clean_iocs.py        # One-off: purge IOCs stored before the validators existed
├── backfill_certs.py    # One-off: backfill certificates for pre-v2/v3 rows
├── backfill_splits.py   # One-off: mark App Bundle splits among older rows
├── backfill_ai.py       # One-off: rate samples a run left unrated (Ollama was down)
├── extract_anchors.py   # One-off: derive YARA anchors from a campaign certificate
├── .env.example         # Example credentials
└── requirements.txt
```

The three `backfill_*` / `clean_*` scripts all run in preview mode by default,
take a database backup before writing, and are resumable — they only pick rows
that have not been processed yet, so an interrupted run can simply be repeated.

## Writing YARA rules

The rules in `yara_rules/` follow a few conventions that are worth knowing
before adding one:

- **Measure the anchor before shipping it.** Every candidate string is checked
  against `output/threat_intel.db` and against real samples first. Several
  obvious-looking anchors were rejected this way — `telegram.org` and
  `static-maps.yandex.ru` turned out to be artefacts of the Telegram client
  source and appear in clean apps.
- **The scanner makes two separate passes.** `rules.match(path)` sees the raw
  file (the v2/v3 signature block, ZIP entry names) and `rules.match(data=...)`
  sees the concatenated decompressed entries (DEX, manifest, resources). A
  single rule cannot mix a string from one pass with a string from the other —
  that branch will never fire, and it will fail silently.
- **Separate the tool from the operator.** A certificate subject that is a
  builder default (`O=Org, L=City, ST=State`) identifies the tool, not the
  person; an RSA modulus identifies one key pair. Those belong in different
  rules, and a shared public key (the AOSP test keys) belongs in neither.
- **Say what is not there.** Each rule file's header records which anchors were
  considered and rejected, and why. That is what stops the same rejected idea
  from being tried again six weeks later.

## Security notes

- APK files are **never executed** — parsed as ZIP archives only
- VirusTotal receives **SHA256 hash first**; file is only uploaded when hash is unknown (new sample)
- AI analysis runs **fully locally** via Ollama — no data sent externally
- Downloaded files are **deleted after analysis**, even on error

## MobSF setup (optional)

MobSF adds security scoring, tracker detection, and manifest analysis on top of the built-in static analysis.

**Static analysis only (no emulator needed):**
```bash
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf
```
Open http://localhost:8000, copy the API key from the top-right corner, add to `.env`:
```
MOBSF_URL=http://localhost:8000
MOBSF_API_KEY=<your_key>
MOBSF_DYNAMIC=false
```

**Dynamic analysis (requires Android emulator):**
1. Install Android Studio and create an AVD — use **Android Open Source** image (no Google Play), API 29, x86
2. Start the emulator
3. Enable root: `adb root && adb remount`
4. Verify ADB sees it: `adb devices`
5. Set `MOBSF_DYNAMIC=true` in `.env`

> **Note:** Dynamic analysis results may be sparse for sophisticated malware (e.g. Mamont trojan) that waits for C2 commands before acting. The 60-second analysis window is sufficient for adware and droppers.

## Automating (Windows Task Scheduler)

Create a scheduled task pointing to:
```
C:\path\to\.venv\Scripts\python.exe  C:\path\to\analyzer.py
```

## Stack

| Component | Technology |
|-----------|------------|
| MWDB client | `mwdblib` |
| APK parsing | `androguard`, apktool (fallback for anti-analysis samples) |
| Threat lookup | VirusTotal API v3, abuse.ch (MalwareBazaar/ThreatFox/URLhaus) |
| Family detection | Custom `yara-python` rules |
| AI analysis | Ollama `qwen2.5:14b` |
| Storage | SQLite (`threat_db.py`) |
| Dashboard | `Flask` |
| Terminal UI | `rich` |
| Email | Gmail SMTP SSL |
