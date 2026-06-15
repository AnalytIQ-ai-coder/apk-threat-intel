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
9. **Sends email report** — HTML body summary + CSV attachment with 35+ fields per sample
10. **Deletes downloaded files** — even on error

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

> **Never commit `.env`** — it is in `.gitignore`.

## Usage

```bash
python analyzer.py
```

- **First run** — fetches all APKs uploaded today
- **Next runs** — fetches only APKs uploaded since last run
- State saved in `output/state.json`

## Project structure

```
├── analyzer.py          # Main entry point
├── mwdb_client.py       # MWDB API client
├── downloader.py        # APK download
├── manifest_parser.py   # AndroidManifest.xml parser + intent filters
├── cert_analyzer.py     # Certificate analysis
├── dex_analyzer.py      # DEX analysis (URLs, APIs, entropy, malware frameworks, hidden DEX)
├── vt_client.py         # VirusTotal lookup + file upload fallback
├── mobsf_client.py      # MobSF static/dynamic analysis (optional)
├── ai_analyzer.py       # Local AI risk assessment via Ollama
├── mailer.py            # Email report with CSV
├── state.py             # Last run timestamp
├── config.py            # Config loader (.env)
├── .env.example         # Example credentials
└── requirements.txt
```

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
| APK parsing | `androguard` |
| Threat lookup | VirusTotal API v3 |
| AI analysis | Ollama `qwen2.5:14b` |
| Terminal UI | `rich` |
| Email | Gmail SMTP SSL |
