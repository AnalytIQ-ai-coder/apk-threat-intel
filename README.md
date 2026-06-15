# apk-threat-intel

Automated Android APK threat analysis pipeline. Downloads samples from [MWDB (CERT Polska)](https://mwdb.cert.pl), performs static analysis, checks VirusTotal, runs local AI risk assessment, and sends an email report.

## What it does

For each new APK sample:

1. **Downloads** from MWDB (incremental — only new samples since last run)
2. **Parses AndroidManifest.xml** — package name, permissions, activities, services, receivers
3. **Analyzes DEX bytecode** — extracts URLs, IPs, domains, targeted app package names, dangerous API usage
4. **Checks certificate** — self-signed detection, validity, SHA1 fingerprint
5. **Calculates entropy** — detects packed/encrypted files (entropy > 7.0)
6. **Checks VirusTotal** — SHA256 lookup first; if hash is unknown, uploads the file and polls for results
7. **MobSF static analysis** — security score, trackers, manifest issues, dangerous permissions (optional, requires Docker)
8. **AI risk assessment** — local Ollama model rates risk as low/medium/high/critical with reasoning
9. **Sends email report** — CSV attachment with all findings
10. **Deletes downloaded files** — even on error

## Example output

```
┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Field          ┃ Value                                        ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Package        │ ru.m7wj6tqqcf.dtcmelbo                       │
│ App name       │ Max_video                                     │
│ Certificate    │ Self-signed: YES (Android Debug Key)         │
│ AI Risk        │ CRITICAL                                      │
│                │ trojan.mamont/pwtrick — banking overlay...   │
│ VirusTotal     │ 13/75 engines                                 │
│ Targeted apps  │ ru.alfabank.mobile.android                   │
│                │ com.idamob.tinkoff.android                    │
│                │ ru.vtb24.mobilebanking.android (+ 26 more)   │
│ Dangerous APIs │ SMS abuse: sendTextMessage                   │
│                │ Account theft: AccountManager                 │
│                │ Overlay attack: TYPE_APPLICATION_OVERLAY      │
│ Permissions    │ android.permission.INTERNET                  │
└━━━━━━━━━━━━━━━━┴━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┘
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
1. Install Android Studio and create an AVD (API 28, x86)
2. Start the emulator
3. Verify ADB sees it: `adb devices`
4. Set `MOBSF_DYNAMIC=true` in `.env`

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
