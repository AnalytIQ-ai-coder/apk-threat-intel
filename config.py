import os
from dotenv import load_dotenv

load_dotenv()

MWDB_API_KEY = os.getenv("MWDB_API_KEY")
MWDB_URL = os.getenv("MWDB_URL")

EMAIL_SENDER = os.getenv("EMAIL_SENDER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
EMAIL_RECIPIENT = os.getenv("EMAIL_RECIPIENT")

VT_API_KEY = os.getenv("VT_API_KEY")

MOBSF_URL = os.getenv("MOBSF_URL", "http://localhost:8000")
MOBSF_API_KEY = os.getenv("MOBSF_API_KEY")
MOBSF_DYNAMIC = os.getenv("MOBSF_DYNAMIC", "false").lower() == "true"

# abuse.ch (ThreatFox / URLhaus / MalwareBazaar). The Auth-Key is optional:
# the API answers without one, just with a lower request budget.
ABUSECH_API_KEY = os.getenv("ABUSECH_API_KEY")
ENRICHMENT_ENABLED = os.getenv("ENRICHMENT_ENABLED", "true").lower() == "true"

if not MWDB_API_KEY:
    raise ValueError("Missing MWDB_API_KEY in .env")
