import os
from dotenv import load_dotenv

load_dotenv()

MWDB_API_KEY = os.getenv("MWDB_API_KEY")
MWDB_URL = os.getenv("MWDB_URL")

EMAIL_SENDER = os.getenv("EMAIL_SENDER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
EMAIL_RECIPIENT = os.getenv("EMAIL_RECIPIENT")

VT_API_KEY = os.getenv("VT_API_KEY")

if not MWDB_API_KEY:
    raise ValueError("Missing MWDB_API_KEY in .env")