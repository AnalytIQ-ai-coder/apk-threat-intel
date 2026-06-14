from mwdblib import MWDB
from config import MWDB_API_KEY, MWDB_URL


def get_client():
    return MWDB(
        api_url=MWDB_URL,
        api_key=MWDB_API_KEY
    )