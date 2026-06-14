import json
import os
from datetime import datetime, timezone

STATE_FILE = "output/state.json"


def load_last_run() -> datetime | None:
    if not os.path.exists(STATE_FILE):
        return None
    with open(STATE_FILE, encoding="utf-8") as f:
        data = json.load(f)
    ts = data.get("last_run")
    if ts:
        return datetime.fromisoformat(ts)
    return None


def save_last_run(dt: datetime):
    os.makedirs("output", exist_ok=True)
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump({"last_run": dt.isoformat()}, f)
