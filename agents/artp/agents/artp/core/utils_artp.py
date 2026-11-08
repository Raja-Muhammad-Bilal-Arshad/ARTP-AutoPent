import json
from pathlib import Path
import datetime

def now_iso():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def load_json(p):
    p = Path(p)
    with p.open("r") as f:
        return json.load(f)

def save_json(obj, p):
    p = Path(p)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w") as f:
        json.dump(obj, f, indent=2, sort_keys=True)
    return p

def ensure_dir(p):
    Path(p).mkdir(parents=True, exist_ok=True)
