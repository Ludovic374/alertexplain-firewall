import os
import requests

def is_scan_enabled() -> bool:
    base = os.getenv("ALERTEXPLAIN_API", "http://127.0.0.1:5000").rstrip("/")
    url = base + "/control"

    try:
        r = requests.get(url, timeout=1.5)
        if r.status_code != 200:
            return True
        data = r.json()
        return bool(data.get("scan_enabled", True))
    except Exception:
        return True