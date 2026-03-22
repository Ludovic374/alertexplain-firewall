import time
import os
import requests


def send_event(payload: dict) -> bool:
    base = os.getenv("ALERTEXPLAIN_API", "http://127.0.0.1:5000").rstrip("/")
    url = base + "/events"

    try:
        r = requests.post(url, json=payload, timeout=3)
        if r.status_code == 200:
            return True
        print(f"[WARN] API status={r.status_code} body={r.text[:200]}")
        return False
    except Exception as e:
        print(f"[WARN] API exception: {e}")
        return False

def is_scan_enabled() -> bool:
    base = os.getenv("ALERTEXPLAIN_API", "http://127.0.0.1:5000").rstrip("/")
    url = base + "/control"

    try:
        r = requests.get(url, timeout=2)
        if r.status_code == 200:
            return bool(r.json().get("scan_enabled", True))
    except Exception as e:
        print(f"[WARN] API control exception: {e}")

    # Par sécurité : si le serveur est down → scan ON
    return True
