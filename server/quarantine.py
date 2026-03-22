# quarantine.py
from __future__ import annotations
from pathlib import Path
import shutil
from datetime import datetime

QUAR_DIR = Path("quarantine")

def ensure_quarantine_dir() -> None:
    QUAR_DIR.mkdir(parents=True, exist_ok=True)

def quarantine_file(path: str) -> str | None:
    """
    Déplace le fichier vers quarantine/ avec un suffixe timestamp.
    Retourne le nouveau chemin (str) ou None si échec.
    """
    ensure_quarantine_dir()
    src = Path(path)
    if not src.exists() or not src.is_file():
        return None

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    dst_name = f"{src.stem}__QUAR__{ts}{src.suffix}"
    dst = QUAR_DIR / dst_name

    try:
        shutil.move(str(src), str(dst))
        return str(dst)
    except Exception:
        return None
