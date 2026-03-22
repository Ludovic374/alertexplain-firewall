#analyze_file.py
from __future__ import annotations
from dataclasses import dataclass, asdict
from pathlib import Path
import hashlib
import math
import os
import time

MAX_BYTES_HASH = 200 * 1024 * 1024  # 200MB : au-delà, on ne hash pas (trop long)
READ_CHUNK = 1024 * 1024  # 1MB

SUSPICIOUS_EXT = {
    ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar",
    ".msi", ".reg", ".lnk", ".hta", ".iso", ".img"
}

DOC_MACRO_EXT = {".docm", ".xlsm", ".pptm"}

@dataclass
class FileReport:
    path: str
    name: str
    ext: str
    size: int
    mtime: float
    sha256: str | None
    entropy: float | None
    is_executable_like: bool
    is_macro_doc: bool
    double_extension: bool

def sha256_file(p: Path) -> str | None:
    try:
        size = p.stat().st_size
        if size > MAX_BYTES_HASH:
            return None
        h = hashlib.sha256()
        with p.open("rb") as f:
            while True:
                chunk = f.read(READ_CHUNK)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def shannon_entropy(p: Path, max_read: int = 2 * 1024 * 1024) -> float | None:
    """
    Entropie sur les premiers 2MB (approx). Haute entropie peut indiquer compression/chiffrement.
    """
    try:
        with p.open("rb") as f:
            data = f.read(max_read)
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        n = len(data)
        ent = 0.0
        for c in freq:
            if c == 0:
                continue
            p_i = c / n
            ent -= p_i * math.log2(p_i)
        return ent
    except Exception:
        return None

def has_double_extension(name: str) -> bool:
    # ex: "facture.pdf.exe" ou "photo.jpg.scr"
    parts = name.lower().split(".")
    if len(parts) < 3:
        return False
    last = "." + parts[-1]
    prev = "." + parts[-2]
    return (last in SUSPICIOUS_EXT) and (prev not in ("", last))

def analyze(path: str) -> FileReport | None:
    p = Path(path)
    if not p.exists() or not p.is_file():
        return None

    try:
        st = p.stat()
        name = p.name
        ext = p.suffix.lower()
        size = st.st_size
        mtime = st.st_mtime
    except Exception:
        return None

    rep = FileReport(
        path=str(p),
        name=name,
        ext=ext,
        size=size,
        mtime=mtime,
        sha256=sha256_file(p),
        entropy=shannon_entropy(p),
        is_executable_like=(ext in SUSPICIOUS_EXT),
        is_macro_doc=(ext in DOC_MACRO_EXT),
        double_extension=has_double_extension(name),
    )
    return rep

def report_to_dict(rep: FileReport) -> dict:
    return asdict(rep)
