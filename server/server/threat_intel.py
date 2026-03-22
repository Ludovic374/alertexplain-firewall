# threat_intel.py
"""
Threat intelligence : requête VirusTotal pour un hash SHA-256.
- Résultats mis en cache dans SQLite pour éviter les requêtes répétées.
- Clé API lue depuis la variable d'environnement VT_API_KEY.
- Graceful degradation : si la clé est absente ou le réseau indisponible,
  retourne un résultat neutre sans crasher.
"""

from __future__ import annotations

import os
import sqlite3
import time
from pathlib import Path
from typing import TypedDict

import requests
from config import VT_API_KEY, VT_CACHE_TTL, VT_TIMEOUT

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

VT_API_KEY  = os.getenv("VT_API_KEY", "")
VT_BASE_URL = "https://www.virustotal.com/api/v3/files"
TIMEOUT     = 6          # secondes
CACHE_TTL   = 86_400     # 24h en secondes — les résultats VT ne changent pas souvent
DB_PATH     = Path(__file__).parent / "threat_cache.db"

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

class VTResult(TypedDict):
    sha256:        str
    found:         bool          # True = hash connu de VT
    malicious:     int           # nb d'antivirus qui détectent comme malveillant
    suspicious:    int
    harmless:      int
    total:         int           # total d'antivirus ayant analysé
    verdict:       str           # "clean" | "suspicious" | "malicious" | "unknown"
    cached:        bool
    error:         str | None


# ---------------------------------------------------------------------------
# Cache SQLite
# ---------------------------------------------------------------------------

def _get_cache_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS vt_cache (
            sha256      TEXT PRIMARY KEY,
            malicious   INTEGER,
            suspicious  INTEGER,
            harmless    INTEGER,
            total       INTEGER,
            verdict     TEXT,
            ts          REAL
        )
    """)
    conn.commit()
    return conn


def _cache_get(sha256: str) -> VTResult | None:
    try:
        conn = _get_cache_conn()
        cur  = conn.execute(
            "SELECT malicious, suspicious, harmless, total, verdict, ts "
            "FROM vt_cache WHERE sha256=?",
            (sha256,)
        )
        row = cur.fetchone()
        conn.close()

        if row is None:
            return None

        malicious, suspicious, harmless, total, verdict, ts = row

        # Expiration du cache
        if time.time() - ts > CACHE_TTL:
            return None

        return VTResult(
            sha256=sha256,
            found=True,
            malicious=malicious,
            suspicious=suspicious,
            harmless=harmless,
            total=total,
            verdict=verdict,
            cached=True,
            error=None,
        )
    except Exception:
        return None


def _cache_set(result: VTResult) -> None:
    try:
        conn = _get_cache_conn()
        conn.execute("""
            INSERT OR REPLACE INTO vt_cache
                (sha256, malicious, suspicious, harmless, total, verdict, ts)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            result["sha256"],
            result["malicious"],
            result["suspicious"],
            result["harmless"],
            result["total"],
            result["verdict"],
            time.time(),
        ))
        conn.commit()
        conn.close()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Verdict helper
# ---------------------------------------------------------------------------

def _compute_verdict(malicious: int, suspicious: int, total: int) -> str:
    if total == 0:
        return "unknown"
    if malicious >= 3:
        return "malicious"
    if malicious >= 1 or suspicious >= 3:
        return "suspicious"
    return "clean"


# ---------------------------------------------------------------------------
# VirusTotal API
# ---------------------------------------------------------------------------

def _query_vt(sha256: str) -> VTResult:
    """Interroge l'API VT v3. Lève des exceptions — à gérer par l'appelant."""
    headers = {"x-apikey": VT_API_KEY}
    url     = f"{VT_BASE_URL}/{sha256}"

    r = requests.get(url, headers=headers, timeout=TIMEOUT)

    # 404 = hash inconnu de VT (fichier jamais soumis)
    if r.status_code == 404:
        return VTResult(
            sha256=sha256, found=False,
            malicious=0, suspicious=0, harmless=0, total=0,
            verdict="unknown", cached=False, error=None,
        )

    r.raise_for_status()

    data  = r.json()
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    malicious  = stats.get("malicious",  0)
    suspicious = stats.get("suspicious", 0)
    harmless   = stats.get("harmless",   0)
    undetected = stats.get("undetected", 0)
    total      = malicious + suspicious + harmless + undetected

    verdict = _compute_verdict(malicious, suspicious, total)

    return VTResult(
        sha256=sha256, found=True,
        malicious=malicious, suspicious=suspicious,
        harmless=harmless, total=total,
        verdict=verdict, cached=False, error=None,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_hash(sha256: str | None) -> VTResult:
    """
    Point d'entrée principal. Retourne un VTResult, jamais d'exception.

    Utilisation :
        from threat_intel import check_hash
        result = check_hash(rep.sha256)
        if result["verdict"] == "malicious":
            ...
    """
    # Pas de clé → dégradé silencieux
    if not sha256:
        return VTResult(
            sha256="", found=False,
            malicious=0, suspicious=0, harmless=0, total=0,
            verdict="unknown", cached=False, error="no_hash",
        )

    if not VT_API_KEY:
        return VTResult(
            sha256=sha256, found=False,
            malicious=0, suspicious=0, harmless=0, total=0,
            verdict="unknown", cached=False, error="no_api_key",
        )

    # Cache hit
    cached = _cache_get(sha256)
    if cached is not None:
        return cached

    # Appel API
    try:
        result = _query_vt(sha256)
        if result["found"]:
            _cache_set(result)
        return result

    except requests.exceptions.Timeout:
        return VTResult(
            sha256=sha256, found=False,
            malicious=0, suspicious=0, harmless=0, total=0,
            verdict="unknown", cached=False, error="timeout",
        )
    except requests.exceptions.HTTPError as e:
        return VTResult(
            sha256=sha256, found=False,
            malicious=0, suspicious=0, harmless=0, total=0,
            verdict="unknown", cached=False, error=f"http_{e.response.status_code}",
        )
    except Exception as e:
        return VTResult(
            sha256=sha256, found=False,
            malicious=0, suspicious=0, harmless=0, total=0,
            verdict="unknown", cached=False, error=str(e),
        )


def verdict_to_severity(verdict: str) -> str:
    """Convertit un verdict VT en sévérité AlertExplain."""
    return {
        "malicious":  "HIGH",
        "suspicious": "MEDIUM",
        "clean":      "LOW",
        "unknown":    "LOW",
    }.get(verdict, "LOW")