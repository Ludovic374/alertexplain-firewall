# file_monitor.py

from __future__ import annotations
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import threading

from server.analyze_file import analyze, report_to_dict
from ai_score import score_file
from server.quarantine import quarantine_file
from threat_intel import check_hash, verdict_to_severity

from client_api import send_event

from config import QUARANTINE_THRESHOLD, MAX_FILESIZE, VT_MALICIOUS_BOOST, VT_SUSPICIOUS_BOOST

# ---------------------------------------------------------------------------
# Seuils
# ---------------------------------------------------------------------------

QUARANTINE_THRESHOLD = 70   # score heuristique >= 70 => quarantaine auto
MAX_FILESIZE         = 300 * 1024 * 1024   # 300 MB : au-delà on ignore

# Seuil VT : dès qu'un antivirus détecte => on monte le score
VT_MALICIOUS_BOOST   = 40   # ajout au score heuristique si VT dit malicious
VT_SUSPICIOUS_BOOST  = 20   # ajout au score heuristique si VT dit suspicious


# ---------------------------------------------------------------------------
# Dossiers surveillés
# ---------------------------------------------------------------------------

def default_watch_dirs() -> list[Path]:
    home = Path.home()
    return [p for d in ["Downloads", "Desktop"] if (p := home / d).exists()]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _adjusted_score(heuristic_score: int, vt_verdict: str) -> int:
    """Combine le score heuristique local et le verdict VirusTotal."""
    boost = {"malicious": VT_MALICIOUS_BOOST, "suspicious": VT_SUSPICIOUS_BOOST}.get(vt_verdict, 0)
    return min(100, heuristic_score + boost)


def _severity_from_score(score: int) -> str:
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------

class Handler(FileSystemEventHandler):
    def __init__(self):
        super().__init__()
        self.seen = set()
        self.lock = threading.Lock()

    def _handle(self, path: str):
        p = Path(path)
        if not p.exists() or not p.is_file():
            return

        try:
            if p.stat().st_size > MAX_FILESIZE:
                return
        except Exception:
            return

        # Anti-doublons : un fichier peut déclencher created + modified + moved
        key = str(p).lower()
        with self.lock:
            if key in self.seen:
                return
            self.seen.add(key)

        # --- 1. Analyse heuristique locale ---
        rep = analyze(str(p))
        if rep is None:
            return

        heuristic_score, heuristic_sev, heuristic_expl = score_file(rep)

        # --- 2. VirusTotal (si SHA-256 disponible) ---
        vt       = check_hash(rep.sha256)
        vt_info  = _build_vt_info(vt)

        # --- 3. Score final combiné ---
        final_score = _adjusted_score(heuristic_score, vt["verdict"])
        final_sev   = _severity_from_score(final_score)

        # --- Event FILE_NEW ---
        send_event({
            "event_type": "FILE_NEW",
            "severity":   "LOW",
            "title":      "Nouveau fichier détecté",
            "src":        None,
            "dst":        None,
            "proto":      "FILE",
            "dport":      None,
            "ports":      None,
            "what":       f"{rep.name} ({rep.ext})",
            "risk":       f"Score initial: {heuristic_score}/100",
            "do":         "Analyse automatique effectuée.",
        })

        # --- Event FILE_RISK ---
        what_parts = [heuristic_expl]
        if vt_info:
            what_parts.append(vt_info)

        send_event({
            "event_type": "FILE_RISK",
            "severity":   final_sev,
            "title":      "Fichier potentiellement dangereux" if final_score >= 40 else "Fichier analysé",
            "src":        None,
            "dst":        None,
            "proto":      "FILE",
            "dport":      None,
            "ports":      None,
            "what":       " | ".join(what_parts),
            "risk":       (
                f"Score={final_score}/100 (heuristique={heuristic_score}, VT={vt['verdict']}) "
                f"| sha256={rep.sha256 or 'n/a'}"
            ),
            "do":         (
                "Quarantaine automatique"
                if final_score >= QUARANTINE_THRESHOLD
                else "Aucune action automatique (surveillance)."
            ),
        })

        # --- Quarantaine auto si score final HIGH ---
        if final_score >= QUARANTINE_THRESHOLD:
            new_path = quarantine_file(str(p))
            send_event({
                "event_type": "FILE_QUARANTINED",
                "severity":   "HIGH",
                "title":      "Fichier mis en quarantaine",
                "src":        None,
                "dst":        None,
                "proto":      "FILE",
                "dport":      None,
                "ports":      None,
                "what":       f"Déplacé vers: {new_path}" if new_path else "Échec quarantaine.",
                "risk":       f"Score={final_score}/100 | VT={vt['verdict']}",
                "do":         "Ouvre quarantine/ et vérifie avant toute suppression.",
            })

    # -----------------------------------------------------------------------
    # Watchdog callbacks
    # -----------------------------------------------------------------------

    def on_created(self, event):
        if not event.is_directory:
            self._handle(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._handle(event.dest_path)


# ---------------------------------------------------------------------------
# VT info string builder
# ---------------------------------------------------------------------------

def _build_vt_info(vt: dict) -> str:
    """Construit une ligne lisible depuis un VTResult."""
    if vt.get("error") == "no_api_key":
        return ""   # silencieux si pas de clé configurée
    if vt.get("error"):
        return f"VT: erreur ({vt['error']})"
    if not vt.get("found"):
        return "VT: hash inconnu (fichier jamais soumis)"

    verdict   = vt.get("verdict", "unknown")
    malicious = vt.get("malicious", 0)
    total     = vt.get("total", 0)
    cached    = " (cache)" if vt.get("cached") else ""

    label = {
        "malicious":  "🔴 MALVEILLANT",
        "suspicious": "🟠 SUSPECT",
        "clean":      "🟢 Propre",
        "unknown":    "⚪ Inconnu",
    }.get(verdict, verdict.upper())

    return f"VT{cached}: {label} — {malicious}/{total} antivirus"


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_file_monitor(watch_dirs: list[str] | None = None):
    dirs = [Path(d) for d in watch_dirs] if watch_dirs else default_watch_dirs()
    if not dirs:
        print("[FILE] Aucun dossier à surveiller (Downloads/Desktop introuvables).")
        return

    print("[FILE] Surveillance fichiers active sur:")
    for d in dirs:
        print("  -", d)

    handler = Handler()
    obs     = Observer()
    for d in dirs:
        obs.schedule(handler, str(d), recursive=True)

    obs.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        obs.stop()
        obs.join()