# ai_score.py
from __future__ import annotations
from typing import Tuple
from analyze_file import FileReport


def score_file(rep: FileReport) -> Tuple[int, str, str]:
    """
    Retourne: (risk_score 0-100, severity, explanation)
    Heuristique robuste: extensions, double-extension, taille, entropie, macros, emplacement…
    """
    score = 0
    reasons = []

    ext = (rep.ext or "").lower()
    name = (rep.name or "").lower()
    path = (rep.path or "").lower()

    # 1) Types dangereux
    if rep.is_executable_like:
        score += 35
        reasons.append(f"Extension exécutable ({ext}).")

    if rep.is_macro_doc:
        score += 25
        reasons.append(f"Document macro ({ext}).")

    # 2) Double extension
    if rep.double_extension:
        score += 30
        reasons.append("Double extension suspecte (ex: .pdf.exe).")

    # 3) Emplacements suspects (temp / appdata)
    if "\\appdata\\local\\temp\\" in path or "\\temp\\" in path:
        score += 15
        reasons.append("Fichier apparu dans un dossier Temp.")

    # 4) Entropie (approx)
    # >7.2 souvent compressé/chiffré => peut être packer
    if rep.entropy is not None and rep.entropy >= 7.2:
        score += 15
        reasons.append(f"Entropie élevée ({rep.entropy:.2f}) => contenu compressé/chiffré possible.")

    # 5) Taille étrange
    if rep.size < 10_000 and rep.is_executable_like:
        score += 10
        reasons.append("Exécutable très petit => potentiellement dropper/script.")

    # 6) Nom “social engineering”
    bait_words = ["facture", "invoice", "payment", "reçu", "recu", "urgent", "scan", "document", "colis", "delivery"]
    if any(w in name for w in bait_words) and rep.is_executable_like:
        score += 10
        reasons.append("Nom ressemble à un document mais extension exécutable.")

    # Clamp
    score = max(0, min(100, score))

    # Severity
    if score >= 70:
        sev = "HIGH"
    elif score >= 40:
        sev = "MEDIUM"
    else:
        sev = "LOW"

    if not reasons:
        reasons.append("Aucun indicateur fort détecté (analyse basique).")

    explanation = " ".join(reasons)
    return score, sev, explanation
