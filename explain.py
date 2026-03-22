# explain.py

EXPLANATIONS = {
    "BLOCKED_IP": {
        "title": "IP bloquée détectée",
        "severity": "HIGH",
        "what": "Une adresse IP déjà identifiée comme dangereuse a tenté une connexion.",
        "risk": "Risque de tentative d'intrusion, vol de données ou installation de malware.",
        "do": "Bloquer l'IP via le pare-feu Windows et vérifier si des connexions sortantes suspectes existent."
    },
    "SENSITIVE_PORT": {
        "title": "Port sensible détecté",
        "severity": "MEDIUM",
        "what": "Du trafic a ciblé un port souvent utilisé/attaqué (ex: RDP/SMB).",
        "risk": "Si le service est exposé, un attaquant peut tenter une connexion ou exploiter une faille.",
        "do": "Vérifier si ce port doit être ouvert. Sinon, le fermer dans le pare-feu Windows."
    },
    "PORT_SCAN": {
        "title": "Scan de ports détecté",
        "severity": "HIGH",
        "what": "Une même IP a testé beaucoup de ports différents sur une courte période.",
        "risk": "C'est souvent une étape de reconnaissance avant une attaque (recherche de ports ouverts).",
        "do": "Surveiller l'IP, et si ça continue, la bloquer via le pare-feu Windows."
    }
}

def explain(event_type: str, context: dict | None) -> dict:
    if context is None:
        context = {}

    base = EXPLANATIONS.get(event_type, {
        "title": "Évènement réseau",
        "severity": "LOW",
        "what": "Activité réseau détectée.",
        "risk": "Risque faible ou inconnu.",
        "do": "Surveiller."
    }).copy()

    details = []
    if "src" in context:
        details.append(f"Source: {context['src']}")
    if "dst" in context:
        details.append(f"Destination: {context['dst']}")
    if "proto" in context:
        details.append(f"Proto: {context['proto']}")
    if "dport" in context and context["dport"] is not None:
        details.append(f"Port: {context['dport']}")
    if "ports" in context and context["ports"]:
        details.append(f"Ports testés: {sorted(list(context['ports']))}")

    base["details"] = " | ".join(details) if details else ""
    return base
