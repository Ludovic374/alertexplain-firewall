# port_explanations.py

PORT_INFO = {
    21: {
        "service": "FTP",
        "description": "Transfert de fichiers",
        "target": "Fichiers transférés / dépôt FTP",
        "risk": "Exfiltration ou dépôt de fichiers",
    },
    22: {
        "service": "SSH",
        "description": "Accès distant sécurisé",
        "target": "Connexion shell distante / administration",
        "risk": "Tentative d'accès distant ou brute force",
    },
    23: {
        "service": "Telnet",
        "description": "Accès distant non sécurisé",
        "target": "Session distante en clair",
        "risk": "Accès distant faible sécurité",
    },
    25: {
        "service": "SMTP",
        "description": "Envoi d'emails",
        "target": "Service mail sortant",
        "risk": "Abus de relais mail ou spam",
    },
    53: {
        "service": "DNS",
        "description": "Résolution de noms",
        "target": "Résolution de domaines",
        "risk": "Reconnaissance réseau ou tunneling DNS",
    },
    80: {
        "service": "HTTP",
        "description": "Web non sécurisé",
        "target": "Serveur web / API",
        "risk": "Exploration web ou tentative applicative",
    },
    110: {
        "service": "POP3",
        "description": "Récupération email",
        "target": "Boîte mail",
        "risk": "Tentative d'accès à des emails",
    },
    135: {
        "service": "RPC",
        "description": "Services Windows RPC",
        "target": "Services système Windows",
        "risk": "Reconnaissance ou exploitation Windows",
    },
    139: {
        "service": "NetBIOS",
        "description": "Partage réseau Windows",
        "target": "Ressources partagées Windows",
        "risk": "Énumération réseau et accès aux partages",
    },
    143: {
        "service": "IMAP",
        "description": "Accès email IMAP",
        "target": "Boîte mail",
        "risk": "Tentative d'accès à des emails",
    },
    443: {
        "service": "HTTPS",
        "description": "Web sécurisé",
        "target": "Serveur web / API sécurisée",
        "risk": "Exploration web, API ou trafic chiffré",
    },
    445: {
        "service": "SMB",
        "description": "Partage de fichiers Windows",
        "target": "Fichiers et dossiers partagés",
        "risk": "Accès aux fichiers Windows / déplacement latéral",
    },
    3389: {
        "service": "RDP",
        "description": "Bureau à distance Windows",
        "target": "Prise de contrôle distante du poste",
        "risk": "Tentative de contrôle à distance",
    },
}

def explain_port(port: int):
    info = PORT_INFO.get(port)
    if info:
        return info

    return {
        "service": f"Port {port}",
        "description": "Service non référencé",
        "target": "Service inconnu",
        "risk": "Activité à analyser manuellement",
    }

def explain_ports_list(ports):
    results = []
    for p in ports:
        info = explain_port(p)
        results.append({
            "port": p,
            "service": info["service"],
            "description": info["description"],
            "target": info["target"],
            "risk": info["risk"],
        })
    return results