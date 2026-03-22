# config.py
"""
Configuration centrale d'AlertExplain Firewall.
Toutes les valeurs tunable sont ici — plus besoin de chercher dans chaque fichier.
Les variables d'environnement ont priorité sur les valeurs par défaut.
"""

import os

# ---------------------------------------------------------------------------
# Réseau — détection
# ---------------------------------------------------------------------------

# Nombre de ports distincts pour déclarer un scan (detector.py)
PORT_THRESHOLD = int(os.getenv("AE_PORT_THRESHOLD", "3"))

# Fenêtre temporelle pour la détection de scan, en secondes (detector.py)
TIME_WINDOW = int(os.getenv("AE_TIME_WINDOW", "30"))

# Nombre de scans confirmés avant blocage automatique (counter.py)
BLOCK_THRESHOLD = int(os.getenv("AE_BLOCK_THRESHOLD", "2"))

# Fenêtre de comptage des scans pour le seuil de blocage, en secondes (counter.py)
BLOCK_WINDOW_SECONDS = int(os.getenv("AE_BLOCK_WINDOW", "120"))

# Ports considérés comme sensibles — trafic vers ces ports génère une alerte MEDIUM (rules.py)
SENSITIVE_PORTS = set(
    int(p) for p in os.getenv("AE_SENSITIVE_PORTS", "22,3389,445,135,139").split(",")
)

# Ports UDP bruités à ignorer (multicast, DHCP, NetBIOS...) (rules.py)
NOISY_UDP_PORTS = set(
    int(p) for p in os.getenv("AE_NOISY_UDP", "5353,1900,137,138,67,68").split(",")
)

# Ports TCP bruités à ignorer (rules.py)
NOISY_TCP_PORTS = set(
    int(p) for p in os.getenv("AE_NOISY_TCP", "80,443").split(",")
)

# Mode IDS (alerte uniquement) ou IPS (alerte + blocage) (main.py)
# Valeurs : "IDS" | "IPS"
MODE = os.getenv("AE_MODE", "IPS")

# ---------------------------------------------------------------------------
# Cooldown des alertes — anti-spam
# ---------------------------------------------------------------------------

# Secondes entre deux alertes pour la même IP blacklistée (cooldown.py)
COOLDOWN_BLACKLIST = int(os.getenv("AE_COOLDOWN_BLACKLIST", "300"))

# Secondes entre deux alertes pour le même port sensible / même IP (cooldown.py)
COOLDOWN_SENSITIVE = int(os.getenv("AE_COOLDOWN_SENSITIVE", "60"))

# Secondes entre deux alertes scan de ports pour la même IP (cooldown.py)
COOLDOWN_SCAN = int(os.getenv("AE_COOLDOWN_SCAN", "30"))

# ---------------------------------------------------------------------------
# Analyse de fichiers
# ---------------------------------------------------------------------------

# Score de risque minimum pour déclencher une quarantaine automatique (file_monitor.py)
QUARANTINE_THRESHOLD = int(os.getenv("AE_QUARANTINE_THRESHOLD", "70"))

# Taille maximale des fichiers analysés, en octets (file_monitor.py / analyze_file.py)
MAX_FILESIZE = int(os.getenv("AE_MAX_FILESIZE", str(300 * 1024 * 1024)))  # 300 MB

# Bonus de score si VirusTotal dit "malicious" (file_monitor.py)
VT_MALICIOUS_BOOST = int(os.getenv("AE_VT_MALICIOUS_BOOST", "40"))

# Bonus de score si VirusTotal dit "suspicious" (file_monitor.py)
VT_SUSPICIOUS_BOOST = int(os.getenv("AE_VT_SUSPICIOUS_BOOST", "20"))

# ---------------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------------

# Clé API VirusTotal (threat_intel.py) — gratuite sur virustotal.com
VT_API_KEY = os.getenv("VT_API_KEY", "")

# Durée du cache des résultats VT, en secondes (threat_intel.py)
VT_CACHE_TTL = int(os.getenv("AE_VT_CACHE_TTL", "86400"))  # 24h

# Timeout des requêtes HTTP vers VT, en secondes (threat_intel.py)
VT_TIMEOUT = int(os.getenv("AE_VT_TIMEOUT", "6"))

# ---------------------------------------------------------------------------
# API Flask
# ---------------------------------------------------------------------------

# Secret partagé pour protéger les routes d'écriture (app.py)
API_SECRET = os.getenv("API_SECRET", "")

# URL de l'API Flask (client_api.py / control_client.py)
API_BASE_URL = os.getenv("ALERTEXPLAIN_API", "http://127.0.0.1:5000")

# Port d'écoute Flask (app.py)
API_PORT = int(os.getenv("AE_API_PORT", "5000"))

# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------

# Taille maximale du fichier alerts.log avant rotation, en octets
LOG_MAX_BYTES = int(os.getenv("AE_LOG_MAX_BYTES", str(10 * 1024 * 1024)))  # 10 MB

# Nombre de fichiers de backup conservés après rotation
LOG_BACKUP_COUNT = int(os.getenv("AE_LOG_BACKUP_COUNT", "5"))

# ---------------------------------------------------------------------------
# Debug
# ---------------------------------------------------------------------------

DEBUG = os.getenv("ALERTEXPLAIN_DEBUG", "0") == "1"


# ---------------------------------------------------------------------------
# Affichage récap au démarrage (optionnel)
# ---------------------------------------------------------------------------

def print_config():
    print("=" * 50)
    print("  AlertExplain — Configuration active")
    print("=" * 50)
    print(f"  MODE              : {MODE}")
    print(f"  PORT_THRESHOLD    : {PORT_THRESHOLD} ports / {TIME_WINDOW}s")
    print(f"  BLOCK_THRESHOLD   : {BLOCK_THRESHOLD} scans / {BLOCK_WINDOW_SECONDS}s")
    print(f"  SENSITIVE_PORTS   : {sorted(SENSITIVE_PORTS)}")
    print(f"  QUARANTINE_THRESHOLD : {QUARANTINE_THRESHOLD}/100")
    print(f"  VT_API_KEY        : {'✅ configurée' if VT_API_KEY else '❌ absente (désactivé)'}")
    no_auth = "absent (pas d'auth)"
    print(f"  API_SECRET        : {'✅ configuré' if API_SECRET else '⚠️  ' + no_auth}")
    print(f"  API_BASE_URL      : {API_BASE_URL}")
    print(f"  DEBUG             : {DEBUG}")
    print("=" * 50)