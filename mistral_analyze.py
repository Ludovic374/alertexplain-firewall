# mistral_analyze.py
"""
Analyse approfondie des paquets suspects via Mistral AI.
- Deep Packet Inspection : extrait et analyse le payload brut
- Appelé uniquement sur les événements HIGH pour limiter les requêtes
- Graceful degradation : si Mistral est indisponible, retourne None sans crasher
"""

from __future__ import annotations
import os
import json
import requests
from typing import Optional

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

MISTRAL_API_KEY = os.getenv("MISTRAL_API_KEY", "")
MISTRAL_URL     = "https://api.mistral.ai/v1/chat/completions"
MISTRAL_MODEL   = "mistral-small-latest"   # gratuit et rapide
TIMEOUT         = 8   # secondes max


# ---------------------------------------------------------------------------
# Deep Packet Inspection — extraction du payload
# ---------------------------------------------------------------------------

def extract_payload_info(pkt) -> dict:
    """
    Extrait les informations utiles du payload d'un paquet Scapy.
    Retourne un dict avec les infos de couche applicative.
    """
    info = {}

    try:
        from scapy.all import IP, TCP, UDP, Raw, DNS, DNSQR, HTTP

        if pkt.haslayer("Raw"):
            raw = bytes(pkt["Raw"].load)
            info["payload_length"] = len(raw)
            info["payload_hex"]    = raw[:32].hex()   # premiers 32 octets en hex
            info["payload_ascii"]  = "".join(
                chr(b) if 32 <= b < 127 else "." for b in raw[:64]
            )

            # Détecter HTTP
            if raw.startswith((b"GET ", b"POST ", b"HTTP/", b"PUT ", b"DELETE ")):
                lines = raw.decode("utf-8", errors="ignore").split("\r\n")
                info["protocol_detected"] = "HTTP"
                info["http_first_line"]   = lines[0] if lines else ""

            # Détecter SSH
            elif raw.startswith(b"SSH-"):
                info["protocol_detected"] = "SSH"
                info["ssh_banner"]         = raw[:32].decode("utf-8", errors="ignore")

            # Détecter TLS/HTTPS
            elif len(raw) > 5 and raw[0] == 0x16 and raw[1] == 0x03:
                info["protocol_detected"] = "TLS/HTTPS"
                info["tls_version"]        = f"0x{raw[1]:02x}{raw[2]:02x}"

            # Détecter FTP
            elif raw.startswith((b"220 ", b"USER ", b"PASS ", b"230 ")):
                info["protocol_detected"] = "FTP"
                info["ftp_command"]        = raw[:32].decode("utf-8", errors="ignore").strip()

            # Détecter SMB
            elif len(raw) > 4 and raw[4:8] == b"\xffSMB" or raw[:4] == b"\xfeSMB":
                info["protocol_detected"] = "SMB"

            else:
                info["protocol_detected"] = "UNKNOWN"

        # DNS
        if pkt.haslayer("DNS"):
            dns = pkt["DNS"]
            if pkt.haslayer("DNSQR"):
                info["protocol_detected"] = "DNS"
                info["dns_query"]          = pkt["DNSQR"].qname.decode("utf-8", errors="ignore")

        # Flags TCP
        if pkt.haslayer("TCP"):
            flags = pkt["TCP"].flags
            flag_str = []
            if flags & 0x02: flag_str.append("SYN")
            if flags & 0x10: flag_str.append("ACK")
            if flags & 0x01: flag_str.append("FIN")
            if flags & 0x04: flag_str.append("RST")
            if flags & 0x08: flag_str.append("PSH")
            if flags & 0x20: flag_str.append("URG")
            info["tcp_flags"] = "+".join(flag_str) if flag_str else "NONE"

    except Exception as e:
        info["extraction_error"] = str(e)

    return info


# ---------------------------------------------------------------------------
# Mistral AI — analyse du paquet
# ---------------------------------------------------------------------------

def analyze_packet_with_mistral(
    event_type: str,
    context: dict,
    payload_info: dict | None = None
) -> Optional[str]:
    """
    Envoie les informations du paquet à Mistral AI pour analyse approfondie.
    Retourne une chaîne d'analyse ou None si Mistral est indisponible.

    Paramètres :
        event_type   : "PORT_SCAN", "SENSITIVE_PORT", "BLOCKED_IP", etc.
        context      : dict avec src, dst, proto, dport, ports
        payload_info : dict retourné par extract_payload_info()
    """
    if not MISTRAL_API_KEY:
        return None

    # Construction du prompt
    src        = context.get("src", "?")
    dst        = context.get("dst", "?")
    proto      = context.get("proto", "?")
    dport      = context.get("dport", "?")
    ports      = context.get("ports", set())
    ports_list = sorted(list(ports)) if ports else []

    prompt_parts = [
        f"Tu es un expert en cybersécurité. Analyse ce trafic réseau suspect détecté par un pare-feu.",
        f"",
        f"ÉVÉNEMENT : {event_type}",
        f"IP source  : {src}",
        f"IP dest    : {dst}",
        f"Protocole  : {proto}",
    ]

    if dport:
        prompt_parts.append(f"Port ciblé : {dport}")
    if ports_list:
        prompt_parts.append(f"Ports scannés : {ports_list}")

    if payload_info:
        proto_detected = payload_info.get("protocol_detected")
        if proto_detected:
            prompt_parts.append(f"Protocole détecté dans le payload : {proto_detected}")
        if payload_info.get("http_first_line"):
            prompt_parts.append(f"Requête HTTP : {payload_info['http_first_line']}")
        if payload_info.get("dns_query"):
            prompt_parts.append(f"Requête DNS : {payload_info['dns_query']}")
        if payload_info.get("ssh_banner"):
            prompt_parts.append(f"Bannière SSH : {payload_info['ssh_banner']}")
        if payload_info.get("tcp_flags"):
            prompt_parts.append(f"Flags TCP : {payload_info['tcp_flags']}")
        if payload_info.get("payload_ascii"):
            prompt_parts.append(f"Contenu (ASCII) : {payload_info['payload_ascii'][:80]}")

    prompt_parts += [
        f"",
        f"Réponds en 3 lignes maximum en français :",
        f"1. NATURE : Ce que fait exactement ce paquet",
        f"2. RISQUE : Le niveau de danger et pourquoi",
        f"3. ACTION : Ce qu'il faut faire",
    ]

    prompt = "\n".join(prompt_parts)

    try:
        response = requests.post(
            MISTRAL_URL,
            headers={
                "Authorization": f"Bearer {MISTRAL_API_KEY}",
                "Content-Type":  "application/json",
            },
            json={
                "model":       MISTRAL_MODEL,
                "messages":    [{"role": "user", "content": prompt}],
                "max_tokens":  200,
                "temperature": 0.3,
            },
            timeout=TIMEOUT,
        )
        response.raise_for_status()
        data    = response.json()
        content = data["choices"][0]["message"]["content"].strip()
        return content

    except requests.exceptions.Timeout:
        return None
    except requests.exceptions.HTTPError as e:
        print(f"[MISTRAL] HTTP error: {e}")
        return None
    except Exception as e:
        print(f"[MISTRAL] Exception: {e}")
        return None


# ---------------------------------------------------------------------------
# Fonction principale — DPI + Mistral combinés
# ---------------------------------------------------------------------------

def deep_analyze(event_type: str, context: dict, pkt=None) -> str | None:
    """
    Point d'entrée principal.
    Extrait le payload si un paquet est fourni, puis appelle Mistral.

    Utilisation dans main.py :
        from mistral_analyze import deep_analyze
        analysis = deep_analyze("PORT_SCAN", context, pkt)
        if analysis:
            print("[MISTRAL]", analysis)
    """
    payload_info = None
    if pkt is not None:
        try:
            payload_info = extract_payload_info(pkt)
        except Exception:
            pass

    return analyze_packet_with_mistral(event_type, context, payload_info)
