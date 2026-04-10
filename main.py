# main.py
import os
DEBUG = os.getenv("ALERTEXPLAIN_DEBUG", "0") == "1"

from logging.handlers import RotatingFileHandler
import logging

import argparse
from threading import Thread
from datetime import datetime

from scapy.all import sniff, get_if_list

from control_client import is_scan_enabled
from file_monitor import run_file_monitor
from cooldown import allow
from client_api import send_event

from rules import extract_flow, should_ignore, BLOCKED_IPS, SENSITIVE_PORTS
from detector import detect_port_scan
from counter import should_block
from blocker import block_ip, load_blocked_cache_from_windows
from explain import explain
from port_explanations import explain_port, explain_ports_list
from config import MODE, DEBUG, print_config
from mistral_analyze import deep_analyze

try:
    from notifier import notify
except Exception:
    notify = None


# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------

def setup_logger():
    os.makedirs("logs", exist_ok=True)
    handler = RotatingFileHandler(
        "logs/alerts.log",
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger = logging.getLogger("alertexplain")
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    return logger

LOGGER = setup_logger()


# ---------------------------------------------------------------------------
# Interface auto-detection
# ---------------------------------------------------------------------------

def find_active_iface() -> str | None:
    from scapy.all import sniff as _sniff
    ifaces = get_if_list()
    print(f"[IFACE] {len(ifaces)} interfaces détectées.")
    for iface in ifaces:
        try:
            pkts = _sniff(iface=iface, store=True, timeout=2, count=1, filter="ip")
            if pkts:
                print(f"[IFACE] Interface active trouvée : {iface}")
                return iface
        except Exception:
            continue
    print("[IFACE] ⚠️  Aucune interface active détectée automatiquement.")
    return None


# ---------------------------------------------------------------------------
# Startup: reload BLOCKED_IPS from Windows Firewall
# ---------------------------------------------------------------------------

def reload_blocked_ips():
    import re, subprocess
    RULE_PREFIX = "AlertExplain_Block_"
    try:
        res = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
            capture_output=True, text=True, timeout=10
        )
        if res.returncode != 0:
            print("[STARTUP] Impossible de lire les règles Windows Firewall.")
            return
        pattern = re.compile(
            rf"Rule Name:\s+{re.escape(RULE_PREFIX)}([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)_(IN|OUT)"
        )
        ips = set()
        for line in res.stdout.splitlines():
            m = pattern.search(line)
            if m:
                ips.add(m.group(1))
        BLOCKED_IPS.update(ips)
        load_blocked_cache_from_windows(list(ips))
        print(f"[STARTUP] {len(ips)} IPs bloquées rechargées depuis Windows Firewall.")
    except Exception as e:
        print(f"[STARTUP] reload_blocked_ips exception: {e}")


# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------

def build_port_context_single(dport: int) -> dict:
    info = explain_port(dport)
    return {
        "service_name":  info["service"],
        "service_desc":  info["description"],
        "likely_target": info["target"],
        "service_risk":  info["risk"],
    }


def build_port_context_multi(ports) -> dict:
    details  = explain_ports_list(ports)
    services = ", ".join([f"{x['port']}={x['service']}" for x in details])
    targets  = " | ".join(sorted(set(x["target"] for x in details)))
    risks    = " | ".join(sorted(set(x["risk"]   for x in details)))
    return {
        "services_summary": services,
        "targets_summary":  targets,
        "risks_summary":    risks,
    }


def enrich_info_with_port_analysis(info: dict, event_type: str, context: dict) -> dict:
    info = dict(info)
    if event_type == "SENSITIVE_PORT" and context.get("dport") is not None:
        extra = build_port_context_single(context["dport"])
        info["what"] = (
            f"{info.get('what','')} | Service: {extra['service_name']} "
            f"({extra['service_desc']}) | Cible probable: {extra['likely_target']}"
        )
        info["risk"] = f"{info.get('risk','')} | Risque service: {extra['service_risk']}"
        info["do"]   = f"{info.get('do','')} | Vérifier si ce service doit être exposé."
    elif event_type == "PORT_SCAN" and context.get("ports"):
        extra = build_port_context_multi(context["ports"])
        info["what"] = (
            f"{info.get('what','')} | Services visés: {extra['services_summary']} | "
            f"Ressources visées: {extra['targets_summary']}"
        )
        info["risk"] = f"{info.get('risk','')} | Risques potentiels: {extra['risks_summary']}"
        info["do"]   = f"{info.get('do','')} | Identifier si ces services sont utilisés sur le poste."
    return info


def log_alert(event_type: str, context: dict):
    info = explain(event_type, context)
    info = enrich_info_with_port_analysis(info, event_type, context)

    ts      = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sev     = info.get("severity", "LOW")
    title   = info.get("title", "Alerte")
    details = info.get("details", "")

    line1 = f"[{ts}] [{sev}] {title}"
    line2 = f"   -> {details}" if details else ""
    line3 = f"   WHAT: {info.get('what','')}"
    line4 = f"   RISK: {info.get('risk','')}"
    line5 = f"   DO:   {info.get('do','')}"

    print(line1)
    if line2: print(line2)
    print(line3)
    print(line4)
    print(line5)

    payload = {
        "event_type": event_type,
        "severity":   sev,
        "title":      title,
        "src":        context.get("src"),
        "dst":        context.get("dst"),
        "proto":      context.get("proto"),
        "dport":      context.get("dport"),
        "ports":      ",".join(map(str, context.get("ports", []))) if context.get("ports") else None,
        "what":       info.get("what", ""),
        "risk":       info.get("risk", ""),
        "do":         info.get("do", ""),
    }

    try:
        ok_api = send_event(payload)
        if not ok_api:
            print("[WARN] API send failed (status != 200)")
    except Exception as e:
        print(f"[WARN] API send exception: {e}")

    if notify is not None:
        try:
            notify(f"{sev} - {title}", info.get("what", "Alerte réseau détectée"))
        except Exception as e:
            print(f"[WARN] Notification failed: {e}")

    LOGGER.info(line1)
    if line2: LOGGER.info(line2)
    LOGGER.info(line3)
    LOGGER.info(line4)
    LOGGER.info(line5 + "\n")


# ---------------------------------------------------------------------------
# Mistral async — Deep Packet Inspection
# ---------------------------------------------------------------------------

def _run_mistral_async(event_type: str, context: dict, pkt):
    """
    Lance l'analyse Mistral dans un thread séparé pour ne pas
    bloquer la capture réseau (Mistral prend ~1-2 secondes).
    """
    def _analyze():
        try:
            analysis = deep_analyze(event_type, context, pkt)
            if analysis:
                src = context.get("src", "?")
                print(f"\n[MISTRAL] {event_type} — {src}")
                print(f"          {analysis}\n")

                send_event({
                    "event_type": "MISTRAL_ANALYSIS",
                    "severity":   "HIGH",
                    "title":      f"Analyse IA — {event_type}",
                    "src":        src,
                    "dst":        context.get("dst"),
                    "proto":      context.get("proto"),
                    "dport":      context.get("dport"),
                    "what":       analysis,
                    "risk":       "Analyse Deep Packet Inspection par Mistral AI",
                    "do":         "Voir l'analyse complète dans le dashboard.",
                })
        except Exception as e:
            print(f"[MISTRAL] Error in async analysis: {e}")

    Thread(target=_analyze, daemon=True).start()


# ---------------------------------------------------------------------------
# Packet handler
# ---------------------------------------------------------------------------

def handle_packet(pkt):
    if not is_scan_enabled():
        if DEBUG and allow("SCAN_OFF_MSG", 3):
            print("[SCAN OFF] packet ignored")
        return

    src, dst, proto, dport = extract_flow(pkt)

    if DEBUG:
        print("PKT", pkt.summary())

    if src is None:
        return

    if DEBUG:
        print("[DEBUG_FLOW]", proto, src, "->", dst, "dport=", dport)

    if dport is None:
        return

    if should_ignore(proto, dport):
        return

    if src in BLOCKED_IPS:
        if allow(f"BLACKLIST:{src}", 300):
            context = {"src": src, "dst": dst, "proto": proto}
            log_alert("BLOCKED_IP", context)
            _run_mistral_async("BLOCKED_IP", context, pkt)
        return

    if dport in SENSITIVE_PORTS:
        if allow(f"SENSITIVE:{src}:{dport}:{proto}", 60):
            context = {"src": src, "dst": dst, "dport": dport, "proto": proto}
            log_alert("SENSITIVE_PORT", context)
            _run_mistral_async("SENSITIVE_PORT", context, pkt)
        return

    key = f"{src}|{proto}"
    scan_detected, ports = detect_port_scan(key, dport)

    if scan_detected and ports:
        if allow(f"PORT_SCAN:{key}", 30):
            context = {"src": src, "dst": dst, "ports": ports, "proto": proto}
            log_alert("PORT_SCAN", context)
            _run_mistral_async("PORT_SCAN", context, pkt)

        if MODE == "IPS" and should_block(key):
            ok = block_ip(src)
            if ok and allow(f"BLOCKED:{src}", 300):
                log_alert("BLOCKED_IP", {"src": src, "dst": dst, "proto": proto})
        return


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="AlertExplain Firewall")
    parser.add_argument(
        "--iface", "-i",
        default=None,
        help="Interface réseau Scapy. Si absent, détection automatique."
    )
    args = parser.parse_args()

    print("✅ Firewall Alert & Explain - Mode surveillance")
    print("⚠️  Lance VS Code en ADMIN sinon sniff peut échouer.")

    reload_blocked_ips()

    iface = args.iface
    if iface is None:
        print("🔍 Détection automatique de l'interface réseau...")
        iface = find_active_iface()

    if iface:
        print(f"📡 Capture sur : {iface}")
    else:
        print("📡 Capture sur toutes les interfaces (fallback).")

    print("🗂️  Module fichiers: ON (Downloads/Desktop)")
    t = Thread(target=run_file_monitor, daemon=True)
    t.start()

    print("🤖 Mistral AI: ON (Deep Packet Inspection)")
    print("Capture en cours... (Ctrl+C pour arrêter)\n")

    sniff_kwargs = dict(prn=handle_packet, store=False, filter="ip")
    if iface:
        sniff_kwargs["iface"] = iface

    sniff(**sniff_kwargs)


if __name__ == "__main__":
    main()