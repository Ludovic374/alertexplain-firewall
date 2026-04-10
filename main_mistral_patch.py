# ============================================================
# Ajoute cet import en haut de main.py avec les autres imports
# ============================================================
from mistral_analyze import deep_analyze


# ============================================================
# Remplace la fonction handle_packet dans main.py par celle-ci
# ============================================================

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

    if dport is None:
        return

    if should_ignore(proto, dport):
        return

    if src in BLOCKED_IPS:
        if allow(f"BLACKLIST:{src}", 300):
            context = {"src": src, "dst": dst, "proto": proto}
            log_alert("BLOCKED_IP", context)

            # Analyse Mistral pour les IPs déjà bloquées
            _run_mistral_async("BLOCKED_IP", context, pkt)
        return

    if dport in SENSITIVE_PORTS:
        if allow(f"SENSITIVE:{src}:{dport}:{proto}", 60):
            context = {"src": src, "dst": dst, "dport": dport, "proto": proto}
            log_alert("SENSITIVE_PORT", context)

            # Analyse Mistral pour les ports sensibles (HIGH risk)
            _run_mistral_async("SENSITIVE_PORT", context, pkt)
        return

    key = f"{src}|{proto}"
    scan_detected, ports = detect_port_scan(key, dport)

    if scan_detected and ports:
        if allow(f"PORT_SCAN:{key}", 30):
            context = {"src": src, "dst": dst, "ports": ports, "proto": proto}
            log_alert("PORT_SCAN", context)

            # Analyse Mistral pour les scans de ports
            _run_mistral_async("PORT_SCAN", context, pkt)

        if MODE == "IPS" and should_block(key):
            ok = block_ip(src)
            if ok and allow(f"BLOCKED:{src}", 300):
                log_alert("BLOCKED_IP", {"src": src, "dst": dst, "proto": proto})
        return


def _run_mistral_async(event_type: str, context: dict, pkt):
    """
    Lance l'analyse Mistral dans un thread séparé pour ne pas
    bloquer la capture réseau (Mistral prend ~1-2 secondes).
    """
    from threading import Thread

    def _analyze():
        try:
            analysis = deep_analyze(event_type, context, pkt)
            if analysis:
                src = context.get("src", "?")
                print(f"\n[MISTRAL] {event_type} — {src}")
                print(f"          {analysis}\n")

                # Envoyer l'analyse Mistral comme event séparé dans le dashboard
                from client_api import send_event
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
