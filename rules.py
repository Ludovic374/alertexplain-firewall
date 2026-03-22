# rules.py
from scapy.all import IP, TCP, UDP
from config import SENSITIVE_PORTS, NOISY_UDP_PORTS, NOISY_TCP_PORTS

BLOCKED_IPS = set([])


SENSITIVE_PORTS = set([22, 3389, 445, 135, 139])

NOISY_UDP_PORTS = set([5353, 1900, 137, 138, 67, 68])
NOISY_TCP_PORTS = set([80, 443])

def extract_flow(pkt):
    if not pkt.haslayer(IP):
        return None, None, None, None

    ip = pkt[IP]
    src = ip.src
    dst = ip.dst

    proto = "OTHER"
    dport = None

    if pkt.haslayer(TCP):
        proto = "TCP"
        dport = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        proto = "UDP"
        dport = pkt[UDP].dport

    # Ignorer le trafic local (évite l'auto-détection Flask/main.py)
    if src == "127.0.0.1" or dst == "127.0.0.1":
        return None, None, None, None

    return src, dst, proto, dport

def should_ignore(proto, dport):
    if dport is None:
        return True
    if proto == "UDP" and dport in NOISY_UDP_PORTS:
        return True
    if proto == "TCP" and dport in NOISY_TCP_PORTS:
        return True
    return False