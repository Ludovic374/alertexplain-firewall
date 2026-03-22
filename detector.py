from collections import defaultdict
from time import time
from config import PORT_THRESHOLD, TIME_WINDOW

TIME_WINDOW = 30
PORT_THRESHOLD = 3

connections = defaultdict(list)

def detect_port_scan(flow_key, dst_port):
    now = time()

    connections[flow_key] = [
        (t, p) for (t, p) in connections[flow_key]
        if now - t <= TIME_WINDOW
    ]

    connections[flow_key].append((now, dst_port))

    unique_ports = {p for (_, p) in connections[flow_key]}

    if len(unique_ports) >= PORT_THRESHOLD:
        return True, unique_ports

    return False, None
