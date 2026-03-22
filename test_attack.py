import socket
import time

TARGET = "203.0.113.1" # ou ton routeur: "192.168.1.1"
print("[TEST] Scan (socket connect) en cours...")

for port in range(20, 31):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2)
        s.connect((TARGET, port))
        s.close()
    except Exception:
        pass
    time.sleep(0.1)

print("[TEST] Scan terminé")
