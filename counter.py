from collections import defaultdict, deque
from time import time
from config import BLOCK_THRESHOLD, BLOCK_WINDOW_SECONDS

WINDOW_SECONDS = 120   # 2 minutes
THRESHOLD = 2          # 2 scans confirmés => blocage

events = defaultdict(deque)

def record_scan(key: str) -> int:
    now = time()
    q = events[key]
    q.append(now)

    # Nettoyage de la fenêtre
    while q and (now - q[0] > WINDOW_SECONDS):
        q.popleft()

    return len(q)

def should_block(key: str) -> bool:
    return record_scan(key) >= THRESHOLD
