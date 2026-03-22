# cooldown.py
from time import time

_last = {}

def allow(event_key: str, cooldown_s: int) -> bool:
    """
    Retourne True si on peut émettre l'alerte (cooldown expiré),
    sinon False.
    """
    now = time()
    last = _last.get(event_key, 0)
    if now - last >= cooldown_s:
        _last[event_key] = now
        return True
    return False
