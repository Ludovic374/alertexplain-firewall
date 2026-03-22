import subprocess
import ipaddress

RULE_PREFIX = "AlertExplain_Block_"

# Cache pour éviter de bloquer/débloquer inutilement
blocked_cache = set()


def is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return True


def rule_exists(rule_name: str) -> bool:
    res = subprocess.run(
        ["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name}"],
        capture_output=True, text=True
    )
    return (res.returncode == 0) and ("No rules match" not in res.stdout)


def block_ip(ip: str) -> bool:
    """
    Bloque une IP entrante et sortante via Windows Defender Firewall.
    Retourne True si succès ou déjà bloquée, False sinon.
    """
    if is_private_ip(ip):
        return False

    if ip in blocked_cache:
        return True

    rule_in  = f"{RULE_PREFIX}{ip}_IN"
    rule_out = f"{RULE_PREFIX}{ip}_OUT"

    if rule_exists(rule_in) and rule_exists(rule_out):
        blocked_cache.add(ip)
        return True

    cmd_in = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_in}", "dir=in", "action=block",
        f"remoteip={ip}", "enable=yes"
    ]
    cmd_out = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_out}", "dir=out", "action=block",
        f"remoteip={ip}", "enable=yes"
    ]

    try:
        res_in  = subprocess.run(cmd_in,  capture_output=True, text=True)
        res_out = subprocess.run(cmd_out, capture_output=True, text=True)

        if res_in.returncode == 0 and res_out.returncode == 0:
            blocked_cache.add(ip)
            return True
        else:
            print(f"[BLOCKER] block_ip failed: IN={res_in.stderr.strip()} OUT={res_out.stderr.strip()}")
            return False

    except Exception as e:
        print(f"[BLOCKER] block_ip exception: {e}")
        return False


def unblock_ip(ip: str) -> bool:
    """
    Supprime les règles de blocage IN/OUT pour une IP donnée.
    Retourne True si les deux règles ont été supprimées (ou n'existaient pas), False si erreur.
    """
    if is_private_ip(ip):
        return False

    rule_in  = f"{RULE_PREFIX}{ip}_IN"
    rule_out = f"{RULE_PREFIX}{ip}_OUT"

    success = True

    for rule_name in (rule_in, rule_out):
        if not rule_exists(rule_name):
            continue  # déjà absent, pas une erreur
        cmd = [
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={rule_name}"
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode != 0:
                print(f"[BLOCKER] unblock_ip failed for {rule_name}: {res.stderr.strip()}")
                success = False
        except Exception as e:
            print(f"[BLOCKER] unblock_ip exception for {rule_name}: {e}")
            success = False

    if success:
        blocked_cache.discard(ip)

    return success


def load_blocked_cache_from_windows(blocked_ips: list[str]):
    """
    Pré-remplit blocked_cache depuis la liste d'IPs déjà bloquées dans Windows Firewall.
    À appeler au démarrage avec le résultat de list_blocked_ips_from_windows().
    """
    for ip in blocked_ips:
        blocked_cache.add(ip)
    if blocked_ips:
        print(f"[BLOCKER] {len(blocked_ips)} IPs pré-chargées dans blocked_cache.")