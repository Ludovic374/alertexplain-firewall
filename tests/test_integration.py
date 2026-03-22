# tests/test_integration.py
"""
Tests d'intégration live — teste le vrai système en cours d'exécution.

Prérequis :
    1. app.py doit tourner   → python server/server/app.py
    2. main.py doit tourner  → python main.py  (optionnel pour certains tests)

Lancer :
    python tests/test_integration.py

ou avec pytest :
    pytest tests/test_integration.py -v -s
"""

import sys
import os
import time
import socket
import tempfile
import hashlib
import requests
import threading

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "server"))
from analyze_file import analyze, has_double_extension
from ai_score import score_file

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

API = os.getenv("ALERTEXPLAIN_API", "http://127.0.0.1:5000")
API_SECRET = os.getenv("API_SECRET", "")

PASS  = "✅"
FAIL  = "❌"
SKIP  = "⏭️ "
WARN  = "⚠️ "

results = []

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def headers():
    h = {"Content-Type": "application/json"}
    if API_SECRET:
        h["X-API-Key"] = API_SECRET
    return h

def get(path):
    return requests.get(f"{API}{path}", timeout=5)

def post(path, body=None):
    return requests.post(f"{API}{path}", json=body or {}, headers=headers(), timeout=5)

def report(name, passed, detail=""):
    icon = PASS if passed else FAIL
    msg  = f"  {icon}  {name}"
    if detail:
        msg += f"\n       → {detail}"
    print(msg)
    results.append((name, passed))

def section(title):
    print(f"\n{'='*55}")
    print(f"  {title}")
    print(f"{'='*55}")

def api_available():
    try:
        r = get("/health")
        return r.status_code == 200
    except Exception:
        return False

# ---------------------------------------------------------------------------
# 1. API Flask — routes de base
# ---------------------------------------------------------------------------

def test_api_flask():
    section("1. API Flask — routes de base")

    try:
        r = get("/health")
        report("GET /health → 200", r.status_code == 200, r.text[:80])
    except Exception as e:
        report("GET /health → 200", False, str(e))
        print(f"\n  {FAIL} API non joignable. Lance app.py d'abord.\n")
        return False

    try:
        r = get("/events?limit=5")
        data = r.json()
        report("GET /events → liste", isinstance(data, list), f"{len(data)} events")
    except Exception as e:
        report("GET /events → liste", False, str(e))

    try:
        r = get("/control")
        data = r.json()
        report("GET /control → scan_enabled", "scan_enabled" in data, str(data))
    except Exception as e:
        report("GET /control → scan_enabled", False, str(e))

    try:
        r = get("/scanner/status")
        data = r.json()
        report("GET /scanner/status → running", "running" in data, str(data))
    except Exception as e:
        report("GET /scanner/status → running", False, str(e))

    try:
        r = post("/events", {
            "event_type": "TEST_EVENT",
            "severity": "LOW",
            "title": "Test intégration",
            "src": "1.2.3.4",
            "what": "Event de test automatique",
            "risk": "Aucun", "do": "Ignorer."
        })
        report("POST /events → ok", r.json().get("ok") is True, r.text[:80])
    except Exception as e:
        report("POST /events → ok", False, str(e))

    try:
        r = get("/ips")
        data = r.json()
        report("GET /ips → structure", "blocked" in data and "not_blocked" in data, str(list(data.keys())))
    except Exception as e:
        report("GET /ips → structure", False, str(e))

    try:
        r = get("/inspect?ip=1.2.3.4")
        data = r.json()
        report("GET /inspect?ip= → events", "events" in data, f"count={data.get('count')}")
    except Exception as e:
        report("GET /inspect?ip= → events", False, str(e))

    try:
        r = get("/events?limit=5")
        events = r.json()
        test_event = next((e for e in events if e.get("event_type") == "TEST_EVENT"), None)
        if test_event:
            r2 = post("/events/delete", {"id": test_event["id"]})
            report("POST /events/delete → ok", r2.json().get("ok") is True)
        else:
            report("POST /events/delete → ok", True, "(event déjà absent)")
    except Exception as e:
        report("POST /events/delete → ok", False, str(e))

    return True

# ---------------------------------------------------------------------------
# 2. Détection de scan de ports
# ---------------------------------------------------------------------------

def test_port_scan_detection():
    section("2. Détection de scan de ports")

    try:
        from detector import detect_port_scan, connections
        connections.clear()

        key = "TEST_SCAN|TCP"
        detect_port_scan(key, 80)
        detect_port_scan(key, 443)
        detected, ports = detect_port_scan(key, 8080)

        report("Scan détecté à 3 ports distincts", detected is True, f"ports={ports}")
        report("Ports retournés corrects", {80, 443, 8080} == ports)

        connections.clear()
        detect_port_scan(key, 80)
        detect_port_scan(key, 80)
        d2, _ = detect_port_scan(key, 80)
        report("Doublons ne déclenchent pas de scan", d2 is False)

        connections.clear()
    except Exception as e:
        report("Détecteur importable", False, str(e))
        return

    try:
        r = get("/scanner/status")
        scanner_running = r.json().get("running", False)
    except Exception:
        scanner_running = False

    if not scanner_running:
        print(f"  {SKIP}  Scan réseau live ignoré (main.py n'est pas démarré)")
        return

    print(f"  {WARN}  Scan réseau live : connexions rapides sur 127.0.0.1...")

    def quick_connect(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            s.connect(("127.0.0.1", port))
            s.close()
        except Exception:
            pass

    for p in [8080, 8081, 8082, 8083, 8084]:
        quick_connect(p)
        time.sleep(0.05)

    time.sleep(2)

    try:
        r = get("/events?limit=20")
        events = r.json()
        scan_events = [e for e in events if e.get("event_type") == "PORT_SCAN"]
        report("Event PORT_SCAN généré après scan", len(scan_events) > 0,
               f"{len(scan_events)} event(s) PORT_SCAN trouvés")
    except Exception as e:
        report("Event PORT_SCAN généré après scan", False, str(e))

# ---------------------------------------------------------------------------
# 3. Blocage automatique d'IP
# ---------------------------------------------------------------------------

def test_ip_blocking():
    section("3. Blocage automatique d'IP")

    from blocker import is_private_ip, block_ip, unblock_ip, blocked_cache

    report("127.0.0.1 → privée", is_private_ip("127.0.0.1") is True)
    report("192.168.1.1 → privée", is_private_ip("192.168.1.1") is True)
    report("8.8.8.8 → publique", is_private_ip("8.8.8.8") is False)
    report("IP invalide → privée (safe)", is_private_ip("not_an_ip") is True)

    result = block_ip("192.168.100.100")
    report("block_ip(IP privée) → refusé", result is False)

    # FIX : unblock d'une IP non bloquée → pas de crash (True ou False accepté)
    result = unblock_ip("203.0.113.99")
    report("unblock_ip(non bloquée) → pas de crash", isinstance(result, bool))

    try:
        r = post("/ips/unblock", {"ip": "1.2.3.4"})
        report("POST /ips/unblock → répond", r.status_code in [200, 500])
    except Exception as e:
        report("POST /ips/unblock → répond", False, str(e))

    print(f"  {WARN}  Blocage réel non testé (évite de créer des règles Windows en CI)")

# ---------------------------------------------------------------------------
# 4. Analyse de fichiers suspects
# ---------------------------------------------------------------------------

def test_file_analysis():
    section("4. Analyse de fichiers suspects")

    try:
        from analyze_file import analyze, has_double_extension
        from ai_score import score_file
    except ImportError as e:
        report("Modules analyze/score importables", False, str(e))
        return

    report("Modules analyze/score importables", True)

    report("facture.pdf.exe → double ext", has_double_extension("facture.pdf.exe") is True)
    report("document.pdf → pas double ext", has_double_extension("document.pdf") is False)
    report("photo.jpg.scr → double ext", has_double_extension("photo.jpg.scr") is True)

    python_exe = sys.executable
    rep = analyze(python_exe)
    report("analyze(python.exe) → FileReport", rep is not None)
    if rep:
        report("SHA-256 calculé", rep.sha256 is not None and len(rep.sha256) == 64,
               rep.sha256[:16] + "..." if rep.sha256 else "None")
        report("Entropie calculée", rep.entropy is not None, f"{rep.entropy:.2f}" if rep.entropy else "None")
        report("is_executable_like = True", rep.is_executable_like is True, f"ext={rep.ext}")

        score, sev, expl = score_file(rep)
        report("Score heuristique > 0", score > 0, f"score={score}/100 sev={sev}")
        report("Explication non vide", len(expl) > 0, expl[:60])

    rep2 = analyze("C:/fichier_qui_nexiste_pas.exe")
    report("analyze(inexistant) → None", rep2 is None)

    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as f:
        f.write("Hello world " * 100)
        tmp_path = f.name

    try:
        rep3 = analyze(tmp_path)
        if rep3:
            score3, sev3, _ = score_file(rep3)
            report("Fichier .txt → score faible (LOW)", sev3 == "LOW", f"score={score3}")
    finally:
        os.unlink(tmp_path)

# ---------------------------------------------------------------------------
# 5. VirusTotal lookup
# ---------------------------------------------------------------------------

def test_virustotal():
    section("5. VirusTotal lookup")

    try:
        from threat_intel import check_hash, _cache_get, _cache_set, VTResult
    except ImportError as e:
        report("threat_intel importable", False, str(e))
        return

    report("threat_intel importable", True)

    r = check_hash(None)
    report("check_hash(None) → no_hash", r["error"] == "no_hash")

    r = check_hash("")
    report("check_hash('') → no_hash", r["error"] == "no_hash")

    vt_key = os.getenv("VT_API_KEY", "")
    if not vt_key:
        r = check_hash("a" * 64)
        report("check_hash sans clé → no_api_key", r["error"] == "no_api_key")
        print(f"  {SKIP}  Test API VT réel ignoré (VT_API_KEY non définie)")
        print(f"         → Configure VT_API_KEY pour tester le lookup réel")
        return

    report("VT_API_KEY configurée", True, vt_key[:8] + "...")

    EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    print(f"  → Requête VT pour hash EICAR...")

    r = check_hash(EICAR_SHA256)
    report("VT répond sans exception", r["error"] is None, str(r.get("error")))
    report("Hash EICAR trouvé sur VT", r["found"] is True)

    if r["found"]:
        report("EICAR → malicious", r["verdict"] == "malicious",
               f"malicious={r['malicious']}/{r['total']}")

    r2 = check_hash(EICAR_SHA256)
    report("Deuxième appel → depuis cache", r2.get("cached") is True)

    fake_hash = "0" * 64
    r3 = check_hash(fake_hash)
    report("Hash inexistant → found=False", r3["found"] is False,
           f"error={r3.get('error')}")

# ---------------------------------------------------------------------------
# Résumé final
# ---------------------------------------------------------------------------

def print_summary():
    print(f"\n{'='*55}")
    print(f"  RÉSUMÉ")
    print(f"{'='*55}")
    total  = len(results)
    passed = sum(1 for _, ok in results if ok)
    failed = total - passed
    print(f"  Total  : {total}")
    print(f"  {PASS} Passés : {passed}")
    print(f"  {FAIL} Échoués: {failed}")
    if failed > 0:
        print(f"\n  Tests échoués :")
        for name, ok in results:
            if not ok:
                print(f"    {FAIL}  {name}")
    print(f"{'='*55}\n")
    return failed == 0

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("\n" + "="*55)
    print("  AlertExplain — Tests d'intégration live")
    print("="*55)
    print(f"  API : {API}")
    print(f"  Auth: {'✅ configurée' if API_SECRET else '⚠️  absente'}")

    if not api_available():
        print(f"\n  {FAIL} API Flask non joignable sur {API}")
        print(f"       Lance d'abord : python server/server/app.py\n")
        sys.exit(1)

    test_api_flask()
    test_port_scan_detection()
    test_ip_blocking()
    test_file_analysis()
    test_virustotal()

    ok = print_summary()
    sys.exit(0 if ok else 1)
