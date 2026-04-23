# app.py
import sqlite3
import subprocess
import re
import os
import html
from flask import Flask, request, jsonify, render_template_string, abort
from datetime import datetime
from db import init_db, insert_event, delete_event, clear_events, set_scan_state, get_scan_state, DB_PATH
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from blocker import unblock_ip
app = Flask(__name__)
from flask_cors import CORS
CORS(app, origins=["http://localhost:5173"])
RULE_PREFIX = "AlertExplain_Block_"

API_SECRET = os.getenv("API_SECRET", "")

import sys
import subprocess as _sp
from pathlib import Path as _Path

_MAIN_PY = str(_Path(__file__).parent.parent.parent / "main.py")
_scanner_proc = None


def _scanner_running() -> bool:
    global _scanner_proc
    return _scanner_proc is not None and _scanner_proc.poll() is None


@app.post("/scanner/start")
def scanner_start():
    global _scanner_proc
    check_auth()
    if _scanner_running():
        return jsonify({"ok": True, "status": "already_running", "pid": _scanner_proc.pid})
    try:
        _scanner_proc = _sp.Popen(
            [sys.executable, _MAIN_PY],
            stdout=open("logs/main.stdout.log", "a"),
            stderr=open("logs/main.stderr.log", "a"),
        )
        set_scan_state(True)
        return jsonify({"ok": True, "status": "started", "pid": _scanner_proc.pid})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.post("/scanner/stop")
def scanner_stop():
    global _scanner_proc
    check_auth()
    set_scan_state(False)
    if not _scanner_running():
        return jsonify({"ok": True, "status": "already_stopped"})
    try:
        _scanner_proc.terminate()
        _scanner_proc.wait(timeout=5)
    except Exception:
        try:
            _scanner_proc.kill()
        except Exception:
            pass
    _scanner_proc = None
    return jsonify({"ok": True, "status": "stopped"})


@app.get("/scanner/status")
def scanner_status():
    running = _scanner_running()
    return jsonify({
        "running": running,
        "pid": _scanner_proc.pid if running else None,
        "scan_enabled": get_scan_state(),
    })


def check_auth():
    if not API_SECRET:
        return
    key = request.headers.get("X-API-Key", "")
    if key != API_SECRET:
        abort(401)


def esc(value) -> str:
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


@app.after_request
def no_cache(resp):
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"]        = "no-cache"
    resp.headers["Expires"]       = "0"
    return resp


def list_blocked_ips_from_windows():
    try:
        res = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
            capture_output=True, text=True, timeout=8
        )
        if res.returncode != 0:
            return {"ok": False, "ips": [], "error": res.stderr[:300]}
        ips     = set()
        pattern = re.compile(
            rf"Rule Name:\s+{re.escape(RULE_PREFIX)}([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)_(IN|OUT)"
        )
        for line in res.stdout.splitlines():
            m = pattern.search(line)
            if m:
                ips.add(m.group(1))
        return {"ok": True, "ips": sorted(ips), "error": None}
    except Exception as e:
        return {"ok": False, "ips": [], "error": str(e)}


@app.get("/health")
def health():
    return jsonify({"ok": True})


@app.get("/events")
def get_events():
    limit = int(request.args.get("limit", 50))
    conn  = sqlite3.connect(DB_PATH)
    cur   = conn.cursor()
    cur.execute("""
        SELECT id, ts, event_type, severity, title, src, dst, proto, dport, ports, what, risk, do
        FROM events ORDER BY id DESC LIMIT ?
    """, (limit,))
    rows = cur.fetchall()
    conn.close()
    keys = ["id", "ts", "event_type", "severity", "title", "src", "dst",
            "proto", "dport", "ports", "what", "risk", "do"]
    return jsonify([dict(zip(keys, r)) for r in rows])


@app.get("/control")
def control_get():
    return jsonify({"scan_enabled": get_scan_state()})


@app.get("/ips")
def ips():
    conn = sqlite3.connect(DB_PATH)
    cur  = conn.cursor()
    cur.execute("""
        SELECT src, COUNT(*), GROUP_CONCAT(DISTINCT dport),
               GROUP_CONCAT(DISTINCT ports), GROUP_CONCAT(DISTINCT what)
        FROM events WHERE src IS NOT NULL
        GROUP BY src ORDER BY COUNT(*) DESC
    """)
    rows = cur.fetchall()
    conn.close()
    blocked_info = list_blocked_ips_from_windows()
    blocked_set  = set(blocked_info["ips"])
    blocked     = []
    not_blocked = []
    for src, count, dports_raw, ports_raw, what_raw in rows:
        ports = set()
        if dports_raw:
            for x in str(dports_raw).split(","):
                x = x.strip()
                if x.isdigit():
                    ports.add(int(x))
        if ports_raw:
            for chunk in str(ports_raw).split(","):
                chunk = chunk.strip()
                if chunk.isdigit():
                    ports.add(int(chunk))
        row = {"ip": src, "count": count, "ports": sorted(ports), "analysis": what_raw or ""}
        (blocked if src in blocked_set else not_blocked).append(row)
    return jsonify({
        "ok": blocked_info["ok"], "blocked": blocked, "not_blocked": not_blocked,
        "blocked_count": len(blocked_info["ips"]), "error": blocked_info["error"],
    })


@app.get("/inspect")
def inspect_ip():
    ip = request.args.get("ip")
    if not ip:
        return jsonify({"error": "missing ip"}), 400
    conn = sqlite3.connect(DB_PATH)
    cur  = conn.cursor()
    cur.execute("""
        SELECT ts, src, dst, proto, dport, ports, event_type, severity, title, what, risk, do
        FROM events WHERE src = ? OR dst = ? ORDER BY id DESC LIMIT 50
    """, (ip, ip))
    rows = cur.fetchall()
    conn.close()
    keys = ["ts", "src", "dst", "proto", "dport", "ports",
            "event_type", "severity", "title", "what", "risk", "do"]
    return jsonify({"ip": ip, "count": len(rows), "events": [dict(zip(keys, r)) for r in rows]})


@app.post("/events")
def post_events():
    check_auth()
    data = request.get_json(silent=True) or {}
    if "event_type" not in data:
        return jsonify({"error": "missing event_type"}), 400
    data["ts"] = data.get("ts") or datetime.utcnow().isoformat(timespec="seconds") + "Z"
    insert_event(data)
    return jsonify({"ok": True})


@app.post("/control/start")
def control_start():
    check_auth()
    set_scan_state(True)
    return jsonify({"ok": True, "scan_enabled": True})


@app.post("/control/stop")
def control_stop():
    check_auth()
    set_scan_state(False)
    return jsonify({"ok": True, "scan_enabled": False})


@app.post("/events/delete")
def events_delete():
    check_auth()
    data     = request.get_json(silent=True) or {}
    event_id = data.get("id")
    if event_id is None:
        clear_events()
        return jsonify({"ok": True, "deleted": "all"})
    try:
        event_id = int(event_id)
    except Exception:
        return jsonify({"error": "id must be int"}), 400
    n = delete_event(event_id)
    return jsonify({"ok": True, "deleted": n, "id": event_id})


@app.post("/ips/unblock")
def ips_unblock():
    check_auth()
    data = request.get_json(silent=True) or {}
    ip   = data.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "missing ip"}), 400
    ok = unblock_ip(ip)
    if ok:
        return jsonify({"ok": True, "ip": ip})
    else:
        return jsonify({"ok": False, "error": f"Failed to unblock {ip}"}), 500


@app.route("/mistral/chat", methods=["POST"])
def mistral_chat():
    import requests as req
    data     = request.get_json() or {}
    question = data.get("question", "").strip()
    if not question:
        return jsonify({"error": "Question vide"}), 400
    mistral_key = os.getenv("MISTRAL_API_KEY", "")
    if not mistral_key:
        return jsonify({"error": "MISTRAL_API_KEY manquante"}), 500
    try:
        conn = sqlite3.connect(DB_PATH)
        cur  = conn.cursor()
        cur.execute("SELECT event_type, src, dst, dport, ports, what, risk FROM events ORDER BY id DESC LIMIT 20")
        rows = cur.fetchall()
        conn.close()
        context = "\n".join([
            f"- [{r[0]}] src={r[1]} port={r[3] or r[4]} | {r[5]}"
            for r in rows
        ]) or "Aucun événement récent."
    except Exception:
        context = "Contexte indisponible."
    try:
        response = req.post(
            "https://api.mistral.ai/v1/chat/completions",
            headers={"Authorization": f"Bearer {mistral_key}", "Content-Type": "application/json"},
            json={
                "model": "mistral-small-latest",
                "messages": [
                    {"role": "system", "content": "Tu es un expert en cybersécurité qui aide un utilisateur Windows. Réponds en français de manière claire et pratique."},
                    {"role": "user", "content": f"Voici les derniers événements de mon pare-feu :\n{context}\n\nMa question : {question}"}
                ],
                "max_tokens": 500, "temperature": 0.4,
            },
            timeout=15,
        )
        response.raise_for_status()
        return jsonify({"answer": response.json()["choices"][0]["message"]["content"].strip()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# Dashboard HTML avec Assistant Mistral intégré
# ---------------------------------------------------------------------------

DASH_HTML = r"""
<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>AlertExplain — Firewall Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&family=Exo+2:wght@300;400;600&display=swap" rel="stylesheet">
<style>
:root {
  --bg: #050810;
  --panel: #080d1a;
  --border: #0d1f3c;
  --accent: #00f5d4;
  --accent2: #f72585;
  --warn: #ff9f1c;
  --ok: #06d6a0;
  --danger: #ff2d55;
  --dim: #1a2a4a;
  --text: #b8cfe8;
  --muted: #4a6080;
  --mono: 'Share Tech Mono', monospace;
  --title: 'Orbitron', sans-serif;
  --body: 'Exo 2', sans-serif;
  --glow-a: 0 0 20px rgba(0,245,212,0.3);
  --glow-r: 0 0 20px rgba(255,45,85,0.3);
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

body {
  background: var(--bg);
  color: var(--text);
  font-family: var(--body);
  min-height: 100vh;
  overflow-x: hidden;
}

/* Animated grid background */
body::before {
  content: '';
  position: fixed; inset: 0;
  background:
    linear-gradient(rgba(0,245,212,0.03) 1px, transparent 1px),
    linear-gradient(90deg, rgba(0,245,212,0.03) 1px, transparent 1px);
  background-size: 40px 40px;
  animation: gridMove 20s linear infinite;
  pointer-events: none; z-index: 0;
}
@keyframes gridMove { from{background-position:0 0} to{background-position:40px 40px} }

/* Scanline effect */
body::after {
  content: '';
  position: fixed; inset: 0;
  background: repeating-linear-gradient(
    0deg, transparent, transparent 2px,
    rgba(0,0,0,0.05) 2px, rgba(0,0,0,0.05) 4px
  );
  pointer-events: none; z-index: 1;
}

/* ── TOPBAR ── */
.topbar {
  position: sticky; top: 0; z-index: 100;
  background: rgba(5,8,16,0.95);
  border-bottom: 1px solid var(--border);
  backdrop-filter: blur(20px);
  padding: 0 24px;
  height: 60px;
  display: flex; align-items: center; gap: 16px;
}
.topbar::after {
  content: '';
  position: absolute; bottom: 0; left: 0; right: 0; height: 1px;
  background: linear-gradient(90deg, transparent, var(--accent), transparent);
  animation: scanline 3s ease-in-out infinite;
}
@keyframes scanline { 0%,100%{opacity:0.3} 50%{opacity:1} }

.logo {
  font-family: var(--title);
  font-size: 16px; font-weight: 900;
  color: var(--accent);
  letter-spacing: 3px;
  text-transform: uppercase;
  text-shadow: var(--glow-a);
  white-space: nowrap;
}
.logo em { color: var(--accent2); font-style: normal; }

.live-dot {
  width: 8px; height: 8px; border-radius: 50%;
  background: var(--ok);
  box-shadow: 0 0 8px var(--ok);
  animation: blink 1.5s ease-in-out infinite;
}
.live-dot.off { background: var(--danger); box-shadow: 0 0 8px var(--danger); }
@keyframes blink { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:0.4;transform:scale(0.8)} }

.live-label {
  font-family: var(--mono); font-size: 10px;
  letter-spacing: 2px; text-transform: uppercase;
  color: var(--ok);
}
.live-label.off { color: var(--danger); }

.spacer { flex: 1; }

.clock {
  font-family: var(--mono); font-size: 13px;
  color: var(--muted); letter-spacing: 2px;
}

/* Topbar buttons */
.tbtn {
  font-family: var(--mono); font-size: 10px;
  letter-spacing: 1.5px; text-transform: uppercase;
  padding: 7px 16px; cursor: pointer;
  border: 1px solid; border-radius: 2px;
  transition: all 0.2s; background: transparent;
  white-space: nowrap;
}
.tbtn-start { border-color: var(--ok); color: var(--ok); }
.tbtn-start:hover { background: var(--ok); color: #000; box-shadow: var(--glow-a); }
.tbtn-stop  { border-color: var(--danger); color: var(--danger); }
.tbtn-stop:hover  { background: var(--danger); color: #fff; box-shadow: var(--glow-r); }
.tbtn-clear { border-color: var(--muted); color: var(--muted); }
.tbtn-clear:hover { border-color: var(--warn); color: var(--warn); }
.tbtn-mistral {
  border-color: var(--warn); color: var(--warn);
  animation: mistralPulse 3s ease-in-out infinite;
}
.tbtn-mistral:hover { background: var(--warn); color: #000; }
@keyframes mistralPulse { 0%,100%{box-shadow:none} 50%{box-shadow:0 0 12px rgba(255,159,28,0.4)} }

/* ── STATS BAR ── */
.statsbar {
  position: relative; z-index: 2;
  display: grid; grid-template-columns: repeat(5, 1fr);
  gap: 1px; background: var(--border);
  border-bottom: 1px solid var(--border);
}
.stat {
  background: var(--panel);
  padding: 16px 20px;
  position: relative; overflow: hidden;
  transition: background 0.3s;
}
.stat::before {
  content: '';
  position: absolute; bottom: 0; left: 0; right: 0; height: 2px;
  background: var(--accent); opacity: 0;
  transition: opacity 0.3s;
}
.stat:hover::before { opacity: 1; }
.stat:hover { background: #0a1020; }
.stat-label {
  font-family: var(--mono); font-size: 9px;
  text-transform: uppercase; letter-spacing: 2px;
  color: var(--muted); margin-bottom: 8px;
}
.stat-val {
  font-family: var(--title); font-size: 28px; font-weight: 700;
  color: var(--accent);
  text-shadow: var(--glow-a);
  transition: all 0.3s;
}
.stat-val.red  { color: var(--danger); text-shadow: var(--glow-r); }
.stat-val.warn { color: var(--warn); text-shadow: 0 0 15px rgba(255,159,28,0.4); }
.stat-val.ok   { color: var(--ok); }

/* ── MAIN LAYOUT ── */
.main {
  position: relative; z-index: 2;
  padding: 20px 24px;
  display: flex; flex-direction: column; gap: 16px;
  max-width: 1600px; margin: 0 auto;
}

/* ── PANELS ── */
.panel {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 2px;
  overflow: hidden;
  animation: fadeIn 0.4s ease;
}
@keyframes fadeIn { from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:none} }

.panel-header {
  padding: 12px 20px;
  border-bottom: 1px solid var(--border);
  display: flex; align-items: center; gap: 10px;
  background: rgba(0,245,212,0.02);
}
.panel-title {
  font-family: var(--mono); font-size: 10px;
  text-transform: uppercase; letter-spacing: 2.5px;
  color: var(--accent);
}
.badge {
  font-family: var(--mono); font-size: 9px;
  padding: 2px 8px;
  border: 1px solid rgba(0,245,212,0.3);
  background: rgba(0,245,212,0.05);
  color: var(--accent);
  border-radius: 1px;
}
.badge-red  { border-color:rgba(255,45,85,0.4); background:rgba(255,45,85,0.08); color:var(--danger); }
.badge-warn { border-color:rgba(255,159,28,0.4); background:rgba(255,159,28,0.08); color:var(--warn); }
.badge-ok   { border-color:rgba(6,214,160,0.4); background:rgba(6,214,160,0.08); color:var(--ok); }

/* ── EVENTS TABLE ── */
.tbl { width: 100%; border-collapse: collapse; }
.tbl th {
  font-family: var(--mono); font-size: 9px;
  text-transform: uppercase; letter-spacing: 1.5px;
  color: var(--muted); text-align: left;
  padding: 10px 14px;
  border-bottom: 1px solid var(--border);
  background: rgba(0,0,0,0.2);
}
.tbl td {
  font-family: var(--mono); font-size: 11px;
  padding: 9px 14px;
  border-bottom: 1px solid rgba(13,31,60,0.6);
  color: var(--text);
  transition: background 0.15s;
}
.tbl tr:hover td { background: rgba(0,245,212,0.03); }
.tbl tr.new-row td { animation: rowFlash 0.6s ease; }
@keyframes rowFlash { from{background:rgba(0,245,212,0.12)} to{background:transparent} }

.sev-HIGH   { color: var(--danger) !important; font-weight: 700; }
.sev-MEDIUM { color: var(--warn)   !important; font-weight: 600; }
.sev-LOW    { color: var(--muted)  !important; }

/* ── IP GRID ── */
.ip-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }

/* ── IP CARD (clickable) ── */
.ip-card {
  background: var(--panel);
  border: 1px solid var(--border);
  padding: 12px 16px;
  cursor: pointer;
  transition: all 0.2s;
  display: flex; align-items: center; gap: 12px;
  border-radius: 2px;
  position: relative; overflow: hidden;
}
.ip-card::before {
  content: ''; position: absolute;
  left: 0; top: 0; bottom: 0; width: 3px;
  background: var(--danger);
  opacity: 0; transition: opacity 0.2s;
}
.ip-card:hover::before { opacity: 1; }
.ip-card:hover { border-color: rgba(255,45,85,0.4); background: rgba(255,45,85,0.05); }
.ip-card.suspect::before { background: var(--warn); }
.ip-card.suspect:hover { border-color: rgba(255,159,28,0.4); background: rgba(255,159,28,0.05); }

.ip-addr {
  font-family: var(--mono); font-size: 13px;
  font-weight: 700; flex: 1;
}
.ip-addr.blocked { color: var(--danger); text-shadow: var(--glow-r); }
.ip-addr.suspect { color: var(--warn); }

.ip-meta { font-size: 10px; color: var(--muted); margin-top: 2px; }

.ip-actions { display: flex; gap: 6px; flex-shrink: 0; }

.abtn {
  font-family: var(--mono); font-size: 9px;
  letter-spacing: 1px; text-transform: uppercase;
  padding: 4px 10px; cursor: pointer; border-radius: 2px;
  border: 1px solid; transition: all 0.15s;
  background: transparent;
}
.abtn-block  { border-color: var(--danger); color: var(--danger); }
.abtn-block:hover  { background: var(--danger); color: #fff; }
.abtn-unblock { border-color: var(--ok); color: var(--ok); }
.abtn-unblock:hover { background: var(--ok); color: #000; }
.abtn-inspect { border-color: var(--accent); color: var(--accent); }
.abtn-inspect:hover { background: var(--accent); color: #000; }

/* ── EMPTY STATE ── */
.empty {
  padding: 40px; text-align: center;
  font-family: var(--mono); font-size: 11px;
  color: var(--muted); letter-spacing: 1px;
}

/* ── ERROR BAR ── */
.errbar {
  background: rgba(255,45,85,0.1);
  border: 1px solid rgba(255,45,85,0.3);
  color: #ff8899; font-family: var(--mono); font-size: 11px;
  padding: 10px 24px; margin: 0 24px;
  animation: fadeIn 0.3s ease;
  position: relative; z-index: 2;
}

/* ── INSPECT PANEL ── */
.inspect-header {
  padding: 14px 20px;
  border-bottom: 1px solid var(--border);
  display: flex; align-items: center; gap: 12px;
}
.inspect-ip {
  font-family: var(--title); font-size: 18px;
  color: var(--accent); text-shadow: var(--glow-a);
}

/* ── ROW BUTTONS ── */
.rbtn {
  font-family: var(--mono); font-size: 9px;
  padding: 3px 8px; cursor: pointer; border-radius: 1px;
  border: 1px solid var(--dim); color: var(--muted);
  background: transparent; transition: all 0.15s;
  margin-right: 4px;
}
.rbtn:hover { color: var(--accent); border-color: var(--accent); }
.rbtn.del:hover { color: var(--danger); border-color: var(--danger); }

/* ── MISTRAL MODAL ── */
#mistral-overlay {
  display: none; position: fixed; inset: 0;
  background: rgba(0,0,0,0.8); z-index: 500;
  align-items: center; justify-content: center;
  backdrop-filter: blur(8px);
}
#mistral-overlay.open { display: flex; }

#mistral-box {
  background: #060a14;
  border: 1px solid var(--warn);
  border-radius: 4px;
  width: 700px; max-width: 95vw; max-height: 85vh;
  display: flex; flex-direction: column;
  box-shadow: 0 0 60px rgba(255,159,28,0.2);
  animation: slideUp 0.3s ease;
}
@keyframes slideUp { from{transform:translateY(20px);opacity:0} to{transform:none;opacity:1} }

#mistral-header {
  padding: 16px 20px; border-bottom: 1px solid #1a1a2e;
  display: flex; align-items: center; justify-content: space-between;
  background: rgba(255,159,28,0.05);
}
.mh-title { font-family: var(--title); font-size: 14px; color: var(--warn); letter-spacing: 2px; }
.mh-sub { font-family: var(--mono); font-size: 10px; color: var(--muted); margin-top: 3px; letter-spacing: 1px; }
#mistral-close {
  background: none; border: 1px solid #333; color: #666;
  font-size: 18px; cursor: pointer; padding: 2px 10px; border-radius: 2px;
}
#mistral-close:hover { color: var(--danger); border-color: var(--danger); }

#mistral-msgs {
  flex: 1; overflow-y: auto; padding: 16px;
  display: flex; flex-direction: column; gap: 12px;
  scrollbar-width: thin; scrollbar-color: var(--dim) transparent;
}
.msg { max-width: 88%; padding: 10px 14px; font-size: 13px; line-height: 1.6; white-space: pre-wrap; border-radius: 3px; }
.msg.bot {
  background: #0d1525; color: #b8cfe8;
  border: 1px solid var(--border); align-self: flex-start;
  border-left: 3px solid var(--warn);
}
.msg.user {
  background: var(--warn); color: #000; font-weight: 600;
  align-self: flex-end;
}
.msg.typing { color: var(--muted); border-style: dashed; animation: typingPulse 1s ease-in-out infinite; }
@keyframes typingPulse { 0%,100%{opacity:0.5} 50%{opacity:1} }

#mistral-sugs {
  padding: 10px 16px; border-top: 1px solid #111;
  display: flex; flex-wrap: wrap; gap: 6px;
}
.sug {
  background: #0a1020; border: 1px solid #1a2a4a; color: #5a7090;
  border-radius: 20px; padding: 4px 12px; font-size: 11px;
  font-family: var(--mono); cursor: pointer; transition: all 0.2s;
}
.sug:hover { border-color: var(--warn); color: var(--warn); }

#mistral-input-row {
  padding: 12px 16px; border-top: 1px solid #1a1a2e;
  display: flex; gap: 8px;
}
#mistral-input {
  flex: 1; background: #0a1020; border: 1px solid #1a2a4a;
  border-radius: 2px; padding: 10px 14px; color: #fff;
  font-family: var(--mono); font-size: 12px; outline: none;
  transition: border-color 0.2s;
}
#mistral-input:focus { border-color: var(--warn); }
#mistral-send {
  background: var(--warn); border: none; border-radius: 2px;
  padding: 10px 18px; color: #000; font-family: var(--mono);
  font-size: 11px; font-weight: 700; letter-spacing: 1px;
  cursor: pointer; transition: all 0.2s;
}
#mistral-send:hover { background: #ffb940; }
#mistral-send:disabled { background: #333; color: #666; cursor: not-allowed; }

/* ── BLOCK CONFIRM MODAL ── */
#confirm-overlay {
  display: none; position: fixed; inset: 0;
  background: rgba(0,0,0,0.7); z-index: 600;
  align-items: center; justify-content: center;
  backdrop-filter: blur(4px);
}
#confirm-overlay.open { display: flex; }
#confirm-box {
  background: #060a14; border: 1px solid var(--danger);
  border-radius: 4px; padding: 28px 32px; max-width: 400px;
  box-shadow: 0 0 40px rgba(255,45,85,0.2);
  animation: slideUp 0.2s ease;
  text-align: center;
}
#confirm-box h3 { font-family: var(--title); color: var(--danger); font-size: 14px; letter-spacing: 2px; margin-bottom: 12px; }
#confirm-box p  { font-family: var(--mono); font-size: 12px; color: var(--muted); margin-bottom: 20px; line-height: 1.6; }
#confirm-ip { color: var(--danger); font-weight: 700; }
.confirm-btns { display: flex; gap: 10px; justify-content: center; }
.cbtn { font-family: var(--mono); font-size: 11px; letter-spacing: 1px; text-transform: uppercase; padding: 8px 20px; cursor: pointer; border-radius: 2px; border: 1px solid; transition: all 0.2s; background: transparent; }
.cbtn-confirm { border-color: var(--danger); color: var(--danger); }
.cbtn-confirm:hover { background: var(--danger); color: #fff; }
.cbtn-cancel  { border-color: var(--muted); color: var(--muted); }
.cbtn-cancel:hover  { border-color: var(--text); color: var(--text); }

/* Scrollbar */
::-webkit-scrollbar { width: 4px; height: 4px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--dim); border-radius: 2px; }
</style>
</head>
<body>

<!-- TOPBAR -->
<div class="topbar">
  <div class="logo">Alert<em>/</em>Explain</div>
  <div class="live-dot" id="liveDot"></div>
  <div class="live-label" id="liveLabel">SCAN ACTIF</div>
  <div style="width:1px;height:20px;background:var(--border);margin:0 4px"></div>
  <button class="tbtn tbtn-start" onclick="startScan()">▶ Start</button>
  <button class="tbtn tbtn-stop"  onclick="stopScan()">⏹ Stop</button>
  <button class="tbtn tbtn-clear" onclick="deleteAll()">⌫ Effacer</button>
  <button class="tbtn tbtn-mistral" onclick="openMistral()">🤖 Mistral AI</button>
  <div class="spacer"></div>
  <div class="clock" id="clk">--:--:--</div>
</div>

<div id="errbar" style="display:none" class="errbar"></div>

<!-- STATS BAR -->
<div class="statsbar">
  <div class="stat"><div class="stat-label">Événements</div><div class="stat-val ok" id="s-total">0</div></div>
  <div class="stat"><div class="stat-label">Alertes HIGH</div><div class="stat-val red" id="s-high">0</div></div>
  <div class="stat"><div class="stat-label">IPs bloquées</div><div class="stat-val warn" id="s-blocked">0</div></div>
  <div class="stat"><div class="stat-label">Scans détectés</div><div class="stat-val red" id="s-scans">0</div></div>
  <div class="stat"><div class="stat-label">Analyses Mistral</div><div class="stat-val" id="s-mistral">0</div></div>
</div>

<div class="main">

  <!-- EVENTS PANEL -->
  <div class="panel" id="panel-events">
    <div class="panel-header">
      <div class="panel-title">⚡ Événements réseau</div>
      <div class="badge" id="b-total">0 TOTAL</div>
      <div class="badge badge-red" id="b-high">0 HIGH</div>
      <div class="badge" id="b-mistral-badge" style="border-color:rgba(255,159,28,0.4);color:var(--warn);background:rgba(255,159,28,0.05)">0 MISTRAL</div>
      <div class="spacer"></div>
    </div>
    <div id="events-body">
      <div class="empty">Aucun événement — en attente de trafic...</div>
    </div>
  </div>

  <!-- IP PANELS -->
  <div class="ip-grid">
    <!-- Blocked IPs -->
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">🔴 IPs bloquées</div>
        <div class="badge badge-red" id="b-blocked-count">0</div>
        <div style="font-family:var(--mono);font-size:9px;color:var(--muted);margin-left:auto">Cliquer pour débloquer</div>
      </div>
      <div id="blocked-list" style="padding:8px">
        <div class="empty">Aucune IP bloquée</div>
      </div>
    </div>

    <!-- Suspect IPs -->
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">🟡 IPs suspectes</div>
        <div class="badge badge-warn" id="b-suspect-count">0</div>
        <div style="font-family:var(--mono);font-size:9px;color:var(--muted);margin-left:auto">Cliquer pour bloquer</div>
      </div>
      <div id="suspect-list" style="padding:8px">
        <div class="empty">Aucune IP suspecte</div>
      </div>
    </div>
  </div>

  <!-- INSPECT PANEL -->
  <div class="panel" id="panel-inspect" style="display:none">
    <div class="inspect-header">
      <div>
        <div style="font-family:var(--mono);font-size:9px;color:var(--muted);letter-spacing:2px;margin-bottom:4px">IP INSPECTÉE</div>
        <div class="inspect-ip" id="inspect-ip-title">—</div>
      </div>
      <div style="display:flex;gap:8px;margin-left:20px">
        <div class="badge" id="inspect-count">0 events</div>
      </div>
      <div class="spacer"></div>
      <button class="rbtn" onclick="closeInspect()">✕ Fermer</button>
    </div>
    <div id="inspect-body"></div>
  </div>

</div>

<!-- BLOCK CONFIRM MODAL -->
<div id="confirm-overlay">
  <div id="confirm-box">
    <h3>⚠ BLOQUER L'IP</h3>
    <p>Voulez-vous bloquer l'adresse<br><span id="confirm-ip">—</span><br>via Windows Firewall ?</p>
    <div class="confirm-btns">
      <button class="cbtn cbtn-confirm" id="confirm-yes">Bloquer</button>
      <button class="cbtn cbtn-cancel"  onclick="closeConfirm()">Annuler</button>
    </div>
  </div>
</div>

<!-- MISTRAL MODAL -->
<div id="mistral-overlay">
  <div id="mistral-box">
    <div id="mistral-header">
      <div>
        <div class="mh-title">🤖 ASSISTANT MISTRAL AI</div>
        <div class="mh-sub">Analyse de sécurité basée sur vos événements réseau</div>
      </div>
      <button id="mistral-close" onclick="closeMistral()">✕</button>
    </div>
    <div id="mistral-msgs">
      <div class="msg bot">👋 Bonjour ! Je suis votre assistant Mistral AI intégré à AlertExplain. Je connais tous vos événements réseau récents. Posez-moi vos questions sur la sécurité de votre système !</div>
    </div>
    <div id="mistral-sugs">
      <div class="sug">L'IP détectée est-elle dangereuse ?</div>
      <div class="sug">Comment bloquer une IP suspecte ?</div>
      <div class="sug">Quels sont les risques d'un scan de ports ?</div>
      <div class="sug">Comment renforcer la sécurité de mon Windows ?</div>
      <div class="sug">Mon PC a-t-il été compromis ?</div>
      <div class="sug">Que faire face au port 22 exposé ?</div>
    </div>
    <div id="mistral-input-row">
      <input id="mistral-input" placeholder="Posez votre question de sécurité..." />
      <button id="mistral-send">ENVOYER</button>
    </div>
  </div>
</div>

<script>
// ── Utils ──────────────────────────────────────────────────────────────
function esc(v) {
  if (v == null) return "";
  return String(v).replace(/&/g,"&amp;").replace(/</g,"&lt;")
    .replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");
}
function setErr(msg) {
  const el = document.getElementById("errbar");
  if (msg) { el.textContent = "⚠ " + msg; el.style.display = "block"; }
  else el.style.display = "none";
}

async function api(url, body=null) {
  try {
    const opt = { method: body!=null?"POST":"GET", cache:"no-store" };
    if (body!=null) { opt.headers={"Content-Type":"application/json"}; opt.body=JSON.stringify(body); }
    const r = await fetch(url + (url.includes("?")?"&":"?") + "t="+Date.now(), opt);
    if (!r.ok) throw new Error("HTTP "+r.status);
    setErr(""); return r.json();
  } catch(e) { setErr("API non joignable — "+e.message); throw e; }
}

// ── Clock ──────────────────────────────────────────────────────────────
setInterval(() => {
  document.getElementById("clk").textContent = new Date().toLocaleTimeString("fr-FR");
}, 1000);

// ── State ──────────────────────────────────────────────────────────────
let prevEventIds = new Set();
let currentInspectIp = null;
let confirmIp = null;
let confirmAction = null; // 'block' | 'unblock'

// ── Refresh ────────────────────────────────────────────────────────────
async function refreshAll() {
  try {
    const [status, events, ipsData] = await Promise.all([
      api("/scanner/status"),
      api("/events?limit=100"),
      api("/ips"),
    ]);
    updateStatus(status);
    updateEvents(events);
    updateIps(ipsData);
    if (currentInspectIp) refreshInspect();
  } catch(e) {}
}

function updateStatus(s) {
  const on = s.running;
  const dot   = document.getElementById("liveDot");
  const label = document.getElementById("liveLabel");
  dot.className   = "live-dot" + (on ? "" : " off");
  label.className = "live-label" + (on ? "" : " off");
  label.textContent = on ? "SCAN ACTIF" : "SCAN ARRÊTÉ";
}

function updateEvents(events) {
  const high    = events.filter(e => e.severity==="HIGH").length;
  const scans   = events.filter(e => e.event_type==="PORT_SCAN").length;
  const mistral = events.filter(e => e.event_type==="MISTRAL_ANALYSIS").length;

  document.getElementById("s-total").textContent   = events.length;
  document.getElementById("s-high").textContent    = high;
  document.getElementById("s-scans").textContent   = scans;
  document.getElementById("s-mistral").textContent = mistral;
  document.getElementById("b-total").textContent   = events.length + " TOTAL";
  document.getElementById("b-high").textContent    = high + " HIGH";
  document.getElementById("b-mistral-badge").textContent = mistral + " MISTRAL";

  if (events.length === 0) {
    document.getElementById("events-body").innerHTML =
      '<div class="empty">Aucun événement — en attente de trafic...</div>';
    return;
  }

  const newIds = new Set(events.map(e => e.id));
  let html = '<table class="tbl"><thead><tr>' +
    '<th></th><th>ID</th><th>TIME</th><th>TYPE</th><th>SEV</th>' +
    '<th>SRC</th><th>PROTO</th><th>PORT</th><th>DÉTAILS</th><th></th>' +
    '</tr></thead><tbody>';

  for (const e of events) {
    const isNew = !prevEventIds.has(e.id);
    const isMistral = e.event_type === "MISTRAL_ANALYSIS";
    const rowStyle = isMistral ? 'style="background:rgba(255,159,28,0.04)"' : '';
    html += `<tr class="${isNew?'new-row':''}" ${rowStyle}>`;
    html += `<td><button class="rbtn del" onclick="deleteOne(${e.id})">✕</button></td>`;
    html += `<td style="color:var(--muted)">${esc(e.id)}</td>`;
    html += `<td style="color:var(--muted)">${esc((e.ts||"").slice(11,19))}</td>`;
    html += `<td style="color:${isMistral?'var(--warn)':'var(--accent)'}">${esc(e.event_type)}</td>`;
    html += `<td class="sev-${esc(e.severity)}">${esc(e.severity)}</td>`;
    html += `<td style="color:var(--accent2)">${esc(e.src)||"—"}</td>`;
    html += `<td>${esc(e.proto)||"—"}</td>`;
    html += `<td>${esc(e.dport)||esc(e.ports)||"—"}</td>`;
    html += `<td style="max-width:500px;color:var(--text);word-break:break-word;white-space:normal;line-height:1.4">${esc(e.title)} — ${esc(e.what)}</td>`;
    html += `<td>${e.src?`<button class="rbtn" onclick="inspectIp('${esc(e.src)}')">🔎</button>`:''}`;
    if (e.src) html += `<button class="rbtn" onclick="askBlock('${esc(e.src)}')">⛔</button>`;
    html += `</td></tr>`;
  }
  html += '</tbody></table>';
  document.getElementById("events-body").innerHTML = html;
  prevEventIds = newIds;
}

function updateIps(data) {
  document.getElementById("s-blocked").textContent = data.blocked_count || 0;
  document.getElementById("b-blocked-count").textContent = (data.blocked_count || 0) + " IPs";
  document.getElementById("b-suspect-count").textContent = (data.not_blocked?.length || 0) + " IPs";

  // Blocked IPs
  const blockedEl = document.getElementById("blocked-list");
  if (!data.blocked?.length) {
    blockedEl.innerHTML = '<div class="empty">Aucune IP bloquée ✓</div>';
  } else {
    blockedEl.innerHTML = data.blocked.map(r => `
      <div class="ip-card" onclick="askUnblock('${esc(r.ip)}')">
        <div style="flex:1">
          <div class="ip-addr blocked">⛔ ${esc(r.ip)}</div>
          <div class="ip-meta">${r.count} events · ports: ${(r.ports||[]).slice(0,4).join(", ")||"—"}</div>
        </div>
        <div class="ip-actions" onclick="event.stopPropagation()">
          <button class="abtn abtn-inspect" onclick="inspectIp('${esc(r.ip)}')">🔎</button>
          <button class="abtn abtn-unblock" onclick="askUnblock('${esc(r.ip)}')">🔓 Débloquer</button>
        </div>
      </div>
    `).join("");
  }

  // Suspect IPs
  const suspectEl = document.getElementById("suspect-list");
  if (!data.not_blocked?.length) {
    suspectEl.innerHTML = '<div class="empty">Aucune IP suspecte détectée</div>';
  } else {
    suspectEl.innerHTML = data.not_blocked.map(r => `
      <div class="ip-card suspect" onclick="askBlock('${esc(r.ip)}')">
        <div style="flex:1">
          <div class="ip-addr suspect">⚠ ${esc(r.ip)}</div>
          <div class="ip-meta">${r.count} events · ports: ${(r.ports||[]).slice(0,4).join(", ")||"—"}</div>
        </div>
        <div class="ip-actions" onclick="event.stopPropagation()">
          <button class="abtn abtn-inspect" onclick="inspectIp('${esc(r.ip)}')">🔎</button>
          <button class="abtn abtn-block" onclick="askBlock('${esc(r.ip)}')">⛔ Bloquer</button>
        </div>
      </div>
    `).join("");
  }
}

// ── Block / Unblock ────────────────────────────────────────────────────
function askBlock(ip) {
  confirmIp = ip; confirmAction = "block";
  document.getElementById("confirm-ip").textContent = ip;
  document.getElementById("confirm-box").querySelector("h3").textContent = "⚠ BLOQUER L'IP";
  document.getElementById("confirm-box").querySelector("p").innerHTML =
    `Voulez-vous bloquer l'adresse<br><span style="color:var(--danger);font-weight:700">${esc(ip)}</span><br>via Windows Firewall ?`;
  document.getElementById("confirm-overlay").classList.add("open");
}

function askUnblock(ip) {
  confirmIp = ip; confirmAction = "unblock";
  document.getElementById("confirm-box").querySelector("h3").textContent = "🔓 DÉBLOQUER L'IP";
  document.getElementById("confirm-box").querySelector("p").innerHTML =
    `Voulez-vous débloquer l'adresse<br><span style="color:var(--ok);font-weight:700">${esc(ip)}</span><br>et supprimer les règles Windows Firewall ?`;
  document.getElementById("confirm-overlay").classList.add("open");
}

function closeConfirm() {
  document.getElementById("confirm-overlay").classList.remove("open");
  confirmIp = null; confirmAction = null;
}

document.getElementById("confirm-yes").onclick = async () => {
  if (!confirmIp) return closeConfirm();
  try {
    if (confirmAction === "block") {
      await api("/events", {
        event_type:"BLOCKED_IP", severity:"HIGH", title:"Blocage manuel",
        proto:"MANUAL", src:confirmIp,
        what:"Blocage manuel depuis le dashboard",
        risk:"Manuel", do:"Surveiller."
      });
    } else {
      await api("/ips/unblock", {ip: confirmIp});
    }
    closeConfirm();
    await refreshAll();
  } catch(e) { closeConfirm(); }
};

// ── Inspect ───────────────────────────────────────────────────────────
function inspectIp(ip) {
  currentInspectIp = ip;
  document.getElementById("panel-inspect").style.display = "block";
  document.getElementById("inspect-ip-title").textContent = ip;
  refreshInspect();
  document.getElementById("panel-inspect").scrollIntoView({behavior:"smooth"});
}

function closeInspect() {
  document.getElementById("panel-inspect").style.display = "none";
  currentInspectIp = null;
}

async function refreshInspect() {
  if (!currentInspectIp) return;
  const data = await api("/inspect?ip=" + encodeURIComponent(currentInspectIp));
  document.getElementById("inspect-count").textContent = data.count + " events";
  if (!data.events?.length) {
    document.getElementById("inspect-body").innerHTML = '<div class="empty">Aucun événement pour cette IP</div>';
    return;
  }
  let html = '<table class="tbl"><thead><tr><th>TIME</th><th>SRC</th><th>DST</th><th>PROTO</th><th>PORT</th><th>TYPE</th><th>SEV</th><th>DÉTAILS</th></tr></thead><tbody>';
  for (const e of data.events) {
    html += `<tr>
      <td style="color:var(--muted)">${esc((e.ts||"").slice(11,19))}</td>
      <td style="color:var(--accent2)">${esc(e.src)||"—"}</td>
      <td>${esc(e.dst)||"—"}</td>
      <td>${esc(e.proto)||"—"}</td>
      <td>${esc(e.dport||e.ports)||"—"}</td>
      <td style="color:var(--accent)">${esc(e.event_type)}</td>
      <td class="sev-${esc(e.severity)}">${esc(e.severity)}</td>
      <td style="max-width:500px;color:var(--text);word-break:break-word;white-space:normal;line-height:1.4">${esc(e.title)} — ${esc(e.what)}</td>
    </tr>`;
  }
  html += '</tbody></table>';
  document.getElementById("inspect-body").innerHTML = html;
}

// ── Delete ────────────────────────────────────────────────────────────
async function deleteOne(id) { await api("/events/delete", {id}); await refreshAll(); }
async function deleteAll()   { await api("/events/delete", {}); await refreshAll(); }

// ── Scan controls ─────────────────────────────────────────────────────
async function startScan() { await api("/scanner/start", {}); }
async function stopScan()  { await api("/scanner/stop",  {}); }

// ── Mistral ───────────────────────────────────────────────────────────
function openMistral()  { document.getElementById("mistral-overlay").classList.add("open"); }
function closeMistral() { document.getElementById("mistral-overlay").classList.remove("open"); }

document.getElementById("mistral-overlay").addEventListener("click", e => {
  if (e.target === document.getElementById("mistral-overlay")) closeMistral();
});

document.querySelectorAll(".sug").forEach(s => {
  s.onclick = () => sendMistral(s.textContent);
});

const minput = document.getElementById("mistral-input");
const msend  = document.getElementById("mistral-send");
minput.addEventListener("keydown", e => { if (e.key==="Enter") sendMistral(); });
msend.onclick = () => sendMistral();

function addMsg(text, role) {
  const div = document.createElement("div");
  div.className = "msg " + role;
  div.textContent = (role==="bot" ? "🤖 " : "") + text;
  const msgs = document.getElementById("mistral-msgs");
  msgs.appendChild(div);
  msgs.scrollTop = msgs.scrollHeight;
  return div;
}

async function sendMistral(q) {
  q = q || minput.value.trim();
  if (!q) return;
  minput.value = "";
  msend.disabled = true;
  addMsg(q, "user");
  const thinking = addMsg("Analyse en cours...", "bot typing");
  try {
    const r = await fetch("/mistral/chat", {
      method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({question:q})
    });
    const data = await r.json();
    thinking.remove();
    addMsg(data.answer || ("Erreur : " + (data.error||"?")), "bot");
  } catch(e) {
    thinking.remove();
    addMsg("❌ Impossible de contacter Mistral AI.", "bot");
  } finally { msend.disabled = false; }
}

// ── Auto refresh ──────────────────────────────────────────────────────
refreshAll();
setInterval(refreshAll, 2000);
</script>
</body>
</html>
"""


INSPECT_PAGE_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Inspection IP</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; background: #0f172a; color: #e5e7eb; }
    h2 { margin: 0 0 12px 0; }
    .card { background: #111827; border: 1px solid #374151; border-radius: 10px; padding: 14px; margin-bottom: 16px; }
    .muted { color: #9ca3af; }
    .grid { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 12px; margin-bottom: 16px; }
    .stat { background: #111827; border: 1px solid #374151; border-radius: 10px; padding: 12px; }
    .stat .label { color: #9ca3af; font-size: 13px; }
    .stat .value { font-size: 22px; font-weight: bold; margin-top: 6px; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #374151; padding: 8px; font-size: 13px; vertical-align: top; }
    th { background: #1f2937; }
    a, button { color: white; text-decoration: none; background: #2563eb; border: none; border-radius: 6px; padding: 8px 12px; cursor: pointer; }
    .secondary { background: #374151; }
    .sev-HIGH { color: #fca5a5; font-weight: bold; }
    .sev-MEDIUM { color: #fde68a; font-weight: bold; }
    .sev-LOW { color: #86efac; font-weight: bold; }
    #err { color: #fca5a5; white-space: pre-wrap; margin-top: 10px; }
  </style>
</head>
<body>
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
    <div>
      <h2>Inspection IP en temps réel</h2>
      <div class="muted" id="ip_title">Chargement...</div>
    </div>
    <a href="/dashboard" class="secondary">← Retour dashboard</a>
  </div>
  <div class="grid">
    <div class="stat"><div class="label">IP inspectée</div><div class="value" id="stat_ip">-</div></div>
    <div class="stat"><div class="label">Événements</div><div class="value" id="stat_count">0</div></div>
    <div class="stat"><div class="label">Dernière activité</div><div class="value" id="stat_last">-</div></div>
  </div>
  <div class="card">
    <h3>Flux récent</h3>
    <div class="muted">Mise à jour automatique toutes les 2 secondes</div>
    <div id="err"></div>
    <table id="tb_inspect">
      <thead><tr><th>Time</th><th>Src</th><th>Dst</th><th>Proto</th><th>Port</th><th>Type</th><th>Sev</th><th>Détails</th></tr></thead>
      <tbody></tbody>
    </table>
  </div>
<script>
function esc(v) {
  if (v===null||v===undefined) return "";
  return String(v).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
    .replace(/"/g,"&quot;").replace(/'/g,"&#39;");
}
const ip = new URLSearchParams(window.location.search).get("ip");
function setErr(msg) { document.getElementById("err").textContent = msg||""; }
async function api(url) {
  try {
    const r = await fetch(url+"?t="+Date.now(), {cache:"no-store"});
    const txt = await r.text();
    if (!r.ok) throw new Error("HTTP "+r.status+" :: "+txt);
    setErr(""); return JSON.parse(txt);
  } catch(e) { setErr("Erreur API: "+e.message); throw e; }
}
async function refresh() {
  if (!ip) { setErr("Aucune IP fournie"); return; }
  const data = await api("/inspect?ip="+encodeURIComponent(ip));
  document.getElementById("ip_title").textContent   = "Vue détaillée de " + esc(data.ip);
  document.getElementById("stat_ip").textContent    = esc(data.ip);
  document.getElementById("stat_count").textContent = esc(data.count||0);
  document.getElementById("stat_last").textContent  =
    (data.events && data.events.length) ? esc(data.events[0].ts||"-") : "-";
  const tb = document.querySelector("#tb_inspect tbody");
  tb.innerHTML = "";
  for (const e of (data.events||[])) {
    const tr = document.createElement("tr");
    tr.innerHTML =
      `<td>${esc(e.ts)}</td><td>${esc(e.src)}</td><td>${esc(e.dst)}</td>` +
      `<td>${esc(e.proto)}</td><td>${esc(e.dport||e.ports)}</td>` +
      `<td>${esc(e.event_type)}</td>` +
      `<td class="sev-${esc(e.severity)}">${esc(e.severity)}</td>` +
      `<td>${esc(e.title)} — ${esc(e.what)}</td>`;
    tb.appendChild(tr);
  }
}
refresh();
setInterval(refresh, 2000);
</script>
</body>
</html>
"""


@app.get("/inspect_page")
def inspect_page():
    return render_template_string(INSPECT_PAGE_HTML)


@app.get("/dashboard")
def dashboard():
    return render_template_string(DASH_HTML)


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)