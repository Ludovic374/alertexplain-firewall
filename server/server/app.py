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

# ---------------------------------------------------------------------------
# Auth — shared secret via env var API_SECRET (optionnel mais recommandé)
# ---------------------------------------------------------------------------

API_SECRET = os.getenv("API_SECRET", "")   # ex: export API_SECRET=mon_secret_local

import sys
import subprocess as _sp
from pathlib import Path as _Path

# Chemin vers main.py — adapte si besoin
_MAIN_PY = str(_Path(__file__).parent.parent.parent / "main.py")
_scanner_proc = None  # référence globale au subprocess


def _scanner_running() -> bool:
    """Retourne True si le subprocess main.py tourne."""
    global _scanner_proc
    return _scanner_proc is not None and _scanner_proc.poll() is None


# ============================================================
# Nouvelles routes — Start / Stop / Status du scanner
# ============================================================

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
    """
    Si API_SECRET est défini, vérifie que le header X-API-Key correspond.
    Appeler au début de chaque route d'écriture/suppression.
    """
    if not API_SECRET:
        return  # pas de secret configuré → pas de vérification (dev mode)
    key = request.headers.get("X-API-Key", "")
    if key != API_SECRET:
        abort(401)


# ---------------------------------------------------------------------------
# XSS-safe escaping pour le dashboard HTML
# ---------------------------------------------------------------------------

def esc(value) -> str:
    """Échappe une valeur pour injection dans du HTML via innerHTML."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Routes — lecture (pas d'auth requise)
# ---------------------------------------------------------------------------

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
        FROM events
        ORDER BY id DESC
        LIMIT ?
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
        FROM events
        WHERE src IS NOT NULL
        GROUP BY src
        ORDER BY COUNT(*) DESC
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

        row = {
            "ip":       src,
            "count":    count,
            "ports":    sorted(ports),
            "analysis": what_raw or "",
        }
        (blocked if src in blocked_set else not_blocked).append(row)

    return jsonify({
        "ok":            blocked_info["ok"],
        "blocked":       blocked,
        "not_blocked":   not_blocked,
        "blocked_count": len(blocked_info["ips"]),
        "error":         blocked_info["error"],
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
        FROM events
        WHERE src = ? OR dst = ?
        ORDER BY id DESC
        LIMIT 50
    """, (ip, ip))
    rows = cur.fetchall()
    conn.close()

    keys = ["ts", "src", "dst", "proto", "dport", "ports",
            "event_type", "severity", "title", "what", "risk", "do"]
    return jsonify({"ip": ip, "count": len(rows), "events": [dict(zip(keys, r)) for r in rows]})


# ---------------------------------------------------------------------------
# Routes — écriture (auth vérifiée)
# ---------------------------------------------------------------------------

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
    """Supprime les règles Windows Firewall pour une IP donnée."""
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


# ---------------------------------------------------------------------------
# Dashboard HTML — toutes les valeurs passent par esc() avant innerHTML
# ---------------------------------------------------------------------------

DASH_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Alert & Explain - Dashboard</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    table { border-collapse: collapse; width: 100%; margin-top: 10px; }
    th, td { border: 1px solid #ddd; padding: 8px; font-size: 14px; vertical-align: top; }
    th { background: #f3f3f3; }
    .HIGH { font-weight: bold; color: #b00020; }
    .MEDIUM { font-weight: bold; color: #e07000; }
    button { margin-right: 8px; padding: 6px 10px; cursor: pointer; }
    .rowbtn { padding: 3px 8px; }
    #err { color: #b00020; margin-top: 8px; white-space: pre-wrap; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
    .card { border: 1px solid #ddd; padding: 12px; border-radius: 8px; }
    .muted { color: #666; }
  </style>
</head>
<body>
  <h2>Alert & Explain — Dashboard</h2>
  <p class="muted">Dernières alertes (auto-refresh toutes les 2s)</p>

  <div style="margin:10px 0;">
    <button id="btnStart">▶ Start scan</button>
    <button id="btnStop">⏹ Stop scan</button>
    <button id="btnDeleteAll">🗑 Supprimer tout</button>
    <span id="state" style="margin-left:10px;"></span>
  </div>
  <div id="err"></div>

  <table id="t">
    <thead>
      <tr>
        <th>Del</th><th>ID</th><th>Time</th><th>Type</th><th>Sev</th>
        <th>Src</th><th>Dst</th><th>Proto</th><th>Port</th><th>Détails</th><th>Actions</th>
      </tr>
    </thead>
    <tbody></tbody>
  </table>

  <h3 style="margin-top:24px;">Analyse IPs détectées</h3>
  <div class="grid">
    <div class="card">
      <b>Bloquées (Windows Firewall)</b>
      <div class="muted" id="blocked_meta"></div>
      <table id="tb_blocked">
        <thead><tr><th>IP</th><th>Events</th><th>Ports</th><th>Analyse</th><th>Actions</th></tr></thead>
        <tbody></tbody>
      </table>
    </div>
    <div class="card">
      <b>Suspectes non bloquées</b>
      <div class="muted">IPs vues dans les events mais pas encore bloquées.</div>
      <table id="tb_not_blocked">
        <thead><tr><th>IP</th><th>Events</th><th>Ports</th><th>Analyse</th><th>Actions</th></tr></thead>
        <tbody></tbody>
      </table>
    </div>
  </div>

  <h3 style="margin-top:24px;">Inspection IP</h3>
  <div class="card">
    <div id="inspect_title"><b>Aucune IP sélectionnée</b></div>
    <table id="tb_inspect">
      <thead><tr><th>Time</th><th>Src</th><th>Dst</th><th>Proto</th><th>Port</th><th>Type</th><th>Sev</th><th>Détails</th></tr></thead>
      <tbody></tbody>
    </table>
  </div>

<script>
// ---------------------------------------------------------------------------
// XSS-safe helper : encode toutes les valeurs avant injection dans le DOM
// ---------------------------------------------------------------------------
function esc(v) {
  if (v === null || v === undefined) return "";
  return String(v)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

let currentInspectIp = null;

function setErr(msg) { document.getElementById("err").textContent = msg || ""; }

async function api(url, body=null) {
  try {
    const opt = { method: body ? "POST" : "GET", cache: "no-store" };
    if (body) {
      opt.headers = {"Content-Type":"application/json"};
      opt.body = JSON.stringify(body);
    }
    const full = url + (url.includes("?") ? "&" : "?") + "t=" + Date.now();
    const r    = await fetch(full, opt);
    const txt  = await r.text();
    if (!r.ok) throw new Error("HTTP " + r.status + " :: " + txt);
    setErr("");
    return JSON.parse(txt);
  } catch(e) {
    setErr("Erreur API: " + e.message);
    throw e;
  }
}

async function refreshState() {
  const s = await api("/control");
  document.getElementById("state").textContent = "Scan: " + (s.scan_enabled ? "ON ✅" : "OFF ⏹");
}

async function refreshEvents() {
  const data = await api("/events?limit=50");
  const tb   = document.querySelector("#t tbody");
  tb.innerHTML = "";
  for (const e of data) {
    const tr = document.createElement("tr");
    // Toutes les valeurs passent par esc() — pas d'innerHTML avec données brutes
    tr.innerHTML =
      `<td><button class="rowbtn" onclick="deleteOne(${parseInt(e.id)||0})">🗑</button></td>` +
      `<td>${esc(e.id)}</td>` +
      `<td>${esc(e.ts)}</td>` +
      `<td>${esc(e.event_type)}</td>` +
      `<td class="${esc(e.severity)}">${esc(e.severity)}</td>` +
      `<td>${esc(e.src)}</td>` +
      `<td>${esc(e.dst)}</td>` +
      `<td>${esc(e.proto)}</td>` +
      `<td>${esc(e.dport)}${e.ports ? " / " + esc(e.ports) : ""}</td>` +
      `<td>${esc(e.title)} — ${esc(e.what)}</td>` +
      `<td>${e.src ? `<button class="rowbtn" onclick="inspectIp(${JSON.stringify(esc(e.src))})">🔎</button>` : ""}</td>`;
    tb.appendChild(tr);
  }
}

async function refreshIps() {
  const data = await api("/ips");
  document.getElementById("blocked_meta").textContent =
    data.ok ? ("Total IP bloquées: " + data.blocked_count) : ("Erreur netsh: " + (data.error || "unknown"));

  function renderIpTable(tbId, rows, showUnblock) {
    const tb = document.querySelector(`#${tbId} tbody`);
    tb.innerHTML = "";
    for (const r of (rows || [])) {
      const tr = document.createElement("tr");
      const unblockBtn = showUnblock
        ? `<button class="rowbtn" onclick="unblockIp(${JSON.stringify(esc(r.ip))})">🔓 Unblock</button>`
        : `<button class="rowbtn" onclick="inspectIp(${JSON.stringify(esc(r.ip))})">🔎</button>`;
      tr.innerHTML =
        `<td>${esc(r.ip)}</td>` +
        `<td>${esc(r.count)}</td>` +
        `<td>${esc((r.ports||[]).join(", "))}</td>` +
        `<td>${esc(r.analysis)}</td>` +
        `<td>${unblockBtn}</td>`;
      tb.appendChild(tr);
    }
  }

  renderIpTable("tb_blocked",     data.blocked,     true);
  renderIpTable("tb_not_blocked", data.not_blocked, false);
}

async function inspectIp(ip) {
  currentInspectIp = ip;
  await refreshInspect();
}

async function refreshInspect() {
  const title = document.getElementById("inspect_title");
  const tb    = document.querySelector("#tb_inspect tbody");
  if (!currentInspectIp) {
    title.innerHTML = "<b>Aucune IP sélectionnée</b>";
    tb.innerHTML    = "";
    return;
  }
  const data = await api("/inspect?ip=" + encodeURIComponent(currentInspectIp));
  title.innerHTML = "<b>IP inspectée :</b> " + esc(data.ip) + " (" + esc(data.count) + " events)";
  tb.innerHTML = "";
  for (const e of (data.events || [])) {
    const tr = document.createElement("tr");
    tr.innerHTML =
      `<td>${esc(e.ts)}</td><td>${esc(e.src)}</td><td>${esc(e.dst)}</td>` +
      `<td>${esc(e.proto)}</td><td>${esc(e.dport||e.ports)}</td>` +
      `<td>${esc(e.event_type)}</td><td>${esc(e.severity)}</td>` +
      `<td>${esc(e.title)} — ${esc(e.what)}</td>`;
    tb.appendChild(tr);
  }
}

async function deleteAll()      { await api("/events/delete", {}); await refreshAll(); }
async function deleteOne(id)    { await api("/events/delete", {id}); await refreshAll(); }
async function startScan() { await api("/scanner/start", {}); await refreshState(); }
async function stopScan()  { await api("/scanner/stop",  {}); await refreshState(); }async function unblockIp(ip) {
  if (!confirm("Débloquer l'IP " + ip + " ?")) return;
  try {
    await api("/ips/unblock", {ip});
    await refreshIps();
  } catch(e) {
    setErr("Unblock failed: " + e.message);
  }
}

async function refreshAll() {
  await refreshState();
  await refreshEvents();
  await refreshIps();
  await refreshInspect();
}

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("btnStart").addEventListener("click", startScan);
  document.getElementById("btnStop").addEventListener("click", stopScan);
  document.getElementById("btnDeleteAll").addEventListener("click", deleteAll);
});

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
      <thead>
        <tr><th>Time</th><th>Src</th><th>Dst</th><th>Proto</th><th>Port</th><th>Type</th><th>Sev</th><th>Détails</th></tr>
      </thead>
      <tbody></tbody>
    </table>
  </div>

<script>
function esc(v) {
  if (v === null || v === undefined) return "";
  return String(v)
    .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
    .replace(/"/g,"&quot;").replace(/'/g,"&#39;");
}

const ip = new URLSearchParams(window.location.search).get("ip");
function setErr(msg) { document.getElementById("err").textContent = msg||""; }

async function api(url) {
  try {
    const r   = await fetch(url+"?t="+Date.now(), {cache:"no-store"});
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