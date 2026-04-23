

import { useState, useEffect, useRef } from "react";
import MistralChat from "./MistralChat";

const API = "http://127.0.0.1:5000";
const API_SECRET = import.meta.env?.VITE_API_SECRET || "";

const FONT = `@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Barlow:wght@400;600;700&display=swap');`;

const css = `
  ${FONT}
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg: #0a0c0f; --panel: #111418; --border: #1e2530; --accent: #00e5ff;
    --warn: #ff6b35; --ok: #39ff14; --dim: #3a4455; --text: #c8d6e5;
    --muted: #5a6a7e; --mono: 'Share Tech Mono', monospace; --sans: 'Barlow', sans-serif;
  }
  body { background: var(--bg); color: var(--text); font-family: var(--sans); }
  .app { min-height: 100vh; display: grid; grid-template-rows: auto 1fr;
    background: repeating-linear-gradient(0deg,transparent,transparent 39px,var(--border) 39px,var(--border) 40px),
                repeating-linear-gradient(90deg,transparent,transparent 39px,var(--border) 39px,var(--border) 40px);
    background-size: 40px 40px; }
  .topbar { background: rgba(10,12,15,0.95); border-bottom: 2px solid var(--accent);
    padding: 0 28px; display: flex; align-items: center; gap: 20px; height: 56px;
    backdrop-filter: blur(8px); position: sticky; top: 0; z-index: 100; }
  .logo { font-family: var(--mono); font-size: 18px; color: var(--accent); letter-spacing: 2px; text-transform: uppercase; }
  .logo span { color: var(--warn); }
  .status-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--ok); box-shadow: 0 0 6px var(--ok); animation: pulse 2s infinite; }
  .status-dot.off { background: var(--warn); box-shadow: 0 0 6px var(--warn); }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }
  .status-label { font-family: var(--mono); font-size: 11px; color: var(--ok); letter-spacing: 1px; }
  .status-label.off { color: var(--warn); }
  .spacer { flex: 1; }
  .ts { font-family: var(--mono); font-size: 11px; color: var(--muted); letter-spacing: 1px; }
  .nav { display: flex; gap: 2px; margin-left: 20px; }
  .nav-btn { background: transparent; border: 1px solid transparent; color: var(--muted);
    font-family: var(--mono); font-size: 11px; letter-spacing: 1px; text-transform: uppercase;
    padding: 6px 14px; cursor: pointer; transition: all .15s; }
  .nav-btn:hover { color: var(--text); border-color: var(--dim); }
  .nav-btn.active { color: var(--accent); border-color: var(--accent); background: rgba(0,229,255,0.06); }
  .main { padding: 28px; display: flex; flex-direction: column; gap: 20px; max-width: 1300px; width: 100%; margin: 0 auto; }
  .panel { background: rgba(17,20,24,0.92); border: 1px solid var(--border); backdrop-filter: blur(4px); }
  .panel-header { border-bottom: 1px solid var(--border); padding: 12px 20px; display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .panel-title { font-family: var(--mono); font-size: 11px; text-transform: uppercase; letter-spacing: 2px; color: var(--accent); }
  .badge { font-family: var(--mono); font-size: 10px; padding: 2px 7px;
    background: rgba(0,229,255,0.1); border: 1px solid rgba(0,229,255,0.3); color: var(--accent); }
  .badge.warn { background: rgba(255,107,53,0.1); border-color: rgba(255,107,53,0.3); color: var(--warn); }
  .badge.ok   { background: rgba(57,255,20,0.1);  border-color: rgba(57,255,20,0.3);  color: var(--ok); }
  .badge.red  { background: rgba(255,68,68,0.1);  border-color: rgba(255,68,68,0.3);  color: #ff4444; }
  .rules-table { width: 100%; border-collapse: collapse; }
  .rules-table th { font-family: var(--mono); font-size: 10px; text-transform: uppercase;
    letter-spacing: 1.5px; color: var(--muted); text-align: left; padding: 10px 16px; border-bottom: 1px solid var(--border); }
  .rules-table td { font-family: var(--mono); font-size: 12px; padding: 10px 16px;
    border-bottom: 1px solid rgba(30,37,48,0.5); color: var(--text); }
  .rules-table tr:hover td { background: rgba(0,229,255,0.03); }
  .sev-HIGH   { color: #ff4444; font-weight: bold; }
  .sev-MEDIUM { color: var(--warn); }
  .sev-LOW    { color: var(--muted); }
  .icon-btn { background: transparent; border: 1px solid var(--dim); color: var(--muted);
    font-size: 12px; padding: 3px 8px; cursor: pointer; font-family: var(--mono); transition: all .15s; margin-right: 4px; }
  .icon-btn:hover { color: var(--accent); border-color: var(--accent); }
  .icon-btn.del:hover { color: #ff4444; border-color: #ff4444; }
  .icon-btn.inspect { color: var(--accent); border-color: var(--accent); }
  .block-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; padding: 20px; }
  .block-input-row { display: flex; gap: 8px; margin-bottom: 16px; }
  .block-input-row input { flex: 1; background: var(--bg); border: 1px solid var(--dim);
    color: var(--text); font-family: var(--mono); font-size: 12px; padding: 7px 10px; outline: none; }
  .block-input-row input:focus { border-color: var(--accent); }
  .blocked-list { display: flex; flex-direction: column; gap: 4px; }
  .blocked-item { display: flex; align-items: center; justify-content: space-between;
    padding: 7px 10px; border: 1px solid var(--border); background: rgba(255,68,68,0.04); }
  .blocked-item span { font-family: var(--mono); font-size: 12px; color: #ff8888; }
  .stats-row { display: grid; grid-template-columns: repeat(4,1fr); gap: 12px; }
  .stat-card { background: rgba(17,20,24,0.92); border: 1px solid var(--border); padding: 16px 20px; }
  .stat-label { font-family: var(--mono); font-size: 10px; text-transform: uppercase; letter-spacing: 1.5px; color: var(--muted); margin-bottom: 6px; }
  .stat-value { font-family: var(--mono); font-size: 26px; font-weight: 700; color: var(--accent); }
  .stat-value.warn { color: var(--warn); } .stat-value.ok { color: var(--ok); } .stat-value.red { color: #ff4444; }
  .empty { padding: 30px; text-align: center; font-family: var(--mono); font-size: 12px; color: var(--muted); }
  .err-bar { background: rgba(255,68,68,0.1); border: 1px solid rgba(255,68,68,0.3);
    color: #ff8888; font-family: var(--mono); font-size: 11px; padding: 8px 16px; margin: 0 28px; }
  .btn { font-family: var(--mono); font-size: 11px; letter-spacing: 1px; text-transform: uppercase;
    padding: 8px 18px; cursor: pointer; border: none; transition: all .15s; }
  .btn-primary { background: var(--accent); color: #000; }
  .btn-primary:hover { background: #fff; }
  .btn-secondary { background: transparent; border: 1px solid var(--dim); color: var(--muted); }
  .btn-secondary:hover { border-color: var(--text); color: var(--text); }
  .btn-danger { background: transparent; border: 1px solid rgba(255,68,68,0.4); color: #ff6666; }
  .btn-danger:hover { background: rgba(255,68,68,0.1); }
  .btn-mistral { background: transparent; border: 1px solid #ff7000; color: #ff7000;
    font-family: var(--mono); font-size: 11px; letter-spacing: 1px; text-transform: uppercase;
    padding: 6px 14px; cursor: pointer; transition: all .15s; }
  .btn-mistral:hover { background: rgba(255,112,0,0.15); color: #ffaa44; border-color: #ffaa44; }

  /* Inspect modal */
  .modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.75);
    display: flex; align-items: center; justify-content: center; z-index: 200; backdrop-filter: blur(4px); }
  .modal { background: #0d1117; border: 1px solid var(--accent); width: 90%; max-width: 1100px;
    max-height: 80vh; display: flex; flex-direction: column; }
  .modal-header { padding: 14px 20px; border-bottom: 1px solid var(--border);
    display: flex; align-items: center; gap: 12px; }
  .modal-title { font-family: var(--mono); font-size: 13px; color: var(--accent); letter-spacing: 1px; flex: 1; }
  .modal-close { background: transparent; border: 1px solid var(--dim); color: var(--muted);
    font-family: var(--mono); font-size: 12px; padding: 4px 12px; cursor: pointer; }
  .modal-close:hover { color: #ff4444; border-color: #ff4444; }
  .modal-stats { display: grid; grid-template-columns: repeat(3,1fr); gap: 12px; padding: 16px 20px;
    border-bottom: 1px solid var(--border); }
  .modal-stat-label { font-family: var(--mono); font-size: 10px; text-transform: uppercase;
    letter-spacing: 1px; color: var(--muted); margin-bottom: 4px; }
  .modal-stat-value { font-family: var(--mono); font-size: 20px; font-weight: 700; color: var(--accent); }
  .modal-body { overflow-y: auto; flex: 1; }
  .modal-body::-webkit-scrollbar { width: 4px; }
  .modal-body::-webkit-scrollbar-track { background: var(--border); }
  .modal-body::-webkit-scrollbar-thumb { background: var(--dim); }
  .modal-empty { padding: 40px; text-align: center; font-family: var(--mono); font-size: 12px; color: var(--muted); }
`;

async function apiFetch(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(API_SECRET ? { "X-API-Key": API_SECRET } : {}) };
  const res = await fetch(`${API}${path}`, { ...options, headers: { ...headers, ...options.headers } });
  if (!res.ok) throw new Error(`API ${path} → HTTP ${res.status}`);
  return res.json();
}

const apiGet  = (path)       => apiFetch(path);
const apiPost = (path, body) => apiFetch(path, { method: "POST", body: JSON.stringify(body) });

// ---------------------------------------------------------------------------
// Inspect Modal
// ---------------------------------------------------------------------------

function InspectModal({ ip, onClose }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        const result = await apiGet(`/inspect?ip=${encodeURIComponent(ip)}`);
        if (active) { setData(result); setLoading(false); }
      } catch { if (active) setLoading(false); }
    }
    load();
    const id = setInterval(load, 3000);
    return () => { active = false; clearInterval(id); };
  }, [ip]);

  return (
    <div className="modal-overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="modal">
        <div className="modal-header">
          <div className="modal-title">🔎 INSPECTION — {ip}</div>
          {data && <div className="badge">{data.count} ÉVÉNEMENTS</div>}
          <button className="modal-close" onClick={onClose}>✕ Fermer</button>
        </div>

        {data && (
          <div className="modal-stats">
            <div>
              <div className="modal-stat-label">IP</div>
              <div className="modal-stat-value" style={{fontSize:14,color:"#ff8888"}}>{data.ip}</div>
            </div>
            <div>
              <div className="modal-stat-label">Événements</div>
              <div className="modal-stat-value">{data.count}</div>
            </div>
            <div>
              <div className="modal-stat-label">Dernière activité</div>
              <div className="modal-stat-value" style={{fontSize:13}}>
                {data.events?.[0]?.ts?.slice(11,19) || "—"}
              </div>
            </div>
          </div>
        )}

        <div className="modal-body">
          {loading && <div className="modal-empty">Chargement...</div>}
          {!loading && (!data || data.events?.length === 0) && (
            <div className="modal-empty">Aucun événement pour cette IP.</div>
          )}
          {!loading && data?.events?.length > 0 && (
            <table className="rules-table">
              <thead>
                <tr>
                  <th>Time</th><th>Type</th><th>Sév.</th><th>Src</th>
                  <th>Dst</th><th>Proto</th><th>Port</th><th>Détails</th>
                </tr>
              </thead>
              <tbody>
                {data.events.map((e, i) => (
                  <tr key={i}>
                    <td>{e.ts?.slice(11,19) || "—"}</td>
                    <td>{e.event_type}</td>
                    <td className={`sev-${e.severity}`}>{e.severity}</td>
                    <td style={{color: e.src === ip ? "#ff8888" : "var(--text)"}}>{e.src || "—"}</td>
                    <td>{e.dst || "—"}</td>
                    <td>{e.proto || "—"}</td>
                    <td>{e.dport || e.ports || "—"}</td>
                    <td style={{maxWidth:300,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>
                      {e.title} — {e.what}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export default function FirewallManager() {
  const [tab, setTab]             = useState("events");
  const [scanOn, setScanOn]       = useState(true);
  const [events, setEvents]       = useState([]);
  const [ipsData, setIpsData]     = useState({ blocked: [], not_blocked: [], blocked_count: 0 });
  const [ipInput, setIpInput]     = useState("");
  const [error, setError]         = useState("");
  const [time, setTime]           = useState(new Date());
  const [inspectIp, setInspectIp] = useState(null);
  const [showMistral, setShowMistral] = useState(false);  // ← NOUVEAU

  useEffect(() => {
    const id = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 2000);
    return () => clearInterval(id);
  }, []);

  async function refresh() {
    try {
      const [ctrl, evts, ips] = await Promise.all([
        apiGet("/scanner/status"),
        apiGet("/events?limit=80"),
        apiGet("/ips"),
      ]);
      setScanOn(ctrl.running);
      setEvents(evts);
      setIpsData(ips);
      setError("");
    } catch (e) {
      setError(`API Flask non joignable (${e.message}). Lance app.py d'abord.`);
    }
  }

  async function toggleScan() {
    try {
      const status = await apiGet("/scanner/status");
      if (status.running) {
        await apiPost("/scanner/stop", {});
        setScanOn(false);
      } else {
        await apiPost("/scanner/start", {});
        setScanOn(true);
      }
    } catch (e) { setError(e.message); }
  }

  async function deleteEvent(id) {
    try { await apiPost("/events/delete", { id }); setEvents(ev => ev.filter(e => e.id !== id)); }
    catch (e) { setError(e.message); }
  }

  async function deleteAllEvents() {
    try { await apiPost("/events/delete", {}); setEvents([]); }
    catch (e) { setError(e.message); }
  }

  async function unblockIP(ip) {
    try { await apiPost("/ips/unblock", { ip }); await refresh(); }
    catch (e) { setError(e.message); }
  }

  async function blockIPManual() {
    const ip = ipInput.trim();
    if (!ip) return;
    try {
      await apiPost("/events", {
        event_type: "BLOCKED_IP", severity: "HIGH", title: "Blocage manuel",
        proto: "MANUAL", src: ip, what: "Blocage manuel depuis le dashboard",
        risk: "Manuel", do: "Surveiller."
      });
      setIpInput("");
      await refresh();
    } catch (e) { setError(e.message); }
  }

  const highCount    = events.filter(e => e.severity === "HIGH").length;
  const blockedCount = ipsData.blocked_count || 0;
  const scanCount    = events.filter(e => e.event_type === "PORT_SCAN").length;
  const fileCount    = events.filter(e => e.event_type?.startsWith("FILE")).length;

  return (
    <>
      <style>{css}</style>

      {/* INSPECT MODAL */}
      {inspectIp && <InspectModal ip={inspectIp} onClose={() => setInspectIp(null)} />}

      {/* MISTRAL CHAT MODAL */}
      {showMistral && <MistralChat onClose={() => setShowMistral(false)} />}

      <div className="app">
        {/* TOPBAR */}
        <div className="topbar">
          <div className="logo">FW<span>/</span>MGR</div>
          <div className={`status-dot${scanOn ? "" : " off"}`} />
          <div className={`status-label${scanOn ? "" : " off"}`}>
            {scanOn ? "SCAN ACTIF" : "SCAN ARRÊTÉ"}
          </div>
          <div className="nav">
            {[["events","Événements"],["ips","IPs"],["block","Bloquer"],["files","Fichiers"]].map(([t,l]) => (
              <button key={t} className={`nav-btn${tab===t?" active":""}`} onClick={() => setTab(t)}>{l}</button>
            ))}
          </div>
          <div className="spacer" />

          {/* BOUTON MISTRAL AI */}
          <button className="btn-mistral" onClick={() => setShowMistral(true)} style={{marginRight: 12}}>
            🤖 Assistant Mistral
          </button>

          <button className="btn btn-secondary" style={{marginRight:8}} onClick={toggleScan}>
            {scanOn ? "⏹ Stop" : "▶ Start"}
          </button>
          <div className="ts">{time.toLocaleTimeString()}</div>
        </div>

        {error && <div className="err-bar">⚠ {error}</div>}

        <div className="main">
          {/* STATS */}
          <div className="stats-row">
            <div className="stat-card">
              <div className="stat-label">Événements</div>
              <div className="stat-value ok">{events.length}</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Alertes HIGH</div>
              <div className="stat-value red">{highCount}</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">IPs bloquées</div>
              <div className="stat-value warn">{blockedCount}</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Scans détectés</div>
              <div className="stat-value red">{scanCount}</div>
            </div>
          </div>

          {/* EVENTS TAB */}
          {tab === "events" && (
            <div className="panel">
              <div className="panel-header">
                <div className="panel-title">Événements réseau</div>
                <div className="badge">{events.length} TOTAL</div>
                <div className="badge red">{highCount} HIGH</div>
                <div className="spacer" />
                <button className="btn btn-danger" onClick={deleteAllEvents}>🗑 Tout effacer</button>
              </div>
              {events.length === 0
                ? <div className="empty">Aucun événement.</div>
                : (
                  <table className="rules-table">
                    <thead><tr>
                      <th>Time</th><th>Type</th><th>Sév.</th><th>Src</th>
                      <th>Proto</th><th>Port</th><th>Détails</th><th></th>
                    </tr></thead>
                    <tbody>
                      {events.map(e => (
                        <tr key={e.id}>
                          <td>{e.ts?.slice(11,19) || "—"}</td>
                          <td>{e.event_type}</td>
                          <td className={`sev-${e.severity}`}>{e.severity}</td>
                          <td>{e.src || "—"}</td>
                          <td>{e.proto || "—"}</td>
                          <td>{e.dport || e.ports || "—"}</td>
                          <td style={{maxWidth:300,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>
                            {e.title} — {e.what}
                          </td>
                          <td style={{whiteSpace:"nowrap"}}>
                            {e.src && (
                              <button className="icon-btn inspect" onClick={() => setInspectIp(e.src)}>🔎</button>
                            )}
                            <button className="icon-btn del" onClick={() => deleteEvent(e.id)}>✕</button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )
              }
            </div>
          )}

          {/* IPS TAB */}
          {tab === "ips" && (
            <div style={{display:"flex",flexDirection:"column",gap:16}}>
              <div className="panel">
                <div className="panel-header">
                  <div className="panel-title">IPs bloquées</div>
                  <div className="badge red">{blockedCount} TOTAL</div>
                </div>
                {ipsData.blocked.length === 0
                  ? <div className="empty">Aucune IP bloquée.</div>
                  : (
                    <table className="rules-table">
                      <thead><tr><th>IP</th><th>Événements</th><th>Ports</th><th>Analyse</th><th></th></tr></thead>
                      <tbody>
                        {ipsData.blocked.map(r => (
                          <tr key={r.ip}>
                            <td style={{color:"#ff8888"}}>{r.ip}</td>
                            <td>{r.count}</td>
                            <td>{(r.ports||[]).join(", ") || "—"}</td>
                            <td style={{maxWidth:260,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{r.analysis}</td>
                            <td style={{whiteSpace:"nowrap"}}>
                              <button className="icon-btn inspect" onClick={() => setInspectIp(r.ip)}>🔎</button>
                              <button className="icon-btn" onClick={() => unblockIP(r.ip)}>🔓 Unblock</button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )
                }
              </div>

              <div className="panel">
                <div className="panel-header">
                  <div className="panel-title">IPs suspectes — non bloquées</div>
                  <div className="badge warn">{ipsData.not_blocked.length} TOTAL</div>
                </div>
                {ipsData.not_blocked.length === 0
                  ? <div className="empty">Aucune IP suspecte.</div>
                  : (
                    <table className="rules-table">
                      <thead><tr><th>IP</th><th>Événements</th><th>Ports</th><th>Analyse</th><th></th></tr></thead>
                      <tbody>
                        {ipsData.not_blocked.map(r => (
                          <tr key={r.ip}>
                            <td style={{color:"var(--warn)"}}>{r.ip}</td>
                            <td>{r.count}</td>
                            <td>{(r.ports||[]).join(", ") || "—"}</td>
                            <td style={{maxWidth:300,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{r.analysis}</td>
                            <td>
                              <button className="icon-btn inspect" onClick={() => setInspectIp(r.ip)}>🔎</button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )
                }
              </div>
            </div>
          )}

          {/* BLOCK TAB */}
          {tab === "block" && (
            <div className="panel">
              <div className="panel-header">
                <div className="panel-title">Blocage manuel d'IP</div>
                <div className="badge warn">netsh advfirewall</div>
              </div>
              <div className="block-grid">
                <div>
                  <div className="panel-title" style={{marginBottom:12}}>Bloquer une IP</div>
                  <div className="block-input-row">
                    <input
                      placeholder="ex: 203.0.113.42"
                      value={ipInput}
                      onChange={e => setIpInput(e.target.value)}
                      onKeyDown={e => e.key === "Enter" && blockIPManual()}
                    />
                    <button className="btn btn-primary" onClick={blockIPManual}>Bloquer</button>
                  </div>
                </div>
                <div>
                  <div className="panel-title" style={{marginBottom:12}}>IPs actuellement bloquées</div>
                  <div className="blocked-list">
                    {ipsData.blocked.length === 0
                      ? <div style={{fontFamily:"var(--mono)",fontSize:11,color:"var(--muted)"}}>Aucune IP bloquée.</div>
                      : ipsData.blocked.map(r => (
                        <div className="blocked-item" key={r.ip}>
                          <span>⛔ {r.ip}</span>
                          <div>
                            <button className="icon-btn inspect" onClick={() => setInspectIp(r.ip)}>🔎</button>
                            <button className="icon-btn del" onClick={() => unblockIP(r.ip)}>Unblock</button>
                          </div>
                        </div>
                      ))
                    }
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* FILES TAB */}
          {tab === "files" && (
            <div className="panel">
              <div className="panel-header">
                <div className="panel-title">Événements fichiers</div>
                <div className="badge">{fileCount} TOTAL</div>
              </div>
              {fileCount === 0
                ? <div className="empty">Aucun événement fichier. Watchdog surveille Downloads/ et Desktop/.</div>
                : (
                  <table className="rules-table">
                    <thead><tr>
                      <th>Time</th><th>Type</th><th>Sév.</th><th>Fichier</th><th>Risque</th><th>Action</th>
                    </tr></thead>
                    <tbody>
                      {events.filter(e => e.event_type?.startsWith("FILE")).map(e => (
                        <tr key={e.id}>
                          <td>{e.ts?.slice(11,19) || "—"}</td>
                          <td>{e.event_type}</td>
                          <td className={`sev-${e.severity}`}>{e.severity}</td>
                          <td style={{maxWidth:200,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{e.what}</td>
                          <td style={{maxWidth:220,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{e.risk}</td>
                          <td style={{color:"var(--muted)"}}>{e.do}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )
              }
            </div>
          )}
        </div>
      </div>
    </>
  );
}
