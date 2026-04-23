// ============================================================
// MistralChat.jsx — Composant de chat Mistral AI
// Ajoute ce fichier dans firewall-ui/src/
// ============================================================

import { useState, useRef, useEffect } from "react";

const API = "http://127.0.0.1:5000";

// Suggestions de questions prédéfinies
const SUGGESTIONS = [
  "L'IP détectée est-elle dangereuse ? Que faire ?",
  "Comment bloquer définitivement une IP suspecte ?",
  "Un scan de ports a été détecté, quels sont les risques ?",
  "Comment renforcer la sécurité de mon Windows ?",
  "Que signifie un accès au port 22 (SSH) depuis l'extérieur ?",
  "Comment savoir si mon PC a été compromis ?",
];

export default function MistralChat({ onClose }) {
  const [messages, setMessages]   = useState([
    {
      role: "assistant",
      text: "👋 Bonjour ! Je suis votre assistant Mistral AI. Je connais les événements récents détectés par votre pare-feu AlertExplain. Posez-moi vos questions sur la sécurité de votre réseau !",
    },
  ]);
  const [input, setInput]         = useState("");
  const [loading, setLoading]     = useState(false);
  const bottomRef                 = useRef(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  async function sendMessage(question) {
    const q = question || input.trim();
    if (!q) return;

    setMessages((m) => [...m, { role: "user", text: q }]);
    setInput("");
    setLoading(true);

    try {
      const res  = await fetch(`${API}/mistral/chat`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ question: q }),
      });
      const data = await res.json();

      if (data.answer) {
        setMessages((m) => [...m, { role: "assistant", text: data.answer }]);
      } else {
        setMessages((m) => [...m, { role: "assistant", text: "❌ Erreur : " + (data.error || "Réponse invalide") }]);
      }
    } catch (e) {
      setMessages((m) => [...m, { role: "assistant", text: "❌ Impossible de contacter Mistral AI. Vérifiez que app.py est démarré." }]);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={{
      position:        "fixed",
      inset:           0,
      background:      "rgba(0,0,0,0.7)",
      display:         "flex",
      alignItems:      "center",
      justifyContent:  "center",
      zIndex:          1000,
    }}>
      <div style={{
        background:    "#1a1a2e",
        borderRadius:  "12px",
        width:         "680px",
        maxWidth:      "95vw",
        maxHeight:     "85vh",
        display:       "flex",
        flexDirection: "column",
        boxShadow:     "0 20px 60px rgba(0,0,0,0.5)",
        border:        "1px solid #ff7000",
      }}>

        {/* Header */}
        <div style={{
          padding:        "16px 20px",
          borderBottom:   "1px solid #333",
          display:        "flex",
          alignItems:     "center",
          justifyContent: "space-between",
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <span style={{ fontSize: "24px" }}>🤖</span>
            <div>
              <div style={{ color: "#ff7000", fontWeight: "bold", fontSize: "16px" }}>
                Assistant Mistral AI
              </div>
              <div style={{ color: "#888", fontSize: "12px" }}>
                Conseils de sécurité basés sur vos événements réseau
              </div>
            </div>
          </div>
          <button
            onClick={onClose}
            style={{
              background: "none",
              border:     "none",
              color:      "#888",
              fontSize:   "24px",
              cursor:     "pointer",
              padding:    "0 4px",
            }}
          >×</button>
        </div>

        {/* Messages */}
        <div style={{
          flex:       1,
          overflowY:  "auto",
          padding:    "16px",
          display:    "flex",
          flexDirection: "column",
          gap:        "12px",
        }}>
          {messages.map((msg, i) => (
            <div key={i} style={{
              display:       "flex",
              justifyContent: msg.role === "user" ? "flex-end" : "flex-start",
            }}>
              <div style={{
                maxWidth:     "85%",
                padding:      "10px 14px",
                borderRadius: msg.role === "user" ? "12px 12px 2px 12px" : "12px 12px 12px 2px",
                background:   msg.role === "user" ? "#ff7000" : "#16213e",
                color:        "#fff",
                fontSize:     "14px",
                lineHeight:   "1.5",
                whiteSpace:   "pre-wrap",
                border:       msg.role === "assistant" ? "1px solid #333" : "none",
              }}>
                {msg.role === "assistant" && (
                  <span style={{ fontSize: "16px", marginRight: "6px" }}>🤖</span>
                )}
                {msg.text}
              </div>
            </div>
          ))}

          {loading && (
            <div style={{ display: "flex", justifyContent: "flex-start" }}>
              <div style={{
                padding:      "10px 14px",
                borderRadius: "12px 12px 12px 2px",
                background:   "#16213e",
                border:       "1px solid #333",
                color:        "#888",
                fontSize:     "14px",
              }}>
                🤖 Analyse en cours...
              </div>
            </div>
          )}
          <div ref={bottomRef} />
        </div>

        {/* Suggestions */}
        <div style={{
          padding:    "8px 16px",
          borderTop:  "1px solid #222",
          display:    "flex",
          flexWrap:   "wrap",
          gap:        "6px",
        }}>
          {SUGGESTIONS.map((s, i) => (
            <button
              key={i}
              onClick={() => sendMessage(s)}
              disabled={loading}
              style={{
                background:   "#16213e",
                border:       "1px solid #333",
                color:        "#aaa",
                borderRadius: "20px",
                padding:      "4px 10px",
                fontSize:     "11px",
                cursor:       "pointer",
                transition:   "all 0.2s",
              }}
              onMouseEnter={(e) => {
                e.target.style.borderColor = "#ff7000";
                e.target.style.color = "#ff7000";
              }}
              onMouseLeave={(e) => {
                e.target.style.borderColor = "#333";
                e.target.style.color = "#aaa";
              }}
            >
              {s}
            </button>
          ))}
        </div>

        {/* Input */}
        <div style={{
          padding:     "12px 16px",
          borderTop:   "1px solid #333",
          display:     "flex",
          gap:         "8px",
        }}>
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && !e.shiftKey && sendMessage()}
            placeholder="Posez votre question sur la sécurité..."
            disabled={loading}
            style={{
              flex:         1,
              background:   "#16213e",
              border:       "1px solid #333",
              borderRadius: "8px",
              padding:      "10px 14px",
              color:        "#fff",
              fontSize:     "14px",
              outline:      "none",
            }}
          />
          <button
            onClick={() => sendMessage()}
            disabled={loading || !input.trim()}
            style={{
              background:   loading || !input.trim() ? "#333" : "#ff7000",
              border:       "none",
              borderRadius: "8px",
              padding:      "10px 16px",
              color:        "#fff",
              cursor:       loading || !input.trim() ? "not-allowed" : "pointer",
              fontSize:     "14px",
              fontWeight:   "bold",
              transition:   "background 0.2s",
            }}
          >
            {loading ? "..." : "Envoyer"}
          </button>
        </div>

      </div>
    </div>
  );
}
