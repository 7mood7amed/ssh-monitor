import React, { useEffect, useMemo, useState, useCallback } from "react";
import API_BASE_URL from "../config";
import "../components/FtpLogs.css";

// ── Helpers ──────────────────────────────────────────────────────────────────

function PriorityBadge({ priority }) {
  const p = (priority || "").toLowerCase();
  return (
    <span className={`pri pri-${p}`}>
      {priority || "—"}
    </span>
  );
}

function StatusBadge({ status }) {
  const s = (status || "new").toLowerCase();
  return (
    <span className={`sta sta-${s}`}>
      {status || "new"}
    </span>
  );
}

function SourceBadge({ source }) {
  const colors = {
    ssh: { color: "#a855f7", bg: "rgba(168,85,247,0.09)", border: "rgba(168,85,247,0.28)" },
    ftp: { color: "#00d4ff", bg: "rgba(0,212,255,0.09)", border: "rgba(0,212,255,0.28)" },
    web: { color: "#00ff88", bg: "rgba(0,255,136,0.09)", border: "rgba(0,255,136,0.26)" },
    nmap: { color: "#ffaa00", bg: "rgba(255,170,0,0.09)", border: "rgba(255,170,0,0.28)" },
    tshark: { color: "#ff3366", bg: "rgba(255,51,102,0.09)", border: "rgba(255,51,102,0.28)" },
    correlation: { color: "#f59e0b", bg: "rgba(245,158,11,0.09)", border: "rgba(245,158,11,0.26)" },
  };
  const c = colors[(source || "").toLowerCase()] || { color: "#94a3b8", bg: "rgba(148,163,184,0.07)", border: "rgba(148,163,184,0.20)" };
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", height: 20,
      padding: "0 8px", borderRadius: 999, fontSize: 11, fontWeight: 700,
      textTransform: "uppercase", letterSpacing: "0.05em",
      color: c.color, background: c.bg, border: `1px solid ${c.border}`,
    }}>
      {source || "—"}
    </span>
  );
}

// ── Critical banner ───────────────────────────────────────────────────────────

function CriticalBanner({ alerts }) {
  if (!alerts.length) return null;
  return (
    <div style={{
      marginBottom: 14,
      padding: "12px 16px",
      borderRadius: 10,
      border: "1px solid rgba(255,51,102,0.45)",
      background: "rgba(255,51,102,0.08)",
      animation: "raven-pulse 2s ease-in-out infinite",
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
        <span style={{ fontSize: 16 }}>⚠</span>
        <span style={{ fontWeight: 700, color: "#ff3366", fontSize: 13 }}>
          {alerts.length} CRITICAL ALERT{alerts.length > 1 ? "S" : ""} — IMMEDIATE ATTENTION REQUIRED
        </span>
      </div>
      {alerts.slice(0, 3).map(a => (
        <div key={a.id} style={{ fontSize: 12, color: "rgba(226,232,240,0.80)", display: "flex", gap: 8, marginTop: 3 }}>
          <SourceBadge source={a.source} />
          <span style={{ fontWeight: 600 }}>{a.title}</span>
          {a.ip_address && (
            <span style={{ fontFamily: "monospace", color: "#00d4ff", fontSize: 11 }}>{a.ip_address}</span>
          )}
        </div>
      ))}
    </div>
  );
}

// ── Alert card row (no horizontal scroll) ────────────────────────────────────

function AlertCard({ alert, selected, onSelect, onAction }) {
  const p = (alert.priority || "").toLowerCase();

  const cardStyle = {
    background: selected ? "rgba(0,212,255,0.04)" : "#0b1221",
    border: selected
      ? "1px solid rgba(0,212,255,0.35)"
      : p === "critical"
        ? "1px solid rgba(255,51,102,0.28)"
        : "1px solid rgba(0,212,255,0.09)",
    borderLeft: p === "critical"
      ? "3px solid rgba(255,51,102,0.60)"
      : p === "high"
        ? "3px solid rgba(255,170,0,0.45)"
        : "3px solid transparent",
    borderRadius: 10,
    padding: "12px 14px",
    cursor: "pointer",
    transition: "border-color 0.15s, background 0.15s",
    marginBottom: 6,
  };

  const ts = alert.created_at
    ? new Date(alert.created_at).toLocaleString("en-GB", {
      day: "2-digit", month: "2-digit", year: "2-digit",
      hour: "2-digit", minute: "2-digit",
    })
    : "—";

  return (
    <div style={cardStyle} onClick={() => onSelect(alert.id)}>
      {/* Row 1: badges + title + actions */}
      <div style={{ display: "flex", alignItems: "flex-start", gap: 10, flexWrap: "wrap" }}>
        {/* Left: badges */}
        <div style={{ display: "flex", gap: 6, alignItems: "center", flexShrink: 0 }}>
          <PriorityBadge priority={alert.priority} />
          <StatusBadge status={alert.status} />
          <SourceBadge source={alert.source} />
        </div>

        {/* Centre: title + meta */}
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontWeight: 600, fontSize: 13, color: "#e2e8f0", lineHeight: 1.3 }}>
            {p === "critical" && <span style={{ color: "#ff3366", marginRight: 5 }}>⚠</span>}
            {alert.title}
          </div>
          <div style={{ display: "flex", gap: 10, marginTop: 3, flexWrap: "wrap", alignItems: "center" }}>
            <span style={{ fontFamily: "monospace", fontSize: 11, color: "rgba(226,232,240,0.40)" }}>{ts}</span>
            {alert.ip_address && (
              <span style={{
                fontFamily: "monospace", fontSize: 11, color: "#00d4ff",
                background: "rgba(0,212,255,0.08)", border: "1px solid rgba(0,212,255,0.18)",
                borderRadius: 4, padding: "1px 6px",
              }}>
                {alert.ip_address}
              </span>
            )}
            {alert.user_name && (
              <span style={{ fontSize: 11, color: "rgba(226,232,240,0.45)" }}>
                user: {alert.user_name}
              </span>
            )}
          </div>
        </div>

        {/* Right: actions */}
        <div
          style={{ display: "flex", gap: 5, flexShrink: 0, flexWrap: "nowrap" }}
          onClick={e => e.stopPropagation()}
        >
          <button className="btn btn-sm" onClick={() => onSelect(alert.id)}>View</button>
          <button className="btn btn-sm" onClick={() => onAction(alert.id, "acknowledged")}>Ack</button>
          <button className="btn btn-sm" onClick={() => onAction(alert.id, "resolved")}>Resolve</button>
          <button
            className="btn btn-sm"
            onClick={() => window.open(`${API_BASE_URL}/api/alerts/${alert.id}/export_csv`, "_blank")}
          >
            CSV
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Investigation panel ───────────────────────────────────────────────────────

function InvestigationPanel({ alertId }) {
  const [details, setDetails] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!alertId) { setDetails(null); return; }
    setLoading(true);
    fetch(`${API_BASE_URL}/api/alerts/${alertId}`)
      .then(r => r.json())
      .then(d => { setDetails(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, [alertId]);

  if (!alertId) return (
    <div style={{ color: "rgba(226,232,240,0.40)", fontSize: 13, marginTop: 20, textAlign: "center" }}>
      Select an alert to investigate
    </div>
  );

  if (loading) return (
    <div style={{ color: "rgba(226,232,240,0.55)", fontSize: 13, marginTop: 20 }}>Loading…</div>
  );

  if (!details) return null;

  const a = details.alert || {};
  const items = details.linked_items || [];

  return (
    <div>
      {/* Alert info */}
      <div style={{ marginBottom: 14 }}>
        <div style={{ fontWeight: 700, fontSize: 15, color: "#e2e8f0", marginBottom: 6 }}>{a.title}</div>
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 8 }}>
          <PriorityBadge priority={a.priority} />
          <StatusBadge status={a.status} />
          <SourceBadge source={a.source} />
        </div>
        {a.ip_address && (
          <div style={{ fontFamily: "monospace", fontSize: 12, color: "#00d4ff", marginBottom: 6 }}>
            IP: {a.ip_address}
          </div>
        )}
        <div style={{ fontSize: 12, color: "rgba(226,232,240,0.65)", lineHeight: 1.6, whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
          {a.description}
        </div>
      </div>

      {/* Evidence */}
      <div style={{ fontSize: 11, fontWeight: 700, color: "rgba(0,212,255,0.65)", textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 8 }}>
        Linked Evidence ({items.length})
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 7, maxHeight: 460, overflowY: "auto" }}>
        {items.length === 0 && (
          <div style={{ color: "rgba(226,232,240,0.40)", fontSize: 12 }}>No linked evidence.</div>
        )}
        {items.map((it, i) => (
          <div key={i} className="inv-evidence-item">
            <div style={{ display: "flex", justifyContent: "space-between", gap: 8, marginBottom: 5 }}>
              <span className="inv-evidence-type">{it.log_type}</span>
              <span className="inv-evidence-ts">{it.time}</span>
            </div>
            <div className="inv-evidence-msg">{it.message}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Main AlertsPage ───────────────────────────────────────────────────────────

export default function AlertsPage({ refreshTrigger }) {
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [priority, setPriority] = useState("all");
  const [status, setStatus] = useState("all");
  const [q, setQ] = useState("");
  const [includeInternal, setIncludeInternal] = useState(true);
  const [page, setPage] = useState(1);
  const [selectedId, setSelectedId] = useState(null);
  const limit = 25;

  const totalPages = useMemo(() => Math.max(1, Math.ceil(total / limit)), [total]);

  const criticalAlerts = useMemo(
    () => items.filter(a => (a.priority || "").toLowerCase() === "critical" && a.status !== "resolved"),
    [items]
  );

  const fetchAlerts = useCallback(async () => {
    const params = new URLSearchParams();
    params.set("page", String(page));
    params.set("limit", String(limit));
    if (priority !== "all") params.set("priority", priority);
    if (status !== "all") params.set("status", status);
    if (q.trim()) params.set("q", q.trim());
    params.set("include_internal", includeInternal ? "1" : "0");

    const res = await fetch(`${API_BASE_URL}/api/alerts?${params}`);
    const data = await res.json();
    setItems(data.items || []);
    setTotal(data.total || 0);
  }, [page, priority, status, q, includeInternal]);

  useEffect(() => {
    fetchAlerts().catch(console.error);
    const id = setInterval(() => fetchAlerts().catch(console.error), 5000);
    return () => clearInterval(id);
  }, [fetchAlerts, refreshTrigger]);
  
  useEffect(() => { setPage(1); }, [priority, status, q, includeInternal]);

  const handleAction = async (alertId, newStatus) => {
    await fetch(`${API_BASE_URL}/api/alerts/${alertId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: newStatus }),
    });
    fetchAlerts().catch(console.error);
  };

  const handleSelect = (id) => setSelectedId(prev => prev === id ? null : id);

  return (
    <div className="content">
      <style>{`
        @keyframes raven-pulse {
          0%,100% { box-shadow: 0 0 0 0 rgba(255,51,102,0); }
          50%      { box-shadow: 0 0 0 3px rgba(255,51,102,0.20); }
        }
        .pri { display:inline-flex;align-items:center;height:24px;padding:0 10px;border-radius:999px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;border:1px solid transparent;white-space:nowrap; }
        .pri-critical { color:#ff3366;background:rgba(255,51,102,0.10);border-color:rgba(255,51,102,0.38);animation:raven-pulse 2s ease-in-out infinite; }
        .pri-high     { color:#ffaa00;background:rgba(255,170,0,0.10);border-color:rgba(255,170,0,0.35); }
        .pri-medium   { color:#f59e0b;background:rgba(245,158,11,0.09);border-color:rgba(245,158,11,0.28); }
        .pri-low      { color:#00ff88;background:rgba(0,255,136,0.09);border-color:rgba(0,255,136,0.26); }
        .sta { display:inline-flex;align-items:center;height:24px;padding:0 10px;border-radius:999px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;border:1px solid transparent;white-space:nowrap; }
        .sta-new          { color:rgba(226,232,240,0.70);background:rgba(148,163,184,0.09);border-color:rgba(148,163,184,0.20); }
        .sta-acknowledged { color:#00d4ff;background:rgba(0,212,255,0.09);border-color:rgba(0,212,255,0.28); }
        .sta-resolved     { color:#00ff88;background:rgba(0,255,136,0.09);border-color:rgba(0,255,136,0.26); }
        .inv-evidence-item { border:1px solid rgba(0,212,255,0.08);border-radius:8px;padding:9px 11px;background:rgba(5,12,26,0.45); }
        .inv-evidence-type { font-size:10px;font-weight:700;color:rgba(0,212,255,0.60);text-transform:uppercase;letter-spacing:.07em; }
        .inv-evidence-msg  { font-size:12px;color:rgba(226,232,240,0.70);word-break:break-all;line-height:1.5;font-family:ui-monospace,Consolas,monospace; }
        .inv-evidence-ts   { font-size:11px;color:rgba(226,232,240,0.32);font-family:ui-monospace,Consolas,monospace; }
      `}</style>

      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">🚨 Alerts</h2>
            <div className="card-subtitle">Security alerts + linked evidence</div>
          </div>
          <button className="btn" onClick={() => fetchAlerts().catch(console.error)}>Refresh</button>
        </div>

        <CriticalBanner alerts={criticalAlerts} />

        {/* Filters */}
        <div className="filters-row" style={{ marginBottom: 14 }}>
          <input
            className="input"
            value={q}
            onChange={e => setQ(e.target.value)}
            placeholder="Search title / description..."
          />
          <select className="select" value={priority} onChange={e => setPriority(e.target.value)}>
            <option value="all">All priorities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select className="select" value={status} onChange={e => setStatus(e.target.value)}>
            <option value="all">All status</option>
            <option value="new">New</option>
            <option value="acknowledged">Acknowledged</option>
            <option value="resolved">Resolved</option>
          </select>
          <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13, color: "rgba(226,232,240,0.70)", cursor: "pointer", flexShrink: 0 }}>
            <input type="checkbox" checked={includeInternal} onChange={e => setIncludeInternal(e.target.checked)} />
            Show internal
          </label>
          <button className="btn" onClick={() => { setQ(""); setPriority("all"); setStatus("all"); setPage(1); }}>
            Clear
          </button>
        </div>

        <div style={{ fontSize: 12, color: "rgba(226,232,240,0.45)", marginBottom: 12 }}>
          <b style={{ color: "#e2e8f0" }}>{total}</b> alerts — Page <b style={{ color: "#e2e8f0" }}>{page}</b> / <b style={{ color: "#e2e8f0" }}>{totalPages}</b>
        </div>

        {/* Two-column layout */}
        <div style={{
          display: "grid",
          gridTemplateColumns: selectedId ? "1fr 380px" : "1fr",
          gap: 14,
          alignItems: "start",
        }}>
          {/* Alert list */}
          <div>
            {items.length === 0 ? (
              <div className="empty">No alerts match your filters.</div>
            ) : (
              items.map(a => (
                <AlertCard
                  key={a.id}
                  alert={a}
                  selected={selectedId === a.id}
                  onSelect={handleSelect}
                  onAction={handleAction}
                />
              ))
            )}

            <div className="pager">
              <button className="btn" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>← Prev</button>
              <span style={{ fontSize: 12, color: "rgba(226,232,240,0.45)" }}>
                {page} / {totalPages}
              </span>
              <button className="btn" disabled={page >= totalPages} onClick={() => setPage(p => p + 1)}>Next →</button>
            </div>
          </div>

          {/* Investigation panel */}
          {selectedId && (
            <div style={{
              background: "#0b1221",
              border: "1px solid rgba(0,212,255,0.14)",
              borderRadius: 12,
              padding: 16,
              position: "sticky",
              top: 16,
            }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
                <div>
                  <div style={{ fontWeight: 700, fontSize: 14, color: "#e2e8f0" }}>Investigation</div>
                  <div style={{ fontSize: 12, color: "rgba(226,232,240,0.42)", marginTop: 2 }}>Case view + linked evidence</div>
                </div>
                <button className="btn btn-sm" onClick={() => setSelectedId(null)}>✕ Close</button>
              </div>
              <InvestigationPanel alertId={selectedId} />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}