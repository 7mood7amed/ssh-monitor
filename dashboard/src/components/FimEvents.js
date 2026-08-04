import React, { useEffect, useMemo, useState } from "react";
import API_BASE_URL from "../config";
import "./FtpLogs.css";
import "./Metrics.css";

const EVENT_TYPES = ["modified", "added", "deleted", "permission_changed"];
const LIMIT_OPTIONS = [20, 50, 100];
const FETCH_LIMIT = 7000;

function normalizeSev(v) {
  const s = String(v || "").trim().toUpperCase();
  return ["LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(s) ? s : "";
}

function SevBadge({ severity }) {
  const s = normalizeSev(severity) || "LOW";
  return <span className={`sev-badge ${s}`}>{s}</span>;
}

function truncateHash(h) {
  if (!h) return "";
  return h.length > 12 ? `${h.slice(0, 12)}…` : h;
}

export default function FimEvents({ refreshTrigger }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [q, setQ] = useState("");
  const [eventType, setEventType] = useState("all");
  const [severity, setSeverity] = useState("all");
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(20);
  const [apiRows, setApiRows] = useState([]);
  const [summary, setSummary] = useState({ filesMonitored: 0, fimChanges24h: 0, fimCritical24h: 0 });

  const fetchEvents = async () => {
    setLoading(true); setError("");
    try {
      const params = new URLSearchParams({ page: "1", limit: String(FETCH_LIMIT) });
      const res = await fetch(`${API_BASE_URL}/api/fim_events?${params}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setApiRows(Array.isArray(data.events) ? data.events : []);
    } catch (e) { setError(e?.message || "Failed to load FIM events"); }
    finally { setLoading(false); }
  };

  const fetchSummary = async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/metrics`);
      if (!res.ok) return;
      const data = await res.json();
      setSummary({
        filesMonitored: data.filesMonitored ?? 0,
        fimChanges24h: data.fimChanges24h ?? 0,
        fimCritical24h: data.fimCritical24h ?? 0,
      });
    } catch (e) { /* summary strip is best-effort */ }
  };

  useEffect(() => {
    fetchEvents();
    fetchSummary();
    const id = setInterval(() => { fetchEvents(); fetchSummary(); }, 5000);
    return () => clearInterval(id);
  }, [refreshTrigger]);

  useEffect(() => { setPage(1); }, [q, eventType, severity, limit]);

  const filtered = useMemo(() => {
    const qv = q.trim().toLowerCase();
    const ev = eventType === "all" ? "" : eventType;
    const sv = severity === "all" ? "" : severity.toUpperCase();

    return apiRows
      .map((r, idx) => ({
        id: `${r.id ?? idx}-${r.detected_at}`,
        detected_at: r.detected_at || "",
        file_path: r.file_path || "",
        event_type: r.event_type || "",
        old_hash: r.old_hash || "",
        new_hash: r.new_hash || "",
        severity: normalizeSev(r.severity) || "LOW",
      }))
      .filter(row => {
        if (ev && row.event_type !== ev) return false;
        if (sv && row.severity !== sv) return false;
        if (qv && !row.file_path.toLowerCase().includes(qv)) return false;
        return true;
      });
  }, [apiRows, q, eventType, severity]);

  const total = filtered.length;
  const totalPages = Math.max(1, Math.ceil(total / limit));
  const safePage = Math.min(page, totalPages);
  const pageRows = filtered.slice((safePage - 1) * limit, safePage * limit);

  const summaryCards = [
    { title: "Files Monitored", value: summary.filesMonitored, icon: "📁", color: "#00d4ff", desc: "Tracked in fim_baseline" },
    { title: "Changes (24h)", value: summary.fimChanges24h, icon: "🔄", color: "#ffaa00", desc: "File integrity events" },
    { title: "Critical Changes (24h)", value: summary.fimCritical24h, icon: "🚨", color: "#ff3366", desc: "passwd / shadow / sudoers" },
  ];

  return (
    <div className="content">
      <section className="metrics-container">
        {summaryCards.map((item, index) => (
          <div className="metric-card" key={index} style={{ borderTopColor: item.color }}>
            <div className="metric-icon">{item.icon}</div>
            <div className="metric-info">
              <h3>{item.value}</h3>
              <p>{item.title}</p>
              <span className="metric-desc">{item.desc}</span>
            </div>
          </div>
        ))}
      </section>

      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">🛡️ File Integrity</h2>
            <div className="card-subtitle">Watched system files &amp; web root — hash / permission / ownership changes</div>
          </div>
          <div className="page-size-buttons">
            {LIMIT_OPTIONS.map(n => (
              <button key={n} type="button"
                className={n === limit ? "pill pill-active" : "pill"}
                onClick={() => setLimit(n)} disabled={loading}>
                {n}
              </button>
            ))}
          </div>
        </div>

        <div className="filters-row">
          <input className="input" placeholder="Search file path…" value={q} onChange={e => setQ(e.target.value)} />
          <select className="select" value={eventType} onChange={e => setEventType(e.target.value)}>
            <option value="all">All Event Types</option>
            {EVENT_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
          </select>
          <select className="select" value={severity} onChange={e => setSeverity(e.target.value)}>
            <option value="all">All Severity</option>
            <option value="low">LOW</option>
            <option value="medium">MEDIUM</option>
            <option value="high">HIGH</option>
            <option value="critical">CRITICAL</option>
          </select>
          <button className="btn" onClick={() => { setQ(""); setEventType("all"); setSeverity("all"); setPage(1); }} disabled={loading}>
            Clear
          </button>
        </div>

        <div className="meta-row">
          <span>{loading ? "Loading…" : `Showing ${pageRows.length} of ${total} results`}</span>
          <span>Page <b>{safePage}</b> / <b>{totalPages}</b></span>
        </div>

        {error && <div className="error">{error}</div>}

        <div className="table-wrap">
          <table className="table" style={{ tableLayout: "fixed", width: "100%" }}>
            <thead>
              <tr>
                <th style={{ width: 150 }}>TIME</th>
                <th>FILE PATH</th>
                <th style={{ width: 160 }}>EVENT TYPE</th>
                <th style={{ width: 130 }}>OLD HASH</th>
                <th style={{ width: 130 }}>NEW HASH</th>
                <th style={{ width: 110 }}>SEVERITY</th>
              </tr>
            </thead>
            <tbody>
              {pageRows.length === 0 ? (
                <tr><td colSpan={6} className="empty">No FIM events match your filters.</td></tr>
              ) : (
                pageRows.map(r => (
                  <tr key={r.id}
                    className={r.severity === "HIGH" || r.severity === "CRITICAL" ? "row-high" : ""}
                    style={{ height: 44 }}>
                    <td className="mono" style={{ fontSize: 11, color: "rgba(226,232,240,0.55)" }}>
                      {r.detected_at || "—"}
                    </td>
                    <td className="mono truncate" style={{ fontSize: 12, color: "rgba(226,232,240,0.75)" }}>
                      {r.file_path || "—"}
                    </td>
                    <td>
                      <span className={`badge badge-${r.event_type}`}>
                        {r.event_type || "other"}
                      </span>
                    </td>
                    <td className="mono" style={{ fontSize: 11, color: "rgba(226,232,240,0.55)" }}>
                      {truncateHash(r.old_hash) || <span style={{ color: "rgba(226,232,240,0.22)" }}>—</span>}
                    </td>
                    <td className="mono" style={{ fontSize: 11, color: "rgba(226,232,240,0.55)" }}>
                      {truncateHash(r.new_hash) || <span style={{ color: "rgba(226,232,240,0.22)" }}>—</span>}
                    </td>
                    <td><SevBadge severity={r.severity} /></td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        <div className="pager">
          <button className="btn" disabled={safePage <= 1 || loading} onClick={() => setPage(p => p - 1)}>← Prev</button>
          <span style={{ fontSize: 12, color: "rgba(226,232,240,0.45)" }}>{safePage} / {totalPages}</span>
          <button className="btn" disabled={safePage >= totalPages || loading} onClick={() => setPage(p => p + 1)}>Next →</button>
        </div>
      </div>
    </div>
  );
}
