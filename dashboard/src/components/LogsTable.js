import React, { useEffect, useMemo, useState } from "react";
import API_BASE_URL from "../config";
import "./FtpLogs.css";

function normalizeSeverity(value) {
  const s = String(value || "").trim().toUpperCase();
  if (["LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(s)) return s;
  return "";
}

function inferSeverityFallback(row) {
  const outcome = (row?.outcome || "").toLowerCase();
  const eventType = (row?.event_type || "").toLowerCase();
  if (eventType === "login_fail" || outcome === "fail") return "HIGH";
  if (eventType === "disconnect") return "MEDIUM";
  return "LOW";
}

function SevBadge({ severity }) {
  const s = normalizeSeverity(severity) || "LOW";
  return (
    <span className={`sev-badge ${s}`}>{s}</span>
  );
}

const LIMIT_OPTIONS = [20, 50, 100];

const LogsTable = () => {
  const [rows, setRows] = useState([]);
  const [q, setQ] = useState("");
  const [user, setUser] = useState("");
  const [ip, setIp] = useState("");
  const [event, setEvent] = useState("All");
  const [outcome, setOutcome] = useState("All");
  const [severity, setSeverity] = useState("All");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [expandedIds, setExpandedIds] = useState(() => new Set());

  useEffect(() => { setPage(1); }, [q, user, ip, event, outcome, severity, pageSize]);
  useEffect(() => { setExpandedIds(new Set()); }, [page, pageSize, q, user, ip, event, outcome, severity]);

  const url = useMemo(() => {
    const p = new URLSearchParams();
    p.set("page", String(page));
    p.set("limit", String(pageSize));
    if (q.trim()) p.set("q", q.trim());
    if (user.trim()) p.set("user", user.trim());
    if (ip.trim()) p.set("ip", ip.trim());
    if (event !== "All") p.set("event", event);
    if (outcome !== "All") p.set("outcome", outcome);
    if (severity !== "All") p.set("severity", severity.toLowerCase());
    return `${API_BASE_URL}/api/ssh_events?${p}`;
  }, [page, pageSize, q, user, ip, event, outcome, severity]);

  useEffect(() => {
    const fetch_ = async () => {
      try {
        const res = await fetch(url);
        const data = await res.json();
        const rows = (Array.isArray(data.events) ? data.events : []).map(r => ({
          ...r,
          severity: normalizeSeverity(r.severity) || inferSeverityFallback(r),
        }));
        setRows(rows);
        setTotal(data.total || 0);
        setTotalPages(data.totalPages || 1);
        if ((data.totalPages || 1) < page) setPage(1);
      } catch (e) { console.error("SSH events fetch failed:", e); }
    };
    
    fetch_();
    const t = setInterval(fetch_, 5000);
    return () => clearInterval(t);
  }, [url, page]);

  const toggleExpand = id => setExpandedIds(prev => {
    const next = new Set(prev);
    next.has(id) ? next.delete(id) : next.add(id);
    return next;
  });

  const clear = () => {
    setQ(""); setUser(""); setIp("");
    setEvent("All"); setOutcome("All"); setSeverity("All");
    setExpandedIds(new Set()); setPage(1);
  };

  return (
    <div className="content">
      <div className="card">
        {/* Header */}
        <div className="card-header">
          <div>
            <h2 className="card-title">📜 SSH Events</h2>
            <div className="card-subtitle">User · IP · login/logout attempts</div>
          </div>
          <div className="page-size-buttons">
            {LIMIT_OPTIONS.map(n => (
              <button key={n} type="button"
                className={n === pageSize ? "pill pill-active" : "pill"}
                onClick={() => { setPageSize(n); setPage(1); }}>
                {n}
              </button>
            ))}
          </div>
        </div>

        {/* Filters */}
        <div className="filters-row">
          <input className="input" placeholder="Search user / IP…" value={q} onChange={e => setQ(e.target.value)} />
          <input className="input" placeholder="Username" value={user} onChange={e => setUser(e.target.value)} />
          <input className="input" placeholder="IP address" value={ip} onChange={e => setIp(e.target.value)} />
          <select className="select" value={event} onChange={e => setEvent(e.target.value)}>
            <option value="All">All Events</option>
            <option value="login_success">Login Success</option>
            <option value="login_fail">Login Fail</option>
            <option value="session_open">Session Open</option>
            <option value="session_close">Session Close</option>
            <option value="disconnect">Disconnect</option>
          </select>
          <select className="select" value={outcome} onChange={e => setOutcome(e.target.value)}>
            <option value="All">All Outcomes</option>
            <option value="success">Success</option>
            <option value="fail">Fail</option>
            <option value="info">Info</option>
          </select>
          <select className="select" value={severity} onChange={e => setSeverity(e.target.value)}>
            <option value="All">All Severity</option>
            <option value="low">LOW</option>
            <option value="medium">MEDIUM</option>
            <option value="high">HIGH</option>
            <option value="critical">CRITICAL</option>
          </select>
          <button className="btn" type="button" onClick={clear}>Clear</button>
        </div>

        {/* Meta */}
        <div className="meta-row">
          <span>Showing <b>{rows.length}</b> of <b>{total}</b> results</span>
          <span>Page <b>{page}</b> / <b>{totalPages}</b></span>
        </div>

        {/* Table — RAW column removed, shown only in expand */}
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th style={{ width: 160 }}>TIME</th>
                <th style={{ width: 120 }}>USER</th>
                <th style={{ width: 140 }}>IP</th>
                <th style={{ width: 150 }}>EVENT</th>
                <th style={{ width: 100 }}>OUTCOME</th>
                <th style={{ width: 110 }}>METHOD</th>
                <th style={{ width: 110 }}>SEVERITY</th>
                <th style={{ width: 40 }} />
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 ? (
                <tr><td colSpan={8} className="empty">No SSH events match your filters.</td></tr>
              ) : (
                rows.map(r => {
                  const expanded = expandedIds.has(r.id);
                  const eventKey = String(r.event_type || "other").toLowerCase().replace(/\s+/g, "_");

                  return (
                    <React.Fragment key={r.id}>
                      <tr className={
                        r.severity === "HIGH" || r.severity === "CRITICAL" ? "row-high" : ""
                      }>
                        <td className="mono" style={{ fontSize: 12 }}>{r.timestamp}</td>
                        <td style={{ fontWeight: 600 }}>{r.username || "—"}</td>
                        <td>
                          {r.ip ? (
                            <span style={{
                              fontFamily: "monospace", fontSize: 12, color: "#00d4ff",
                              background: "rgba(0,212,255,0.08)", border: "1px solid rgba(0,212,255,0.18)",
                              borderRadius: 4, padding: "1px 6px",
                            }}>{r.ip}</span>
                          ) : "—"}
                        </td>
                        <td>
                          <span className={`badge badge-${eventKey}`}>{r.event_type}</span>
                        </td>
                        <td style={{ color: "rgba(226,232,240,0.65)", fontSize: 12 }}>{r.outcome || "—"}</td>
                        <td style={{ color: "rgba(226,232,240,0.65)", fontSize: 12 }}>{r.auth_method || "—"}</td>
                        <td><SevBadge severity={r.severity} /></td>
                        <td>
                          <button className="icon-pill" type="button"
                            onClick={() => toggleExpand(r.id)}
                            title={expanded ? "Hide raw" : "Show raw log"}>
                            {expanded ? "▲" : "▼"}
                          </button>
                        </td>
                      </tr>

                      {/* Expand: show raw message */}
                      {expanded && (
                        <tr>
                          <td colSpan={8} style={{ padding: "0 12px 12px" }}>
                            <div style={{ fontSize: 11, color: "rgba(0,212,255,0.60)", textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 5 }}>
                              Raw Log Line
                            </div>
                            <pre className="raw-pre">{r.message}</pre>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pager */}
        <div className="pager">
          <button className="btn" onClick={() => setPage(p => Math.max(p - 1, 1))} disabled={page === 1}>← Prev</button>
          <span style={{ fontSize: 12, color: "rgba(226,232,240,0.45)" }}>{page} / {totalPages}</span>
          <button className="btn" onClick={() => setPage(p => Math.min(p + 1, totalPages))} disabled={page >= totalPages}>Next →</button>
        </div>
      </div>
    </div>
  );
};

export default LogsTable;