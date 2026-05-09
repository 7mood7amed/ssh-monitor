import React, { useEffect, useMemo, useState } from "react";
import API_BASE_URL from "../config";
import "./FtpLogs.css";

function normalizeSeverity(value) {
  const s = String(value || "").trim().toLowerCase();
  if (["low", "medium", "high", "critical"].includes(s)) return s;
  return "";
}

function SevBadge({ severity }) {
  const s = normalizeSeverity(severity) || "low";
  return <span className={`sev-badge ${s.toUpperCase()}`}>{s.toUpperCase()}</span>;
}

function MethodBadge({ method }) {
  const colors = {
    GET: { color: "#00d4ff", bg: "rgba(0,212,255,0.09)", border: "rgba(0,212,255,0.25)" },
    POST: { color: "#00ff88", bg: "rgba(0,255,136,0.09)", border: "rgba(0,255,136,0.25)" },
    PUT: { color: "#ffaa00", bg: "rgba(255,170,0,0.09)", border: "rgba(255,170,0,0.25)" },
    DELETE: { color: "#ff3366", bg: "rgba(255,51,102,0.09)", border: "rgba(255,51,102,0.25)" },
    PATCH: { color: "#a855f7", bg: "rgba(168,85,247,0.09)", border: "rgba(168,85,247,0.25)" },
  };
  const c = colors[method?.toUpperCase()] || { color: "#94a3b8", bg: "rgba(148,163,184,0.07)", border: "rgba(148,163,184,0.20)" };
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", height: 22,
      padding: "0 8px", borderRadius: 999,
      fontSize: 11, fontWeight: 700,
      color: c.color, background: c.bg, border: `1px solid ${c.border}`,
    }}>
      {method}
    </span>
  );
}

function StatusCode({ status }) {
  const n = Number(status);
  const color = n >= 500 ? "#ff3366" : n >= 400 ? "#ffaa00" : n >= 300 ? "#00d4ff" : "#00ff88";
  return (
    <span style={{ fontFamily: "monospace", fontSize: 13, fontWeight: 700, color }}>
      {status}
    </span>
  );
}

const LIMIT_OPTIONS = [20, 50, 100];

const WebTraffic = () => {
  const [logs, setLogs] = useState([]);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [searchTerm, setSearchTerm] = useState("");
  const [statusFilter, setStatus] = useState("All");
  const [severityFilter, setSev] = useState("All");
  const [expandedKeys, setExpandedKeys] = useState(() => new Set());

  useEffect(() => { setPage(1); }, [searchTerm, statusFilter, severityFilter, pageSize]);
  useEffect(() => { setExpandedKeys(new Set()); }, [page, pageSize, searchTerm, statusFilter, severityFilter]);

  const url = useMemo(() => {
    const p = new URLSearchParams();
    p.set("page", String(page));
    p.set("limit", String(pageSize));
    if (searchTerm.trim()) p.set("q", searchTerm.trim());
    if (statusFilter !== "All") p.set("status", statusFilter);
    if (severityFilter !== "All") p.set("severity", severityFilter.toLowerCase());
    return `${API_BASE_URL}/api/web_logs?${p}`;
  }, [page, pageSize, searchTerm, statusFilter, severityFilter]);

  useEffect(() => {
    const fetch_ = async () => {
      try {
        const res = await fetch(url);
        const data = await res.json();
        setLogs(Array.isArray(data.logs) ? data.logs : []);
        setTotal(data.total || 0);
        setTotalPages(data.totalPages || 1);
      } catch (e) { console.error("Web logs fetch failed:", e); }
    };
    fetch_();
    const t = setInterval(fetch_, 5000);
    return () => clearInterval(t);
  }, [url]);

  const toggleExpand = key => setExpandedKeys(prev => {
    const next = new Set(prev);
    next.has(key) ? next.delete(key) : next.add(key);
    return next;
  });

  const clear = () => {
    setSearchTerm(""); setStatus("All"); setSev("All");
    setExpandedKeys(new Set()); setPage(1);
  };

  return (
    <div className="content">
      <div className="card">
        {/* Header */}
        <div className="card-header">
          <div>
            <h2 className="card-title">🌐 Web Traffic</h2>
            <div className="card-subtitle">Apache access log · requests · status codes</div>
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
          <input className="input" type="text"
            placeholder="Search URL or IP…"
            value={searchTerm} onChange={e => setSearchTerm(e.target.value)} />
          <select className="select" value={statusFilter} onChange={e => setStatus(e.target.value)}>
            <option value="All">All Status Codes</option>
            <option value="200">200 OK</option>
            <option value="301">301 Redirect</option>
            <option value="302">302 Redirect</option>
            <option value="401">401 Unauthorized</option>
            <option value="403">403 Forbidden</option>
            <option value="404">404 Not Found</option>
            <option value="429">429 Rate Limit</option>
            <option value="500">500 Server Error</option>
          </select>
          <select className="select" value={severityFilter} onChange={e => setSev(e.target.value)}>
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
          <span>Showing <b>{logs.length}</b> of <b>{total}</b> results</span>
          <span>Page <b>{page}</b> / <b>{totalPages}</b></span>
        </div>

        {/* Table — USER-AGENT truncated to 1 line */}
        <div className="table-wrap">
          <table className="table" style={{ tableLayout: "fixed", width: "100%" }}>
            <thead>
              <tr>
                <th style={{ width: 140 }}>TIME</th>
                <th style={{ width: 140 }}>IP</th>
                <th style={{ width: 80 }}>METHOD</th>
                <th>URL</th>
                <th style={{ width: 70 }}>STATUS</th>
                <th style={{ width: 100 }}>SEVERITY</th>
                <th style={{ width: 180 }}>USER-AGENT</th>
                <th style={{ width: 40 }} />
              </tr>
            </thead>
            <tbody>
              {logs.length === 0 ? (
                <tr><td colSpan={8} className="empty">No web traffic logs match your filters.</td></tr>
              ) : (
                logs.map((log, i) => {
                  const key = `${log.timestamp}-${log.ip}-${log.method}-${log.status}-${i}`;
                  const expanded = expandedKeys.has(key);
                  const sev = normalizeSeverity(log.severity) || "low";

                  return (
                    <React.Fragment key={key}>
                      <tr className={sev === "high" || sev === "critical" ? "row-high" : ""}>
                        <td className="mono" style={{ fontSize: 11, color: "rgba(226,232,240,0.55)" }}>
                          {log.timestamp}
                        </td>
                        <td>
                          <span style={{
                            fontFamily: "monospace", fontSize: 12, color: "#00d4ff",
                            background: "rgba(0,212,255,0.08)", border: "1px solid rgba(0,212,255,0.18)",
                            borderRadius: 4, padding: "1px 6px",
                          }}>{log.ip}</span>
                        </td>
                        <td><MethodBadge method={log.method} /></td>
                        <td>
                          {/* URL: truncated, full shown on expand */}
                          <div style={{
                            fontFamily: "monospace", fontSize: 12,
                            color: "rgba(226,232,240,0.82)",
                            whiteSpace: "nowrap", overflow: "hidden",
                            textOverflow: "ellipsis", maxWidth: "100%",
                          }} title={log.url}>
                            {log.url}
                          </div>
                        </td>
                        <td><StatusCode status={log.status} /></td>
                        <td><SevBadge severity={log.severity} /></td>
                        <td>
                          {/* USER-AGENT: single line truncated */}
                          <div style={{
                            fontSize: 11,
                            color: "rgba(226,232,240,0.45)",
                            whiteSpace: "nowrap", overflow: "hidden",
                            textOverflow: "ellipsis", maxWidth: 170,
                          }} title={log.user_agent}>
                            {log.user_agent}
                          </div>
                        </td>
                        <td>
                          <button className="icon-pill" type="button"
                            aria-label={expanded ? "Collapse" : "Expand"}
                            onClick={() => toggleExpand(key)}>
                            {expanded ? "▲" : "▼"}
                          </button>
                        </td>
                      </tr>

                      {/* Expand: full URL + full user agent */}
                      {expanded && (
                        <tr>
                          <td colSpan={8} style={{ padding: "0 12px 12px" }}>
                            <div style={{ display: "grid", gap: 8 }}>
                              <div>
                                <div style={{ fontSize: 11, color: "rgba(0,212,255,0.60)", textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 4 }}>Full URL</div>
                                <pre className="raw-pre">{log.url}</pre>
                              </div>
                              <div>
                                <div style={{ fontSize: 11, color: "rgba(0,212,255,0.60)", textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 4 }}>User-Agent</div>
                                <pre className="raw-pre">{log.user_agent}</pre>
                              </div>
                            </div>
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
          <button className="btn" onClick={() => setPage(p => Math.min(p + 1, totalPages || 1))} disabled={page >= totalPages}>Next →</button>
        </div>
      </div>
    </div>
  );
};

export default WebTraffic;