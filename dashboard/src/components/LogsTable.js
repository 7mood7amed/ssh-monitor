// =========================================================
// SSH Events table component (uses /api/ssh_events)
// File: dashboard/src/components/LogsTable.js
// =========================================================

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

function SeverityBadge({ severity }) {
  const sev = normalizeSeverity(severity);
  const label = sev || "LOW";

  const style = {
    display: "inline-block",
    padding: "2px 8px",
    borderRadius: "999px",
    fontSize: "12px",
    fontWeight: 700,
    letterSpacing: "0.4px",
    textTransform: "uppercase",
    border: "1px solid rgba(255,255,255,0.12)",
    background:
      label === "CRITICAL"
        ? "rgba(239,68,68,0.25)"
        : label === "HIGH"
        ? "rgba(249,115,22,0.22)"
        : label === "MEDIUM"
        ? "rgba(234,179,8,0.20)"
        : "rgba(34,197,94,0.18)",
  };

  return <span style={style}>{label}</span>;
}

const LIMIT_OPTIONS = [20, 50, 100];

const LogsTable = () => {
  const [rows, setRows] = useState([]);

  // Filters
  const [q, setQ] = useState("");
  const [user, setUser] = useState("");
  const [ip, setIp] = useState("");
  const [event, setEvent] = useState("All");
  const [outcome, setOutcome] = useState("All");
  const [severity, setSeverity] = useState("All");

  // Pagination
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(1);

  // Expand rows
  const [expandedIds, setExpandedIds] = useState(() => new Set());

  useEffect(() => {
    setPage(1);
  }, [q, user, ip, event, outcome, severity, pageSize]);

  useEffect(() => {
    setExpandedIds(new Set());
  }, [page, pageSize, q, user, ip, event, outcome, severity]);

  const url = useMemo(() => {
    const params = new URLSearchParams();
    params.set("page", String(page));
    params.set("limit", String(pageSize));
    if (q.trim()) params.set("q", q.trim());
    if (user.trim()) params.set("user", user.trim());
    if (ip.trim()) params.set("ip", ip.trim());
    if (event !== "All") params.set("event", event);
    if (outcome !== "All") params.set("outcome", outcome);
    if (severity !== "All") params.set("severity", severity.toLowerCase());

    return `${API_BASE_URL}/api/ssh_events?${params.toString()}`;
  }, [page, pageSize, q, user, ip, event, outcome, severity]);

  useEffect(() => {
    const fetchEvents = async () => {
      try {
        const res = await fetch(url);
        const data = await res.json();

        const incoming = Array.isArray(data.events) ? data.events : [];
        const normalized = incoming.map((r) => {
          const sev = normalizeSeverity(r.severity) || inferSeverityFallback(r);
          return { ...r, severity: sev };
        });

        setRows(normalized);
        setTotal(data.total || 0);
        setTotalPages(data.totalPages || 1);
        if ((data.totalPages || 1) < page) setPage(1);
      } catch (e) {
        console.error("Error fetching ssh events:", e);
      }
    };

    fetchEvents();
    const interval = setInterval(fetchEvents, 10000);
    return () => clearInterval(interval);
  }, [url, page]);

  const toggleExpand = (id) => {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const clear = () => {
    setQ("");
    setUser("");
    setIp("");
    setEvent("All");
    setOutcome("All");
    setSeverity("All");
    setExpandedIds(new Set());
    setPage(1);
  };

  return (
    <div className="content">
      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">📜 SSH Events</h2>
            <div className="card-subtitle">User + IP + login/logout attempts</div>
          </div>

          <div className="page-size-buttons" role="group" aria-label="Page size">
            {LIMIT_OPTIONS.map((n) => (
              <button
                key={n}
                type="button"
                className={n === pageSize ? "pill pill-active" : "pill"}
                onClick={() => {
                  setPageSize(n);
                  setPage(1);
                }}
              >
                {n}
              </button>
            ))}
          </div>
        </div>

        <div className="filters-row">
          <input className="input" placeholder="Search raw/user/ip..." value={q} onChange={(e) => setQ(e.target.value)} />
          <input className="input" placeholder="Username" value={user} onChange={(e) => setUser(e.target.value)} />
          <input className="input" placeholder="IP" value={ip} onChange={(e) => setIp(e.target.value)} />

          <select className="select" value={event} onChange={(e) => setEvent(e.target.value)}>
            <option value="All">All Events</option>
            <option value="login_success">Login Success</option>
            <option value="login_fail">Login Fail</option>
            <option value="session_open">Session Open</option>
            <option value="session_close">Session Close</option>
            <option value="disconnect">Disconnect</option>
          </select>

          <select className="select" value={outcome} onChange={(e) => setOutcome(e.target.value)}>
            <option value="All">All Outcomes</option>
            <option value="success">Success</option>
            <option value="fail">Fail</option>
            <option value="info">Info</option>
          </select>

          <select className="select" value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="All">All Severity</option>
            <option value="low">LOW</option>
            <option value="medium">MEDIUM</option>
            <option value="high">HIGH</option>
            <option value="critical">CRITICAL</option>
          </select>

          <button className="btn btn-secondary" type="button" onClick={clear}>
            Clear
          </button>
        </div>

        <div className="meta-row">
          <div className="meta-left">
            Showing <b>{rows.length}</b> of <b>{total}</b> results
          </div>
          <div className="meta-right">
            Page <b>{page}</b> / <b>{totalPages}</b>
          </div>
        </div>

        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th style={{ width: 180 }}>TIME</th>
                <th style={{ width: 140 }}>USER</th>
                <th style={{ width: 160 }}>IP</th>
                <th style={{ width: 160 }}>EVENT</th>
                <th style={{ width: 120 }}>OUTCOME</th>
                <th style={{ width: 140 }}>METHOD</th>
                <th style={{ width: 140 }}>SEVERITY</th>
                <th>RAW</th>
                <th style={{ width: 70 }} />
              </tr>
            </thead>

            <tbody>
              {rows.length === 0 ? (
                <tr>
                  <td colSpan={9} className="empty">
                    No SSH events match your filters.
                  </td>
                </tr>
              ) : (
                rows.map((r) => {
                  const expanded = expandedIds.has(r.id);

                  const eventKey = String(r.event_type || "other")
                    .toLowerCase()
                    .trim()
                    .replace(/\s+/g, "_");

                  return (
                    <React.Fragment key={r.id}>
                      <tr>
                        <td className="mono" title={r.timestamp}>
                          {r.timestamp}
                        </td>
                        <td title={r.username || ""}>{r.username || ""}</td>
                        <td className="mono" title={r.ip || ""}>
                          {r.ip || ""}
                        </td>


                        <td title={r.event_type}>
                          <span className={`badge badge-${eventKey}`}>{r.event_type}</span>
                        </td>

                        <td title={r.outcome || ""}>{r.outcome || ""}</td>
                        <td title={r.auth_method || ""}>{r.auth_method || ""}</td>

                        <td title={r.severity || ""}>
                          <SeverityBadge severity={r.severity} />
                        </td>

                        <td className="mono" title={r.message}>
                          {r.message}
                        </td>


                        <td>
                          <button className="icon-pill" type="button" onClick={() => toggleExpand(r.id)} aria-label="Toggle raw">
                            {expanded ? "▲" : "▼"}
                          </button>
                        </td>
                      </tr>

                      {expanded && (
                        <tr>
                          <td colSpan={9}>
                            <div style={{ padding: "12px 2px" }}>
                              <div style={{ color: "rgba(226,232,240,0.75)", fontSize: 12, marginBottom: 6 }}>
                                Full Raw Line
                              </div>
                              <pre className="raw-pre">{r.message}</pre>
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

        <div className="pager">
          <button className="btn btn-secondary" onClick={() => setPage((p) => Math.max(p - 1, 1))} disabled={page === 1}>
            Prev
          </button>

          <button
            className="btn btn-secondary"
            onClick={() => setPage((p) => Math.min(p + 1, totalPages))}
            disabled={page === totalPages || totalPages === 0}
          >
            Next
          </button>
        </div>
      </div>
    </div>
  );
};

export default LogsTable;