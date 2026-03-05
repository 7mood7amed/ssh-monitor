import React, { useEffect, useMemo, useState } from "react";
import API_BASE_URL from "../config";
import "./FtpLogs.css";

function normalizeSeverity(value) {
  const s = String(value || "").trim().toLowerCase();
  if (["low", "medium", "high", "critical"].includes(s)) return s;
  return "";
}

function SeverityBadge({ severity }) {
  const sev = normalizeSeverity(severity) || "low";
  const label = sev.toUpperCase();

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

const WebTraffic = () => {
  const [logs, setLogs] = useState([]);

  // Pagination
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(1);

  // Filters
  const [searchTerm, setSearchTerm] = useState("");
  const [statusFilter, setStatusFilter] = useState("All");
  const [severityFilter, setSeverityFilter] = useState("All");

  // Expand rows
  const [expandedKeys, setExpandedKeys] = useState(() => new Set());

  // Reset to page 1 when filters change
  useEffect(() => {
    setPage(1);
  }, [searchTerm, statusFilter, severityFilter, pageSize]);

  // Auto-collapse expanded rows when page/filters/pageSize change
  useEffect(() => {
    setExpandedKeys(new Set());
  }, [page, pageSize, searchTerm, statusFilter, severityFilter]);

  const url = useMemo(() => {
    const params = new URLSearchParams();
    params.set("page", String(page));
    params.set("limit", String(pageSize));

    if (searchTerm.trim()) params.set("q", searchTerm.trim());
    if (statusFilter !== "All") params.set("status", statusFilter);
    if (severityFilter !== "All") params.set("severity", severityFilter.toLowerCase());

    return `${API_BASE_URL}/api/web_logs?${params.toString()}`;
  }, [page, pageSize, searchTerm, statusFilter, severityFilter]);

  useEffect(() => {
    const fetchWebLogs = async () => {
      try {
        const res = await fetch(url);
        const data = await res.json();

        setLogs(Array.isArray(data.logs) ? data.logs : []);
        setTotal(data.total || 0);
        setTotalPages(data.totalPages || 1);
      } catch (err) {
        console.error("Error fetching web logs:", err);
      }
    };

    fetchWebLogs();
    const interval = setInterval(fetchWebLogs, 10000);
    return () => clearInterval(interval);
  }, [url]);

  const toggleExpand = (key) => {
    setExpandedKeys((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const clear = () => {
    setSearchTerm("");
    setStatusFilter("All");
    setSeverityFilter("All");
    setExpandedKeys(new Set());
    setPage(1);
  };

  const handlePrev = () => setPage((p) => Math.max(p - 1, 1));
  const handleNext = () => setPage((p) => Math.min(p + 1, totalPages || 1));

  return (
    <div className="content">
      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">🌐 Web Traffic</h2>
            <div className="card-subtitle">Apache Access Log (requests, status codes, user-agents)</div>
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
          <input
            className="input"
            type="text"
            placeholder="Search by URL or IP..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />

          <select className="select" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
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

          <select className="select" value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
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
            Showing <b>{logs.length}</b> of <b>{total}</b> results
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
                <th style={{ width: 160 }}>IP</th>
                <th style={{ width: 110 }}>METHOD</th>
                <th>URL</th>
                <th style={{ width: 110 }}>STATUS</th>
                <th style={{ width: 140 }}>SEVERITY</th>
                <th style={{ width: 260 }}>USER-AGENT</th>
                <th style={{ width: 70 }} />
              </tr>
            </thead>

            <tbody>
              {logs.length === 0 ? (
                <tr>
                  <td colSpan={8} className="empty">
                    No web traffic logs match your filters.
                  </td>
                </tr>
              ) : (
                logs.map((log, i) => {
                  const key = `${log.timestamp}-${log.ip}-${log.method}-${log.status}-${i}`;
                  const expanded = expandedKeys.has(key);

                  return (
                    <React.Fragment key={key}>
                      <tr>
                        <td className="mono" title={log.timestamp}>
                          {log.timestamp}
                        </td>
                        <td className="mono" title={log.ip}>
                          {log.ip}
                        </td>
                        <td title={log.method}>{log.method}</td>
                        <td className="mono" title={log.url}>
                          {log.url}
                        </td>
                        <td className="mono" title={String(log.status)}>
                          {log.status}
                        </td>
                        <td title={String(log.severity || "")}>
                          <SeverityBadge severity={log.severity} />
                        </td>
                        <td className="mono" title={log.user_agent}>
                          {log.user_agent}
                        </td>
                        <td>
                          <button
                            className="icon-pill"
                            type="button"
                            aria-label={expanded ? "Collapse row" : "Expand row"}
                            onClick={() => toggleExpand(key)}
                          >
                            {expanded ? "▲" : "▼"}
                          </button>
                        </td>
                      </tr>

                      {expanded && (
                        <tr>
                          <td colSpan={8}>
                            <div style={{ padding: "12px 2px" }}>
                              <div style={{ color: "rgba(226,232,240,0.75)", fontSize: 12, marginBottom: 6 }}>
                                Full URL
                              </div>
                              <pre className="raw-pre">{log.url}</pre>

                              <div style={{ height: 10 }} />

                              <div style={{ color: "rgba(226,232,240,0.75)", fontSize: 12, marginBottom: 6 }}>
                                Full User-Agent
                              </div>
                              <pre className="raw-pre">{log.user_agent}</pre>
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
          <button className="btn btn-secondary" onClick={handlePrev} disabled={page === 1}>
            Prev
          </button>

          <button className="btn btn-secondary" onClick={handleNext} disabled={page === totalPages || totalPages === 0}>
            Next
          </button>
        </div>
      </div>
    </div>
  );
};

export default WebTraffic;