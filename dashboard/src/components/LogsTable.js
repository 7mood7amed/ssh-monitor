// =========================================================
// (4) REPLACE SSH page table component to use /api/ssh_events
// File: dashboard/src/components/LogsTable.js
// =========================================================
import React, { useEffect, useMemo, useState } from "react";
import API_BASE_URL from "../config";
import "./Table.css";

const LogsTable = () => {
  const [rows, setRows] = useState([]);

  // Filters
  const [q, setQ] = useState("");
  const [user, setUser] = useState("");
  const [ip, setIp] = useState("");
  const [event, setEvent] = useState("All");
  const [outcome, setOutcome] = useState("All");

  // Pagination
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(1);

  // Expand rows
  const [expandedIds, setExpandedIds] = useState(() => new Set());

  // Reset to page 1 when filters change
  useEffect(() => {
    setPage(1);
  }, [q, user, ip, event, outcome]);

  // Auto-collapse expanded rows when page/filters/pageSize change
  useEffect(() => {
    setExpandedIds(new Set());
  }, [page, pageSize, q, user, ip, event, outcome]);

  const url = useMemo(() => {
    const params = new URLSearchParams();
    params.set("page", String(page));
    params.set("limit", String(pageSize));
    if (q.trim()) params.set("q", q.trim());
    if (user.trim()) params.set("user", user.trim());
    if (ip.trim()) params.set("ip", ip.trim());
    if (event !== "All") params.set("event", event);
    if (outcome !== "All") params.set("outcome", outcome);
    return `${API_BASE_URL}/api/ssh_events?${params.toString()}`;
  }, [page, pageSize, q, user, ip, event, outcome]);

  useEffect(() => {
    const fetchEvents = async () => {
      try {
        const res = await fetch(url);
        const data = await res.json();
        setRows(data.events || []);
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
    setExpandedIds(new Set());
  };

  return (
    <div className="table-card">
      <h2 className="table-title">📜 SSH Events (user + IP + login/logout attempts)</h2>

      <div className="filter-bar">
        <input placeholder="Search raw/user/ip..." value={q} onChange={(e) => setQ(e.target.value)} />
        <input placeholder="Username" value={user} onChange={(e) => setUser(e.target.value)} />
        <input placeholder="IP" value={ip} onChange={(e) => setIp(e.target.value)} />

        <select value={event} onChange={(e) => setEvent(e.target.value)}>
          <option value="All">All Events</option>
          <option value="login_success">Login Success</option>
          <option value="login_fail">Login Fail</option>
          <option value="session_open">Session Open</option>
          <option value="session_close">Session Close</option>
          <option value="disconnect">Disconnect</option>
        </select>

        <select value={outcome} onChange={(e) => setOutcome(e.target.value)}>
          <option value="All">All Outcomes</option>
          <option value="success">Success</option>
          <option value="fail">Fail</option>
          <option value="info">Info</option>
        </select>

        <button className="page-btn" type="button" onClick={clear}>Clear</button>

        <span className="result-count">
          Showing <b>{rows.length}</b> of {total} events (page {page} of {totalPages})
        </span>
      </div>

      <div className="table-wrapper">
        <table className="data-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>User</th>
              <th>IP</th>
              <th>Event</th>
              <th>Outcome</th>
              <th>Method</th>
              <th>Raw</th>
              <th />
            </tr>
          </thead>

          <tbody>
            {rows.map((r) => {
              const expanded = expandedIds.has(r.id);
              return (
                <React.Fragment key={r.id}>
                  <tr>
                    <td className="cell-mono" title={r.timestamp}>{r.timestamp}</td>
                    <td title={r.username || ""}>{r.username || ""}</td>
                    <td className="cell-mono" title={r.ip || ""}>{r.ip || ""}</td>
                    <td title={r.event_type}>{r.event_type}</td>
                    <td title={r.outcome || ""}>{r.outcome || ""}</td>
                    <td title={r.auth_method || ""}>{r.auth_method || ""}</td>
                    <td className="cell-truncate" title={r.message}>{r.message}</td>
                    <td>
                      <button className="expand-btn" type="button" onClick={() => toggleExpand(r.id)}>
                        {expanded ? "▲" : "▼"}
                      </button>
                    </td>
                  </tr>

                  {expanded && (
                    <tr className="expanded-row">
                      <td colSpan={8}>
                        <div className="expanded-content">
                          <div className="expanded-label">Full Raw Line</div>
                          <pre className="expanded-pre">{r.message}</pre>
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
          </tbody>
        </table>
      </div>

      {rows.length === 0 && <p className="no-results">No SSH events found.</p>}

      <div className="pagination-bar">
        <button className="page-btn" onClick={() => setPage((p) => Math.max(p - 1, 1))} disabled={page === 1}>
          ◀ Prev
        </button>

        <span className="page-info">
          Page <b>{page}</b> of {totalPages}
        </span>

        <button
          className="page-btn"
          onClick={() => setPage((p) => Math.min(p + 1, totalPages))}
          disabled={page === totalPages || totalPages === 0}
        >
          Next ▶
        </button>

        <div className="page-size-control">
          <span>Show:</span>
          <select
            value={pageSize}
            onChange={(e) => {
              setPageSize(Number(e.target.value));
              setPage(1);
            }}
          >
            <option value={10}>10</option>
            <option value={20}>20</option>
            <option value={50}>50</option>
            <option value={100}>100</option>
          </select>
          <span>per page</span>
        </div>
      </div>
    </div>
  );
};

export default LogsTable;
