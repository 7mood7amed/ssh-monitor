import React, { useEffect, useMemo, useState } from "react";
import API_BASE_URL from "../config";
import "./FtpLogs.css";

const IMPORTANT_ACTIONS = [
  "LOGIN_SUCCESS",
  "LOGIN_FAIL",
  "UPLOAD",
  "DOWNLOAD",
  "DELETE",
  "RENAME",
  "MKDIR",
  "RMDIR",
];

const LIMIT_OPTIONS = [20, 50, 100];

// We fetch a bigger chunk, then FILTER + PAGINATE locally
const FETCH_LIMIT = 7000;

function cleanIp(ip) {
  if (!ip) return "";
  return String(ip).replace(/^::ffff:/, "");
}

function extractFileFromRaw(raw) {
  const msg = String(raw || "").replace("\x00", "").trim();
  if (!msg) return "";

  const uploadPath = msg.match(/"((?:\/upload|\/uploads)[^"]+)"/i)?.[1];
  if (uploadPath) return uploadPath;

  const stor = msg.match(/"STOR\s+([^"]+)"/i)?.[1];
  if (stor) return stor.trim();

  const retr = msg.match(/"RETR\s+([^"]+)"/i)?.[1];
  if (retr) return retr.trim();

  const dele = msg.match(/"DELE\s+([^"]+)"/i)?.[1];
  if (dele) return dele.trim();

  const rnfr = msg.match(/"RNFR\s+([^"]+)"/i)?.[1];
  const rnto = msg.match(/"RNTO\s+([^"]+)"/i)?.[1];
  if (rnfr && rnto) return `${rnfr.trim()} → ${rnto.trim()}`;
  if (rnfr) return rnfr.trim();
  if (rnto) return rnto.trim();

  const mkdir = msg.match(/"(?:MKD|MKDIR)\s+([^"]+)"/i)?.[1];
  if (mkdir) return mkdir.trim();

  const rmdir = msg.match(/"(?:RMD|RMDIR)\s+([^"]+)"/i)?.[1];
  if (rmdir) return rmdir.trim();

  return "";
}

function normalizeSeverity(value) {
  const s = String(value || "").trim().toUpperCase();
  if (["LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(s)) return s;
  return "";
}

// fallback in case backend hasn't been patched yet
function inferFtpSeverityFallback(action) {
  const a = String(action || "").toUpperCase();

  if (a === "RMDIR") return "CRITICAL";
  if (a === "DELETE") return "HIGH";
  if (a === "LOGIN_FAIL") return "HIGH";
  if (a === "RENAME" || a === "MKDIR") return "MEDIUM";
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

export default function FtpLogs({ refreshTrigger }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  // filters
  const [q, setQ] = useState("");
  const [username, setUsername] = useState("");
  const [ip, setIp] = useState("");
  const [action, setAction] = useState("all");
  const [severity, setSeverity] = useState("all");

  // paging (LOCAL paging after filtering)
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(20);

  // rows from API
  const [apiRows, setApiRows] = useState([]);

  const fetchLogs = async () => {
    setLoading(true);
    setError("");

    try {
      const params = new URLSearchParams();
      params.set("page", "1");
      params.set("limit", String(FETCH_LIMIT));

      const res = await fetch(`${API_BASE_URL}/api/ftp_logs?${params.toString()}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      const data = await res.json();
      const rows = Array.isArray(data.logs) ? data.logs : [];
      setApiRows(rows);
    } catch (e) {
      setError(e?.message || "Failed to load FTP logs");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [refreshTrigger]);

  // When any filter changes -> go back to page 1
  useEffect(() => {
    setPage(1);
  }, [q, username, ip, action, severity, limit]);

  const filtered = useMemo(() => {
    const qv = q.trim().toLowerCase();
    const uv = username.trim().toLowerCase();
    const ipv = ip.trim().toLowerCase();
    const av = action === "all" ? "" : action.toUpperCase();
    const sv = severity === "all" ? "" : severity.toUpperCase();

    const normalized = apiRows.map((r, idx) => {
      const raw = r.raw || "";
      const fileFromRaw = extractFileFromRaw(raw);

      const actionU = String(r.action || "OTHER").toUpperCase();
      const sevU = normalizeSeverity(r.severity) || inferFtpSeverityFallback(actionU);

      return {
        id: `${r.timestamp || "t"}-${idx}`,
        timestamp: r.timestamp || "",
        user: r.user || "",
        ip: cleanIp(r.ip || ""),
        action: actionU,
        severity: sevU,
        file: r.file_target || fileFromRaw || "-",
        raw,
      };
    });

    return normalized.filter((row) => {
      if (av && row.action !== av) return false;
      if (sv && row.severity !== sv) return false;

      if (uv && !String(row.user || "").toLowerCase().includes(uv)) return false;
      if (ipv && !String(row.ip || "").toLowerCase().includes(ipv)) return false;

      if (qv) {
        const hay = `${row.user} ${row.ip} ${row.file} ${row.raw}`.toLowerCase();
        if (!hay.includes(qv)) return false;
      }

      return true;
    });
  }, [apiRows, q, username, ip, action, severity]);

  const total = filtered.length;
  const totalPages = Math.max(1, Math.ceil(total / limit));

  const safePage = Math.min(page, totalPages);
  const start = (safePage - 1) * limit;
  const end = start + limit;
  const pageRows = filtered.slice(start, end);

  const clearFilters = () => {
    setQ("");
    setUsername("");
    setIp("");
    setAction("all");
    setSeverity("all");
    setPage(1);
  };

  const canPrev = safePage > 1;
  const canNext = safePage < totalPages;

  return (
    <div className="content">
      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">📁 FTP Events</h2>
            <div className="card-subtitle">Showing only: {IMPORTANT_ACTIONS.join(", ")}</div>
          </div>

          <div className="page-size-buttons" role="group" aria-label="Page size">
            {LIMIT_OPTIONS.map((n) => (
              <button
                key={n}
                type="button"
                className={n === limit ? "pill pill-active" : "pill"}
                onClick={() => setLimit(n)}
                disabled={loading}
              >
                {n}
              </button>
            ))}
          </div>
        </div>

        <div className="filters-row">
          <input
            className="input"
            placeholder="Search (user / ip / file / raw)…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
          <input
            className="input"
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
          <input className="input" placeholder="IP" value={ip} onChange={(e) => setIp(e.target.value)} />

          <select className="select" value={action} onChange={(e) => setAction(e.target.value)}>
            <option value="all">All Actions</option>
            {IMPORTANT_ACTIONS.map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </select>

          {/* ✅ new: severity filter */}
          <select className="select" value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="all">All Severity</option>
            <option value="low">LOW</option>
            <option value="medium">MEDIUM</option>
            <option value="high">HIGH</option>
            <option value="critical">CRITICAL</option>
          </select>

          <button className="btn btn-secondary" onClick={clearFilters} disabled={loading}>
            Clear
          </button>
        </div>

        <div className="meta-row">
          <div className="meta-left">{loading ? "Loading…" : `Showing ${pageRows.length} of ${total} results`}</div>
          <div className="meta-right">
            Page <b>{safePage}</b> / <b>{totalPages}</b>
          </div>
        </div>

        {error ? <div className="error">{error}</div> : null}

        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th style={{ width: 180 }}>TIME</th>
                <th style={{ width: 140 }}>USER</th>
                <th style={{ width: 160 }}>IP</th>
                <th style={{ width: 160 }}>ACTION</th>
                {/* ✅ new */}
                <th style={{ width: 140 }}>SEVERITY</th>
                <th>FILE / TARGET</th>
              </tr>
            </thead>
            <tbody>
              {pageRows.length === 0 ? (
                <tr>
                  <td colSpan={6} className="empty">
                    No FTP logs match your filters.
                  </td>
                </tr>
              ) : (
                pageRows.map((r) => (
                  <tr key={r.id}>
                    <td className="mono">{r.timestamp || "-"}</td>
                    <td className="mono">{r.user || "-"}</td>
                    <td className="mono">{r.ip || "-"}</td>
                    <td>
                      <span className={`badge badge-${String(r.action).toLowerCase().replace(/\s+/g, "-")}`}>
                        {r.action}
                      </span>
                    </td>
                    <td>
                      <SeverityBadge severity={r.severity} />
                    </td>
                    <td className="mono">{r.file || "-"}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        <div className="pager">
          <button className="btn btn-secondary" disabled={!canPrev || loading} onClick={() => setPage((p) => p - 1)}>
            Prev
          </button>
          <button className="btn btn-secondary" disabled={!canNext || loading} onClick={() => setPage((p) => p + 1)}>
            Next
          </button>
        </div>
      </div>
    </div>
  );
}