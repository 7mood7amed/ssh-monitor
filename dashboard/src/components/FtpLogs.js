import React, { useEffect, useMemo, useState } from "react";
import API_BASE_URL from "../config";
import "./FtpLogs.css";

const IMPORTANT_ACTIONS = ["LOGIN_SUCCESS", "LOGIN_FAIL", "UPLOAD", "DOWNLOAD", "DELETE", "RENAME", "MKDIR", "RMDIR"];
const LIMIT_OPTIONS = [20, 50, 100];
const FETCH_LIMIT = 7000;

function cleanIp(ip) {
  return String(ip || "").replace(/^::ffff:/, "");
}

function extractFileFromRaw(raw) {
  const msg = String(raw || "").replace("\x00", "").trim();
  if (!msg) return "";
  const patterns = [
    [/"STOR\s+([^"]+)"/i, m => m[1].trim()],
    [/"RETR\s+([^"]+)"/i, m => m[1].trim()],
    [/"DELE\s+([^"]+)"/i, m => m[1].trim()],
    [/"(?:MKD|MKDIR)\s+([^"]+)"/i, m => m[1].trim()],
    [/"(?:RMD|RMDIR)\s+([^"]+)"/i, m => m[1].trim()],
    [/"RNFR\s+([^"]+)"/i, m => {
      const to = msg.match(/"RNTO\s+([^"]+)"/i);
      return to ? `${m[1].trim()} → ${to[1].trim()}` : m[1].trim();
    }],
    [/((?:\/upload|\/uploads)[^"]+)/i, m => m[1]],
  ];
  for (const [re, fn] of patterns) {
    const m = msg.match(re);
    if (m) return fn(m);
  }
  return "";
}

function normalizeSev(v) {
  const s = String(v || "").trim().toUpperCase();
  return ["LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(s) ? s : "";
}

function inferSev(action) {
  const a = String(action || "").toUpperCase();
  if (a === "RMDIR") return "CRITICAL";
  if (a === "DELETE") return "HIGH";
  if (a === "LOGIN_FAIL") return "HIGH";
  if (["RENAME", "MKDIR"].includes(a)) return "MEDIUM";
  return "LOW";
}

function SevBadge({ severity }) {
  const s = normalizeSev(severity) || "LOW";
  return <span className={`sev-badge ${s}`}>{s}</span>;
}

export default function FtpLogs({ refreshTrigger }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [q, setQ] = useState("");
  const [username, setUsername] = useState("");
  const [ip, setIp] = useState("");
  const [action, setAction] = useState("all");
  const [severity, setSeverity] = useState("all");
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(20);
  const [apiRows, setApiRows] = useState([]);

  const fetchLogs = async () => {
    setLoading(true); setError("");
    try {
      const params = new URLSearchParams({ page: "1", limit: String(FETCH_LIMIT) });
      const res = await fetch(`${API_BASE_URL}/api/ftp_logs?${params}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setApiRows(Array.isArray(data.logs) ? data.logs : []);
    } catch (e) { setError(e?.message || "Failed to load FTP logs"); }
    finally { setLoading(false); }
  };

  useEffect(() => { fetchLogs(); }, [refreshTrigger]);
  useEffect(() => { setPage(1); }, [q, username, ip, action, severity, limit]);

  const filtered = useMemo(() => {
    const qv = q.trim().toLowerCase();
    const uv = username.trim().toLowerCase();
    const ipv = ip.trim().toLowerCase();
    const av = action === "all" ? "" : action.toUpperCase();
    const sv = severity === "all" ? "" : severity.toUpperCase();

    return apiRows
      .map((r, idx) => {
        const actionU = String(r.action || "OTHER").toUpperCase();
        const sevU = normalizeSev(r.severity) || inferSev(actionU);
        return {
          id: `${r.timestamp}-${idx}`,
          timestamp: r.timestamp || "",
          user: r.user || "",
          ip: cleanIp(r.ip || ""),
          action: actionU,
          severity: sevU,
          file: r.file_target || extractFileFromRaw(r.raw) || "",
          raw: r.raw || "",
        };
      })
      .filter(row => {
        if (av && row.action !== av) return false;
        if (sv && row.severity !== sv) return false;
        if (uv && !row.user.toLowerCase().includes(uv)) return false;
        if (ipv && !row.ip.toLowerCase().includes(ipv)) return false;
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
  const pageRows = filtered.slice((safePage - 1) * limit, safePage * limit);

  return (
    <div className="content">
      <div className="card">
        {/* Header */}
        <div className="card-header">
          <div>
            <h2 className="card-title">📁 FTP Events</h2>
            <div className="card-subtitle">Login · uploads · downloads · file operations</div>
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

        {/* Filters */}
        <div className="filters-row">
          <input className="input" placeholder="Search user / IP / file…" value={q} onChange={e => setQ(e.target.value)} />
          <input className="input" placeholder="Username" value={username} onChange={e => setUsername(e.target.value)} />
          <input className="input" placeholder="IP address" value={ip} onChange={e => setIp(e.target.value)} />
          <select className="select" value={action} onChange={e => setAction(e.target.value)}>
            <option value="all">All Actions</option>
            {IMPORTANT_ACTIONS.map(a => <option key={a} value={a}>{a}</option>)}
          </select>
          <select className="select" value={severity} onChange={e => setSeverity(e.target.value)}>
            <option value="all">All Severity</option>
            <option value="low">LOW</option>
            <option value="medium">MEDIUM</option>
            <option value="high">HIGH</option>
            <option value="critical">CRITICAL</option>
          </select>
          <button className="btn" onClick={() => { setQ(""); setUsername(""); setIp(""); setAction("all"); setSeverity("all"); setPage(1); }} disabled={loading}>
            Clear
          </button>
        </div>

        {/* Meta */}
        <div className="meta-row">
          <span>{loading ? "Loading…" : `Showing ${pageRows.length} of ${total} results`}</span>
          <span>Page <b>{safePage}</b> / <b>{totalPages}</b></span>
        </div>

        {error && <div className="error">{error}</div>}

        {/* Table */}
        <div className="table-wrap">
          <table className="table" style={{ tableLayout: "fixed", width: "100%" }}>
            <thead>
              <tr>
                <th style={{ width: 150 }}>TIME</th>
                <th style={{ width: 130 }}>USER</th>
                <th style={{ width: 150 }}>IP</th>
                <th style={{ width: 140 }}>ACTION</th>
                <th style={{ width: 110 }}>SEVERITY</th>
                <th>FILE / TARGET</th>
              </tr>
            </thead>
            <tbody>
              {pageRows.length === 0 ? (
                <tr><td colSpan={6} className="empty">No FTP logs match your filters.</td></tr>
              ) : (
                pageRows.map(r => (
                  <tr key={r.id}
                    className={r.severity === "HIGH" || r.severity === "CRITICAL" ? "row-high" : ""}
                    style={{ height: 44 }}>
                    <td className="mono" style={{ fontSize: 11, color: "rgba(226,232,240,0.55)" }}>
                      {r.timestamp || "—"}
                    </td>
                    <td style={{ fontWeight: 600, fontSize: 13 }}>{r.user || "—"}</td>
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
                      <span className={`badge badge-${r.action.toLowerCase()}`}>
                        {r.action}
                      </span>
                    </td>
                    <td><SevBadge severity={r.severity} /></td>
                    <td className="mono" style={{ fontSize: 12, color: "rgba(226,232,240,0.65)" }}>
                      {r.file || <span style={{ color: "rgba(226,232,240,0.22)" }}>—</span>}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pager */}
        <div className="pager">
          <button className="btn" disabled={safePage <= 1 || loading} onClick={() => setPage(p => p - 1)}>← Prev</button>
          <span style={{ fontSize: 12, color: "rgba(226,232,240,0.45)" }}>{safePage} / {totalPages}</span>
          <button className="btn" disabled={safePage >= totalPages || loading} onClick={() => setPage(p => p + 1)}>Next →</button>
        </div>
      </div>
    </div>
  );
}