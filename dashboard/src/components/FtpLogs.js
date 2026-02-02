// dashboard/src/components/FtpLogs.js
import React, { useEffect, useMemo, useState } from "react";
import API_BASE_URL from "../config";
import "./FtpLogs.css";

// Only keep these actions (as you requested)
const IMPORTANT_ACTIONS = [
  "LOGIN SUCCESS",
  "LOGIN FAIL",
  "UPLOAD",
  "DOWNLOAD",
  "DELETE",
  "RENAME",
  "MKDIR",
  "RMDIR",
];

// UI page size options (like SSH/Web)
const LIMIT_OPTIONS = [20, 50, 100];

// We fetch a bigger chunk, then FILTER + PAGINATE locally
// so "Show 20" always shows 20 AFTER filtering.
const FETCH_LIMIT = 2000;

function cleanIp(ip) {
  if (!ip) return "";
  return ip.replace(/^::ffff:/, "");
}

function parseVsftpdLine(raw) {
  const msg = (raw || "").replace("\x00", "").trim();
  if (!msg) return null;

  // Client IP
  const ipMatch = msg.match(/Client\s+"([^"]+)"/i);
  const ip = cleanIp(ipMatch?.[1] || "");

  // User in [hero]
  const userMatch = msg.match(/\[([^\]]+)\]/);
  const user = userMatch?.[1] || "";

  // File/path often in "...", "/upload/xxx"
  const quotedPath = msg.match(/,\s+"(\/[^"]+)"/)?.[1] || "";

  // Extract filenames from commands too (STOR/RETR/etc)
  const storName = msg.match(/"STOR\s+([^"]+)"/i)?.[1] || "";
  const retrName = msg.match(/"RETR\s+([^"]+)"/i)?.[1] || "";
  const deleName = msg.match(/"DELE\s+([^"]+)"/i)?.[1] || "";
  const rnfrName = msg.match(/"RNFR\s+([^"]+)"/i)?.[1] || "";
  const rntoName = msg.match(/"RNTO\s+([^"]+)"/i)?.[1] || "";
  const mkdirName = msg.match(/"(?:MKD|MKDIR)\s+([^"]+)"/i)?.[1] || "";
  const rmdirName = msg.match(/"(?:RMD|RMDIR)\s+([^"]+)"/i)?.[1] || "";

  // Helpers
  const fileOrDash = (v) => (v && v.trim() ? v.trim() : "-");

  // --- ACTIONS (only the important ones) ---

  // Login success
  if (/OK LOGIN/i.test(msg)) {
    return { action: "LOGIN SUCCESS", user, ip, file: "-" };
  }

  // Login fail (vsftpd variants)
  if (/FAIL LOGIN/i.test(msg) || /LOGIN FAILED/i.test(msg) || /Login incorrect/i.test(msg)) {
    return { action: "LOGIN FAIL", user, ip, file: "-" };
  }

  // Upload
  if (/OK UPLOAD/i.test(msg) || /FTP command:.*"STOR\b/i.test(msg)) {
    return { action: "UPLOAD", user, ip, file: fileOrDash(quotedPath || storName) };
  }

  // Download
  if (/OK DOWNLOAD/i.test(msg) || /FTP command:.*"RETR\b/i.test(msg)) {
    return { action: "DOWNLOAD", user, ip, file: fileOrDash(quotedPath || retrName) };
  }

  // Delete
  if (/OK DELETE/i.test(msg) || /FTP command:.*"DELE\b/i.test(msg)) {
    return { action: "DELETE", user, ip, file: fileOrDash(quotedPath || deleName) };
  }

  // Rename (RNFR/RNTO/OK RENAME)
  if (/OK RENAME/i.test(msg) || /FTP command:.*"RNFR\b/i.test(msg) || /FTP command:.*"RNTO\b/i.test(msg)) {
    const pretty = rnfrName && rntoName ? `${rnfrName} → ${rntoName}` : "";
    return { action: "RENAME", user, ip, file: fileOrDash(pretty || rnfrName || rntoName || quotedPath) };
  }

  // MKDIR
  if (/OK MKDIR/i.test(msg) || /FTP command:.*"(MKD|MKDIR)\b/i.test(msg)) {
    return { action: "MKDIR", user, ip, file: fileOrDash(mkdirName || quotedPath) };
  }

  // RMDIR
  if (/OK RMDIR/i.test(msg) || /FTP command:.*"(RMD|RMDIR)\b/i.test(msg)) {
    return { action: "RMDIR", user, ip, file: fileOrDash(rmdirName || quotedPath) };
  }

  // Not important
  return { action: "OTHER", user, ip, file: "-" };
}

export default function FtpLogs({ refreshTrigger }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  // filters
  const [q, setQ] = useState("");
  const [username, setUsername] = useState("");
  const [ip, setIp] = useState("");
  const [action, setAction] = useState("all");

  // paging (LOCAL paging after filtering)
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(20);

  // raw logs from API
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

  // When any filter changes -> go back to page 1 (your request)
  useEffect(() => {
    setPage(1);
  }, [q, username, ip, action, limit]);

  const filtered = useMemo(() => {
    const qv = q.trim().toLowerCase();
    const uv = username.trim().toLowerCase();
    const ipv = ip.trim().toLowerCase();
    const av = action === "all" ? "" : action;

    const parsed = apiRows
      .map((r) => {
        const p = parseVsftpdLine(r.message);
        if (!p) return null;

        return {
          id: r.id,
          timestamp: r.timestamp || r.log_time || "",
          source: r.source || "",
          raw: r.message || "",
          ...p,
        };
      })
      .filter(Boolean);

    return parsed.filter((row) => {
      // keep only important actions
      if (!IMPORTANT_ACTIONS.includes(row.action)) return false;

      if (av && row.action !== av) return false;
      if (uv && !String(row.user || "").toLowerCase().includes(uv)) return false;
      if (ipv && !String(row.ip || "").toLowerCase().includes(ipv)) return false;

      if (qv) {
        const hay = `${row.user} ${row.ip} ${row.file} ${row.raw}`.toLowerCase();
        if (!hay.includes(qv)) return false;
      }
      return true;
    });
  }, [apiRows, q, username, ip, action]);

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
            <div className="card-subtitle">
              Showing only: {IMPORTANT_ACTIONS.join(", ")}
            </div>
          </div>

          {/* Page size buttons like your SSH/Web style */}
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

        {/* Filters row (same vibe as WebTraffic) */}
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
          <input
            className="input"
            placeholder="IP"
            value={ip}
            onChange={(e) => setIp(e.target.value)}
          />
          <select className="select" value={action} onChange={(e) => setAction(e.target.value)}>
            <option value="all">All Actions</option>
            {IMPORTANT_ACTIONS.map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </select>

          <button className="btn btn-secondary" onClick={clearFilters} disabled={loading}>
            Clear
          </button>
        </div>

        <div className="meta-row">
          <div className="meta-left">
            {loading ? "Loading…" : `Showing ${pageRows.length} of ${total} results`}
          </div>
          <div className="meta-right">
            Page <b>{safePage}</b> / <b>{totalPages}</b>
          </div>
        </div>

        {error ? <div className="error">{error}</div> : null}

        {/* Table (same structure as WebTraffic/SSH tables) */}
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th style={{ width: 180 }}>TIME</th>
                <th style={{ width: 140 }}>USER</th>
                <th style={{ width: 160 }}>IP</th>
                <th style={{ width: 160 }}>ACTION</th>
                <th>FILE / TARGET</th>
              </tr>
            </thead>
            <tbody>
              {pageRows.length === 0 ? (
                <tr>
                  <td colSpan={5} className="empty">
                    No FTP logs match your filters.
                  </td>
                </tr>
              ) : (
                pageRows.map((r) => (
                  <tr key={r.id || `${r.timestamp}-${r.raw}`}>
                    <td className="mono">{r.timestamp || "-"}</td>
                    <td className="mono">{r.user || "-"}</td>
                    <td className="mono">{r.ip || "-"}</td>
                    <td>
                      <span className={`badge badge-${String(r.action).toLowerCase().replace(/\s+/g, "-")}`}>
                        {r.action}
                      </span>
                    </td>
                    <td className="mono">{r.file || "-"}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pager */}
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