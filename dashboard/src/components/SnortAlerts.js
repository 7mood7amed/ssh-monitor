import React, { useEffect, useMemo, useState } from "react";
import API_BASE_URL from "../config";
import "./FtpLogs.css";
import "./Metrics.css";

const LIMIT_OPTIONS = [20, 50, 100];
const FETCH_LIMIT = 7000;

// captured_at comes from the backend as a genuinely-UTC value with no timezone
// marker (Postgres NOW() default) -- mark it as UTC before converting so it
// displays real Bahrain time.
function fmtTs(d) {
  if (!d) return "—";
  let iso = d;
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/.test(d)) {
    iso = d.replace(" ", "T") + "Z";
  }
  return new Date(iso).toLocaleString("en-GB", {
    timeZone: "Asia/Bahrain",
    day: "2-digit", month: "2-digit", year: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

function normalizeSev(v) {
  const s = String(v || "").trim().toUpperCase();
  return ["LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(s) ? s : "";
}

function SevBadge({ severity }) {
  const s = normalizeSev(severity) || "LOW";
  return <span className={`sev-badge ${s}`}>{s}</span>;
}

export default function SnortAlerts({ refreshTrigger }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [q, setQ] = useState("");
  const [srcIp, setSrcIp] = useState("");
  const [dstIp, setDstIp] = useState("");
  const [severity, setSeverity] = useState("all");
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(20);
  const [apiRows, setApiRows] = useState([]);
  const [summary, setSummary] = useState({ snortAlerts24h: 0, snortCritical24h: 0 });

  const fetchAlerts = async () => {
    setLoading(true); setError("");
    try {
      const params = new URLSearchParams({ page: "1", limit: String(FETCH_LIMIT) });
      const res = await fetch(`${API_BASE_URL}/api/snort_alerts?${params}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setApiRows(Array.isArray(data.events) ? data.events : []);
    } catch (e) { setError(e?.message || "Failed to load Snort alerts"); }
    finally { setLoading(false); }
  };

  const fetchSummary = async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/metrics`);
      if (!res.ok) return;
      const data = await res.json();
      setSummary({
        snortAlerts24h: data.snortAlerts24h ?? 0,
        snortCritical24h: data.snortCritical24h ?? 0,
      });
    } catch (e) { /* summary strip is best-effort */ }
  };

  useEffect(() => {
    fetchAlerts();
    fetchSummary();
    const id = setInterval(() => { fetchAlerts(); fetchSummary(); }, 5000);
    return () => clearInterval(id);
  }, [refreshTrigger]);

  useEffect(() => { setPage(1); }, [q, srcIp, dstIp, severity, limit]);

  const filtered = useMemo(() => {
    const qv = q.trim().toLowerCase();
    const srcV = srcIp.trim().toLowerCase();
    const dstV = dstIp.trim().toLowerCase();
    const sv = severity === "all" ? "" : severity.toUpperCase();

    return apiRows
      .map((r, idx) => ({
        id: `${r.id ?? idx}-${r.captured_at}`,
        captured_at: r.captured_at || "",
        sid: r.sid,
        message: r.message || "",
        classification: r.classification || "",
        protocol: r.protocol || "",
        src_ip: r.src_ip || "",
        src_port: r.src_port,
        dst_ip: r.dst_ip || "",
        dst_port: r.dst_port,
        severity: normalizeSev(r.severity) || "LOW",
      }))
      .filter(row => {
        if (sv && row.severity !== sv) return false;
        if (srcV && !row.src_ip.toLowerCase().includes(srcV)) return false;
        if (dstV && !row.dst_ip.toLowerCase().includes(dstV)) return false;
        if (qv) {
          const hay = `${row.message} ${row.classification} ${row.sid}`.toLowerCase();
          if (!hay.includes(qv)) return false;
        }
        return true;
      });
  }, [apiRows, q, srcIp, dstIp, severity]);

  const total = filtered.length;
  const totalPages = Math.max(1, Math.ceil(total / limit));
  const safePage = Math.min(page, totalPages);
  const pageRows = filtered.slice((safePage - 1) * limit, safePage * limit);

  const summaryCards = [
    { title: "Alerts (24h)", value: summary.snortAlerts24h, icon: "🐗", color: "#00d4ff", desc: "Signature + portscan matches" },
    { title: "Critical (24h)", value: summary.snortCritical24h, icon: "🚨", color: "#ff3366", desc: "Priority 1 exploit/attack signatures" },
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
            <h2 className="card-title">🐗 Snort IDS Alerts</h2>
            <div className="card-subtitle">Signature-based detection — known exploits, malware traffic, attack payloads</div>
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
          <input className="input" placeholder="Search message / classification / sid…" value={q} onChange={e => setQ(e.target.value)} />
          <input className="input" placeholder="Source IP" value={srcIp} onChange={e => setSrcIp(e.target.value)} />
          <input className="input" placeholder="Destination IP" value={dstIp} onChange={e => setDstIp(e.target.value)} />
          <select className="select" value={severity} onChange={e => setSeverity(e.target.value)}>
            <option value="all">All Severity</option>
            <option value="low">LOW</option>
            <option value="medium">MEDIUM</option>
            <option value="high">HIGH</option>
            <option value="critical">CRITICAL</option>
          </select>
          <button className="btn" onClick={() => { setQ(""); setSrcIp(""); setDstIp(""); setSeverity("all"); setPage(1); }} disabled={loading}>
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
                <th style={{ width: 170 }}>SOURCE</th>
                <th style={{ width: 170 }}>DESTINATION</th>
                <th style={{ width: 80 }}>PROTO</th>
                <th>MESSAGE</th>
                <th style={{ width: 110 }}>SEVERITY</th>
              </tr>
            </thead>
            <tbody>
              {pageRows.length === 0 ? (
                <tr><td colSpan={6} className="empty">No Snort alerts match your filters.</td></tr>
              ) : (
                pageRows.map(r => (
                  <tr key={r.id}
                    className={r.severity === "HIGH" || r.severity === "CRITICAL" ? "row-high" : ""}
                    style={{ height: 44 }}>
                    <td className="mono" style={{ fontSize: 11, color: "rgba(226,232,240,0.55)" }}>
                      {fmtTs(r.captured_at)}
                    </td>
                    <td className="mono" style={{ fontSize: 12, color: "rgba(226,232,240,0.75)" }}>
                      {r.src_ip ? `${r.src_ip}${r.src_port ? ":" + r.src_port : ""}` : "—"}
                    </td>
                    <td className="mono" style={{ fontSize: 12, color: "rgba(226,232,240,0.75)" }}>
                      {r.dst_ip ? `${r.dst_ip}${r.dst_port ? ":" + r.dst_port : ""}` : "—"}
                    </td>
                    <td className="mono" style={{ fontSize: 11, color: "rgba(226,232,240,0.55)" }}>
                      {r.protocol || "—"}
                    </td>
                    <td className="truncate" style={{ fontSize: 12, color: "rgba(226,232,240,0.85)" }}>
                      {r.message || "—"}
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
