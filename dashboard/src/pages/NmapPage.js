import React, { useEffect, useMemo, useState } from "react";
import API_BASE_URL from "../config";
import "../components/FtpLogs.css";

function SeverityBadge({ severity }) {
  const s = String(severity || "low").toLowerCase();
  const label = s.toUpperCase();

  const style = {
    display: "inline-block",
    padding: "2px 10px",
    borderRadius: "999px",
    fontSize: "12px",
    fontWeight: 700,
    letterSpacing: "0.4px",
    textTransform: "uppercase",
    border: "1px solid rgba(255,255,255,0.12)",
    background:
      s === "critical"
        ? "rgba(239,68,68,0.25)"
        : s === "high"
          ? "rgba(249,115,22,0.22)"
          : s === "medium"
            ? "rgba(234,179,8,0.20)"
            : "rgba(34,197,94,0.18)",
  };

  return <span style={style}>{label}</span>;
}

const LIMIT_OPTIONS = [20, 50, 100];

export default function NmapPage() {
  const [rows, setRows] = useState([]);

  const [q, setQ] = useState("");
  const [host, setHost] = useState("");
  const [port, setPort] = useState("");
  const [state, setState] = useState("All");
  const [service, setService] = useState("All");
  const [severity, setSeverity] = useState("All");

  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(1);

  useEffect(() => {
    setPage(1);
  }, [q, host, port, state, service, severity, pageSize]);

  const url = useMemo(() => {
    const params = new URLSearchParams();
    params.set("page", String(page));
    params.set("limit", String(pageSize));

    if (q.trim()) params.set("q", q.trim());
    if (host.trim()) params.set("host", host.trim());
    if (port.trim()) params.set("port", port.trim());
    if (state !== "All") params.set("state", state);
    if (service !== "All") params.set("service", service);

    return `${API_BASE_URL}/api/nmap_findings?${params.toString()}`;
  }, [page, pageSize, q, host, port, state, service]);

  useEffect(() => {
    const fetchFindings = async () => {
      try {
        const res = await fetch(url);
        const data = await res.json();

        setRows(Array.isArray(data.items) ? data.items : []);
        setTotal(data.total || 0);
        setTotalPages(data.totalPages || 1);

        if ((data.totalPages || 1) < page) setPage(1);
      } catch (e) {
        console.error("Error fetching nmap findings:", e);
      }
    };

    fetchFindings();
    const interval = setInterval(fetchFindings, 15000);
    return () => clearInterval(interval);
  }, [url, page]);

  const clear = () => {
    setQ("");
    setHost("");
    setPort("");
    setState("All");
    setService("All");
    setSeverity("All");
    setPage(1);
  };

  const filteredRows = useMemo(() => {
    let result = rows;

    if (severity !== "All") {
      const sv = severity.toLowerCase();
      result = result.filter((r) => String(r.severity || "").toLowerCase() === sv);
    }

    const seen = new Set();

    return result.filter((r) => {
      const key = [
        r.host || r.target || "",
        r.port || "",
        r.proto || "",
        r.state || "",
        r.service || "",
      ].join("|");

      if (seen.has(key)) return false;

      seen.add(key);
      return true;
    });
  }, [rows, severity]);

  const servicesByIp = useMemo(() => {
    const grouped = {};

    filteredRows
      .filter((r) => String(r.state || "").toLowerCase() === "open")
      .forEach((r) => {
        const ip = r.host || r.target || "Unknown IP";
        const serviceName = r.service || "unknown";
        const portNumber = r.port || "unknown";
        const proto = r.proto || "tcp";
        const serviceLabel = `${serviceName} (${portNumber}/${proto})`;

        if (!grouped[ip]) {
          grouped[ip] = new Set();
        }

        grouped[ip].add(serviceLabel);
      });

    const servicePriority = {
      ftp: 1,
      ssh: 2,
      http: 3,
      https: 4,
      mysql: 5,
      postgresql: 6,
      upnp: 7,
    };

    const getServicePriority = (label) => {
      const name = String(label).split(" ")[0].toLowerCase();
      return servicePriority[name] || 99;
    };

    return Object.entries(grouped)
      .map(([ip, services]) => ({
        ip,
        services: Array.from(services).sort(
          (a, b) => getServicePriority(a) - getServicePriority(b)
        ),
      }))
      .sort((a, b) => b.services.length - a.services.length);
  }, [filteredRows]);

  const handlePrev = () => setPage((p) => Math.max(p - 1, 1));
  const handleNext = () => setPage((p) => Math.min(p + 1, totalPages || 1));

  return (
    <div className="content">
      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">🧭 Network Exposure Findings</h2>
            <div className="card-subtitle">
              Open services grouped by host/IP, with detailed scan results below.
            </div>
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
          <input className="input" placeholder="Search target/host/service..." value={q} onChange={(e) => setQ(e.target.value)} />
          <input className="input" placeholder="Host (e.g. 127.0.0.1)" value={host} onChange={(e) => setHost(e.target.value)} />
          <input className="input" placeholder="Port (e.g. 22)" value={port} onChange={(e) => setPort(e.target.value)} />

          <select className="select" value={state} onChange={(e) => setState(e.target.value)}>
            <option value="All">All States</option>
            <option value="open">open</option>
            <option value="closed">closed</option>
            <option value="filtered">filtered</option>
          </select>

          <select className="select" value={service} onChange={(e) => setService(e.target.value)}>
            <option value="All">All Services</option>
            <option value="ssh">ssh</option>
            <option value="ftp">ftp</option>
            <option value="http">http</option>
            <option value="mysql">mysql</option>
            <option value="postgresql">postgresql</option>
            <option value="upnp">upnp</option>
          </select>

          {/* <select className="select" value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="All">All Severity</option>
            <option value="critical">critical</option>
            <option value="high">high</option>
            <option value="medium">medium</option>
            <option value="low">low</option>
          </select> */}

          <button className="btn btn-secondary" type="button" onClick={clear}>
            Clear
          </button>
        </div>

        <div className="meta-row">
          <div className="meta-left">
            Showing <b>{filteredRows.length}</b> of <b>{total}</b> results
          </div>
          <div className="meta-right">
            Page <b>{page}</b> / <b>{totalPages}</b>
          </div>
        </div>

        <div className="card" style={{ marginBottom: 18 }}>
          <h3 className="card-title">Exposed Services By Host</h3>
          <div className="card-subtitle">
            This groups open services by IP so analysts can quickly identify hosts exposing multiple services.
          </div>

          {servicesByIp.length === 0 ? (
            <p className="empty">No open services found for the current filters.</p>
          ) : (
            <div style={{ marginTop: 12, display: "grid", gap: 10 }}>
              {servicesByIp.map(({ ip, services }) => (
                <div
                  key={ip}
                  style={{
                    padding: "12px",
                    borderRadius: "12px",
                    border: "1px solid rgba(255,255,255,0.10)",
                    background: "rgba(255,255,255,0.04)",
                  }}
                >
                  <div
                    className="mono"
                    style={{
                      fontWeight: 800,
                      marginBottom: 6,
                      display: "flex",
                      alignItems: "center",
                      gap: "10px",
                    }}
                  >
                    <span>{ip}</span>
                    <span
                      style={{
                        fontSize: "12px",
                        padding: "3px 9px",
                        borderRadius: "999px",
                        border: "1px solid rgba(56,189,248,0.35)",
                        background: "rgba(56,189,248,0.12)",
                        color: "#e0f2fe",
                      }}
                    >
                      {services.length} Services
                    </span>
                  </div>
                  <div>
                    <b>{services.length}</b> open service(s): {services.join(", ")}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th style={{ width: 170 }}>SCAN TIME</th>
                <th style={{ width: 110 }}>AGENT</th>
                <th style={{ width: 160 }}>TARGET</th>
                <th style={{ width: 160 }}>HOST</th>
                <th style={{ width: 90 }}>PORT</th>
                <th style={{ width: 80 }}>PROTO</th>
                <th style={{ width: 110 }}>STATE</th>
                <th style={{ width: 130 }}>SERVICE</th>
                {/* <th style={{ width: 140 }}>SEVERITY</th> */}
                <th>EXTRA</th>
              </tr>
            </thead>

            <tbody>
              {filteredRows.length === 0 ? (
                <tr>
                  <td colSpan={9} className="empty">
                    No NMAP findings match your filters.
                  </td>
                </tr>
              ) : (
                filteredRows.map((r) => (
                  <tr key={r.id}>
                    <td className="mono">{r.scan_time}</td>
                    <td>{r.agent_name}</td>
                    <td className="mono">{r.target}</td>
                    <td className="mono">{r.host}</td>
                    <td className="mono">{r.port}</td>
                    <td>{r.proto}</td>
                    <td>{r.state}</td>
                    <td>{r.service}</td>
                    <td>
                      {/* <SeverityBadge severity={r.severity} /> */}
                    </td>
                    <td className="mono" title={r.extra || ""}>
                      {r.extra || ""}
                    </td>
                  </tr>
                ))
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
}