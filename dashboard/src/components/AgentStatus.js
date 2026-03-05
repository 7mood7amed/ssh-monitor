import React, { useEffect, useMemo, useState } from "react";
import API_BASE_URL from "../config";
import "./FtpLogs.css";

function normalizeStatus(value) {
  const s = String(value || "").trim().toLowerCase();
  if (!s) return "unknown";
  if (s === "active" || s === "up" || s === "online") return "active";
  if (s === "inactive" || s === "down" || s === "offline") return "inactive";
  return s;
}

function StatusBadge({ status }) {
  const s = normalizeStatus(status);
  const label = s.toUpperCase();

  const style = {
    display: "inline-block",
    padding: "2px 10px",
    borderRadius: "999px",
    fontSize: "12px",
    fontWeight: 800,
    letterSpacing: "0.4px",
    textTransform: "uppercase",
    border: "1px solid rgba(255,255,255,0.12)",
    background:
      s === "active"
        ? "rgba(34,197,94,0.18)"
        : s === "inactive"
        ? "rgba(239,68,68,0.20)"
        : "rgba(148,163,184,0.14)",
    color: "rgba(226,232,240,0.92)",
  };

  return <span style={style}>{label}</span>;
}

export default function AgentStatus() {
  const [agents, setAgents] = useState([]);
  const [apiOk, setApiOk] = useState(true);

  const total = agents.length;

  const url = useMemo(() => `${API_BASE_URL}/api/agents`, []);

  useEffect(() => {
    let alive = true;

    const fetchAgents = async () => {
      try {
        const res = await fetch(url);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();

        if (!alive) return;
        setApiOk(true);
        setAgents(Array.isArray(data) ? data : []);
      } catch (err) {
        console.error("Error fetching agent data:", err);
        if (!alive) return;
        setApiOk(false);
        setAgents([]);
      }
    };

    fetchAgents();
    const interval = setInterval(fetchAgents, 10000);
    return () => {
      alive = false;
      clearInterval(interval);
    };
  }, [url]);

  const activeCount = useMemo(() => {
    return agents.filter((a) => normalizeStatus(a.status) === "active").length;
  }, [agents]);

  return (
    <div className="content">
      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">🛰 Agent Status</h2>
            <div className="card-subtitle">Agent heartbeats + health</div>
          </div>

          {}
          <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
            <span
              style={{
                fontSize: 12,
                fontWeight: 700,
                color: apiOk ? "rgba(226,232,240,0.75)" : "rgba(239,68,68,0.9)",
              }}
              title={apiOk ? "API reachable" : "API unreachable"}
            >
              {apiOk ? "API: OK" : "API: OFFLINE"}
            </span>
          </div>
        </div>

        {}
        <div className="meta-row">
          <div className="meta-left">
            Showing <b>{total}</b> agents • Active: <b>{activeCount}</b>
          </div>
          <div className="meta-right">
            {}
          </div>
        </div>

        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th style={{ width: 220 }}>AGENT</th>
                <th style={{ width: 240 }}>LAST HEARTBEAT</th>
                <th style={{ width: 180 }}>STATUS</th>
              </tr>
            </thead>

            <tbody>
              {agents.length === 0 ? (
                <tr>
                  <td colSpan={3} className="empty">
                    {apiOk ? "No agents found." : "Agents API is offline (check backend)."}
                  </td>
                </tr>
              ) : (
                agents.map((agent) => (
                  <tr key={agent.agent_name}>
                    <td title={agent.agent_name || ""}>{agent.agent_name || ""}</td>
                    <td className="mono" title={agent.last_heartbeat || ""}>
                      {agent.last_heartbeat || "—"}
                    </td>
                    <td title={agent.status || ""}>
                      <StatusBadge status={agent.status} />
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}