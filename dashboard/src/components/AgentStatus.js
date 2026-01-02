// File: dashboard/src/components/AgentStatus.js
import React, { useEffect, useState } from "react";
import API_BASE_URL from "../config";
import "./AgentStatus.css";

const AgentStatus = ({ refreshTrigger }) => {
  const [agents, setAgents] = useState([]);
  const [apiOnline, setApiOnline] = useState(true);

  useEffect(() => {
    const fetchAgents = async () => {
      try {
        const res = await fetch(`${API_BASE_URL}/api/agents`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        setAgents(Array.isArray(data) ? data : []);
        setApiOnline(true);
      } catch (err) {
        console.error("Error fetching agents:", err);
        setApiOnline(false);
      }
    };

    fetchAgents();
  }, [refreshTrigger]);

  return (
    <section className="agent-status-container">
      <h2>🧭 Agent Heartbeats</h2>

      {!apiOnline && (
        <p className="agent-api-offline">API Offline (Raven unreachable)</p>
      )}

      <div className="agent-table-wrapper">
        <table className="agent-table">
          <thead>
            <tr>
              <th>Agent Name</th>
              <th>Last Heartbeat</th>
              <th>Status</th>
            </tr>
          </thead>

          <tbody>
            {agents.map((agent) => {
              const status = (agent.status || "").toLowerCase();
              const isActive = status === "active";

              return (
                <tr key={agent.agent_name}>
                  <td>{agent.agent_name}</td>
                  <td>{agent.last_heartbeat}</td>
                  <td>
                    <span
                      className={`status-badge ${isActive ? "status-active" : "status-inactive"
                        }`}
                      title={
                        agent.seconds_since_heartbeat != null
                          ? `${agent.seconds_since_heartbeat}s since heartbeat`
                          : ""
                      }
                    >
                      {isActive ? "Active" : "Inactive"}
                    </span>
                  </td>
                </tr>
              );
            })}

            {agents.length === 0 && (
              <tr>
                <td colSpan={3} className="agent-empty">
                  No agent records found.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
};

export default AgentStatus;
