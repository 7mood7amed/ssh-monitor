// File: dashboard/src/components/AgentStatus.js
import React, { useEffect, useState } from "react";
import API_BASE_URL from "../config";
import "./Table.css";
import "./AgentStatus.css";

const AgentStatus = () => {
  const [agents, setAgents] = useState([]);

  useEffect(() => {
    const fetchAgents = async () => {
      try {
        const res = await fetch(`${API_BASE_URL}/api/agents`);
        const data = await res.json();
        setAgents(data || []);
      } catch (error) {
        console.error("Error fetching agent data:", error);
      }
    };

    fetchAgents();
    const interval = setInterval(fetchAgents, 10000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="table-card">
      <h2 className="table-title">🛰 Agent Status</h2>

      <div className="table-wrapper">
        <table className="data-table">
          <thead>
            <tr>
              <th>Agent</th>
              <th>Last Heartbeat</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {agents.map((agent) => (
              <tr key={agent.agent_name}>
                <td>{agent.agent_name}</td>
                <td className="cell-mono" title={agent.last_heartbeat}>{agent.last_heartbeat}</td>
                <td>{agent.status}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {agents.length === 0 && <p className="no-results">No agents found.</p>}
    </div>
  );
};

export default AgentStatus;
