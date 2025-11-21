import React, { useEffect, useState } from "react";
// import getApiBaseUrl from "../config";
import "./AgentStatus.css";
import API_BASE_URL from "../config";

const AgentStatus = () => {
  const [agents, setAgents] = useState([]);

  useEffect(() => {
    const fetchAgents = async () => {
      try {
        const res = await fetch(`${API_BASE_URL}/api/agents`);
        const data = await res.json();
        setAgents(data);
      } catch (error) {
        console.error("Error fetching agent data:", error);
      }
    };

    fetchAgents();
    const interval = setInterval(fetchAgents, 10000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="agent-status-container">
      <h2>🧭 Agent Heartbeats</h2>
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
            {agents.map((agent, index) => (
              <tr key={index}>
                <td className="agent-name">{agent.agent_name}</td>
                <td>{agent.last_heartbeat}</td>
                <td>
                  <span
                    className={`status-badge ${agent.status.toLowerCase()}`}
                  >
                    {agent.status}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default AgentStatus;
