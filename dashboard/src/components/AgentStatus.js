import React, { useEffect, useState } from "react";
<<<<<<< HEAD
// import getApiBaseUrl from "../config";
=======
>>>>>>> 194bfd6edf34649557b1bda3cbdd1ca563c3d9c8
import "./AgentStatus.css";

const AgentStatus = () => {
  const [agents, setAgents] = useState([]);

  useEffect(() => {
    const fetchAgents = async () => {
      try {
<<<<<<< HEAD
        const res = await fetch("http://192.168.1.55:5000/api/agents");
=======
        const res = await fetch("http://192.168.1.13:5000/api/agents");
>>>>>>> 194bfd6edf34649557b1bda3cbdd1ca563c3d9c8
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
