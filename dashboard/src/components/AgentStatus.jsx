import React from "react";
import "./AgentStatus.css";

function AgentStatus() {
    // Temporary static data (will connect to PostgreSQL later via Flask)
    const agents = [
        { name: "Raven", lastHeartbeat: "2025-11-07 09:45", status: "Active" },
        { name: "Falcon", lastHeartbeat: "2025-11-07 09:30", status: "Inactive" },
        { name: "Phoenix", lastHeartbeat: "2025-11-07 09:15", status: "Active" },
    ];

    return (
        <div className="agent-status-container">
            <h2>Agent Status</h2>
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
                            <td>{agent.name}</td>
                            <td>{agent.lastHeartbeat}</td>
                            <td>
                                <span
                                    className={`status-badge ${agent.status === "Active" ? "active" : "inactive"
                                        }`}
                                >
                                    {agent.status}
                                </span>
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}

export default AgentStatus;
