import React from "react";
import "./Metrics.css";

function Metrics() {
    const metrics = [
        { label: "Total Logs", value: "10,248" },
        { label: "Active Agents", value: "3" },
        { label: "Last Sync", value: "Just now" },
        { label: "Detected Anomalies", value: "12" },
    ];

    return (
        <div className="metrics-container">
            {metrics.map((metric, index) => (
                <div key={index} className="metric-card">
                    <h3>{metric.label}</h3>
                    <p>{metric.value}</p>
                </div>
            ))}
        </div>
    );
}

export default Metrics;