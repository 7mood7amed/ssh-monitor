import React, { useEffect, useState } from "react";
import API_BASE_URL from "../config";
import "./Metrics.css";

const Metrics = ({ refreshTrigger }) => {
  const [metrics, setMetrics] = useState({
    totalLogs: 0,
    activeAgents: 0,
    anomalies: 0,
  });

  useEffect(() => {
    const fetchMetrics = async () => {
      try {
        const res = await fetch(`${API_BASE_URL}/api/metrics`);
        const data = await res.json();
        setMetrics(data);
      } catch (error) {
        console.error("Error fetching metrics:", error);
      }
    };

    fetchMetrics();
  }, [refreshTrigger]);

  const metricData = [
    { title: "Total Logs", value: metrics.totalLogs, icon: "📘", color: "#0066cc" },
    { title: "Active Agents", value: metrics.activeAgents, icon: "🧩", color: "#28a745" },
    { title: "Anomalies Detected", value: metrics.anomalies, icon: "⚠️", color: "#dc3545" },
  ];

  return (
    <section className="metrics-container">
      {metricData.map((item, index) => (
        <div className="metric-card" key={index} style={{ borderTopColor: item.color }}>
          <div className="metric-icon">{item.icon}</div>
          <div className="metric-info">
            <h3>{item.value}</h3>
            <p>{item.title}</p>
          </div>
        </div>
      ))}
    </section>
  );
};

export default Metrics;
