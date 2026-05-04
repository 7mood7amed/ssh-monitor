import React, { useEffect, useState } from "react";
import API_BASE_URL from "../config";
import "./Metrics.css";

const Metrics = ({ refreshTrigger }) => {
  const [metrics, setMetrics] = useState({
    totalLogs: 0,
    activeAgents: 0,
    anomalies: 0,
    passiveScans: 0,
    alertsLast24h: 0,
    correlatedEntities: 0,
    suspiciousWebRequests: 0,
  });

  useEffect(() => {
    const fetchMetrics = async () => {
      try {
        const res = await fetch(`${API_BASE_URL}/api/metrics`);
        const data = await res.json();

        setMetrics({
          totalLogs: data.totalLogs ?? 0,
          activeAgents: data.activeAgents ?? 0,
          anomalies: data.anomalies ?? 0,
          passiveScans: data.passiveScans ?? 0,
          alertsLast24h: data.alertsLast24h ?? data.alerts ?? 0,
          correlatedEntities: data.correlatedEntities ?? data.correlated_ips ?? 0,
          suspiciousWebRequests:
            data.suspiciousWebRequests ?? data.suspicious_web_requests ?? 0,
        });
      } catch (error) {
        console.error("Error fetching metrics:", error);
      }
    };

    fetchMetrics();
  }, [refreshTrigger]);

  const metricData = [
    {
      title: "Total Logs",
      value: metrics.totalLogs,
      icon: "📘",
      color: "#38bdf8",
      desc: "Collected useful security logs",
    },
    {
      title: "Active Agents",
      value: metrics.activeAgents,
      icon: "🧩",
      color: "#22c55e",
      desc: "Collectors reporting heartbeat",
    },
    {
      title: "Alerts Last 24h",
      value: metrics.alertsLast24h,
      icon: "🚨",
      color: "#f97316",
      desc: "Rule-based detections",
    },
    {
      title: "Anomalies",
      value: metrics.anomalies,
      icon: "⚠️",
      color: "#ef4444",
      desc: "Suspicious activity indicators",
    },
    {
      title: "Passive Scans",
      value: metrics.passiveScans,
      icon: "🛰️",
      color: "#8b5cf6",
      desc: "Passive network scan indicators",
    },
    {
      title: "Suspicious Web",
      value: metrics.suspiciousWebRequests,
      icon: "🌐",
      color: "#f59e0b",
      desc: "Suspicious web requests",
    },
  ];

  return (
    <section className="metrics-container">
      {metricData.map((item, index) => (
        <div
          className="metric-card"
          key={index}
          style={{ borderTopColor: item.color }}
        >
          <div className="metric-icon">{item.icon}</div>

          <div className="metric-info">
            <h3>{item.value}</h3>
            <p>{item.title}</p>
            <span className="metric-desc">{item.desc}</span>
          </div>
        </div>
      ))}
    </section>
  );
};

export default Metrics;