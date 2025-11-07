import React from "react";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from "recharts";
import "./ChartPanel.css";

function ChartPanel() {
  // Temporary mock data – later we’ll replace this with real log stats
  const logVolumeData = [
    { time: "09:00", logs: 120 },
    { time: "09:30", logs: 160 },
    { time: "10:00", logs: 200 },
    { time: "10:30", logs: 170 },
    { time: "11:00", logs: 210 },
  ];

  const severityData = [
    { name: "Low", value: 40 },
    { name: "Medium", value: 25 },
    { name: "High", value: 10 },
  ];

  const COLORS = ["#2ecc71", "#f39c12", "#e74c3c"];

  return (
    <div className="chart-panel">
      <h2>System Activity Overview</h2>
      <div className="charts-grid">
        <div className="chart-card">
          <h3>Log Volume Over Time</h3>
          <ResponsiveContainer width="100%" height={250}>
            <LineChart data={logVolumeData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="time" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Line
                type="monotone"
                dataKey="logs"
                stroke="#004643"
                strokeWidth={2}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-card">
          <h3>Severity Distribution</h3>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie
                data={severityData}
                cx="50%"
                cy="50%"
                labelLine={false}
                outerRadius={90}
                fill="#8884d8"
                dataKey="value"
                label={({ name, value }) => `${name}: ${value}`}
              >
                {severityData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}

export default ChartPanel;
