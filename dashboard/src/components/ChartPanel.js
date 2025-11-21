import React, { useEffect, useState } from "react";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";
import "./ChartPanel.css";
import API_BASE_URL from "../config";

const ChartPanel = ({ refreshTrigger }) => {
  const [chartData, setChartData] = useState([]);

  useEffect(() => {
    const fetchChartData = async () => {
      try {
        const res = await fetch(`${API_BASE_URL}/api/chart`);
        const data = await res.json();
        setChartData(data);
      } catch (error) {
        console.error("Error fetching chart data:", error);
      }
    };

    fetchChartData();
  }, [refreshTrigger]);

  return (
    <section className="chart-section">
      <h2>📊 Log Volume Over Time</h2>
      <div className="chart-card">
        <ResponsiveContainer width="100%" height={300}>
          <LineChart data={chartData}>
            <CartesianGrid strokeDasharray="3 3" stroke="#ddd" />
            <XAxis dataKey="time" stroke="#555" />
            <YAxis />
            <Tooltip />
            <Line type="monotone" dataKey="logs" stroke="#004c7f" strokeWidth={2} dot={{ r: 3 }} />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </section>
  );
};

export default ChartPanel;
