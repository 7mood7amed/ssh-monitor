import React, { useEffect, useState } from "react";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";
import "./ChartPanel.css";
import getApiBaseUrl from "../config";

const ChartPanel = ({ refreshTrigger }) => {
  const [chartData, setChartData] = useState([]);

  useEffect(() => {
    const fetchChartData = async () => {
      try {
<<<<<<< HEAD
        const res = await fetch("http://192.168.1.55:5000/api/chart");
=======
        const res = await fetch("http://192.168.1.13:5000/api/chart");
>>>>>>> 194bfd6edf34649557b1bda3cbdd1ca563c3d9c8
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
