import React, { useEffect, useState, useRef, useMemo } from "react";
import Header from "./components/Header";
import Metrics from "./components/Metrics";
import AgentStatus from "./components/AgentStatus";
import ChartPanel from "./components/ChartPanel";
import LogsTable from "./components/LogsTable";
import WebTraffic from "./components/WebTraffic";
import Footer from "./components/Footer";
import "./App.css";

function App() {
  const [refreshTrigger, setRefreshTrigger] = useState(0);
  const [lastUpdated, setLastUpdated] = useState(new Date().toLocaleTimeString());
  const REFRESH_INTERVAL = 30000; // 30 seconds

  useEffect(() => {
    const interval = setInterval(() => {
      setRefreshTrigger((prev) => prev + 1);
      setLastUpdated(new Date().toLocaleTimeString());
      console.log("🔄 Dashboard refreshed at", new Date().toLocaleTimeString());
    }, REFRESH_INTERVAL);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="app">
      <Header lastUpdated={lastUpdated} />
      <main>
        <Metrics refreshTrigger={refreshTrigger} />
        <ChartPanel refreshTrigger={refreshTrigger} />
        <AgentStatus refreshTrigger={refreshTrigger} />
        <LogsTable refreshTrigger={refreshTrigger} />
        <WebTraffic refreshTrigger={refreshTrigger} />
      </main>
      <Footer />
    </div>
  );
}

export default App;
