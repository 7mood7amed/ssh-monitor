import React from "react";
import "./App.css";
import Header from "./components/Header";
import Metrics from "./components/Metrics";
import AgentStatus from "./components/AgentStatus";
import LogTable from "./components/LogTable";
import ChartPanel from "./components/ChartPanel";


function App() {
  return (
    <div className="app-container">
      <Header />
      <Metrics />
      {/* We’ll add AgentStatus, LogTable, and ChartPanel next */}
      <AgentStatus />
      <LogTable />
      <ChartPanel />
    </div>
  );
}

export default App;
