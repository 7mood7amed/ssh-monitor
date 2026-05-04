import React from "react";
import Metrics from "../components/Metrics";
// import AIInsights from "../components/AIInsights";
import ChartPanel from "../components/ChartPanel";
import AgentStatus from "../components/AgentStatus";
import LevelActivity from "../components/LevelActivity";
import "../components/FtpLogs.css";

export default function OverviewPage({ refreshTrigger }) {
  return (
    <main className="content">
      <section className="home-hero-card">
        <div>
          <p className="home-kicker">Security Operations Overview</p>
          <h2>Raven Monitoring Summary</h2>
          <p>
            Live overview of collected logs, active agents, anomaly indicators,
            service exposure, and AI-assisted investigation signals.
          </p>
        </div>
      </section>

      <Metrics refreshTrigger={refreshTrigger} />

      <section className="home-section">
        <LevelActivity refreshTrigger={refreshTrigger} />
      </section>

      <section className="home-section">
        <ChartPanel refreshTrigger={refreshTrigger} />
      </section>

      {/* <section className="home-section">
        <AIInsights refreshTrigger={refreshTrigger} />
      </section> */}

      <section className="home-section">
        <AgentStatus refreshTrigger={refreshTrigger} />
      </section>
    </main>
  );
}