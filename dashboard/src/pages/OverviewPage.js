import React from "react";
import Metrics from "../components/Metrics";
import ChartPanel from "../components/ChartPanel";
import AgentStatus from "../components/AgentStatus";
import LevelActivity from "../components/LevelActivity";

export default function OverviewPage({ refreshTrigger }) {
  return (
    <>
      <Metrics refreshTrigger={refreshTrigger} />
      <LevelActivity refreshTrigger={refreshTrigger} />
      <ChartPanel refreshTrigger={refreshTrigger} />
      <AgentStatus refreshTrigger={refreshTrigger} />
    </>
  );
}
