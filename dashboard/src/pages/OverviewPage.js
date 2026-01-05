import React from "react";
import Metrics from "../components/Metrics";
import ChartPanel from "../components/ChartPanel";
import AgentStatus from "../components/AgentStatus";

export default function OverviewPage({ refreshTrigger }) {
    return (
        <>
            <Metrics refreshTrigger={refreshTrigger} />
            <ChartPanel refreshTrigger={refreshTrigger} />
            <AgentStatus refreshTrigger={refreshTrigger} />
        </>
    );
}