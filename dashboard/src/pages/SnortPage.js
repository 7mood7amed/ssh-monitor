import React from "react";
import SnortAlerts from "../components/SnortAlerts";

export default function SnortPage({ refreshTrigger }) {
  return (
    <div className="page">
      <SnortAlerts refreshTrigger={refreshTrigger} />
    </div>
  );
}
