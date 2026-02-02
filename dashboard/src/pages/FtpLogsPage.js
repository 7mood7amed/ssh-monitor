import React from "react";
import FtpLogs from "../components/FtpLogs";

export default function FtpLogsPage({ refreshTrigger }) {
  return (
    <div className="page">
      <FtpLogs refreshTrigger={refreshTrigger} />
    </div>
  );
}