import React from "react";
import LogsTable from "../components/LogsTable";

export default function SshLogsPage({ refreshTrigger }) {
    return <LogsTable refreshTrigger={refreshTrigger} />;
}