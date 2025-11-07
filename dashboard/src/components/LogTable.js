import React from "react";
import "./LogTable.css";

function LogTable() {
  // Temporary static data – will later come from the Flask API
  const logs = [
    {
      timestamp: "2025-11-07 09:45:22",
      agent: "Raven",
      source: "/var/log/auth.log",
      message: "sshd: Accepted publickey for hero from 192.168.56.1 port 54321",
      severity: "Low",
    },
    {
      timestamp: "2025-11-07 09:44:10",
      agent: "Falcon",
      source: "/var/log/vsftpd.log",
      message: "FTP upload completed for file data.csv",
      severity: "Medium",
    },
    {
      timestamp: "2025-11-07 09:40:08",
      agent: "Phoenix",
      source: "/var/log/syslog",
      message: "sudo: hero : TTY=pts/0 ; PWD=/home/hero ; USER=root ; COMMAND=/bin/systemctl restart postgresql",
      severity: "High",
    },
  ];

  return (
    <div className="log-table-container">
      <h2>Log Entries</h2>
      <table className="log-table">
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Agent</th>
            <th>Source</th>
            <th>Message</th>
            <th>Severity</th>
          </tr>
        </thead>
        <tbody>
          {logs.map((log, index) => (
            <tr key={index}>
              <td>{log.timestamp}</td>
              <td>{log.agent}</td>
              <td>{log.source}</td>
              <td className="log-message">{log.message}</td>
              <td>
                <span className={`severity-badge ${log.severity.toLowerCase()}`}>
                  {log.severity}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default LogTable;
