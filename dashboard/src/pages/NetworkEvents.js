import React, { useEffect, useMemo, useState } from "react";
import API_BASE_URL from "../config";
import "./NetworkEvents.css";

function NetworkEvents() {
    const [logs, setLogs] = useState([]);
    const [loading, setLoading] = useState(true);
    const [activeProtocol, setActiveProtocol] = useState("ALL");
    const [searchTerm, setSearchTerm] = useState("");

    const fetchNetworkEvents = () => {
        setLoading(true);

        fetch(`${API_BASE_URL}/api/logs?agent_name=TSHARK&limit=100&sort=log_time&order=desc`).then((res) => res.json())
            .then((data) => setLogs(data.logs || []))
            .catch((err) => console.error("Failed to fetch network events:", err))
            .finally(() => setLoading(false));
    };

    useEffect(() => {
        fetchNetworkEvents();
    }, []);

    const getProtocol = (message = "") => {
        const match = message.match(/^\[(.*?)\]/);
        return match ? match[1].toUpperCase() : "OTHER";
    };

    const cleanMessage = (message = "") => {
        return message.replace(/^\[.*?\]\s*/, "");
    };

    const isSuspiciousPacket = (log) => {
        const message = String(log.message || "").toLowerCase();
        const severity = String(log.severity || "").toLowerCase();

        return (
            severity === "high" ||
            severity === "critical" ||
            message.includes("anomaly") ||
            message.includes("scan") ||
            message.includes("sweep") ||
            message.includes("reconnaissance") ||
            message.includes("[syn]")
        );
    };

    const protocolOptions = ["ALL", "SUSPICIOUS", "ICMP", "DNS", "HTTP", "SSH", "TCP", "OTHER"];
    const filteredLogs = useMemo(() => {
        return logs.filter((log) => {
            const protocol = getProtocol(log.message);
            const message = cleanMessage(log.message).toLowerCase();
            const search = searchTerm.toLowerCase();

            const matchesProtocol =
                activeProtocol === "ALL" ||
                protocol === activeProtocol ||
                (activeProtocol === "SUSPICIOUS" && isSuspiciousPacket(log));

            const matchesSearch =
                search === "" ||
                message.includes(search) ||
                String(log.timestamp || "").toLowerCase().includes(search) ||
                String(log.agent_name || "").toLowerCase().includes(search) ||
                String(log.severity || "").toLowerCase().includes(search) ||
                protocol.toLowerCase().includes(search);

            return matchesProtocol && matchesSearch;
        });
    }, [logs, activeProtocol, searchTerm]);

    return (
        <section className="network-page network-card-wrap">
            <div className="network-hero">
                <div>
                    <p className="network-label">Packet Monitoring</p>
                    <h2>Network Events</h2>
                    <p>
                        Live packet-level activity captured from the monitoring interface using TShark.
                    </p>
                </div>

                <button className="refresh-btn" onClick={fetchNetworkEvents}>
                    Refresh
                </button>
            </div>

            <div className="network-stats">
                <div className="network-stat-card">
                    <span>Total Events</span>
                    <strong>{logs.length}</strong>
                </div>

                <div className="network-stat-card">
                    <span>Filtered Events</span>
                    <strong>{filteredLogs.length}</strong>
                </div>

                <div className="network-stat-card">
                    <span>Agent</span>
                    <strong>TSHARK</strong>
                </div>

                <div className="network-stat-card">
                    <span>Source</span>
                    <strong>/usr/bin/tshark</strong>
                </div>
            </div>

            <div className="network-filter-card">
                <div className="network-filter-header">
                    <div>
                        <h3>Packet Filters</h3>
                        <p>Filter captured packet summaries by protocol or keyword.</p>
                    </div>

                    <button
                        className="clear-filter-btn"
                        onClick={() => {
                            setActiveProtocol("ALL");
                            setSearchTerm("");
                        }}
                    >
                        Clear Filters
                    </button>
                </div>

                <div className="protocol-filter-row">
                    {protocolOptions.map((protocol) => (
                        <button
                            key={protocol}
                            className={`protocol-filter-btn ${activeProtocol === protocol ? "active" : ""
                                }`}
                            onClick={() => setActiveProtocol(protocol)}
                        >
                            {protocol}
                        </button>
                    ))}
                </div>

                <input
                    className="network-search"
                    type="text"
                    placeholder="Search packet message, protocol, severity, or timestamp..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                />
            </div>

            <div className="network-table-card">
                <div className="table-header">
                    <h3>Captured Packets</h3>
                    <p>
                        Showing {filteredLogs.length} of {logs.length} latest packet summaries
                    </p>
                </div>

                {loading ? (
                    <p className="empty-message">Loading network events...</p>
                ) : filteredLogs.length === 0 ? (
                    <p className="empty-message">No matching network events found.</p>
                ) : (
                    <div className="network-table-wrapper">
                        <table className="network-table">
                            <thead>
                                <tr>
                                    <th>Time</th>
                                    <th>Protocol</th>
                                    <th>Agent</th>
                                    <th>Packet Summary</th>
                                    <th>Severity</th>
                                </tr>
                            </thead>

                            <tbody>
                                {filteredLogs.map((log, index) => {
                                    const protocol = getProtocol(log.message);
                                    const suspicious = isSuspiciousPacket(log);

                                    return (
                                        <tr key={log.id || index} className={suspicious ? "suspicious-row" : ""}>
                                            <td>{log.timestamp || log.log_time || "—"}</td>

                                            <td>
                                                <span className={`protocol-pill ${protocol.toLowerCase()}`}>
                                                    {protocol}
                                                </span>
                                            </td>

                                            <td>
                                                <span className="agent-pill">{log.agent_name || "TSHARK"}</span>
                                            </td>

                                            <td className="packet-summary">
                                                {suspicious && <span className="suspicious-badge">Suspicious</span>}
                                                {cleanMessage(log.message)}
                                            </td>
                                            
                                            <td>
                                                <span
                                                    className={`severity-pill ${String(
                                                        log.severity || "info"
                                                    ).toLowerCase()}`}
                                                >
                                                    {log.severity || "info"}
                                                </span>
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
        </section>
    );
}

export default NetworkEvents;