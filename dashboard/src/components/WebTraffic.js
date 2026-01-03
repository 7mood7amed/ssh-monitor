// =========================================
// File: dashboard/src/components/WebTraffic.js
// (ADD: severity column + severity filter + badge)
// =========================================
import React, { useEffect, useState } from "react";
import API_BASE_URL from "../config";
import "./LogsTable.css"; // includes .severity-badge.{low,medium,high}
import "./WebTraffic.css";

const WebTraffic = () => {
    const [logs, setLogs] = useState([]);
    const [page, setPage] = useState(1);
    const [pageSize, setPageSize] = useState(50);
    const [total, setTotal] = useState(0);
    const [totalPages, setTotalPages] = useState(1);

    const [searchTerm, setSearchTerm] = useState("");
    const [statusFilter, setStatusFilter] = useState("All");
    const [severityFilter, setSeverityFilter] = useState("All");

    useEffect(() => {
        const fetchWebLogs = async () => {
            try {
                const res = await fetch(
                    `${API_BASE_URL}/api/web_logs?page=${page}&limit=${pageSize}`
                );
                const data = await res.json();
                setLogs(data.logs || []);
                setTotal(data.total || 0);
                setTotalPages(data.totalPages || 1);
            } catch (err) {
                console.error("Error fetching web logs:", err);
            }
        };

        fetchWebLogs();
    }, [page, pageSize]);

    const filtered = logs.filter((log) => {
        const url = (log.url || "").toLowerCase();
        const ip = (log.ip || "").toLowerCase();
        const sev = (log.severity || "").toLowerCase();

        const matchSearch =
            url.includes(searchTerm.toLowerCase()) ||
            ip.includes(searchTerm.toLowerCase());

        const matchStatus =
            statusFilter === "All" || String(log.status) === statusFilter;

        const matchSeverity =
            severityFilter === "All" || sev === severityFilter.toLowerCase();

        return matchSearch && matchStatus && matchSeverity;
    });

    const handlePrev = () => setPage((p) => Math.max(p - 1, 1));
    const handleNext = () => setPage((p) => Math.min(p + 1, totalPages || 1));

    return (
        <section className="log-table-container web-traffic-container">
            <h2>🌐 Web Traffic (Apache Access Log)</h2>

            <div className="filter-bar">
                <input
                    type="text"
                    placeholder="Search by URL or IP..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                />

                <select
                    value={statusFilter}
                    onChange={(e) => setStatusFilter(e.target.value)}
                >
                    <option value="All">All Status Codes</option>
                    <option value="200">200 OK</option>
                    <option value="301">301 Redirect</option>
                    <option value="302">302 Redirect</option>
                    <option value="403">403 Forbidden</option>
                    <option value="404">404 Not Found</option>
                    <option value="500">500 Server Error</option>
                </select>

                <select
                    value={severityFilter}
                    onChange={(e) => setSeverityFilter(e.target.value)}
                >
                    <option value="All">All Severity</option>
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                </select>

                <span className="result-count">
                    Showing <b>{filtered.length}</b> of {total} requests (page {page} of{" "}
                    {totalPages})
                </span>
            </div>

            <div className="table-wrapper">
                <table className="log-table web-table">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>IP</th>
                            <th>Method</th>
                            <th>URL</th>
                            <th>Severity</th>
                            <th>Status</th>
                            <th>User-Agent</th>
                        </tr>
                    </thead>
                    <tbody>
                        {filtered.map((log, i) => {
                            const sev = (log.severity || "low").toLowerCase();
                            return (
                                <tr key={i}>
                                    <td>{log.timestamp}</td>
                                    <td>{log.ip}</td>
                                    <td>{log.method}</td>
                                    <td className="log-message url-cell">{log.url}</td>
                                    <td>
                                        <span className={`severity-badge ${sev}`}>
                                            {sev}
                                        </span>
                                    </td>
                                    <td>{log.status}</td>
                                    <td className="log-message">{log.user_agent}</td>
                                </tr>
                            );
                        })}
                    </tbody>
                </table>
            </div>

            {filtered.length === 0 && (
                <p className="no-results">No web traffic logs found.</p>
            )}

            <div className="pagination-bar">
                <button
                    className="page-btn"
                    onClick={handlePrev}
                    disabled={page === 1}
                >
                    ◀ Prev
                </button>

                <span className="page-info">
                    Page <b>{page}</b> of {totalPages}
                </span>

                <button
                    className="page-btn"
                    onClick={handleNext}
                    disabled={page === totalPages || totalPages === 0}
                >
                    Next ▶
                </button>

                <div className="page-size-control">
                    <span>Show:</span>
                    <select
                        value={pageSize}
                        onChange={(e) => {
                            setPageSize(Number(e.target.value));
                            setPage(1);
                        }}
                    >
                        <option value={20}>20</option>
                        <option value={50}>50</option>
                        <option value={100}>100</option>
                    </select>
                    <span>per page</span>
                </div>
            </div>
        </section>
    );
};

export default WebTraffic;
