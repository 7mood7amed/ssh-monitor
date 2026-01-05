import React, { useEffect, useState } from "react";
import API_BASE_URL from "../config";
import "./Table.css";
import "./WebTraffic.css";

const WebTraffic = () => {
    const [logs, setLogs] = useState([]);
    const [page, setPage] = useState(1);
    const [pageSize, setPageSize] = useState(50);
    const [total, setTotal] = useState(0);
    const [totalPages, setTotalPages] = useState(1);

    const [searchTerm, setSearchTerm] = useState("");
    const [statusFilter, setStatusFilter] = useState("All");

    // Auto-collapse expanded rows when page/filters/pageSize change
    useEffect(() => {
        setExpandedKeys(new Set());
    }, [page, pageSize, searchTerm, statusFilter]);

    const [expandedKeys, setExpandedKeys] = useState(() => new Set());

    useEffect(() => {
        const fetchWebLogs = async () => {
            try {
                const res = await fetch(`${API_BASE_URL}/api/web_logs?page=${page}&limit=${pageSize}`);
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
        const matchSearch = url.includes(searchTerm.toLowerCase()) || ip.includes(searchTerm.toLowerCase());
        const matchStatus = statusFilter === "All" || String(log.status) === statusFilter;
        return matchSearch && matchStatus;
    });

    const toggleExpand = (key) => {
        setExpandedKeys((prev) => {
            const next = new Set(prev);
            if (next.has(key)) next.delete(key);
            else next.add(key);
            return next;
        });
    };

    const handlePrev = () => setPage((p) => Math.max(p - 1, 1));
    const handleNext = () => setPage((p) => Math.min(p + 1, totalPages || 1));

    return (
        <section className="table-card web-traffic-container">
            <h2 className="table-title">🌐 Web Traffic (Apache Access Log)</h2>

            <div className="filter-bar">
                <input
                    type="text"
                    placeholder="Search by URL or IP..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                />

                <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
                    <option value="All">All Status Codes</option>
                    <option value="200">200 OK</option>
                    <option value="301">301 Redirect</option>
                    <option value="302">302 Redirect</option>
                    <option value="401">401 Unauthorized</option>
                    <option value="403">403 Forbidden</option>
                    <option value="404">404 Not Found</option>
                    <option value="500">500 Server Error</option>
                </select>

                <span className="result-count">
                    Showing <b>{filtered.length}</b> of {total} requests (page {page} of {totalPages})
                </span>
            </div>

            <div className="table-wrapper">
                <table className="data-table web-table">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>IP</th>
                            <th>Method</th>
                            <th>URL</th>
                            <th>Status</th>
                            <th>User-Agent</th>
                            <th />
                        </tr>
                    </thead>

                    <tbody>
                        {filtered.map((log, i) => {
                            const key = `${log.timestamp}-${log.ip}-${log.method}-${log.status}-${i}`;
                            const expanded = expandedKeys.has(key);

                            return (
                                <React.Fragment key={key}>
                                    <tr>
                                        <td className="cell-mono" title={log.timestamp}>
                                            {log.timestamp}
                                        </td>
                                        <td className="cell-mono" title={log.ip}>
                                            {log.ip}
                                        </td>
                                        <td title={log.method}>{log.method}</td>
                                        <td className="cell-truncate" title={log.url}>
                                            {log.url}
                                        </td>
                                        <td className="cell-mono" title={String(log.status)}>
                                            {log.status}
                                        </td>
                                        <td className="cell-truncate" title={log.user_agent}>
                                            {log.user_agent}
                                        </td>
                                        <td>
                                            <button
                                                className="expand-btn"
                                                type="button"
                                                aria-label={expanded ? "Collapse row" : "Expand row"}
                                                onClick={() => toggleExpand(key)}
                                            >
                                                {expanded ? "▲" : "▼"}
                                            </button>
                                        </td>
                                    </tr>

                                    {expanded && (
                                        <tr className="expanded-row">
                                            <td colSpan={7}>
                                                <div className="expanded-content">
                                                    <div className="expanded-label">Full URL</div>
                                                    <pre className="expanded-pre">{log.url}</pre>
                                                    <div className="expanded-label">Full User-Agent</div>
                                                    <pre className="expanded-pre">{log.user_agent}</pre>
                                                </div>
                                            </td>
                                        </tr>
                                    )}
                                </React.Fragment>
                            );
                        })}
                    </tbody>
                </table>
            </div>

            {filtered.length === 0 && <p className="no-results">No web traffic logs found.</p>}

            <div className="pagination-bar">
                <button className="page-btn" onClick={handlePrev} disabled={page === 1}>
                    ◀ Prev
                </button>

                <span className="page-info">
                    Page <b>{page}</b> of {totalPages}
                </span>

                <button className="page-btn" onClick={handleNext} disabled={page === totalPages || totalPages === 0}>
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