// File: dashboard/src/components/WebTraffic.js
import React, { useEffect, useMemo, useState } from "react";
import API_BASE_URL from "../config";
import "./LogsTable.css";
import "./WebTraffic.css";

const toDateTimeLocalValue = (d) => {
    if (!d) return "";
    const pad = (n) => String(n).padStart(2, "0");
    const yyyy = d.getFullYear();
    const mm = pad(d.getMonth() + 1);
    const dd = pad(d.getDate());
    const hh = pad(d.getHours());
    const mi = pad(d.getMinutes());
    return `${yyyy}-${mm}-${dd}T${hh}:${mi}`;
};

const WebTraffic = () => {
    const [logs, setLogs] = useState([]);

    const [page, setPage] = useState(1);
    const [pageSize, setPageSize] = useState(50);
    const [total, setTotal] = useState(0);
    const [totalPages, setTotalPages] = useState(1);

    const [searchTerm, setSearchTerm] = useState("");
    const [statusFilter, setStatusFilter] = useState("All");

    const [sortField, setSortField] = useState("timestamp"); // timestamp|status|ip|url|method
    const [sortOrder, setSortOrder] = useState("desc"); // asc|desc

    // Optional date range (datetime-local)
    const [start, setStart] = useState("");
    const [end, setEnd] = useState("");

    // Reset to page 1 when filters change
    useEffect(() => {
        setPage(1);
    }, [searchTerm, statusFilter, pageSize, sortField, sortOrder, start, end]);

    const queryString = useMemo(() => {
        const params = new URLSearchParams();
        params.set("page", String(page));
        params.set("limit", String(pageSize));

        if (searchTerm.trim()) params.set("search", searchTerm.trim());
        if (statusFilter !== "All") params.set("status", statusFilter);

        if (start) params.set("start", start);
        if (end) params.set("end", end);

        params.set("sort", sortField);
        params.set("order", sortOrder);
        return params.toString();
    }, [page, pageSize, searchTerm, statusFilter, sortField, sortOrder, start, end]);

    useEffect(() => {
        const fetchWebLogs = async () => {
            try {
                const res = await fetch(`${API_BASE_URL}/api/web_logs?${queryString}`);
                const data = await res.json();
                setLogs(data.logs || []);
                setTotal(data.total || 0);
                setTotalPages(data.totalPages || 1);
            } catch (err) {
                console.error("Error fetching web logs:", err);
            }
        };

        fetchWebLogs();
    }, [queryString]);

    const handlePrev = () => setPage((p) => Math.max(p - 1, 1));
    const handleNext = () => setPage((p) => Math.min(p + 1, totalPages || 1));

    // Client-side filtering removed (server-side now). Keep for safety display only.
    const visible = logs;

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

                <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
                    <option value="All">All Status Codes</option>
                    <option value="200">200 OK</option>
                    <option value="301">301 Redirect</option>
                    <option value="302">302 Redirect</option>
                    <option value="403">403 Forbidden</option>
                    <option value="404">404 Not Found</option>
                    <option value="500">500 Server Error</option>
                </select>

                <select value={sortField} onChange={(e) => setSortField(e.target.value)}>
                    <option value="timestamp">Sort: Time</option>
                    <option value="status">Sort: Status</option>
                    <option value="ip">Sort: IP</option>
                    <option value="url">Sort: URL</option>
                    <option value="method">Sort: Method</option>
                </select>

                <select value={sortOrder} onChange={(e) => setSortOrder(e.target.value)}>
                    <option value="desc">Order: Desc</option>
                    <option value="asc">Order: Asc</option>
                </select>

                <input
                    type="datetime-local"
                    value={start}
                    onChange={(e) => setStart(e.target.value)}
                    title="Start time"
                />
                <input
                    type="datetime-local"
                    value={end}
                    onChange={(e) => setEnd(e.target.value)}
                    title="End time"
                />

                <button
                    className="clear-btn"
                    onClick={() => {
                        setSearchTerm("");
                        setStatusFilter("All");
                        setSortField("timestamp");
                        setSortOrder("desc");
                        setStart("");
                        setEnd("");
                    }}
                >
                    Clear
                </button>

                <span className="result-count">
                    Showing <b>{visible.length}</b> of {total} requests (page {page} of {totalPages})
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
                            <th>Status</th>
                            <th>User-Agent</th>
                        </tr>
                    </thead>
                    <tbody>
                        {visible.map((log, i) => (
                            <tr key={i}>
                                <td>{log.timestamp}</td>
                                <td>{log.ip}</td>
                                <td>{log.method}</td>
                                <td className="log-message url-cell">{log.url}</td>
                                <td>{log.status}</td>
                                <td className="log-message">{log.user_agent}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>

            {visible.length === 0 && <p className="no-results">No web traffic logs found.</p>}

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
