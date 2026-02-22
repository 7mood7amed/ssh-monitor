import React, { useEffect, useMemo, useState } from "react";
import API_BASE_URL from "../config";
import "../components/Table.css";

export default function NmapPage() {
    const [rows, setRows] = useState([]);

    // Filters
    const [q, setQ] = useState("");
    const [host, setHost] = useState("");
    const [port, setPort] = useState("");
    const [state, setState] = useState("All");
    const [service, setService] = useState("All");

    // Pagination
    const [page, setPage] = useState(1);
    const [pageSize, setPageSize] = useState(50);
    const [total, setTotal] = useState(0);
    const [totalPages, setTotalPages] = useState(1);

    // Reset to page 1 when filters change
    useEffect(() => {
        setPage(1);
    }, [q, host, port, state, service]);

    const url = useMemo(() => {
        const params = new URLSearchParams();
        params.set("page", String(page));
        params.set("limit", String(pageSize));

        if (q.trim()) params.set("q", q.trim());
        if (host.trim()) params.set("host", host.trim());
        if (port.trim()) params.set("port", port.trim());
        if (state !== "All") params.set("state", state);
        if (service !== "All") params.set("service", service);

        return `${API_BASE_URL}/api/nmap_findings?${params.toString()}`;
    }, [page, pageSize, q, host, port, state, service]);

    useEffect(() => {
        const fetchFindings = async () => {
            try {
                const res = await fetch(url);
                const data = await res.json();

                setRows(data.items || []);
                setTotal(data.total || 0);
                setTotalPages(data.totalPages || 1);

                // Safety: if filters reduce totalPages below current page
                if ((data.totalPages || 1) < page) setPage(1);
            } catch (e) {
                console.error("Error fetching nmap findings:", e);
            }
        };

        fetchFindings();
        const interval = setInterval(fetchFindings, 15000); // refresh every 15s
        return () => clearInterval(interval);
    }, [url, page]);

    const clear = () => {
        setQ("");
        setHost("");
        setPort("");
        setState("All");
        setService("All");
    };

    return (
        <div className="table-card">
            <h2 className="table-title">🧭 NMAP Findings (Port Scan Results)</h2>

            <div className="filter-bar">
                <input
                    placeholder="Search target/host/service..."
                    value={q}
                    onChange={(e) => setQ(e.target.value)}
                />

                <input
                    placeholder="Host (e.g. 127.0.0.1)"
                    value={host}
                    onChange={(e) => setHost(e.target.value)}
                />

                <input
                    placeholder="Port (e.g. 22)"
                    value={port}
                    onChange={(e) => setPort(e.target.value)}
                />

                <select value={state} onChange={(e) => setState(e.target.value)}>
                    <option value="All">All States</option>
                    <option value="open">open</option>
                    <option value="closed">closed</option>
                    <option value="filtered">filtered</option>
                </select>

                <select value={service} onChange={(e) => setService(e.target.value)}>
                    <option value="All">All Services</option>
                    <option value="ssh">ssh</option>
                    <option value="ftp">ftp</option>
                    <option value="http">http</option>
                    <option value="mysql">mysql</option>
                    <option value="postgresql">postgresql</option>
                    <option value="upnp">upnp</option>
                </select>

                <button className="page-btn" type="button" onClick={clear}>
                    Clear
                </button>

                <span className="result-count">
                    Showing <b>{rows.length}</b> of {total} findings (page {page} of{" "}
                    {totalPages})
                </span>
            </div>

            <div className="table-wrapper">
                <table className="data-table">
                    <thead>
                        <tr>
                            <th>Scan Time</th>
                            <th>Agent</th>
                            <th>Target</th>
                            <th>Host</th>
                            <th>Port</th>
                            <th>Proto</th>
                            <th>State</th>
                            <th>Service</th>
                            <th>Extra</th>
                        </tr>
                    </thead>

                    <tbody>
                        {rows.map((r) => (
                            <tr key={r.id}>
                                <td className="cell-mono">{r.scan_time}</td>
                                <td>{r.agent_name}</td>
                                <td>{r.target}</td>
                                <td className="cell-mono">{r.host}</td>
                                <td className="cell-mono">{r.port}</td>
                                <td>{r.proto}</td>
                                <td>{r.state}</td>
                                <td>{r.service}</td>
                                <td className="cell-truncate" title={r.extra || ""}>
                                    {r.extra || ""}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>

            {rows.length === 0 && <p className="no-results">No NMAP findings yet.</p>}

            <div className="pagination-bar">
                <button
                    className="page-btn"
                    onClick={() => setPage((p) => Math.max(p - 1, 1))}
                    disabled={page === 1}
                >
                    ◀ Prev
                </button>

                <span className="page-info">
                    Page <b>{page}</b> of {totalPages}
                </span>

                <button
                    className="page-btn"
                    onClick={() => setPage((p) => Math.min(p + 1, totalPages))}
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
        </div>
    );
}