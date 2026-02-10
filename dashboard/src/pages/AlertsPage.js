import React, { useEffect, useMemo, useState } from "react";
import API_BASE_URL from "../config"; // adjust if your config path differs

const PRIORITY_META = {
    critical: { label: "CRITICAL", bg: "#ef4444", fg: "#fff" },
    high: { label: "HIGH", bg: "#f97316", fg: "#fff" },
    medium: { label: "MEDIUM", bg: "#eab308", fg: "#111827" },
    low: { label: "LOW", bg: "#3b82f6", fg: "#fff" },
};

function PriorityBadge({ priority }) {
    const p = (priority || "").toLowerCase();
    const meta = PRIORITY_META[p] || { label: p || "—", bg: "#6b7280", fg: "#fff" };

    return (
        <span
            style={{
                display: "inline-block",
                padding: "4px 10px",
                borderRadius: 999,
                fontSize: 12,
                fontWeight: 700,
                background: meta.bg,
                color: meta.fg,
                letterSpacing: 0.5,
            }}
            title={priority}
        >
            {meta.label}
        </span>
    );
}

function StatusBadge({ status }) {
    const s = (status || "").toLowerCase();
    const meta =
        s === "resolved"
            ? { bg: "#16a34a", fg: "#fff" }
            : s === "acknowledged"
                ? { bg: "#0ea5e9", fg: "#fff" }
                : { bg: "#6b7280", fg: "#fff" };

    return (
        <span
            style={{
                display: "inline-block",
                padding: "4px 10px",
                borderRadius: 999,
                fontSize: 12,
                fontWeight: 700,
                background: meta.bg,
                color: meta.fg,
            }}
            title={status}
        >
            {(status || "new").toUpperCase()}
        </span>
    );
}

function formatDateTime(createdAt) {
    if (!createdAt) return "—";
    // backend returns RFC-like "Tue, 10 Feb 2026 ..."
    const dt = new Date(createdAt);
    if (Number.isNaN(dt.getTime())) return String(createdAt);
    return dt.toLocaleString();
}

export default function AlertsPage({ refreshTrigger }) {
    const [items, setItems] = useState([]);
    const [total, setTotal] = useState(0);

    // filters
    const [priority, setPriority] = useState("all");
    const [status, setStatus] = useState("all");
    const [q, setQ] = useState("");

    // paging
    const [page, setPage] = useState(1);
    const limit = 20;

    // details
    const [selectedId, setSelectedId] = useState(null);
    const [details, setDetails] = useState(null);
    const [detailsLoading, setDetailsLoading] = useState(false);

    const totalPages = useMemo(() => {
        if (!total) return 1;
        return Math.max(1, Math.ceil(total / limit));
    }, [total]);

    async function fetchAlerts() {
        const params = new URLSearchParams();
        params.set("page", String(page));
        params.set("limit", String(limit));
        if (priority !== "all") params.set("priority", priority);
        if (status !== "all") params.set("status", status);
        if (q.trim()) params.set("q", q.trim());

        const res = await fetch(`${API_BASE_URL}/api/alerts?${params.toString()}`);
        if (!res.ok) throw new Error(`Failed to fetch alerts: ${res.status}`);
        const data = await res.json();
        setItems(data.items || []);
        setTotal(data.total || 0);
    }

    async function fetchAlertDetails(alertId) {
        setDetailsLoading(true);
        setDetails(null);
        try {
            const res = await fetch(`${API_BASE_URL}/api/alerts/${alertId}`);
            if (!res.ok) throw new Error(`Failed to fetch alert details: ${res.status}`);
            const data = await res.json();
            setDetails(data);
        } finally {
            setDetailsLoading(false);
        }
    }

    async function updateStatus(alertId, newStatus) {
        const res = await fetch(`${API_BASE_URL}/api/alerts/${alertId}`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ status: newStatus }),
        });

        if (!res.ok) {
            const txt = await res.text();
            throw new Error(`Failed to update status (${res.status}): ${txt}`);
        }

        // refresh list and details
        await fetchAlerts();
        if (selectedId === alertId) await fetchAlertDetails(alertId);
    }

    function exportCsv(alertId) {
        // triggers download in browser
        window.open(`${API_BASE_URL}/api/alerts/${alertId}/export_csv`, "_blank");
    }

    useEffect(() => {
        fetchAlerts().catch((e) => console.error(e));
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [page, priority, status, refreshTrigger]);

    // search should reset paging
    useEffect(() => {
        setPage(1);
    }, [priority, status, q]);

    useEffect(() => {
        if (selectedId == null) return;
        fetchAlertDetails(selectedId).catch((e) => console.error(e));
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [selectedId]);

    return (
        <div style={{ padding: 16 }}>
            <h2 style={{ marginTop: 0 }}>Alerts</h2>

            {/* Filters */}
            <div
                style={{
                    display: "flex",
                    gap: 12,
                    flexWrap: "wrap",
                    alignItems: "center",
                    marginBottom: 12,
                }}
            >
                <input
                    value={q}
                    onChange={(e) => setQ(e.target.value)}
                    placeholder="Search title/description..."
                    style={{ padding: 10, borderRadius: 8, border: "1px solid #d1d5db", minWidth: 240 }}
                />

                <select
                    value={priority}
                    onChange={(e) => setPriority(e.target.value)}
                    style={{ padding: 10, borderRadius: 8, border: "1px solid #d1d5db" }}
                >
                    <option value="all">All priorities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                </select>

                <select
                    value={status}
                    onChange={(e) => setStatus(e.target.value)}
                    style={{ padding: 10, borderRadius: 8, border: "1px solid #d1d5db" }}
                >
                    <option value="all">All statuses</option>
                    <option value="new">New</option>
                    <option value="acknowledged">Acknowledged</option>
                    <option value="resolved">Resolved</option>
                </select>

                <button
                    onClick={() => fetchAlerts().catch((e) => console.error(e))}
                    style={{
                        padding: "10px 14px",
                        borderRadius: 8,
                        border: "1px solid #d1d5db",
                        background: "#fff",
                        cursor: "pointer",
                        fontWeight: 700,
                    }}
                >
                    Refresh
                </button>
            </div>

            {/* Table */}
            <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                    <thead>
                        <tr style={{ textAlign: "left" }}>
                            <th style={{ padding: 10, borderBottom: "1px solid #e5e7eb" }}>Time</th>
                            <th style={{ padding: 10, borderBottom: "1px solid #e5e7eb" }}>Priority</th>
                            <th style={{ padding: 10, borderBottom: "1px solid #e5e7eb" }}>Status</th>
                            <th style={{ padding: 10, borderBottom: "1px solid #e5e7eb" }}>Title</th>
                            <th style={{ padding: 10, borderBottom: "1px solid #e5e7eb" }}>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {items.map((a) => (
                            <tr key={a.id}>
                                <td style={{ padding: 10, borderBottom: "1px solid #f3f4f6", whiteSpace: "nowrap" }}>
                                    {formatDateTime(a.created_at)}
                                </td>
                                <td style={{ padding: 10, borderBottom: "1px solid #f3f4f6" }}>
                                    <PriorityBadge priority={a.priority} />
                                </td>
                                <td style={{ padding: 10, borderBottom: "1px solid #f3f4f6" }}>
                                    <StatusBadge status={a.status} />
                                </td>
                                <td style={{ padding: 10, borderBottom: "1px solid #f3f4f6" }}>
                                    <div style={{ fontWeight: 800 }}>{a.title}</div>
                                    <div style={{ opacity: 0.8 }}>{a.description}</div>
                                </td>
                                <td style={{ padding: 10, borderBottom: "1px solid #f3f4f6", whiteSpace: "nowrap" }}>
                                    <button
                                        onClick={() => setSelectedId(a.id)}
                                        style={{
                                            padding: "8px 10px",
                                            borderRadius: 8,
                                            border: "1px solid #d1d5db",
                                            background: "#fff",
                                            cursor: "pointer",
                                            fontWeight: 700,
                                            marginRight: 8,
                                        }}
                                    >
                                        View
                                    </button>

                                    <button
                                        onClick={() => updateStatus(a.id, "acknowledged").catch((e) => alert(e.message))}
                                        style={{
                                            padding: "8px 10px",
                                            borderRadius: 8,
                                            border: "1px solid #d1d5db",
                                            background: "#fff",
                                            cursor: "pointer",
                                            fontWeight: 700,
                                            marginRight: 8,
                                        }}
                                    >
                                        Ack
                                    </button>

                                    <button
                                        onClick={() => updateStatus(a.id, "resolved").catch((e) => alert(e.message))}
                                        style={{
                                            padding: "8px 10px",
                                            borderRadius: 8,
                                            border: "1px solid #d1d5db",
                                            background: "#fff",
                                            cursor: "pointer",
                                            fontWeight: 700,
                                            marginRight: 8,
                                        }}
                                    >
                                        Resolve
                                    </button>

                                    <button
                                        onClick={() => exportCsv(a.id)}
                                        style={{
                                            padding: "8px 10px",
                                            borderRadius: 8,
                                            border: "1px solid #d1d5db",
                                            background: "#fff",
                                            cursor: "pointer",
                                            fontWeight: 700,
                                        }}
                                    >
                                        Export CSV
                                    </button>
                                </td>
                            </tr>
                        ))}

                        {!items.length && (
                            <tr>
                                <td colSpan={5} style={{ padding: 14, opacity: 0.8 }}>
                                    No alerts found.
                                </td>
                            </tr>
                        )}
                    </tbody>
                </table>
            </div>

            {/* Pagination */}
            <div style={{ display: "flex", gap: 10, alignItems: "center", marginTop: 12 }}>
                <button
                    disabled={page <= 1}
                    onClick={() => setPage((p) => Math.max(1, p - 1))}
                    style={{
                        padding: "8px 12px",
                        borderRadius: 8,
                        border: "1px solid #d1d5db",
                        background: page <= 1 ? "#f3f4f6" : "#fff",
                        cursor: page <= 1 ? "not-allowed" : "pointer",
                        fontWeight: 700,
                    }}
                >
                    Prev
                </button>

                <div style={{ fontWeight: 700 }}>
                    Page {page} / {totalPages} (Total: {total})
                </div>

                <button
                    disabled={page >= totalPages}
                    onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                    style={{
                        padding: "8px 12px",
                        borderRadius: 8,
                        border: "1px solid #d1d5db",
                        background: page >= totalPages ? "#f3f4f6" : "#fff",
                        cursor: page >= totalPages ? "not-allowed" : "pointer",
                        fontWeight: 700,
                    }}
                >
                    Next
                </button>
            </div>

            {/* Details panel */}
            {selectedId != null && (
                <div
                    style={{
                        marginTop: 16,
                        padding: 14,
                        border: "1px solid #e5e7eb",
                        borderRadius: 12,
                        background: "#fff",
                    }}
                >
                    <div style={{ display: "flex", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
                        <div style={{ fontWeight: 900, fontSize: 16 }}>Alert Details (ID: {selectedId})</div>
                        <button
                            onClick={() => {
                                setSelectedId(null);
                                setDetails(null);
                            }}
                            style={{
                                padding: "8px 10px",
                                borderRadius: 8,
                                border: "1px solid #d1d5db",
                                background: "#fff",
                                cursor: "pointer",
                                fontWeight: 700,
                            }}
                        >
                            Close
                        </button>
                    </div>

                    {detailsLoading && <div style={{ marginTop: 10 }}>Loading…</div>}

                    {!detailsLoading && details?.alert && (
                        <>
                            <div style={{ marginTop: 10, display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
                                <PriorityBadge priority={details.alert.priority} />
                                <StatusBadge status={details.alert.status} />
                                <div style={{ opacity: 0.8 }}>{formatDateTime(details.alert.created_at)}</div>
                            </div>

                            <div style={{ marginTop: 10 }}>
                                <div style={{ fontWeight: 900 }}>{details.alert.title}</div>
                                <div style={{ opacity: 0.9 }}>{details.alert.description}</div>
                            </div>

                            <div style={{ marginTop: 12, fontWeight: 900 }}>Linked Logs</div>
                            <div style={{ overflowX: "auto", marginTop: 8 }}>
                                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                                    <thead>
                                        <tr style={{ textAlign: "left" }}>
                                            <th style={{ padding: 8, borderBottom: "1px solid #e5e7eb" }}>Time</th>
                                            <th style={{ padding: 8, borderBottom: "1px solid #e5e7eb" }}>Source</th>
                                            <th style={{ padding: 8, borderBottom: "1px solid #e5e7eb" }}>Message</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {(details.linked_logs || []).map((l) => (
                                            <tr key={l.id}>
                                                <td style={{ padding: 8, borderBottom: "1px solid #f3f4f6", whiteSpace: "nowrap" }}>
                                                    {l.log_time ? new Date(l.log_time).toLocaleString() : "—"}
                                                </td>
                                                <td style={{ padding: 8, borderBottom: "1px solid #f3f4f6" }}>{l.source}</td>
                                                <td style={{ padding: 8, borderBottom: "1px solid #f3f4f6" }}>{l.message}</td>
                                            </tr>
                                        ))}

                                        {!details.linked_logs?.length && (
                                            <tr>
                                                <td colSpan={3} style={{ padding: 10, opacity: 0.8 }}>
                                                    No linked logs found for this alert.
                                                </td>
                                            </tr>
                                        )}
                                    </tbody>
                                </table>
                            </div>
                        </>
                    )}
                </div>
            )}
        </div>
    );
}