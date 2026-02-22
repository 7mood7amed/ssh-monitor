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
    const [includeInternal, setIncludeInternal] = useState(true);

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
        params.set("include_internal", includeInternal ? "1" : "0");

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
        window.open(`${API_BASE_URL}/api/alerts/${alertId}/export_csv`, "_blank");
    }

    useEffect(() => {
        fetchAlerts().catch((e) => console.error(e));
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [page, priority, status, includeInternal, refreshTrigger]);

    // search/filter should reset paging
    useEffect(() => {
        setPage(1);
    }, [priority, status, q, includeInternal]);

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
                    placeholder="Search title/description."
                    style={{ padding: 10, borderRadius: 8, border: "1px solid #d1d5db", minWidth: 240 }}
                />

                <label style={{ display: "flex", alignItems: "center", gap: 8, userSelect: "none" }}>
                    <input
                        type="checkbox"
                        checked={includeInternal}
                        onChange={(e) => setIncludeInternal(e.target.checked)}
                    />
                    <span style={{ fontSize: 13, color: "#374151" }}>
                        Show internal (127.0.0.1 / ::1)
                    </span>
                </label>

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
                    <option value="all">All status</option>
                    <option value="new">New</option>
                    <option value="acknowledged">Acknowledged</option>
                    <option value="resolved">Resolved</option>
                </select>

                <button
                    onClick={() => fetchAlerts().catch((e) => console.error(e))}
                    style={{
                        padding: "10px 14px",
                        borderRadius: 10,
                        border: "1px solid #d1d5db",
                        cursor: "pointer",
                        background: "#fff",
                        fontWeight: 600,
                    }}
                >
                    Refresh
                </button>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 420px", gap: 16 }}>
                {/* List */}
                <div
                    style={{
                        border: "1px solid #e5e7eb",
                        borderRadius: 12,
                        overflow: "hidden",
                        background: "#fff",
                    }}
                >
                    <div
                        style={{
                            display: "grid",
                            gridTemplateColumns: "180px 90px 120px 1fr 260px",
                            gap: 8,
                            padding: 12,
                            background: "#f9fafb",
                            borderBottom: "1px solid #e5e7eb",
                            fontWeight: 700,
                            fontSize: 13,
                            color: "#374151",
                        }}
                    >
                        <div>Time</div>
                        <div>Priority</div>
                        <div>Status</div>
                        <div>Title</div>
                        <div>Actions</div>
                    </div>

                    {items.map((a) => (
                        <div
                            key={a.id}
                            style={{
                                display: "grid",
                                gridTemplateColumns: "180px 90px 120px 1fr 260px",
                                gap: 8,
                                padding: 12,
                                borderBottom: "1px solid #f3f4f6",
                                cursor: "pointer",
                                background: selectedId === a.id ? "#f0f9ff" : "#fff",
                            }}
                            onClick={() => setSelectedId(a.id)}
                            title={a.description || ""}
                        >
                            <div style={{ fontSize: 13 }}>{formatDateTime(a.created_at)}</div>
                            <div><PriorityBadge priority={a.priority} /></div>
                            <div><StatusBadge status={a.status} /></div>
                            <div style={{ fontWeight: 700 }}>{a.title}</div>

                            <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
                                <button
                                    onClick={(e) => { e.stopPropagation(); setSelectedId(a.id); }}
                                    style={{ padding: "8px 10px", borderRadius: 10, border: "1px solid #d1d5db", background: "#fff", cursor: "pointer" }}
                                >
                                    View
                                </button>
                                <button
                                    onClick={(e) => {
                                        e.stopPropagation();
                                        updateStatus(a.id, "acknowledged").catch((err) => alert(err.message));
                                    }}
                                    style={{ padding: "8px 10px", borderRadius: 10, border: "1px solid #d1d5db", background: "#fff", cursor: "pointer" }}
                                >
                                    Ack
                                </button>
                                <button
                                    onClick={(e) => {
                                        e.stopPropagation();
                                        updateStatus(a.id, "resolved").catch((err) => alert(err.message));
                                    }}
                                    style={{ padding: "8px 10px", borderRadius: 10, border: "1px solid #d1d5db", background: "#fff", cursor: "pointer" }}
                                >
                                    Resolve
                                </button>
                                <button
                                    onClick={(e) => { e.stopPropagation(); exportCsv(a.id); }}
                                    style={{ padding: "8px 10px", borderRadius: 10, border: "1px solid #d1d5db", background: "#fff", cursor: "pointer" }}
                                >
                                    Export CSV
                                </button>
                            </div>
                        </div>
                    ))}

                    {/* Pagination */}
                    <div style={{ display: "flex", justifyContent: "space-between", padding: 12, alignItems: "center" }}>
                        <div style={{ fontSize: 13, color: "#6b7280" }}>
                            Total: {total}
                        </div>
                        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                            <button
                                disabled={page <= 1}
                                onClick={() => setPage((p) => Math.max(1, p - 1))}
                                style={{
                                    padding: "8px 10px",
                                    borderRadius: 10,
                                    border: "1px solid #d1d5db",
                                    background: "#fff",
                                    cursor: page <= 1 ? "not-allowed" : "pointer",
                                    opacity: page <= 1 ? 0.5 : 1,
                                }}
                            >
                                Prev
                            </button>
                            <div style={{ fontSize: 13 }}>
                                Page {page} / {totalPages}
                            </div>
                            <button
                                disabled={page >= totalPages}
                                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                                style={{
                                    padding: "8px 10px",
                                    borderRadius: 10,
                                    border: "1px solid #d1d5db",
                                    background: "#fff",
                                    cursor: page >= totalPages ? "not-allowed" : "pointer",
                                    opacity: page >= totalPages ? 0.5 : 1,
                                }}
                            >
                                Next
                            </button>
                        </div>
                    </div>
                </div>

                {/* Details */}
                <div
                    style={{
                        border: "1px solid #e5e7eb",
                        borderRadius: 12,
                        padding: 12,
                        background: "#fff",
                        minHeight: 240,
                    }}
                >
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <h3 style={{ margin: 0 }}>Details</h3>
                        {selectedId != null && (
                            <button
                                onClick={() => fetchAlertDetails(selectedId).catch((e) => console.error(e))}
                                style={{ padding: "8px 10px", borderRadius: 10, border: "1px solid #d1d5db", background: "#fff", cursor: "pointer" }}
                            >
                                Refresh
                            </button>
                        )}
                    </div>

                    {selectedId == null ? (
                        <div style={{ color: "#6b7280", marginTop: 12 }}>Select an alert to view linked evidence.</div>
                    ) : detailsLoading ? (
                        <div style={{ marginTop: 12 }}>Loading...</div>
                    ) : !details ? (
                        <div style={{ color: "#6b7280", marginTop: 12 }}>No details loaded.</div>
                    ) : (
                        <div style={{ marginTop: 12 }}>
                            <div style={{ fontSize: 13, color: "#6b7280" }}>Alert</div>
                            <div style={{ fontWeight: 800, marginTop: 4 }}>{details.alert?.title}</div>
                            <div style={{ marginTop: 6, fontSize: 13 }}>{details.alert?.description}</div>

                            <div style={{ marginTop: 12, fontSize: 13, color: "#6b7280" }}>Linked evidence</div>
                            <div style={{ marginTop: 6, display: "grid", gap: 8 }}>
                                {(details.linked_items || []).map((it, idx) => (
                                    <div
                                        key={idx}
                                        style={{
                                            border: "1px solid #e5e7eb",
                                            borderRadius: 10,
                                            padding: 10,
                                            background: "#f9fafb",
                                        }}
                                    >
                                        <div style={{ display: "flex", justifyContent: "space-between", gap: 10 }}>
                                            <div style={{ fontWeight: 800, fontSize: 13 }}>
                                                {it.log_type}
                                            </div>
                                            <div style={{ fontSize: 12, color: "#6b7280" }}>
                                                {it.time}
                                            </div>
                                        </div>
                                        <div style={{ marginTop: 6, fontSize: 12, color: "#374151" }}>
                                            <div><b>Source:</b> {it.source}</div>
                                            <div style={{ marginTop: 4, whiteSpace: "pre-wrap" }}>
                                                <b>Message:</b> {it.message}
                                            </div>
                                        </div>
                                    </div>
                                ))}
                                {(!details.linked_items || details.linked_items.length === 0) && (
                                    <div style={{ color: "#6b7280" }}>No linked items.</div>
                                )}
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}