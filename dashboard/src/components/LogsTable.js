import React, { useEffect, useState } from "react";
import API_BASE_URL from "../config";
import "./LogsTable.css";

const LogsTable = () => {
  const [logs, setLogs] = useState([]);
  const [filteredLogs, setFilteredLogs] = useState([]);

  // Filters
  const [searchTerm, setSearchTerm] = useState("");
  const [severityFilter, setSeverityFilter] = useState("All");
  const [agentFilter, setAgentFilter] = useState("All");
  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");

  // Pagination
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20); // default 20
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(1);

  // Fetch logs (paginated)
  useEffect(() => {
    const fetchLogs = async () => {
      try {
        const res = await fetch(
          `${API_BASE_URL}/api/logs?page=${page}&limit=${pageSize}`
        );
        const data = await res.json();

        setLogs(data.logs || []);
        setFilteredLogs(data.logs || []);
        setTotal(data.total || 0);
        setTotalPages(data.totalPages || 1);
      } catch (error) {
        console.error("Error fetching logs:", error);
      }
    };

    fetchLogs();
    const interval = setInterval(fetchLogs, 10000);
    return () => clearInterval(interval);
  }, [page, pageSize]);

  // Apply client-side filters to current page
  useEffect(() => {
    let filtered = logs.filter((log) => {
      const matchesSearch =
        log.message.toLowerCase().includes(searchTerm.toLowerCase()) ||
        log.agent_name.toLowerCase().includes(searchTerm.toLowerCase());

      const matchesSeverity =
        severityFilter === "All" || log.severity === severityFilter;

      const matchesAgent =
        agentFilter === "All" || log.agent_name === agentFilter;

      // Date parsing
      let logDate = new Date(log.timestamp);
      if (isNaN(logDate)) {
        const parts = log.timestamp.split(" ");
        if (parts.length >= 3) {
          const month = parts[0];
          const day = parts[1];
          const time = parts[2];
          const year = new Date().getFullYear();
          logDate = new Date(`${month} ${day}, ${year} ${time}`);
        }
      }

      const matchesDate =
        (!startDate || logDate >= new Date(startDate)) &&
        (!endDate || logDate <= new Date(endDate + "T23:59:59"));

      return matchesSearch && matchesSeverity && matchesAgent && matchesDate;
    });

    setFilteredLogs(filtered);
  }, [logs, searchTerm, severityFilter, agentFilter, startDate, endDate]);

  const agentNames = ["All", ...new Set(logs.map((log) => log.agent_name))];

  const clearFilters = () => {
    setSearchTerm("");
    setSeverityFilter("All");
    setAgentFilter("All");
    setStartDate("");
    setEndDate("");
  };

  const handleExportCSV = () => {
    window.location.href = `${API_BASE_URL}/api/export`;
  };

  const handlePrevPage = () => {
    setPage((prev) => Math.max(prev - 1, 1));
  };

  const handleNextPage = () => {
    setPage((prev) => Math.min(prev + 1, totalPages));
  };

  const handlePageSizeChange = (e) => {
    const newSize = Number(e.target.value);
    setPageSize(newSize);
    setPage(1); // reset to first page when page size changes
  };

  return (
    <div className="log-table-container">
      <h2>📜 Recent Log Entries</h2>

      {/* Filters */}
      <div className="filter-bar">
        <input
          type="text"
          placeholder="Search by message or agent..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
        />

        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
        >
          <option value="All">All Severities</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>

        <select
          value={agentFilter}
          onChange={(e) => setAgentFilter(e.target.value)}
        >
          {agentNames.map((agent, i) => (
            <option key={i} value={agent}>
              {agent}
            </option>
          ))}
        </select>

        <div className="date-filters">
          <label>From:</label>
          <input
            type="date"
            value={startDate}
            onChange={(e) => setStartDate(e.target.value)}
          />
          <label>To:</label>
          <input
            type="date"
            value={endDate}
            onChange={(e) => setEndDate(e.target.value)}
          />
        </div>

        <button className="clear-btn" onClick={clearFilters}>
          Clear Filters
        </button>

        {/* CSV export button – same styling family */}
        <button className="clear-btn export-btn" onClick={handleExportCSV}>
          Export CSV
        </button>

        <span className="result-count">
          Showing <b>{filteredLogs.length}</b> of {total} logs (page {page} of{" "}
          {totalPages})
        </span>
      </div>

      {/* Table */}
      <div className="table-wrapper">
        <table className="log-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Agent</th>
              <th>Message</th>
              <th>Severity</th>
            </tr>
          </thead>
          <tbody>
            {filteredLogs.map((log, index) => (
              <tr key={index}>
                <td>{log.timestamp}</td>
                <td>{log.agent_name}</td>
                <td className="log-message">{log.message}</td>
                <td>
                  <span
                    className={`severity-badge ${log.severity.toLowerCase()}`}
                  >
                    {log.severity}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {filteredLogs.length === 0 && (
        <p className="no-results">No matching logs found.</p>
      )}

      {/* Pagination controls */}
      <div className="pagination-bar">
        <button
          className="page-btn"
          onClick={handlePrevPage}
          disabled={page === 1}
        >
          ◀ Prev
        </button>

        <span className="page-info">
          Page <b>{page}</b> of {totalPages}
        </span>

        <button
          className="page-btn"
          onClick={handleNextPage}
          disabled={page === totalPages || totalPages === 0}
        >
          Next ▶
        </button>

        <div className="page-size-control">
          <span>Show:</span>
          <select value={pageSize} onChange={handlePageSizeChange}>
            <option value={10}>10</option>
            <option value={20}>20</option>
            <option value={50}>50</option>
            <option value={100}>100</option>
          </select>
          <span>per page</span>
        </div>
      </div>
    </div>
  );
};

export default LogsTable;