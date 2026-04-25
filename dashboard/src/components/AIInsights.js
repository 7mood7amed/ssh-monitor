import React, { useCallback, useEffect, useMemo, useState, useRef } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";
import API_BASE_URL from "../config";
import "./AIInsights.css";
import "./FtpLogs.css";

function SectionChip({ label, value, tone = "neutral" }) {
  return (
    <span className={`ai-chip ai-chip-${tone}`}>
      <span className="ai-chip-label">{label}</span>
      <span className="ai-chip-value">{value}</span>
    </span>
  );
}

function safeArray(value) {
  return Array.isArray(value) ? value : [];
}

function prettyJson(value) {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function getSummaryText(data) {
  if (!data || typeof data !== "object") return "No AI summary available.";

  return (
    data.summary ||
    data.explanation ||
    data.analysis ||
    data.report ||
    data.narrative ||
    data.message ||
    "AI analysis completed, but no summary text was returned."
  );
}

function getTopActivity(data) {
  if (!data || typeof data !== "object") return null;
  return data?.report_data?.top_activity || null;
}

function getTopExternal(data) {
  if (!data || typeof data !== "object") return null;
  return data?.report_data?.top_external || null;
}

function getTopInternal(data) {
  if (!data || typeof data !== "object") return null;
  return data?.report_data?.top_internal || null;
}

function getCorrelations(data) {
  if (!data || typeof data !== "object") return [];
  return safeArray(
    data.top_correlations ||
    data.correlations ||
    data.items ||
    data.results ||
    data.correlated_ips
  );
}

function getMultiSourceIps(analyzeData, correlationData) {
  const fromAnalyze = safeArray(
    analyzeData?.correlations?.multi_source_ips ||
    analyzeData?.report_data?.multi_source_ips
  );

  const fromCorrelation = safeArray(correlationData?.multi_source_ips);

  return fromAnalyze.length > 0 ? fromAnalyze : fromCorrelation;
}

function getRiskLevel(data) {
  return data?.risk?.level?.toUpperCase() || "UNKNOWN";
}

function getRiskScore(data) {
  return data?.risk?.score ?? "-";
}

function getRiskReasons(data) {
  return safeArray(data?.risk?.reasons);
}

function getItemKey(item, index) {
  return item?.ip || item?.source_ip || item?.id || `${index}`;
}

function getItemIp(item) {
  return (
    item?.ip ||
    item?.source_ip ||
    item?.host ||
    item?.target ||
    item?.entity ||
    "—"
  );
}

function getItemScore(item) {
  return (
    item?.activity_score ??
    item?.score ??
    item?.risk_score ??
    item?.count ??
    item?.total ??
    "—"
  );
}

function getItemAssessment(item) {
  return (
    item?.assessment ||
    item?.summary ||
    item?.reason ||
    item?.classification ||
    item?.label ||
    "No assessment"
  );
}

function getScopeTone(item) {
  const scope = String(item?.ip_scope || item?.scope || "").toLowerCase();
  if (scope.includes("external")) return "danger";
  if (scope.includes("internal") || scope.includes("test")) return "info";
  return "neutral";
}

function getScopeLabel(item) {
  return item?.ip_scope || item?.scope || "unknown";
}

function getSourceCount(item) {
  return item?.source_count ?? safeArray(item?.sources).length ?? 0;
}

function getPatternCount(item) {
  return (
    safeArray(item?.probable_patterns).length +
    safeArray(item?.patterns).length
  );
}

function getUsernames(item) {
  return safeArray(item?.usernames);
}

function buildEntityDetails(item) {
  if (!item) return [];

  return [
    { label: "IP / Entity", value: getItemIp(item) },
    { label: "Score", value: getItemScore(item) },
    { label: "Scope", value: getScopeLabel(item) },
    { label: "Assessment", value: getItemAssessment(item) },
    { label: "Sources", value: safeArray(item?.sources).join(", ") || "—" },
    { label: "Patterns", value: safeArray(item?.probable_patterns).join(", ") || "—" },
    { label: "Usernames", value: safeArray(item?.usernames).join(", ") || "—" },
    { label: "SSH Failures", value: item?.ssh_failures ?? 0 },
    { label: "SSH Successes", value: item?.ssh_successes ?? 0 },
    { label: "FTP Failures", value: item?.ftp_failures ?? 0 },
    { label: "FTP Successes", value: item?.ftp_successes ?? 0 },
    { label: "Web Hits", value: item?.web_hits ?? 0 },
    { label: "Alert Count", value: item?.alert_count ?? 0 },
    { label: "Nmap Port Count", value: item?.nmap_port_count ?? 0 },
  ];
}

function FindingCard({ title, item, emptyText, tone = "neutral" }) {
  return (
    <div className={`ai-finding-card ai-finding-${tone}`}>
      <div className="ai-finding-header">
        <div className="ai-finding-title">{title}</div>
        {item && (
          <SectionChip
            label="score"
            value={getItemScore(item)}
            tone={tone}
          />
        )}
      </div>

      {!item ? (
        <div className="empty">{emptyText}</div>
      ) : (
        <>
          <div className="ai-finding-ip">{getItemIp(item)}</div>
          <div className="ai-finding-assessment">{getItemAssessment(item)}</div>

          <div className="ai-finding-meta">
            <SectionChip label="scope" value={getScopeLabel(item)} tone={tone} />
            <SectionChip label="sources" value={getSourceCount(item)} tone="neutral" />
            <SectionChip label="patterns" value={getPatternCount(item)} tone="neutral" />
          </div>

          {getUsernames(item).length > 0 && (
            <div className="ai-inline-tags">
              {getUsernames(item).map((username, index) => (
                <span className="badge" key={`${username}-${index}`}>
                  {username}
                </span>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}

function MiniList({ title, items, emptyText }) {
  return (
    <div className="ai-mini-card">
      <div className="ai-mini-title">{title}</div>

      {items.length === 0 ? (
        <div className="empty">{emptyText}</div>
      ) : (
        <div className="ai-mini-list">
          {items.slice(0, 5).map((item, index) => (
            <div className="ai-mini-row" key={getItemKey(item, index)}>
              <div className="ai-mini-main">
                <div className="ai-mini-ip">{getItemIp(item)}</div>
                <div className="ai-mini-assessment">{getItemAssessment(item)}</div>
              </div>

              <div className="ai-mini-side">
                <SectionChip
                  label="score"
                  value={getItemScore(item)}
                  tone={getScopeTone(item)}
                />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function buildReasoningPoints(data, correlationData) {
  const points = [];

  const riskLevel = data?.risk?.level;
  const riskScore = data?.risk?.score;
  const riskReasons = safeArray(data?.risk?.reasons);

  const topActivity = data?.report_data?.top_activity;
  const topInternal = data?.report_data?.top_internal;
  const topExternal = data?.report_data?.top_external;

  const totals = data?.report_data?.totals || {};
  const correlatedIps = safeArray(
    correlationData?.correlated_ips || data?.correlations?.correlated_ips
  );

  if (riskLevel || riskScore !== undefined) {
    points.push(
      `Overall risk is ${String(riskLevel || "unknown").toUpperCase()} with a score of ${riskScore ?? "-"}.`
    );
  }

  riskReasons.forEach((reason) => {
    points.push(`Risk driver: ${reason}.`);
  });

  if (topActivity?.ip) {
    points.push(
      `Top activity is linked to ${topActivity.ip}, classified as ${topActivity.assessment || "unknown activity"}, with score ${topActivity.activity_score ?? 0}.`
    );
  }

  if (topActivity?.nmap_port_count > 0) {
    points.push(
      `${topActivity.nmap_port_count} open port finding(s) were associated with the top activity entity.`
    );
  }

  if (safeArray(topActivity?.probable_patterns).length > 0) {
    points.push(
      `Detected pattern(s): ${safeArray(topActivity.probable_patterns).join(", ")}.`
    );
  }

  if ((totals?.ssh_failures ?? 0) > 0) {
    points.push(
      `${totals.ssh_failures} SSH failure event(s) were observed in the selected window, which may indicate login probing or brute-force behavior.`
    );
  }

  if ((totals?.ftp_failures ?? 0) > 0) {
    points.push(
      `${totals.ftp_failures} FTP failure event(s) were observed in the selected window.`
    );
  }

  if ((totals?.alerts ?? 0) > 0) {
    points.push(
      `${totals.alerts} alert record(s) were generated by the rule-based detection layer.`
    );
  }

  if ((totals?.nmap_findings ?? 0) > 0) {
    points.push(
      `${totals.nmap_findings} Nmap finding(s) were included in the analysis evidence.`
    );
  }

  if (topInternal?.ip) {
    points.push(
      `The strongest internal/test activity currently maps to ${topInternal.ip}.`
    );
  }

  if (topExternal?.ip) {
    points.push(
      `The strongest external activity currently maps to ${topExternal.ip}.`
    );
  } else {
    points.push(`No dominant external source was identified in the current analysis window.`);
  }

  if (correlatedIps.length > 1) {
    points.push(
      `${correlatedIps.length} correlated IP/entities were included in the cross-source analysis set.`
    );
  }

  return points.slice(0, 7);
}

function buildVerdict(data) {
  const risk = data?.risk?.level || "unknown";
  const totals = data?.report_data?.totals || {};
  const top = data?.report_data?.top_activity;

  if (risk === "high") {
    return "High risk activity detected. Immediate investigation recommended.";
  }

  if ((totals?.ssh_failures ?? 0) > 5) {
    return "Likely brute-force activity detected with repeated SSH failures.";
  }

  if (top?.ip && top?.ip_scope === "internal") {
    return "Internal/test activity detected with no strong external threat indicators.";
  }

  return "No critical threat detected in the current analysis window.";
}

export default function AIInsights({ refreshTrigger }) {
  const [analyzeData, setAnalyzeData] = useState(null);
  const [correlationData, setCorrelationData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [lastRun, setLastRun] = useState(null);
  const [error, setError] = useState("");
  const [windowHours, setWindowHours] = useState("1");
  const [selectedEntity, setSelectedEntity] = useState(null);
  const selectedEntityRef = useRef(null);

  useEffect(() => {
    selectedEntityRef.current = selectedEntity;
  }, [selectedEntity]);

  const analyzeUrl = useMemo(
    () => `${API_BASE_URL}/api/ai/analyze?hours=${windowHours}`,
    [windowHours]
  );

  const correlationsUrl = useMemo(
    () => `${API_BASE_URL}/api/ai/top-correlations?hours=${windowHours}`,
    [windowHours]
  );

  const runAnalysis = useCallback(async () => {
    try {
      setLoading(true);
      setError("");

      const [analyzeRes, corrRes] = await Promise.all([
        fetch(analyzeUrl),
        fetch(correlationsUrl),
      ]);

      if (!analyzeRes.ok) {
        throw new Error(`/api/ai/analyze returned HTTP ${analyzeRes.status}`);
      }

      if (!corrRes.ok) {
        throw new Error(`/api/ai/top-correlations returned HTTP ${corrRes.status}`);
      }

      const [analyzeJson, corrJson] = await Promise.all([
        analyzeRes.json(),
        corrRes.json(),
      ]);

      setAnalyzeData(analyzeJson);
      setCorrelationData(corrJson);
      setLastRun(new Date().toLocaleTimeString());

      const currentEntity = selectedEntityRef.current;

      if (currentEntity?.ip) {
        const refreshedMatch = safeArray(corrJson?.correlated_ips).find(
          (item) => getItemIp(item) === selectedEntity?.ip
        );
        if (refreshedMatch) {
          setSelectedEntity(refreshedMatch);
        }
      }
    } catch (err) {
      console.error("AI insights fetch failed:", err);
      setError(err.message || "Failed to load AI insights.");
    } finally {
      setLoading(false);
    }
  }, [analyzeUrl, correlationsUrl]);

  useEffect(() => {
    let alive = true;

    const wrappedRun = async () => {
      if (!alive) return;
      await runAnalysis();
    };

    wrappedRun();
    const interval = setInterval(wrappedRun, 30000);

    return () => {
      alive = false;
      clearInterval(interval);
    };
  }, [analyzeUrl, correlationsUrl, refreshTrigger]);

  const chartData = [
    {
      name: "SSH Success",
      value: analyzeData?.facts?.ssh_successes?.[0]?.count ?? 0,
    },
    {
      name: "SSH Failures",
      value: analyzeData?.report_data?.totals?.ssh_failures ?? 0,
    },
    {
      name: "FTP Failures",
      value: analyzeData?.report_data?.totals?.ftp_failures ?? 0,
    },
    {
      name: "Alerts",
      value: analyzeData?.report_data?.totals?.alerts ?? 0,
    },
    {
      name: "Nmap",
      value: analyzeData?.report_data?.totals?.nmap_findings ?? 0,
    },
  ];

  const summaryText = getSummaryText(analyzeData);
  const topActivity = getTopActivity(analyzeData);
  const topExternal = getTopExternal(analyzeData);
  const topInternal = getTopInternal(analyzeData);
  const topCorrelations = getCorrelations(correlationData);
  const multiSourceIps = getMultiSourceIps(analyzeData, correlationData);
  const riskReasons = getRiskReasons(analyzeData);
  const reasoningPoints = buildReasoningPoints(analyzeData, correlationData);
  const verdict = buildVerdict(analyzeData);
  const selectedEntityDetails = buildEntityDetails(selectedEntity);

  const totalActivity = topActivity ? 1 : 0;
  const totalExternal = topExternal ? 1 : 0;
  const totalInternal = topInternal ? 1 : 0;
  const totalCorrelations = topCorrelations.length;
  const totalMultiSource = multiSourceIps.length;

  useEffect(() => {
    console.log("Selected Entity:", selectedEntity);
  }, [selectedEntity]);

  return (
    <div className="content ai-insights-wrap">
      <div className="card ai-card">
        <div className="card-header">
          <div>
            <h2 className="card-title">🧠 AI Investigation Workspace</h2>
            <div className="card-subtitle">
              Analyst-facing correlation, explanation, activity classification, and evidence review
            </div>
          </div>

          <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
            <span
              style={{
                fontSize: 12,
                fontWeight: 700,
                color: error ? "rgba(239,68,68,0.9)" : "rgba(226,232,240,0.75)",
              }}
            >
              {loading ? "AI: LOADING" : error ? "AI: ERROR" : "AI: OK"}
            </span>

            {lastRun && (
              <span style={{ fontSize: 12, color: "rgba(226,232,240,0.65)" }}>
                Last run: {lastRun}
              </span>
            )}
          </div>
        </div>

        <div className="meta-row">
          <div className="meta-left" style={{ flexWrap: "wrap" }}>
            <SectionChip label="top activity" value={totalActivity} tone="neutral" />
            <SectionChip label="external" value={totalExternal} tone="danger" />
            <SectionChip label="internal/test" value={totalInternal} tone="info" />
            <SectionChip label="correlations" value={totalCorrelations} tone="neutral" />
            <SectionChip label="multi-source" value={totalMultiSource} tone="neutral" />
            <SectionChip label="window" value={`${windowHours}h`} tone="neutral" />
          </div>
        </div>

        <div
          className="ai-risk"
          style={{ marginBottom: 12, display: "flex", gap: 8, flexWrap: "wrap" }}
        >
          <span className="badge">
            Risk: {getRiskLevel(analyzeData)}
          </span>
          <span className="badge">
            Score: {getRiskScore(analyzeData)}
          </span>
          {riskReasons.map((reason, index) => (
            <span className="badge" key={`${reason}-${index}`}>
              {reason}
            </span>
          ))}
        </div>

        <div className="ai-summary-card" style={{ marginBottom: 14 }}>
          <div className="ai-summary-title">What the AI Score Is Based On</div>
          <div className="ai-summary-text">
            The AI score is a rule-based investigation score calculated from recent security evidence.
            It increases when the selected time window contains high-priority alerts, repeated SSH or FTP
            login failures, suspicious web activity, sensitive open ports, and IP addresses appearing across
            multiple monitored sources. Higher scores mean the activity should be reviewed with higher priority.
          </div>
        </div>

        {error && <div className="error">{error}</div>}

        <div className="ai-controls">
          <button className="btn" onClick={runAnalysis} disabled={loading}>
            {loading ? "Running..." : "▶ Run AI Analysis"}
          </button>

          <select
            className="select"
            value={windowHours}
            onChange={(e) => setWindowHours(e.target.value)}
          >
            <option value="1">Last 1 hour</option>
            <option value="6">Last 6 hours</option>
            <option value="24">Last 24 hours</option>
          </select>
        </div>

        <div className="ai-findings-grid">
          <div
            onClick={() => topActivity && setSelectedEntity(topActivity)}
            style={{ cursor: topActivity ? "pointer" : "default" }}
          >
            <FindingCard
              title="Top Activity"
              item={topActivity}
              emptyText="No top activity entity returned."
              tone={
                topActivity?.activity_score > 25
                  ? "danger"
                  : topActivity?.activity_score > 10
                    ? "warning"
                    : "neutral"
              }
            />
          </div>

          <div
            onClick={() => topInternal && setSelectedEntity(topInternal)}
            style={{ cursor: topInternal ? "pointer" : "default" }}
          >
            <FindingCard
              title="Top Internal / Test"
              item={topInternal}
              emptyText="No internal/test entity returned."
              tone="info"
            />
          </div>

          <div
            onClick={() => {
              if (!topExternal) return;
              setSelectedEntity(topExternal);
            }}
            style={{ cursor: topExternal ? "pointer" : "default" }}
          >
            <FindingCard
              title="Top External"
              item={topExternal}
              emptyText="No external entity returned."
              tone="danger"
            />
          </div>

          <div className="ai-finding-card ai-finding-neutral">
            <div className="ai-finding-header">
              <div className="ai-finding-title">Multi-Source IPs</div>
              <SectionChip label="count" value={totalMultiSource} tone="neutral" />
            </div>

            {multiSourceIps.length === 0 ? (
              <div className="empty">No multi-source overlap detected.</div>
            ) : (
              <div className="ai-inline-tags">
                {multiSourceIps.map((item, index) => (
                  <div key={`${getItemIp(item)}-${index}`} className="ai-mini-row">
                    <div>
                      <strong>{getItemIp(item)}</strong>
                      <div style={{ fontSize: 12, opacity: 0.7 }}>
                        {getItemAssessment(item)}
                      </div>
                      <div style={{ fontSize: 11, opacity: 0.6 }}>
                        Sources: {safeArray(item?.sources).join(", ")}
                      </div>
                    </div>

                    <div>
                      <SectionChip label="sources" value={getSourceCount(item)} />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="ai-evidence-grid">
          <SectionChip label="SSH Success" value={analyzeData?.facts?.ssh_successes?.[0]?.count ?? 0} />
          <SectionChip label="SSH Failures" value={analyzeData?.report_data?.totals?.ssh_failures ?? 0} />
          <SectionChip label="FTP Failures" value={analyzeData?.report_data?.totals?.ftp_failures ?? 0} />
          <SectionChip label="Alerts" value={analyzeData?.report_data?.totals?.alerts ?? 0} />
          <SectionChip label="Nmap Findings" value={analyzeData?.report_data?.totals?.nmap_findings ?? 0} />
        </div>

        <div className="ai-chart-card">
          <div className="ai-chart-title">Activity Overview</div>

          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={chartData}>
              <XAxis dataKey="name" stroke="#94a3b8" />
              <YAxis stroke="#94a3b8" />
              <Tooltip />
              <Bar dataKey="value">
                {chartData.map((entry, index) => {
                  let color = "#38bdf8";

                  if (entry.name.includes("FTP")) color = "#f97316";
                  if (entry.name.includes("SSH Failure")) color = "#ef4444";
                  if (entry.name.includes("Alerts")) color = "#f59e0b";
                  if (entry.name.includes("Nmap")) color = "#8b5cf6";

                  return <Cell key={index} fill={color} />;
                })}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="ai-verdict">
          AI Verdict: {verdict}
        </div>

        <div className="ai-summary-card">
          <div className="ai-summary-title">AI Summary</div>
          <div className="ai-summary-text">
            {loading ? "Loading AI summary..." : summaryText}
          </div>
        </div>

        <div className="ai-reasoning-card">
          <div className="ai-reasoning-title">AI Reasoning</div>

          {loading ? (
            <div className="ai-summary-text">Preparing reasoning...</div>
          ) : reasoningPoints.length === 0 ? (
            <div className="empty">No reasoning points available.</div>
          ) : (
            <ul className="ai-reasoning-list">
              {reasoningPoints.map((point, index) => (
                <li key={index}>{point}</li>
              ))}
            </ul>
          )}
        </div>

        <div className="ai-investigation-card">
          <div className="ai-investigation-header">
            <div className="ai-investigation-title">Entity Investigation Panel</div>
            {selectedEntity && (
              <button
                type="button"
                className="btn"
                onClick={() => setSelectedEntity(null)}
              >
                Clear Selection
              </button>
            )}
          </div>

          {!selectedEntity ? (
            <div className="empty">Click a top entity or table IP to inspect it in detail.</div>
          ) : (
            <>
              <div className="ai-investigation-highlight">
                Investigating: <span className="mono">
                  {selectedEntity ? getItemIp(selectedEntity) : "—"}
                </span>
              </div>

              <div className="ai-investigation-grid">
                {selectedEntityDetails.map((row, index) => (
                  <div className="ai-investigation-row" key={`${row.label}-${index}`}>
                    <div className="ai-investigation-label">{row.label}</div>
                    <div className="ai-investigation-value">{row.value}</div>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>

        <div className="ai-grid">
          <MiniList
            title="Top External Activity"
            items={topExternal ? [topExternal] : []}
            emptyText="No external items returned."
          />

          <MiniList
            title="Top Internal / Test Activity"
            items={topInternal ? [topInternal] : []}
            emptyText="No internal/test items returned."
          />
        </div>

        <div className="table-wrap ai-table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th style={{ width: 180 }}>IP / ENTITY</th>
                <th style={{ width: 120 }}>SCORE</th>
                <th style={{ width: 140 }}>SCOPE</th>
                <th style={{ width: 220 }}>ASSESSMENT</th>
                <th>SOURCES / PATTERNS</th>
              </tr>
            </thead>

            <tbody>
              {topCorrelations.length === 0 ? (
                <tr>
                  <td colSpan={5} className="empty">
                    {loading
                      ? "Loading top correlations..."
                      : "No correlation data returned."}
                  </td>
                </tr>
              ) : (
                topCorrelations.slice(0, 10).map((item, index) => (
                  <tr key={getItemKey(item, index)}>
                    <td className="mono">
                      <button
                        type="button"
                        className="ai-ip-link"
                        onClick={() => setSelectedEntity(item)}
                      >
                        {getItemIp(item)}
                      </button>
                    </td>
                    <td>{getItemScore(item)}</td>
                    <td>
                      <span className={`badge ai-scope-badge ai-scope-${getScopeTone(item)}`}>
                        {getScopeLabel(item)}
                      </span>
                    </td>
                    <td>{getItemAssessment(item)}</td>
                    <td>
                      <div className="ai-tags">
                        {safeArray(item?.sources).map((src, i) => (
                          <span className="badge" key={`${src}-${i}`}>
                            {src}
                          </span>
                        ))}
                        {safeArray(item?.probable_patterns).map((pattern, i) => (
                          <span className="badge" key={`${pattern}-${i}`}>
                            {pattern}
                          </span>
                        ))}
                        {safeArray(item?.patterns).map((pattern, i) => (
                          <span className="badge" key={`${pattern}-${i}`}>
                            {pattern}
                          </span>
                        ))}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        <details className="ai-debug">
          <summary>Raw AI payloads</summary>
          <div className="ai-debug-grid">
            <div>
              <div className="ai-debug-title">/api/ai/analyze</div>
              <pre className="raw-pre">{prettyJson(analyzeData)}</pre>
            </div>

            <div>
              <div className="ai-debug-title">/api/ai/top-correlations</div>
              <pre className="raw-pre">{prettyJson(correlationData)}</pre>
            </div>
          </div>
        </details>
      </div>
    </div>
  );
}
