import React, { useEffect, useMemo, useState } from "react";
import API_BASE_URL from "../config";
import "./LevelActivity.css";

function clamp01(x) {
  if (x < 0) return 0;
  if (x > 1) return 1;
  return x;
}

function Ring({ label, value, total, accentClass }) {
  const pct = total > 0 ? clamp01(value / total) : 0;
  const deg = Math.round(pct * 360);
  const pctDisplay = total > 0 ? Math.round(pct * 100) : 0;

  return (
    <div className="la-item">
      <div
        className={`la-ring ${accentClass}`}
        style={{ "--deg": `${deg}deg` }}
        title={`${label}: ${value} events (${pctDisplay}%)`}
      >
        <div className="la-center">
          <div className="la-count">{value}</div>
          <div className="la-pct">{pctDisplay}%</div>
        </div>
      </div>
      <div className="la-label">{label}</div>
    </div>
  );
}

export default function LevelActivity({ refreshTrigger }) {
  const [data, setData] = useState({ critical: 0, high: 0, medium: 0, low: 0, total: 0 });

  const url = useMemo(() => `${API_BASE_URL}/api/severity_summary?hours=24`, []);

  useEffect(() => {
    let alive = true;

    const fetchSummary = async () => {
      try {
        const res = await fetch(url);
        const json = await res.json();
        if (!alive) return;

        const counts = json?.counts ?? {};
        const critical = Number(counts.critical ?? 0);
        const high = Number(counts.high ?? 0);
        const medium = Number(counts.medium ?? 0);
        const low = Number(counts.low ?? 0);
        const computed = critical + high + medium + low;
        const total = Number.isFinite(Number(json?.total)) ? Number(json.total) : computed;

        setData({ critical, high, medium, low, total });
      } catch (e) {
        console.error("severity_summary fetch failed:", e);
      }
    };

    fetchSummary();
    const t = setInterval(fetchSummary, 15000);
    return () => { alive = false; clearInterval(t); };
  }, [url, refreshTrigger]);

  const { critical, high, medium, low, total } = data;

  return (
    <section className="la-card">
      <div className="la-title">
        Severity Activity — Last 24h &nbsp;
        <span style={{ color: "rgba(226,232,240,0.45)", fontWeight: 400, fontSize: 11 }}>
          {total} total events
        </span>
      </div>
      <div className="la-row">
        <Ring label="Critical" value={critical} total={total} accentClass="la-critical" />
        <Ring label="High" value={high} total={total} accentClass="la-high" />
        <Ring label="Medium" value={medium} total={total} accentClass="la-medium" />
        <Ring label="Low" value={low} total={total} accentClass="la-low" />
      </div>
    </section>
  );
}