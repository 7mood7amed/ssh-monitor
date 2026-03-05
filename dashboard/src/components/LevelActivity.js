// LevelActivity.js
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

  // Conic ring fill using CSS var (--deg) in degrees
  const deg = Math.round(pct * 360);

  return (
    <div className="la-item">
      <div
        className={`la-ring ${accentClass}`}
        style={{ ["--deg"]: `${deg}deg` }}
        aria-label={`${label} ${value} of ${total}`}
        title={`${label}: ${value}/${total}`}
      >
        <div className="la-center">
          <div className="la-value">
            {value}/{total}
          </div>
        </div>
      </div>
      <div className="la-label">{label}</div>
    </div>
  );
}

export default function LevelActivity({ refreshTrigger }) {
  const [data, setData] = useState({
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    total: 0,
  });

  const url = useMemo(() => `${API_BASE_URL}/api/severity_summary?hours=24`, []);

  useEffect(() => {
    let alive = true;

    const fetchSummary = async () => {
      try {
        const res = await fetch(url);
        const json = await res.json();
        if (!alive) return;

        // API shape is:
        // { counts: { critical, high, medium, low }, total, window }
        const counts = json?.counts ?? {};

        const critical = Number(counts.critical ?? 0);
        const high = Number(counts.high ?? 0);
        const medium = Number(counts.medium ?? 0);
        const low = Number(counts.low ?? 0);

        // Prefer json.total, but fall back to computed total if missing/bad
        const computedTotal = critical + high + medium + low;
        const total =
          Number.isFinite(Number(json?.total)) && Number(json?.total) >= 0
            ? Number(json.total)
            : computedTotal;

        setData({ critical, high, medium, low, total });
      } catch (e) {
        // keep old values if request fails
        console.error("severity_summary fetch failed:", e);
      }
    };

    fetchSummary();
    const t = setInterval(fetchSummary, 10000); // refresh every 10s
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [url, refreshTrigger]);

  const { critical, high, medium, low, total } = data;

  return (
    <section className="la-card">
      <div className="la-title">Level Activity</div>

      <div className="la-row">
        <Ring label="Critical" value={critical} total={total} accentClass="la-critical" />
        <Ring label="High" value={high} total={total} accentClass="la-high" />
        <Ring label="Medium" value={medium} total={total} accentClass="la-medium" />
        <Ring label="Low" value={low} total={total} accentClass="la-low" />
      </div>
    </section>
  );
}