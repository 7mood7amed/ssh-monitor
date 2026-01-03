# File: ssh-monitor/api_server.py
#!/usr/bin/env python3
from __future__ import annotations

import os
import re
import ipaddress
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import psycopg2
from flask import Flask, jsonify, request
from flask_cors import CORS

# === Flask App ===
app = Flask(__name__)
CORS(app)

# === PostgreSQL Connection Info ===
DB_CONFIG = {
    "dbname": os.environ.get("DB_NAME", "logdb"),
    "user": os.environ.get("DB_USER", "hero"),
    "password": os.environ.get("DB_PASS", "hero"),
    "host": os.environ.get("DB_HOST", "localhost"),
    "port": int(os.environ.get("DB_PORT", "5432")),
}

# === Agent "active" window (seconds) ===
ACTIVE_WINDOW_SECONDS = int(os.environ.get("ACTIVE_WINDOW_SECONDS", "120"))

# === Rate-based severity rules ===
RATE_WINDOW_SECONDS = int(os.environ.get("RATE_WINDOW_SECONDS", "60"))
RATE_DISTINCT_URL_THRESHOLD = int(os.environ.get("RATE_DISTINCT_URL_THRESHOLD", "30"))
RATE_TOTAL_REQ_THRESHOLD = int(os.environ.get("RATE_TOTAL_REQ_THRESHOLD", "0"))  # 0 disables req-count threshold


def get_db_connection():
    return psycopg2.connect(**DB_CONFIG)


def _safe_int(value, default, min_value=1, max_value=None):
    try:
        v = int(value)
    except (TypeError, ValueError):
        return default
    if v < min_value:
        v = min_value
    if max_value is not None and v > max_value:
        v = max_value
    return v


def _format_dt(dt: Any) -> str:
    if dt is None:
        return ""
    if isinstance(dt, datetime):
        return dt.replace(microsecond=0).isoformat(sep=" ")
    return str(dt)


def _parse_iso_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        v = value.strip().replace(" ", "T")
        dt = datetime.fromisoformat(v)
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    except ValueError:
        return None


def _utcnow_naive() -> datetime:
    return datetime.utcnow().replace(tzinfo=None, microsecond=0)


def _agent_status_from_heartbeat(last_heartbeat: Optional[datetime]) -> str:
    if not last_heartbeat:
        return "inactive"
    lh = last_heartbeat
    if lh.tzinfo is not None:
        lh = lh.astimezone(timezone.utc).replace(tzinfo=None)
    seconds = int((_utcnow_naive() - lh).total_seconds())
    return "active" if seconds <= ACTIVE_WINDOW_SECONDS else "inactive"


# =========================================================
# ROUTE 1: Fetch logs with pagination
# =========================================================
@app.route("/api/logs", methods=["GET"])
def get_logs():
    try:
        page = _safe_int(request.args.get("page"), 1, min_value=1)
        limit = _safe_int(request.args.get("limit"), 20, min_value=1, max_value=200)
        offset = (page - 1) * limit

        def classify_severity(msg: str) -> str:
            msg_l = (msg or "").lower()
            if any(k in msg_l for k in ("failed password", "authentication failure", "invalid user")):
                return "high"
            if any(k in msg_l for k in ("error", "denied", "refused", "unauthorized")):
                return "medium"
            return "low"

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM logs;")
                total = cur.fetchone()[0]

                cur.execute(
                    """
                    SELECT log_time, source, message, agent_name
                    FROM logs
                    ORDER BY log_time DESC
                    LIMIT %s OFFSET %s;
                    """,
                    (limit, offset),
                )
                rows = cur.fetchall()

        logs = [
            {
                "timestamp": _format_dt(log_time),
                "source": source,
                "message": message,
                "agent_name": agent_name,
                "severity": classify_severity(message),
            }
            for (log_time, source, message, agent_name) in rows
        ]

        total_pages = (total + limit - 1) // limit if total else 1
        return jsonify({"logs": logs, "total": total, "totalPages": total_pages, "page": page})
    except Exception as e:
        print("Error in /api/logs:", e)
        return jsonify({"error": str(e)}), 500


# =========================================================
# ROUTE 2: Agent heartbeats (computed status)
# =========================================================
@app.route("/api/agents", methods=["GET"])
def get_agents():
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT agent_name, last_heartbeat, status
                    FROM agent_status
                    ORDER BY agent_name ASC;
                    """
                )
                rows = cur.fetchall()

        agents = []
        for agent_name, last_heartbeat, stored_status in rows:
            agents.append(
                {
                    "agent_name": agent_name,
                    "last_heartbeat": _format_dt(last_heartbeat),
                    "status": _agent_status_from_heartbeat(last_heartbeat),
                    "stored_status": stored_status,
                }
            )
        return jsonify(agents)
    except Exception as e:
        print("Error in /api/agents:", e)
        return jsonify({"error": str(e)}), 500


# === ROUTE 3: Dashboard metrics ===
@app.route("/api/metrics", methods=["GET"])
def get_metrics():
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # Total logs
                cur.execute("SELECT COUNT(*) FROM logs;")
                total_logs = cur.fetchone()[0]

                # Active agents (heartbeat)
                cur.execute(
                    "SELECT COUNT(*) FROM agent_status WHERE last_heartbeat >= NOW() - INTERVAL '120 seconds';"
                )
                active_agents = cur.fetchone()[0]

                # --- SSH anomalies (existing logic) ---
                cur.execute(
                    """
                    SELECT COUNT(*) FROM logs
                    WHERE LOWER(message) LIKE '%failed password%'
                       OR LOWER(message) LIKE '%authentication failure%'
                       OR LOWER(message) LIKE '%invalid user%';
                    """
                )
                ssh_anomalies = cur.fetchone()[0]

                # --- Web anomalies (Apache access logs) ---
                like_apache = "%apache2%"
                like_access = "%access.log%"

                # Regex extractors (same idea you used elsewhere)
                status_expr = "substring(message from '\"\\\\s(\\\\d{3})\\\\s')"
                ip_expr = "substring(message from '^(\\\\S+)')"
                url_expr = "substring(message from '\"\\\\S+\\\\s+(\\\\S+)')"

                # 1) Status + suspicious-path anomalies (all-time, like your SSH anomalies)
                cur.execute(
                    f"""
                    WITH extracted AS (
                        SELECT
                            CAST(NULLIF({status_expr}, '') AS INTEGER) AS status,
                            LOWER(message) AS msg
                        FROM logs
                        WHERE source ILIKE %s AND (source ILIKE %s OR filename ILIKE %s)
                    )
                    SELECT COUNT(*)
                    FROM extracted
                    WHERE status >= 500
                       OR status IN (401, 403)
                       OR (
                            (msg LIKE '%%wp-admin%%'
                             OR msg LIKE '%%wp-login%%'
                             OR msg LIKE '%%.env%%'
                             OR msg LIKE '%%cgi-bin%%'
                             OR msg LIKE '%%phpmyadmin%%')
                            AND status >= 400
                       );
                    """,
                    (like_apache, like_access, like_access),
                )
                web_anomalies = cur.fetchone()[0]

                # 2) Rate anomalies (last 60s by default): >= 30 distinct URLs per IP
                # Configurable via env in your newer file:
                rate_window_seconds = int(os.environ.get("RATE_WINDOW_SECONDS", "60"))
                rate_distinct_threshold = int(os.environ.get("RATE_DISTINCT_URL_THRESHOLD", "30"))

                cur.execute(
                    f"""
                    WITH extracted AS (
                        SELECT
                            COALESCE({ip_expr}, '') AS ip,
                            COALESCE({url_expr}, '') AS url
                        FROM logs
                        WHERE source ILIKE %s
                          AND (source ILIKE %s OR filename ILIKE %s)
                          AND log_time >= NOW() - (%s || ' seconds')::interval
                    ),
                    scanners AS (
                        SELECT ip
                        FROM extracted
                        GROUP BY ip
                        HAVING COUNT(DISTINCT url) >= %s
                    )
                    SELECT COUNT(*)
                    FROM extracted
                    WHERE ip IN (SELECT ip FROM scanners);
                    """,
                    (like_apache, like_access, like_access, rate_window_seconds, rate_distinct_threshold),
                )
                web_rate_anomalies = cur.fetchone()[0]

        anomalies_total = int(ssh_anomalies) + int(web_anomalies) + int(web_rate_anomalies)

        return jsonify(
            {
                "totalLogs": int(total_logs),
                "activeAgents": int(active_agents),
                "anomalies": anomalies_total,             # <-- your card uses this
                "sshAnomalies": int(ssh_anomalies),       # optional breakdown
                "webAnomalies": int(web_anomalies),       # optional breakdown
                "webRateAnomalies": int(web_rate_anomalies),  # optional breakdown
                "rateWindowSeconds": rate_window_seconds,
                "rateDistinctUrlThreshold": rate_distinct_threshold,
            }
        )

    except Exception as e:
        print(f"Error fetching metrics: {e}")
        return jsonify({"error": str(e)}), 500



# =========================================================
# ROUTE 4: Log volume over time
# =========================================================
@app.route("/api/chart", methods=["GET"])
def get_chart_data():
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT DATE_TRUNC('hour', log_time) AS hour, COUNT(*)
                    FROM logs
                    WHERE log_time >= NOW() - INTERVAL '24 hours'
                    GROUP BY hour
                    ORDER BY hour DESC
                    LIMIT 24;
                    """
                )
                rows = cur.fetchall()

        data = [{"time": hour.strftime("%H:%M"), "logs": count} for (hour, count) in reversed(rows)]
        return jsonify(data)
    except Exception as e:
        print("Error fetching chart data:", e)
        return jsonify({"error": str(e)}), 500


# =========================================================
# WEB TRAFFIC: parsing + severity
# =========================================================
_APACHE_COMBINED_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<url>\S+)'
    r'(?:\s+[^"]*)?"\s+(?P<status>\d{3})\s+\S+\s+"[^"]*"\s+"(?P<ua>[^"]*)"'
)
_APACHE_COMMON_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<url>\S+)'
    r'(?:\s+[^"]*)?"\s+(?P<status>\d{3})\s+\S+'
)

# Suspicious patterns (includes phpmyadmin)
_SUSPICIOUS_URL_SNIPPETS = (
    "wp-admin",
    "wp-login",
    ".env",
    "cgi-bin",
    "phpmyadmin",  # requested
)

# Safe admin panels (treat as low if internal + successful)
_SAFE_ADMIN_PREFIXES = (
    "/phppgadmin/",
    "/phpmyadmin/",
)


def _is_private_ip(ip: str) -> bool:
    ip_s = (ip or "").strip()
    if ip_s in ("::1", "127.0.0.1"):
        return True
    try:
        return ipaddress.ip_address(ip_s).is_private
    except ValueError:
        return False


def _classify_web_severity_base(status: int, url: str, ip: str) -> str:
    """
    Practical severity:
      - HIGH: 5xx, 401/403, suspicious endpoints failing (>=400)
      - MEDIUM: other 4xx, suspicious endpoints even if 2xx/3xx, non-internal admin access
      - LOW: normal 2xx/3xx, including /phppgadmin/ and /phpmyadmin/ when internal + successful
    """
    url_l = (url or "").lower()

    if status >= 500 or status in (401, 403):
        return "high"

    if any(url_l.startswith(p) for p in _SAFE_ADMIN_PREFIXES):
        if _is_private_ip(ip) and status < 400:
            return "low"
        return "medium"

    if any(s in url_l for s in _SUSPICIOUS_URL_SNIPPETS):
        return "high" if status >= 400 else "medium"

    if status >= 400:
        return "medium"

    return "low"


def _parse_apache_access_line(line: str, fallback_time: Any) -> Optional[dict]:
    raw = (line or "").strip()
    if not raw:
        return None

    m = _APACHE_COMBINED_RE.match(raw) or _APACHE_COMMON_RE.match(raw)
    if not m:
        return None

    ip = m.group("ip")
    method = m.group("method")
    url = m.group("url")
    status = int(m.group("status"))

    ts_raw = m.group("ts")
    timestamp = _format_dt(fallback_time)
    try:
        ts = datetime.strptime(ts_raw, "%d/%b/%Y:%H:%M:%S %z")
        timestamp = ts.astimezone(timezone.utc).replace(tzinfo=None, microsecond=0).isoformat(sep=" ")
    except ValueError:
        pass

    return {
        "timestamp": timestamp,
        "ip": ip,
        "method": method,
        "url": url,
        "status": status,
        "user_agent": m.groupdict().get("ua", "") or "",
        # severity is finalized later (after rate-based analysis)
        "severity": _classify_web_severity_base(status, url, ip),
        "rate_flag": False,
        "rate_distinct_urls_60s": None,
        "rate_total_reqs_60s": None,
    }


def _web_sql_extractors():
    """
    Extract fields from Apache access-log line stored in logs.message.
    Works best for common/combined formats.
    """
    ip_expr = "substring(message from '^(\\\\S+)')"
    url_expr = "substring(message from '\"\\\\S+\\\\s+(\\\\S+)')"
    method_expr = "substring(message from '\"(\\\\S+)\\\\s')"
    status_expr = "substring(message from '\"\\\\s(\\\\d{3})\\\\s')"
    return ip_expr, url_expr, method_expr, status_expr


def _rate_stats_for_ips(conn, ips: List[str]) -> Dict[str, Dict[str, int]]:
    """
    Returns: { ip: { "total": int, "distinct_urls": int } } for last RATE_WINDOW_SECONDS.
    Uses logs.log_time + SQL extraction to avoid schema changes.
    """
    ips = [ip for ip in ips if ip]
    if not ips:
        return {}

    ip_expr, url_expr, _, _ = _web_sql_extractors()

    placeholders = ",".join(["%s"] * len(ips))
    window_start = _utcnow_naive()
    window_start = window_start.replace(microsecond=0)
    # Use DB-side NOW() for consistency; pass seconds, not python time, but keep simple:
    # We'll filter with NOW() - interval.

    sql = f"""
        WITH extracted AS (
            SELECT
                COALESCE({ip_expr}, '') AS ip,
                COALESCE({url_expr}, '') AS url
            FROM logs
            WHERE
                source ILIKE %s
                AND (source ILIKE %s OR filename ILIKE %s)
                AND log_time >= NOW() - (%s || ' seconds')::interval
                AND COALESCE({ip_expr}, '') IN ({placeholders})
        )
        SELECT
            ip,
            COUNT(*) AS total,
            COUNT(DISTINCT url) AS distinct_urls
        FROM extracted
        GROUP BY ip;
    """

    params: List[Any] = [
        "%apache2%",
        "%access.log%",
        "%access.log%",
        RATE_WINDOW_SECONDS,
        *ips,
    ]

    stats: Dict[str, Dict[str, int]] = {}
    with conn.cursor() as cur:
        cur.execute(sql, params)
        for ip, total, distinct_urls in cur.fetchall():
            stats[ip] = {"total": int(total), "distinct_urls": int(distinct_urls)}
    return stats


def _apply_rate_based_severity(items: List[dict], rate_stats: Dict[str, Dict[str, int]]) -> None:
    """
    Escalate severity to HIGH if:
      - distinct_urls in last window >= threshold, and
      - (optional) total requests >= RATE_TOTAL_REQ_THRESHOLD (if set > 0)
    """
    for it in items:
        ip = (it.get("ip") or "").strip()
        st = rate_stats.get(ip)
        if not st:
            continue

        total = st.get("total", 0)
        distinct_urls = st.get("distinct_urls", 0)

        it["rate_total_reqs_60s"] = total
        it["rate_distinct_urls_60s"] = distinct_urls

        distinct_hit = distinct_urls >= RATE_DISTINCT_URL_THRESHOLD
        total_hit = True if RATE_TOTAL_REQ_THRESHOLD <= 0 else total >= RATE_TOTAL_REQ_THRESHOLD

        if distinct_hit and total_hit:
            it["rate_flag"] = True
            it["severity"] = "high"


# =========================================================
# ROUTE 4b: Web Traffic (Apache Access Log)
# server-side filtering + sorting + date range + severity
# =========================================================
@app.route("/api/web_logs", methods=["GET"])
def get_web_logs():
    """
    Query params:
      - page, limit
      - search: matches IP or URL (best-effort SQL extraction)
      - status: exact code (e.g. 200, 404)
      - start, end: ISO datetime (filters on logs.log_time)
      - sort: timestamp|status|ip|url|method
      - order: asc|desc
    Returns:
      { logs: [...], total, totalPages, page, rateWindowSeconds, rateDistinctUrlThreshold }
    """
    try:
        page = _safe_int(request.args.get("page"), 1, min_value=1)
        limit = _safe_int(request.args.get("limit"), 50, min_value=1, max_value=200)
        offset = (page - 1) * limit

        search = (request.args.get("search") or "").strip()
        status_raw = (request.args.get("status") or "").strip()
        start_dt = _parse_iso_dt(request.args.get("start"))
        end_dt = _parse_iso_dt(request.args.get("end"))

        sort = (request.args.get("sort") or "timestamp").strip().lower()
        order = (request.args.get("order") or "desc").strip().lower()
        order_sql = "ASC" if order == "asc" else "DESC"

        like_apache = "%apache2%"
        like_access = "%access.log%"

        ip_expr, url_expr, method_expr, status_expr = _web_sql_extractors()

        where_clauses = [
            "source ILIKE %s",
            "(source ILIKE %s OR filename ILIKE %s)",
        ]
        params: List[Any] = [like_apache, like_access, like_access]

        if start_dt is not None:
            where_clauses.append("log_time >= %s")
            params.append(start_dt)
        if end_dt is not None:
            where_clauses.append("log_time <= %s")
            params.append(end_dt)

        if status_raw and status_raw.lower() != "all":
            try:
                status_int = int(status_raw)
                where_clauses.append(f"CAST(NULLIF({status_expr}, '') AS INTEGER) = %s")
                params.append(status_int)
            except ValueError:
                pass

        if search:
            like = f"%{search}%"
            where_clauses.append(
                f"(COALESCE({ip_expr}, '') ILIKE %s OR COALESCE({url_expr}, '') ILIKE %s)"
            )
            params.extend([like, like])

        where_sql = " AND ".join(where_clauses)

        sort_map = {
            "timestamp": "log_time",
            "status": f"CAST(NULLIF({status_expr}, '') AS INTEGER)",
            "ip": f"COALESCE({ip_expr}, '')",
            "url": f"COALESCE({url_expr}, '')",
            "method": f"COALESCE({method_expr}, '')",
        }
        sort_expr = sort_map.get(sort, "log_time")

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(f"SELECT COUNT(*) FROM logs WHERE {where_sql};", tuple(params))
                total = cur.fetchone()[0] or 0

                cur.execute(
                    f"""
                    SELECT log_time, message
                    FROM logs
                    WHERE {where_sql}
                    ORDER BY {sort_expr} {order_sql}, log_time DESC
                    LIMIT %s OFFSET %s;
                    """,
                    tuple(params + [limit, offset]),
                )
                rows = cur.fetchall()

            # Parse the page
            parsed_logs: List[dict] = []
            ips_on_page: List[str] = []
            for log_time, message in rows:
                item = _parse_apache_access_line(message, log_time)
                if item is not None:
                    parsed_logs.append(item)
                    ip = (item.get("ip") or "").strip()
                    if ip:
                        ips_on_page.append(ip)

            # Rate stats for IPs on this page (last RATE_WINDOW_SECONDS)
            rate_stats = _rate_stats_for_ips(conn, sorted(set(ips_on_page)))
            _apply_rate_based_severity(parsed_logs, rate_stats)

        total_pages = (total + limit - 1) // limit if total else 1
        return jsonify(
            {
                "logs": parsed_logs,
                "total": total,
                "totalPages": total_pages,
                "page": page,
                "rateWindowSeconds": RATE_WINDOW_SECONDS,
                "rateDistinctUrlThreshold": RATE_DISTINCT_URL_THRESHOLD,
                "rateTotalReqThreshold": RATE_TOTAL_REQ_THRESHOLD,
            }
        )

    except Exception as e:
        print("Error in /api/web_logs:", e)
        return jsonify({"error": str(e)}), 500


# =========================================================
# ROUTE 5: Export logs as CSV
# =========================================================
@app.route("/api/export", methods=["GET"])
def export_logs():
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT log_time, agent_name, source, message
                    FROM logs
                    ORDER BY log_time DESC;
                    """
                )
                rows = cur.fetchall()

        lines = ["timestamp,agent,source,message"]
        for log_time, agent_name, source, message in rows:
            ts = _format_dt(log_time).replace(",", " ")
            an = (agent_name or "unknown").replace(",", " ")
            src = (source or "").replace(",", " ")
            msg = (message or "").replace(",", " ").replace("\n", " ").replace("\r", " ")
            lines.append(f"{ts},{an},{src},{msg}")

        csv_data = "\n".join(lines)
        return (
            csv_data,
            200,
            {"Content-Type": "text/csv", "Content-Disposition": "attachment; filename=logs_export.csv"},
        )
    except Exception as e:
        print("Export error:", e)
        return jsonify({"error": str(e)}), 500


@app.route("/", methods=["GET"])
def home():
    return jsonify(
        {
            "message": "Raven API is running",
            "activeWindowSeconds": ACTIVE_WINDOW_SECONDS,
            "rateWindowSeconds": RATE_WINDOW_SECONDS,
            "rateDistinctUrlThreshold": RATE_DISTINCT_URL_THRESHOLD,
            "rateTotalReqThreshold": RATE_TOTAL_REQ_THRESHOLD,
            "endpoints": ["/api/logs", "/api/agents", "/api/metrics", "/api/chart", "/api/web_logs", "/api/export"],
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
