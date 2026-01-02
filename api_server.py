# =========================================
# File: ssh-monitor/api_server.py
# (FULL file - replace your current api_server.py)
# =========================================
#!/usr/bin/env python3
from flask import Flask, jsonify, request
from flask_cors import CORS
import psycopg2
import re
from datetime import datetime, timezone

app = Flask(__name__)
CORS(app)

DB_CONFIG = {
    "dbname": "logdb",
    "user": "hero",
    "password": "hero",
    "host": "localhost",
    "port": 5432,
}

ACTIVE_WINDOW_SECONDS = 120


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


def _format_dt(dt):
    if dt is None:
        return ""
    if isinstance(dt, datetime):
        return dt.replace(microsecond=0).isoformat(sep=" ")
    return str(dt)


def _parse_iso_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    # Accept: "YYYY-MM-DD", "YYYY-MM-DDTHH:MM", "YYYY-MM-DD HH:MM:SS", etc.
    try:
        v = value.strip().replace(" ", "T")
        # datetime-local sends without seconds sometimes; fromisoformat handles both.
        dt = datetime.fromisoformat(v)
        # Normalize aware -> naive UTC (DB is timestamp without tz)
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    except ValueError:
        return None


# === ROUTE 1: Fetch logs with pagination ===
@app.route("/api/logs", methods=["GET"])
def get_logs():
    try:
        page = _safe_int(request.args.get("page"), 1, min_value=1)
        limit = _safe_int(request.args.get("limit"), 20, min_value=1, max_value=200)
        offset = (page - 1) * limit

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

        def classify_severity(msg: str):
            msg = (msg or "").lower()
            if "failed password" in msg or "authentication failure" in msg or "invalid user" in msg:
                return "high"
            if "error" in msg or "denied" in msg or "refused" in msg:
                return "medium"
            return "low"

        logs = []
        for r in rows:
            logs.append(
                {
                    "timestamp": _format_dt(r[0]),
                    "source": r[1],
                    "message": r[2],
                    "agent_name": r[3],
                    "severity": classify_severity(r[2]),
                }
            )

        total_pages = (total + limit - 1) // limit if total else 1
        return jsonify({"logs": logs, "total": total, "totalPages": total_pages, "page": page})
    except Exception as e:
        print("Error in /api/logs:", e)
        return jsonify({"error": str(e)}), 500


# === ROUTE 2: Agent heartbeats ===
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
        now = datetime.utcnow().replace(tzinfo=None)

        for agent_name, last_heartbeat, stored_status in rows:
            if last_heartbeat is None:
                computed = "inactive"
            else:
                lh = last_heartbeat
                if lh.tzinfo is not None:
                    lh = lh.astimezone(timezone.utc).replace(tzinfo=None)
                seconds = int((now - lh).total_seconds())
                computed = "active" if seconds <= ACTIVE_WINDOW_SECONDS else "inactive"

            agents.append(
                {
                    "agent_name": agent_name,
                    "last_heartbeat": _format_dt(last_heartbeat),
                    "status": computed,
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
                cur.execute("SELECT COUNT(*) FROM logs;")
                total_logs = cur.fetchone()[0]

                cur.execute(
                    "SELECT COUNT(*) FROM agent_status WHERE last_heartbeat >= NOW() - INTERVAL '120 seconds';"
                )
                active_agents = cur.fetchone()[0]

                cur.execute(
                    """
                    SELECT COUNT(*) FROM logs
                    WHERE LOWER(message) LIKE '%failed password%'
                       OR LOWER(message) LIKE '%authentication failure%'
                       OR LOWER(message) LIKE '%invalid user%';
                    """
                )
                anomalies = cur.fetchone()[0]

        return jsonify({"totalLogs": total_logs, "activeAgents": active_agents, "anomalies": anomalies})
    except Exception as e:
        print("Error fetching metrics:", e)
        return jsonify({"error": str(e)}), 500


# === ROUTE 4: Log volume over time ===
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

        data = [{"time": r[0].strftime("%H:%M"), "logs": r[1]} for r in reversed(rows)]
        return jsonify(data)
    except Exception as e:
        print("Error fetching chart data:", e)
        return jsonify({"error": str(e)}), 500


# === ROUTE 4b: Web Traffic (Apache Access Log) ===
_APACHE_COMBINED_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<url>\S+)'
    r'(?:\s+[^"]*)?"\s+(?P<status>\d{3})\s+\S+\s+"[^"]*"\s+"(?P<ua>[^"]*)"'
)
_APACHE_COMMON_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<url>\S+)'
    r'(?:\s+[^"]*)?"\s+(?P<status>\d{3})\s+\S+'
)


def _parse_apache_access_line(line: str, fallback_time) -> dict | None:
    raw = (line or "").strip()
    if not raw:
        return None

    m = _APACHE_COMBINED_RE.match(raw) or _APACHE_COMMON_RE.match(raw)
    if not m:
        return None

    ts_raw = m.group("ts")  # 10/Oct/2000:13:55:36 -0700
    timestamp = _format_dt(fallback_time)
    try:
        ts = datetime.strptime(ts_raw, "%d/%b/%Y:%H:%M:%S %z")
        timestamp = ts.astimezone(timezone.utc).replace(tzinfo=None, microsecond=0).isoformat(sep=" ")
    except ValueError:
        pass

    return {
        "timestamp": timestamp,
        "ip": m.group("ip"),
        "method": m.group("method"),
        "url": m.group("url"),
        "status": int(m.group("status")),
        "user_agent": m.groupdict().get("ua", "") or "",
    }


def _web_sql_extractors():
    # Extract fields from Apache access-log line stored in logs.message (best-effort).
    ip_expr = "substring(message from '^(\\\\S+)')"
    url_expr = "substring(message from '\"\\\\S+\\\\s+(\\\\S+)')"
    method_expr = "substring(message from '\"(\\\\S+)\\\\s')"
    status_expr = "substring(message from '\"\\\\s(\\\\d{3})\\\\s')"
    return ip_expr, url_expr, method_expr, status_expr


@app.route("/api/web_logs", methods=["GET"])
def get_web_logs():
    """
    Supports server-side filtering + sorting:
      - search: matches IP or URL (extracted) (ILIKE)
      - status: 200/301/302/403/404/500
      - start/end: ISO datetime (filters on log_time)
      - sort: timestamp|status|ip|url|method
      - order: asc|desc
      - page/limit: pagination
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
        params = [like_apache, like_access, like_access]

        # Date range filters (use DB log_time)
        if start_dt is not None:
            where_clauses.append("log_time >= %s")
            params.append(start_dt)
        if end_dt is not None:
            where_clauses.append("log_time <= %s")
            params.append(end_dt)

        # Status filter (extract status from message; cast safely)
        if status_raw and status_raw.lower() != "all":
            try:
                status_int = int(status_raw)
                where_clauses.append(f"CAST(NULLIF({status_expr}, '') AS INTEGER) = %s")
                params.append(status_int)
            except ValueError:
                pass

        # Search filter (match extracted ip or url)
        if search:
            like = f"%{search}%"
            where_clauses.append(
                f"(COALESCE({ip_expr}, '') ILIKE %s OR COALESCE({url_expr}, '') ILIKE %s)"
            )
            params.extend([like, like])

        where_sql = " AND ".join(where_clauses)

        # Whitelisted sort keys (prevents SQL injection)
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

        parsed_logs = []
        for log_time, message in rows:
            item = _parse_apache_access_line(message, log_time)
            if item is not None:
                parsed_logs.append(item)

        total_pages = (total + limit - 1) // limit if total else 1
        return jsonify(
            {
                "logs": parsed_logs,
                "total": total,
                "totalPages": total_pages,
                "page": page,
                "filters": {
                    "search": search,
                    "status": status_raw,
                    "start": _format_dt(start_dt),
                    "end": _format_dt(end_dt),
                    "sort": sort,
                    "order": order_sql.lower(),
                },
            }
        )
    except Exception as e:
        print("Error in /api/web_logs:", e)
        return jsonify({"error": str(e)}), 500


# === ROUTE 5: Export logs as CSV ===
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
        for r in rows:
            ts = _format_dt(r[0]).replace(",", " ")
            agent = (r[1] or "unknown").replace(",", " ")
            source = (r[2] or "").replace(",", " ")
            message = (r[3] or "").replace(",", " ").replace("\n", " ").replace("\r", " ")
            lines.append(f"{ts},{agent},{source},{message}")

        csv_data = "\n".join(lines)
        return (
            csv_data,
            200,
            {
                "Content-Type": "text/csv",
                "Content-Disposition": "attachment; filename=logs_export.csv",
            },
        )
    except Exception as e:
        print("Export error:", e)
        return jsonify({"error": str(e)}), 500


@app.route("/", methods=["GET"])
def home():
    return jsonify(
        {"message": "Raven API is running", "endpoints": ["/api/logs", "/api/agents", "/api/metrics", "/api/chart", "/api/web_logs"]}
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)