
#!/usr/bin/env python3
# =========================================
# File: ssh-monitor/api_server.py
# Enforces "allowed sources only" across all endpoints
# Allowed sources: auth.log*, apache2/access.log*, apache2/error.log*, vsftpd.log
# + Adds /api/ftp_logs endpoint for FTP view
#
# =========================================

from __future__ import annotations
from ai_engine import analyze_recent_activity
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
import ipaddress
import psycopg2
import psycopg2.extras
from flask import Flask, jsonify, request, Response
from flask_cors import CORS
import csv
import io
from functools import lru_cache

# -----------------------------
# Flask
# -----------------------------

app = Flask(__name__)
CORS(app)

# -----------------------------
# DB config
# -----------------------------

DB_CONFIG = {
    "dbname": os.environ.get("DB_NAME", "logdb"),
    "user": os.environ.get("DB_USER", "hero"),
    "password": os.environ.get("DB_PASS", "hero"),
    "host": os.environ.get("DB_HOST", "localhost"),
    "port": int(os.environ.get("DB_PORT", "5432")),
}


def get_db_connection():
    return psycopg2.connect(**DB_CONFIG)


# -----------------------------
# Allowed sources (Task 8 safety)
# -----------------------------
# We only expose rows from these sources.
ALLOWED_AUTH_PREFIX = "/var/log/auth.log"
ALLOWED_APACHE_ACCESS_PREFIX = "/var/log/apache2/access.log"
ALLOWED_APACHE_ERROR_PREFIX = "/var/log/apache2/error.log"
ALLOWED_VSFTPD_PREFIX = "/var/log/vsftpd.log"


def allowed_logs_where_sql(alias: str = "l") -> str:
    col = f"{alias}.source"
    return f"""(
        {col} LIKE %s OR
        {col} LIKE %s OR
        {col} LIKE %s OR
        {col} LIKE %s OR
        {col} = '/usr/bin/tshark'
    )"""


def allowed_logs_where_params() -> Tuple[str, str, str, str]:
    return (
        f"{ALLOWED_AUTH_PREFIX}%",
        f"{ALLOWED_APACHE_ACCESS_PREFIX}%",
        f"{ALLOWED_APACHE_ERROR_PREFIX}%",
        f"{ALLOWED_VSFTPD_PREFIX}%",
    )


# -----------------------------
# Small helpers
# -----------------------------

def _safe_int(value, default: int, min_value: int = 1, max_value: Optional[int] = None) -> int:
    try:
        v = int(value)
    except (TypeError, ValueError):
        return default
    if v < min_value:
        v = min_value
    if max_value is not None and v > max_value:
        v = max_value
    return v


def _parse_dt_param(s: Optional[str]) -> Optional[datetime]:
    """
    Accepts:
      - 'YYYY-MM-DD'
      - 'YYYY-MM-DD HH:MM:SS'
      - ISO-ish
    Returns naive datetime (server local).
    """
    if not s:
        return None
    s = s.strip()
    if not s:
        return None
    for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            pass
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    except Exception:
        return None


def _format_dt(dt: Any) -> str:
    if dt is None:
        return ""
    if isinstance(dt, datetime):
        return dt.replace(microsecond=0).isoformat(sep=" ")
    return str(dt)


def _apply_time_range(where: List[str], params: List[Any], col: str, dt_from: Optional[datetime], dt_to: Optional[datetime]) -> None:
    if dt_from is not None:
        where.append(f"{col} >= %s")
        params.append(dt_from)
    if dt_to is not None:
        where.append(f"{col} <= %s")
        params.append(dt_to)


# -----------------------------
# Schema helpers (backward compatibility)
# -----------------------------

@lru_cache(maxsize=128)
def table_has_column(table: str, column: str) -> bool:
    """
    Returns True if public.<table> has <column>.
    Cached to avoid repeated information_schema hits.
    """
    try:
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT 1
                    FROM information_schema.columns
                    WHERE table_schema = 'public'
                      AND table_name = %s
                      AND column_name = %s
                    LIMIT 1;
                    """,
                    (table, column),
                )
                return cur.fetchone() is not None
        finally:
            conn.close()
    except Exception:
        return False


def normalize_sev_param(raw: str) -> Optional[str]:
    """
    Accepts: low/medium/high/critical or LOW/MEDIUM/HIGH/CRITICAL or 'all'
    Returns uppercase severity or None.
    """
    if not raw:
        return None
    s = raw.strip().upper()
    if not s or s == "ALL":
        return None
    if s in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        return s
    return None


# -----------------------------
# Severity summary (LOG-based)
# -----------------------------

_INTERNAL_NETS = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
]

_SENSITIVE_PORTS = {
    21,   # ftp
    22,   # ssh
    23,   # telnet
    25,   # smtp
    53,   # dns
    80,   # http
    110,  # pop3
    139,  # smb
    143,  # imap
    443,  # https
    445,  # smb
    3306, # mysql
    3389, # rdp
    5432, # postgres
    6379, # redis
    9200, # elastic
    27017 # mongo
}

_DB_PORTS = {3306, 5432, 6379, 9200, 27017}

def _is_internal_ip_quick(ip: str) -> bool:
    if not ip:
        return False

    ip = str(ip).strip()

    return ip in {"192.168.56.104", "127.0.0.1", "::1"}

def compute_ssh_severity(event_type: str, outcome: str) -> str:
    et = (event_type or "").lower()
    oc = (outcome or "").lower()

    # brute attempts show up as login_fail
    if et == "login_fail" or oc == "fail":
        return "high"

    # successful login is usually low unless you want "medium" for external later
    if et == "login_success" or oc == "success":
        return "low"

    # disconnect/session/info
    return "low"

def compute_ftp_severity(action: str) -> str:
    a = (action or "").upper()

    if a == "LOGIN_FAIL":
        return "high"

    # destructive actions -> medium
    if a in {"DELETE", "RMDIR", "RENAME"}:
        return "medium"

    # normal ops
    if a in {"UPLOAD", "DOWNLOAD", "LOGIN_SUCCESS", "MKDIR"}:
        return "low"

    return "low"

def compute_nmap_severity(host: str, port: int, state: str, service: str) -> str:
    st = (state or "").lower()
    svc = (service or "").lower()
    internal = _is_internal_ip_quick(host)

    # if not open -> low (closed/filtered)
    if st != "open":
        return "low"

    # external open ports are more serious
    if not internal:
        if port in _DB_PORTS:
            return "critical"      # external DB open = very bad
        if port in _SENSITIVE_PORTS or svc in {"ssh", "ftp", "mysql", "postgresql", "redis", "mongodb"}:
            return "high"
        return "medium"

    # internal (lab) open ports: still can be risky, but lower than external
    if port in _DB_PORTS:
        return "high"
    if port in {21, 22, 3389}:
        return "high"
    if port in {80, 443, 8080, 8443}:
        return "medium"

    return "low"


# -----------------------------
# NMAP severity helpers (smart)
# -----------------------------

_INTERNAL_NETS_NMAP = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "::1/128",
    "fc00::/7",   # unique local IPv6
    "fe80::/10",  # link-local IPv6
]

def _is_internal_ip_nmap(ip: str) -> bool:
    if not ip:
        return False

    ip = str(ip).strip()

    return ip in {"192.168.56.104", "127.0.0.1", "::1"}

def compute_nmap_severity(host: str, state: str, service: str, port: int) -> str:
    """
    Smart Nmap severity:
      - Only open ports matter
      - External exposure boosts severity
      - Internal exposure reduces severity one level
    """
    st = (state or "").lower()
    svc = (service or "").lower()
    p = int(port or 0)

    if st != "open":
        return "low"

    internal = _is_internal_ip_nmap(host)

    # Base severity by port/service
    base = "low"

    # Critical exposure ports
    critical_ports = {21, 22, 23, 3389, 445, 139, 3306, 5432, 6379, 27017}
    high_services = {"ftp", "telnet", "rdp", "smb", "snmp"}

    if p in critical_ports:
        base = "critical"
    elif svc in high_services:
        base = "high"
    elif p not in {80, 443, 53, 8080, 8443}:
        base = "medium"
    else:
        base = "low"

    # Adjust by internal/external:
    # - external: keep as-is
    # - internal: drop one level (critical->high, high->medium, medium->low)
    if internal:
        if base == "critical":
            return "high"
        if base == "high":
            return "medium"
        if base == "medium":
            return "low"
        return "low"

    return base


# -----------------------------
# Apache parsing (access.log)
# -----------------------------

_APACHE_COMBINED_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<url>\S+)'
    r'(?:\s+[^"]*)?"\s+(?P<status>\d{3})\s+\S+\s+"[^"]*"\s+"(?P<ua>[^"]*)"'
)
_APACHE_COMMON_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<url>\S+)'
    r'(?:\s+[^"]*)?"\s+(?P<status>\d{3})\s+\S+'
)


def _parse_apache_time(ts_raw: str) -> Optional[datetime]:
    try:
        ts = datetime.strptime(ts_raw, "%d/%b/%Y:%H:%M:%S %z")
        return ts.astimezone(timezone.utc).replace(tzinfo=None, microsecond=0)
    except Exception:
        return None


def _parse_apache_access_line(line: str, fallback_time: Optional[datetime]) -> Optional[dict]:
    raw = (line or "").replace("\x00", "").strip()
    if not raw:
        return None

    m = _APACHE_COMBINED_RE.match(raw) or _APACHE_COMMON_RE.match(raw)
    if not m:
        return None

    ts = fallback_time
    ts_raw = m.group("ts")
    parsed = _parse_apache_time(ts_raw)
    if parsed is not None:
        ts = parsed

    ua = m.groupdict().get("ua", "") or ""
    return {
        "timestamp": _format_dt(ts),
        "ip": m.group("ip"),
        "method": m.group("method"),
        "url": m.group("url"),
        "status": int(m.group("status")),
        "user_agent": ua,
        "raw": raw,
    }


# -----------------------------
# API: agents
# -----------------------------

@app.route("/api/agents", methods=["GET"])
def get_agents():
    """
    Returns collector agents:
      SSH / FTP / APACHE / NMAP / TSHARK
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        allowed_agents = ["SSH", "FTP", "APACHE", "NMAP", "TSHARK"]

        cur.execute(
            """
            SELECT agent_name, last_heartbeat
            FROM public.agent_status
            WHERE agent_name = ANY(%s)
            ORDER BY agent_name;
            """,
            (allowed_agents,),
        )

        rows = cur.fetchall()
        cur.close()
        conn.close()

        now = datetime.utcnow()

        def compute_status(agent: str, last_hb: Optional[datetime]) -> str:
            if not last_hb:
                return "inactive"

            age = now - last_hb

            if agent == "NMAP":
                if age <= timedelta(minutes=15):
                    return "active"
                if age <= timedelta(minutes=60):
                    return "warning"
                return "inactive"

            if agent == "TSHARK":
                if age <= timedelta(minutes=2):
                    return "active"
                if age <= timedelta(minutes=5):
                    return "warning"
                return "inactive"

            if age <= timedelta(minutes=5):
                return "active"
            if age <= timedelta(minutes=15):
                return "warning"
            return "inactive"

        agents = []
        for r in rows:
            agent = r["agent_name"]
            hb = r["last_heartbeat"]
            agents.append(
                {
                    "agent_name": agent,
                    "last_heartbeat": _format_dt(hb),
                    "status": compute_status(agent, hb),
                }
            )

        return jsonify(agents)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -----------------------------
# API: metrics (allowed logs only)
# -----------------------------

@app.route("/api/metrics", methods=["GET"])
def get_metrics():
    """
    totalLogs: count of allowed-source rows in public.logs
    activeAgents: heartbeat in last 120 seconds
    anomalies: ssh login_fail + web suspicious status in last 24h
    passiveScans: tshark scan alerts
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        allowed_where = allowed_logs_where_sql("l")
        allowed_params = list(allowed_logs_where_params())

        cur.execute(
            f"""
            SELECT COUNT(*)
            FROM public.logs l
            WHERE {allowed_where};
            """,
            allowed_params,
        )
        total_logs = cur.fetchone()[0] or 0

        cur.execute(
            """
            SELECT
            SUM(
                CASE
                WHEN agent_name = 'NMAP'
                    AND last_heartbeat >= NOW() - INTERVAL '15 minutes'
                THEN 1
                WHEN agent_name = 'TSHARK'
                    AND last_heartbeat >= NOW() - INTERVAL '2 minutes'
                THEN 1
                WHEN agent_name NOT IN ('NMAP', 'TSHARK')
                    AND last_heartbeat >= NOW() - INTERVAL '5 minutes'
                THEN 1
                ELSE 0
                END
            )
            FROM public.agent_status
            WHERE agent_name IN ('SSH', 'FTP', 'APACHE', 'NMAP', 'TSHARK');
            """
        )
        active_agents = cur.fetchone()[0] or 0

        cur.execute(
            """
            SELECT COUNT(*)
            FROM public.ssh_events
            WHERE event_time >= NOW() - INTERVAL '24 hours'
              AND event_type = 'login_fail';
            """
        )
        ssh_anom = cur.fetchone()[0] or 0

        cur.execute(
            f"""
            SELECT COUNT(*)
            FROM public.logs l
            WHERE {allowed_where}
              AND l.source LIKE %s
              AND (
                l.message ~* '\"\\s+(401|403|404|429|5\\d\\d)\\s+'
                OR l.message ILIKE %s
            OR l.message ILIKE %s
            OR l.message ILIKE %s
            OR l.message ILIKE %s
            OR l.message ILIKE %s
              )
              AND l.log_time >= NOW() - INTERVAL '24 hours';
            """,
            allowed_params + [
                f"{ALLOWED_APACHE_ACCESS_PREFIX}%",
                "%/admin%",
                "%/login%",
                "%/phpmyadmin%",
                "%/phppgadmin%",
                "%/.env%",
            ],
        )
        web_anom = cur.fetchone()[0] or 0

        cur.execute(
            """
            SELECT COUNT(*)
            FROM public.alerts
            WHERE source = 'tshark'
              AND created_at >= NOW() - INTERVAL '24 hours';
            """
        )
        passive_scans = cur.fetchone()[0] or 0

        anomalies = int(ssh_anom) + int(web_anom) + int(passive_scans)

        cur.close()
        conn.close()

        return jsonify(
            {
                "totalLogs": int(total_logs),
                "activeAgents": int(active_agents),
                "anomalies": int(anomalies),
                "passiveScans": int(passive_scans),
            }
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -----------------------------
# API: chart (allowed logs only)
# -----------------------------

@app.route("/api/chart", methods=["GET"])
def get_chart_data():
    """
    Log volume per hour (last 24 hours), allowed sources only.
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        allowed_where = allowed_logs_where_sql("l")
        allowed_params = list(allowed_logs_where_params())

        cur.execute(
            f"""
            SELECT DATE_TRUNC('hour', l.log_time) AS hour, COUNT(*)
            FROM public.logs l
            WHERE l.log_time >= NOW() - INTERVAL '24 hours'
              AND {allowed_where}
            GROUP BY hour
            ORDER BY hour DESC
            LIMIT 24;
            """,
            allowed_params,
        )
        rows = cur.fetchall()

        cur.close()
        conn.close()

        data = [{"time": r[0].strftime("%H:%M"), "logs": int(r[1])} for r in reversed(rows)]
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -----------------------------
# API: SSH raw logs page (auth.log only)
# -----------------------------

@app.route("/api/logs", methods=["GET"])
def get_logs():
    """
    Logs endpoint.

    Default:
    - Shows SSH/auth logs only.

    With agent_name:
    - Shows logs for that specific agent, including TSHARK.
    """
    try:
        page = _safe_int(request.args.get("page"), 1, min_value=1)
        limit = _safe_int(request.args.get("limit"), 20, min_value=1, max_value=200)
        offset = (page - 1) * limit

        q = (request.args.get("q") or "").strip()
        source_filter = (request.args.get("source") or "").strip()
        agent_filter = (request.args.get("agent_name") or "").strip().upper()
        sev_param = normalize_sev_param(request.args.get("severity") or "")
        dt_from = _parse_dt_param(request.args.get("from"))
        dt_to = _parse_dt_param(request.args.get("to"))

        sort = (request.args.get("sort") or "log_time").strip().lower()
        order = (request.args.get("order") or "desc").strip().lower()

        if sort not in {"log_time", "source"}:
            sort = "log_time"
        if order not in {"asc", "desc"}:
            order = "desc"

        # Important:
        # If agent_name is provided, do NOT use allowed_logs_where_sql(),
        # because it excludes TSHARK source /usr/bin/tshark.
        if agent_filter:
            where = ["UPPER(l.agent_name) = %s"]
            params: List[Any] = [agent_filter]
        else:
            where = [allowed_logs_where_sql("l"), "l.source LIKE %s"]
            params: List[Any] = list(allowed_logs_where_params()) + [f"{ALLOWED_AUTH_PREFIX}%"]

        if q:
            where.append("(l.message ILIKE %s OR l.source ILIKE %s OR l.agent_name ILIKE %s)")
            params.extend([f"%{q}%", f"%{q}%", f"%{q}%"])

        if source_filter:
            where.append("l.source ILIKE %s")
            params.append(f"%{source_filter}%")

        if sev_param:
            where.append("COALESCE(l.severity,'LOW') = %s")
            params.append(sev_param)

        _apply_time_range(where, params, "l.log_time", dt_from, dt_to)

        where_sql = " AND ".join(where)

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute(
            f"""
            SELECT COUNT(*)
            FROM public.logs l
            WHERE {where_sql};
            """,
            params,
        )
        total = int(cur.fetchone()[0] or 0)

        cur.execute(
            f"""
            SELECT
                l.log_time,
                l.source,
                l.message,
                l.agent_name,
                COALESCE(l.severity,'LOW') AS severity
            FROM public.logs l
            WHERE {where_sql}
            ORDER BY l.{sort} {order}
            LIMIT %s OFFSET %s;
            """,
            params + [limit, offset],
        )

        rows = cur.fetchall()

        cur.close()
        conn.close()

        logs = [
            {
                "timestamp": _format_dt(r[0]),
                "source": r[1],
                "message": r[2],
                "agent_name": r[3],
                "severity": (r[4] or "LOW"),
            }
            for r in rows
        ]

        total_pages = (total + limit - 1) // limit if total else 1

        return jsonify({
            "logs": logs,
            "total": total,
            "totalPages": total_pages,
            "page": page
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# -----------------------------
# API: SSH structured events
# -----------------------------

@app.route("/api/ssh_events", methods=["GET"])
def get_ssh_events():
    try:
        page = _safe_int(request.args.get("page"), 1, min_value=1)
        limit = _safe_int(request.args.get("limit"), 20, min_value=1, max_value=200)
        offset = (page - 1) * limit

        q = (request.args.get("q") or "").strip()
        user = (request.args.get("user") or "").strip()
        ip = (request.args.get("ip") or "").strip()
        event = (request.args.get("event") or "").strip()
        outcome = (request.args.get("outcome") or "").strip()
        sev_param = normalize_sev_param(request.args.get("severity") or "")

        dt_from = _parse_dt_param(request.args.get("from"))
        dt_to = _parse_dt_param(request.args.get("to"))

        sort = (request.args.get("sort") or "event_time").strip().lower()
        order = (request.args.get("order") or "desc").strip().lower()
        allowed_sorts = {"event_time", "username", "ip", "event_type", "outcome"}
        if sort not in allowed_sorts:
            sort = "event_time"
        if order not in {"asc", "desc"}:
            order = "desc"

        where = ["1=1"]
        params: List[Any] = []

        if q:
            where.append(
                """
              (
                COALESCE(raw,'') ILIKE %s OR
                COALESCE(username,'') ILIKE %s OR
                COALESCE(ip,'') ILIKE %s
              )
            """
            )
            params.extend([f"%{q}%"] * 3)

        if user:
            where.append("username ILIKE %s")
            params.append(f"%{user}%")

        if ip:
            where.append("ip = %s")
            params.append(ip)

        if event and event.lower() != "all":
            where.append("event_type = %s")
            params.append(event)

        if outcome and outcome.lower() != "all":
            where.append("outcome = %s")
            params.append(outcome)

        _apply_time_range(where, params, "event_time", dt_from, dt_to)

        has_sev = table_has_column("ssh_events", "severity")
        if has_sev and sev_param:
            where.append("COALESCE(severity,'LOW') = %s")
            params.append(sev_param)

        where_sql = " AND ".join(where)

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute(f"SELECT COUNT(*) FROM public.ssh_events WHERE {where_sql};", params)
        total = int(cur.fetchone()[0] or 0)

        if has_sev:
            select_sql = f"""
                SELECT
                    id,
                    event_time,
                    username,
                    ip,
                    event_type,
                    outcome,
                    auth_method,
                    raw,
                    COALESCE(severity,'LOW') AS severity
                FROM public.ssh_events
                WHERE {where_sql}
                ORDER BY {sort} {order}
                LIMIT %s OFFSET %s;
            """
        else:
            select_sql = f"""
                SELECT
                    id,
                    event_time,
                    username,
                    ip,
                    event_type,
                    outcome,
                    auth_method,
                    raw
                FROM public.ssh_events
                WHERE {where_sql}
                ORDER BY {sort} {order}
                LIMIT %s OFFSET %s;
            """

        cur.execute(select_sql, params + [limit, offset])
        rows = cur.fetchall()

        cur.close()
        conn.close()

        events = []
        for r in rows:
            if has_sev:
                (rid, et, un, ip_, etype, outc, method, raw, sev) = r
            else:
                (rid, et, un, ip_, etype, outc, method, raw) = r
                sev = None

            events.append(
                {
                    "id": rid,
                    "timestamp": _format_dt(et),
                    "username": un,
                    "ip": ip_,
                    "event_type": etype,
                    "outcome": outc,
                    "auth_method": method,
                    "message": raw,
                    **({"severity": sev} if sev else {}),
                }
            )

        total_pages = (total + limit - 1) // limit if total else 1
        return jsonify({"events": events, "total": total, "totalPages": total_pages, "page": page})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -----------------------------
# API: Web traffic (apache access only)
# -----------------------------

@app.route("/api/web_logs", methods=["GET"])
def get_web_logs():
    """
    Reads from public.logs but ONLY apache access.log.
    Now returns DB-backed severity (l.severity) and supports SQL severity filter.
    """
    try:
        page = _safe_int(request.args.get("page"), 1, min_value=1)
        limit = _safe_int(request.args.get("limit"), 50, min_value=1, max_value=200)
        offset = (page - 1) * limit

        q = (request.args.get("q") or "").strip()
        status = (request.args.get("status") or "").strip()
        sev_param = normalize_sev_param(request.args.get("severity") or "")

        dt_from = _parse_dt_param(request.args.get("from"))
        dt_to = _parse_dt_param(request.args.get("to"))

        sort = (request.args.get("sort") or "log_time").strip().lower()
        order = (request.args.get("order") or "desc").strip().lower()
        if sort not in {"log_time"}:
            sort = "log_time"
        if order not in {"asc", "desc"}:
            order = "desc"

        where = [allowed_logs_where_sql("l"), "l.source LIKE %s"]
        params: List[Any] = list(allowed_logs_where_params()) + [f"{ALLOWED_APACHE_ACCESS_PREFIX}%"]

        if q:
            where.append("l.message ILIKE %s")
            params.append(f"%{q}%")

        if status and status.isdigit():
            where.append("l.message ~ %s")
            params.append(rf'"\s+{status}\s+')

        if sev_param:
            where.append("COALESCE(l.severity,'LOW') = %s")
            params.append(sev_param)

        _apply_time_range(where, params, "l.log_time", dt_from, dt_to)
        where_sql = " AND ".join(where)

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute(
            f"""
            SELECT COUNT(*)
            FROM public.logs l
            WHERE {where_sql};
            """,
            params,
        )
        total = int(cur.fetchone()[0] or 0)

        cur.execute(
            f"""
            SELECT l.log_time, l.message, COALESCE(l.severity,'LOW') AS severity
            FROM public.logs l
            WHERE {where_sql}
            ORDER BY l.{sort} {order}
            LIMIT %s OFFSET %s;
            """,
            params + [limit, offset],
        )
        rows = cur.fetchall()

        cur.close()
        conn.close()

        parsed_logs: List[dict] = []
        for log_time, message, severity in rows:
            item = _parse_apache_access_line(message, log_time)
            if item is None:
                continue
            item["severity"] = severity
            parsed_logs.append(item)

        total_pages = (total + limit - 1) // limit if total else 1
        return jsonify({"logs": parsed_logs, "total": total, "totalPages": total_pages, "page": page})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -----------------------------
# FTP severity helper
# -----------------------------

def compute_ftp_severity(action: str) -> str:
    """
    FTP severity rules (simple + useful):
      - CRITICAL: destructive directory removal
      - HIGH: login failures + deletes
      - MEDIUM: rename/mkdir (changes)
      - LOW: everything else
    """
    a = (action or "").strip().upper()

    if a == "RMDIR":
        return "critical"
    if a in {"LOGIN_FAIL"}:
        return "medium"
    if a in {"RENAME", "DELETE"}:
        return "medium"
    return "low"


# -----------------------------
# API: FTP logs (vsftpd.log only)
# -----------------------------

@app.route("/api/ftp_logs", methods=["GET"])
def get_ftp_logs():
    """
    Reads from public.ftp_events (structured).
    Server-side pagination + filters.

    Query params:
      page, limit
      q (search raw/file_target/username/ip)
      username
      ip
      action
      severity (low|medium|high|critical)
      from, to   (event_time)
      sort (event_time|username|ip|action) order (asc|desc)

    Returns:
      { logs: [{timestamp,user,ip,action,file_target,raw,severity}], total, totalPages, page }
    """
    try:
        # Enforce allowed FTP actions only (hide noisy "OTHER" etc.)
        ALLOWED_FTP_ACTIONS = [
            "LOGIN_SUCCESS",
            "LOGIN_FAIL",
            "UPLOAD",
            "DOWNLOAD",
            "DELETE",
            "RENAME",
            "MKDIR",
            "RMDIR",
        ]

        page = _safe_int(request.args.get("page"), 1, min_value=1)
        limit = _safe_int(request.args.get("limit"), 50, min_value=1, max_value=200)
        offset = (page - 1) * limit

        q = (request.args.get("q") or "").strip()
        username = (request.args.get("username") or "").strip()
        ip = (request.args.get("ip") or "").strip()
        action = (request.args.get("action") or "").strip().upper()
        severity = (request.args.get("severity") or "").strip().lower()

        dt_from = _parse_dt_param(request.args.get("from"))
        dt_to = _parse_dt_param(request.args.get("to"))

        sort = (request.args.get("sort") or "event_time").strip().lower()
        order = (request.args.get("order") or "desc").strip().lower()
        if sort not in {"event_time", "username", "ip", "action"}:
            sort = "event_time"
        if order not in {"asc", "desc"}:
            order = "desc"

        # ALWAYS restrict to allowed actions (so "OTHER" never appears)
        where = ["action = ANY(%s)"]
        params: List[Any] = [ALLOWED_FTP_ACTIONS]

        if q:
            where.append("""
              (
                COALESCE(raw,'') ILIKE %s OR
                COALESCE(file_target,'') ILIKE %s OR
                COALESCE(username,'') ILIKE %s OR
                COALESCE(ip,'') ILIKE %s
              )
            """)
            params.extend([f"%{q}%"] * 4)

        if username:
            where.append("username ILIKE %s")
            params.append(f"%{username}%")

        if ip:
            where.append("ip = %s")
            params.append(ip)

        if action and action != "ALL":
            where.append("action = %s")
            params.append(action)

        _apply_time_range(where, params, "event_time", dt_from, dt_to)

        where_sql = " AND ".join(where)

        conn = get_db_connection()
        cur = conn.cursor()

        # total (DB total without severity filter applied yet)
        cur.execute(
            f"SELECT COUNT(*) FROM public.ftp_events WHERE {where_sql};",
            params,
        )
        total_db = int(cur.fetchone()[0] or 0)

        # page rows
        cur.execute(
            f"""
            SELECT event_time, username, ip, action, file_target, raw
            FROM public.ftp_events
            WHERE {where_sql}
            ORDER BY {sort} {order}
            LIMIT %s OFFSET %s;
            """,
            params + [limit, offset],
        )
        rows = cur.fetchall()
        cur.close()
        conn.close()

        logs_out = []
        for r in rows:
            sev = compute_ftp_severity(r[3])

            # optional server-side severity filter (applied after fetch)
            # This keeps the SQL simple and stable.
            if severity and severity != "all" and sev != severity:
                continue

            logs_out.append(
                {
                    "timestamp": _format_dt(r[0]),
                    "user": r[1],
                    "ip": r[2],
                    "action": r[3],
                    "file_target": r[4],
                    "raw": r[5],
                    "severity": sev,  # ✅ new
                }
            )

        # If severity filter is used, counts should match returned list better.
        # Since we filter post-fetch, total_pages might be slightly off,
        # but your UI is doing local paging anyway for FTP.
        total = total_db
        if severity and severity != "all":
            total = len(logs_out)

        total_pages = (total + limit - 1) // limit if total else 1
        return jsonify({"logs": logs_out, "total": total, "totalPages": total_pages, "page": page})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# -----------------------------
# API: nmap findings
# -----------------------------

@app.route("/api/nmap_findings", methods=["GET"])
def get_nmap_findings():
    """
    NMAP findings API
    Supports filtering + pagination.
    Adds smart severity tagging (internal vs external aware).
    """

    try:
        page = _safe_int(request.args.get("page"), 1, min_value=1)
        limit = _safe_int(request.args.get("limit"), 50, min_value=1, max_value=200)
        offset = (page - 1) * limit

        q = (request.args.get("q") or "").strip()
        host = (request.args.get("host") or "").strip()
        port = (request.args.get("port") or "").strip()
        state = (request.args.get("state") or "").strip().lower()
        service = (request.args.get("service") or "").strip().lower()

        sort = "scan_time"
        order = "desc"

        where = []
        params = []

        if q:
            where.append("""
                (
                    COALESCE(target,'') ILIKE %s OR
                    COALESCE(host,'') ILIKE %s OR
                    COALESCE(service,'') ILIKE %s
                )
            """)
            params.extend([f"%{q}%"] * 3)

        if host:
            where.append("host = %s")
            params.append(host)

        if port:
            where.append("port = %s")
            params.append(port)

        if state and state != "all":
            where.append("state = %s")
            params.append(state)

        if service and service != "all":
            where.append("service = %s")
            params.append(service)

        where_sql = " AND ".join(where) if where else "TRUE"

        conn = get_db_connection()
        cur = conn.cursor()

        # total count
        cur.execute(
            f"""
            SELECT COUNT(*)
            FROM public.nmap_findings
            WHERE {where_sql};
            """,
            params,
        )
        total = int(cur.fetchone()[0] or 0)

        # paginated rows
        cur.execute(
            f"""
            SELECT
                id,
                scan_time,
                agent_name,
                target,
                host,
                port,
                proto,
                state,
                service,
                product,
                version,
                extra
            FROM public.nmap_findings
            WHERE {where_sql}
            ORDER BY {sort} {order}
            LIMIT %s OFFSET %s;
            """,
            params + [limit, offset],
        )

        rows = cur.fetchall()
        cur.close()
        conn.close()

        # Build response with smart severity
        items = []
        for r in rows:
            items.append(
                {
                    "id": r[0],
                    "scan_time": _format_dt(r[1]),
                    "agent_name": r[2],
                    "target": r[3],
                    "host": r[4],
                    "port": r[5],
                    "proto": r[6],
                    "state": r[7],
                    "service": r[8],
                    "product": r[9],
                    "version": r[10],
                    "extra": r[11],
                    "severity": compute_nmap_severity(
                        r[4],   # host
                        r[7],   # state
                        r[8],   # service
                        r[5],   # port
                    ),
                }
            )

        total_pages = (total + limit - 1) // limit if total else 1

        return jsonify(
            {
                "items": items,
                "total": total,
                "totalPages": total_pages,
                "page": page,
            }
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# -----------------------------
# API: export (allowed sources only)
# -----------------------------

@app.route("/api/export", methods=["GET"])
def export_logs():
    """
    Exports ONLY allowed sources.
    Optional: service=ssh|web|apache_error|ftp
    Now includes severity column.
    """
    try:
        service = (request.args.get("service") or "").strip().lower()

        where = [allowed_logs_where_sql("l")]
        params: List[Any] = list(allowed_logs_where_params())

        if service == "ssh":
            where.append("l.source LIKE %s")
            params.append(f"{ALLOWED_AUTH_PREFIX}%")
        elif service == "web":
            where.append("l.source LIKE %s")
            params.append(f"{ALLOWED_APACHE_ACCESS_PREFIX}%")
        elif service in {"apache_error", "error"}:
            where.append("l.source LIKE %s")
            params.append(f"{ALLOWED_APACHE_ERROR_PREFIX}%")
        elif service == "ftp":
            where.append("l.source LIKE %s")
            params.append(f"{ALLOWED_VSFTPD_PREFIX}%")

        where_sql = " AND ".join(where)

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            f"""
            SELECT l.log_time, l.agent_name, l.source, l.message, COALESCE(l.severity,'LOW') AS severity
            FROM public.logs l
            WHERE {where_sql}
            ORDER BY l.log_time DESC;
            """,
            params,
        )
        rows = cur.fetchall()
        cur.close()
        conn.close()

        lines = ["timestamp,agent,source,severity,message"]
        for r in rows:
            ts = _format_dt(r[0]).replace(",", " ")
            agent = (r[1] or "").replace(",", " ")
            source = (r[2] or "").replace(",", " ")
            sev = (r[4] or "LOW").replace(",", " ")
            message = (r[3] or "").replace(",", " ")
            lines.append(f"{ts},{agent},{source},{sev},{message}")

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
        return jsonify({"error": str(e)}), 500


@app.route("/", methods=["GET"])
def home():
    return jsonify(
        {
            "message": "Raven API is running",
            "db": f"{DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['dbname']}",
            "allowed_sources": [
                f"{ALLOWED_AUTH_PREFIX}*",
                f"{ALLOWED_APACHE_ACCESS_PREFIX}*",
                f"{ALLOWED_APACHE_ERROR_PREFIX}*",
                f"{ALLOWED_VSFTPD_PREFIX}*",
            ],
            "endpoints": [
                "/api/logs",
                "/api/agents",
                "/api/metrics",
                "/api/chart",
                "/api/web_logs",
                "/api/ftp_logs",
                "/api/ssh_events",
                "/api/nmap_findings",
                "/api/export",
                "/api/alerts",
                "/api/ai/analyze",
                "/api/ai/top-correlations",
            ],
        }
    )


# -----------------------------
# alerts
# -----------------------------

@app.get("/api/alerts")
def list_alerts():
    page = max(int(request.args.get("page", 1)), 1)
    limit = min(max(int(request.args.get("limit", 20)), 1), 200)
    offset = (page - 1) * limit

    priority = request.args.get("priority")
    status = request.args.get("status")
    source = request.args.get("source")
    q = request.args.get("q")

    include_internal = request.args.get("include_internal", "1")
    include_internal = str(include_internal).strip().lower() not in {"0", "false", "no", "off"}

    where = []
    params = {}

    if priority:
        where.append("priority = %(priority)s")
        params["priority"] = priority

    if status:
        where.append("status = %(status)s")
        params["status"] = status

    if source:
        where.append("source = %(source)s")
        params["source"] = source

    if q:
        where.append("(title ILIKE %(q)s OR description ILIKE %(q)s)")
        params["q"] = f"%{q}%"

    if not include_internal:
        where.append("(ip_address IS NULL OR ip_address NOT IN ('127.0.0.1', '::1'))")

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(f"SELECT COUNT(*) AS cnt FROM alerts {where_sql}", params)
            total = cur.fetchone()["cnt"]

            cur.execute(
                f"""
                SELECT id, created_at, source, priority, title, description,
                       user_name, ip_address, file_target, status
                FROM alerts
                {where_sql}
                ORDER BY created_at DESC
                LIMIT %(limit)s OFFSET %(offset)s
                """,
                {**params, "limit": limit, "offset": offset},
            )
            rows = cur.fetchall()

        return jsonify({"page": page, "limit": limit, "total": total, "items": rows})
    finally:
        conn.close()


@app.get("/api/alerts/<int:alert_id>")
def get_alert(alert_id: int):
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, created_at, source, priority, title, description,
                       user_name, ip_address, file_target, status
                FROM alerts
                WHERE id = %s
            """,
                (alert_id,),
            )
            alert = cur.fetchone()
            if not alert:
                return jsonify({"error": "Alert not found"}), 404

            cur.execute(
                """
                SELECT log_type, log_id
                FROM alert_log_links
                WHERE alert_id = %s
                ORDER BY id ASC
            """,
                (alert_id,),
            )
            links = cur.fetchall()

            ids_by_type = {}
            for row in links:
                ids_by_type.setdefault(row["log_type"], []).append(row["log_id"])

            linked_items = []

            def add_item(log_type: str, time_val, source_val, message_val, extra=None):
                item = {
                    "log_type": log_type,
                    "time": _format_dt(time_val),
                    "source": source_val or "",
                    "message": message_val or "",
                }
                if extra:
                    item.update(extra)
                linked_items.append(item)

            # logs (Task 8 safety) + include severity
            if ids_by_type.get("logs"):
                allowed_where = allowed_logs_where_sql("l")
                allowed_params = list(allowed_logs_where_params())

                cur.execute(
                    f"""
                    SELECT l.id, l.log_time, l.source, l.message, l.agent_name, COALESCE(l.severity,'LOW') AS severity
                    FROM logs l
                    WHERE l.id = ANY(%s)
                      AND {allowed_where}
                    ORDER BY l.log_time DESC
                    """,
                    (ids_by_type["logs"], *allowed_params),
                )
                for r in cur.fetchall():
                    add_item(
                        "logs",
                        r["log_time"],
                        r["source"],
                        r["message"],
                        {"id": r["id"], "agent_name": r.get("agent_name") or "", "severity": r.get("severity") or "LOW"},
                    )

            # ftp_events
            if ids_by_type.get("ftp_events"):
                cur.execute(
                    """
                    SELECT id, event_time, ip, username, action, file_target, raw
                    FROM ftp_events
                    WHERE id = ANY(%s)
                    ORDER BY event_time DESC
                    """,
                    (ids_by_type["ftp_events"],),
                )
                for r in cur.fetchall():
                    msg = f"{r.get('action') or ''} user={r.get('username') or ''} ip={r.get('ip') or ''} target={r.get('file_target') or ''}"
                    add_item(
                        "ftp_events",
                        r["event_time"],
                        r.get("ip") or "",
                        msg.strip(),
                        {"id": r["id"], "raw": r.get("raw") or "", "action": r.get("action") or ""},
                    )

            # ssh_events
            if ids_by_type.get("ssh_events"):
                cur.execute(
                    """
                    SELECT id, event_time, ip, username, event_type, outcome, auth_method, raw
                    FROM ssh_events
                    WHERE id = ANY(%s)
                    ORDER BY event_time DESC
                    """,
                    (ids_by_type["ssh_events"],),
                )
                for r in cur.fetchall():
                    msg = f"{r.get('event_type')} outcome={r.get('outcome')} user={r.get('username') or ''} ip={r.get('ip') or ''}"
                    add_item(
                        "ssh_events",
                        r["event_time"],
                        r.get("ip") or "",
                        msg.strip(),
                        {"id": r["id"], "raw": r.get("raw") or "", "auth_method": r.get("auth_method") or ""},
                    )

            # nmap_findings
            if ids_by_type.get("nmap_findings"):
                cur.execute(
                    """
                    SELECT id, scan_time, agent_name, target, host, port, proto, state, service, product, version, extra
                    FROM nmap_findings
                    WHERE id = ANY(%s)
                    ORDER BY scan_time DESC, port ASC
                    """,
                    (ids_by_type["nmap_findings"],),
                )
                for r in cur.fetchall():
                    msg = (
                        f"host={r.get('host')}, port={r.get('port')}/{r.get('proto')}, "
                        f"target={r.get('target')}, state={r.get('state')}, service={r.get('service')}"
                    )
                    add_item(
                        "nmap_findings",
                        r["scan_time"],
                        r.get("host") or "",
                        msg,
                        {"id": r["id"], "port": r.get("port"), "proto": r.get("proto"),
                         "state": r.get("state"), "service": r.get("service")},
                    )

            # Backwards-compatible "linked_logs" (logs table only)
            linked_logs = []
            for it in linked_items:
                if it["log_type"] == "logs":
                    linked_logs.append(
                        {
                            "id": it.get("id"),
                            "log_time": it.get("time"),
                            "source": it.get("source"),
                            "message": it.get("message"),
                            "agent_name": it.get("agent_name"),
                            "severity": it.get("severity"),
                        }
                    )

            return jsonify({"alert": alert, "linked_logs": linked_logs, "linked_items": linked_items})
    finally:
        conn.close()


@app.patch("/api/alerts/<int:alert_id>")
def update_alert_status(alert_id: int):
    data = request.get_json(silent=True) or {}
    new_status = (data.get("status") or "").strip().lower()

    allowed = {"new", "acknowledged", "resolved"}
    if new_status not in allowed:
        return jsonify({"error": f"Invalid status. Allowed: {sorted(allowed)}"}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE alerts SET status=%s WHERE id=%s", (new_status, alert_id))
        if cur.rowcount == 0:
            cur.close()
            conn.close()
            return jsonify({"error": "Alert not found"}), 404

        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"ok": True, "id": alert_id, "status": new_status})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.get("/api/alerts/<int:alert_id>/export_csv")
def export_alert_logs_csv(alert_id: int):
    """
    Export linked items for this alert as CSV (supports logs/ssh_events/ftp_events/nmap_findings).
    Keeps Task 8 safety when exporting logs.
    Includes severity for logs rows.
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        cur.execute("SELECT id, title FROM alerts WHERE id=%s", (alert_id,))
        alert = cur.fetchone()
        if not alert:
            cur.close()
            conn.close()
            return jsonify({"error": "Alert not found"}), 404

        cur.execute(
            """
            SELECT log_type, log_id
            FROM alert_log_links
            WHERE alert_id = %s
            ORDER BY id ASC
        """,
            (alert_id,),
        )
        links = cur.fetchall()

        ids_by_type = {}
        for row in links:
            ids_by_type.setdefault(row["log_type"], []).append(row["log_id"])

        rows_out = []

        # logs (Task 8 safety)
        if ids_by_type.get("logs"):
            allowed_where = allowed_logs_where_sql("l")
            allowed_params = list(allowed_logs_where_params())
            cur.execute(
                f"""
                SELECT l.id, l.log_time AS time, l.source, l.message, COALESCE(l.severity,'LOW') AS severity
                FROM logs l
                WHERE l.id = ANY(%s)
                  AND {allowed_where}
                ORDER BY l.log_time DESC
                """,
                (ids_by_type["logs"], *allowed_params),
            )
            for r in cur.fetchall():
                rows_out.append(
                    {
                        "log_type": "logs",
                        "id": r["id"],
                        "time": _format_dt(r["time"]),
                        "source": r["source"],
                        "severity": r.get("severity") or "LOW",
                        "message": r["message"],
                    }
                )

        # ftp_events
        if ids_by_type.get("ftp_events"):
            cur.execute(
                """
                SELECT id, event_time AS time, ip AS source, raw AS message
                FROM ftp_events
                WHERE id = ANY(%s)
                ORDER BY event_time DESC
                """,
                (ids_by_type["ftp_events"],),
            )
            for r in cur.fetchall():
                rows_out.append(
                    {
                        "log_type": "ftp_events",
                        "id": r["id"],
                        "time": _format_dt(r["time"]),
                        "source": r["source"] or "",
                        "severity": "",
                        "message": r["message"] or "",
                    }
                )

        # ssh_events
        if ids_by_type.get("ssh_events"):
            cur.execute(
                """
                SELECT id, event_time AS time, ip AS source, raw AS message
                FROM ssh_events
                WHERE id = ANY(%s)
                ORDER BY event_time DESC
                """,
                (ids_by_type["ssh_events"],),
            )
            for r in cur.fetchall():
                rows_out.append(
                    {
                        "log_type": "ssh_events",
                        "id": r["id"],
                        "time": _format_dt(r["time"]),
                        "source": r["source"] or "",
                        "severity": "",
                        "message": r["message"] or "",
                    }
                )

        # nmap_findings
        if ids_by_type.get("nmap_findings"):
            cur.execute(
                """
                SELECT id,
                       scan_time AS time,
                       host AS source,
                       ('target=' || target || ' host=' || host || ' port=' || port || '/' || proto || ' state=' || state || ' service=' || COALESCE(service,'')) AS message
                FROM nmap_findings
                WHERE id = ANY(%s)
                ORDER BY scan_time DESC, port ASC
                """,
                (ids_by_type["nmap_findings"],),
            )
            for r in cur.fetchall():
                rows_out.append(
                    {
                        "log_type": "nmap_findings",
                        "id": r["id"],
                        "time": _format_dt(r["time"]),
                        "source": r["source"] or "",
                        "severity": "",
                        "message": r["message"] or "",
                    }
                )

        cur.close()
        conn.close()

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["log_type", "id", "time", "source", "severity", "message"])
        for r in rows_out:
            writer.writerow([r["log_type"], r["id"], r["time"], r["source"], r["severity"], r["message"]])

        csv_data = output.getvalue()
        output.close()

        filename = f"alert_{alert_id}_linked_items.csv"
        return Response(
            csv_data,
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/severity_summary", methods=["GET"])
def severity_summary():
    """
    Unified severity summary (last N hours, default 24h)
    - SSH/Web/Apache: from public.logs (allowed sources only)
    - FTP: from public.ftp_events using compute_ftp_severity(action)
    - Nmap: from public.nmap_findings using compute_nmap_severity(...)
    Returns: { window: "24h", total: X, counts: {critical, high, medium, low} }
    """
    hours = request.args.get("hours", "24")
    try:
        hours_int = int(hours)
        if hours_int <= 0 or hours_int > 720:
            hours_int = 24
    except Exception:
        hours_int = 24

    levels = ["critical", "high", "medium", "low"]
    counts = {k: 0 for k in levels}
    total = 0

    def bump(sev: str, n: int = 1) -> None:
        nonlocal total
        s = (sev or "").strip().lower()
        if s not in counts:
            s = "low"
        counts[s] += int(n)
        total += int(n)

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # -------------------------
        # 1) LOGS (allowed sources)
        # -------------------------
        allowed_where = allowed_logs_where_sql("l")
        allowed_params = list(allowed_logs_where_params())

        # Count by DB-backed severity (fast + consistent)
        cur.execute(
            f"""
            SELECT LOWER(COALESCE(l.severity, 'LOW')) AS sev, COUNT(*)
            FROM public.logs l
            WHERE {allowed_where}
              AND l.log_time >= NOW() - (%s || ' hours')::interval
            GROUP BY sev;
            """,
            allowed_params + [hours_int],
        )
        for sev, cnt in cur.fetchall():
            bump(sev, cnt)

        # -------------------------
        # 2) FTP (structured table)
        # -------------------------
        cur.execute(
            """
            SELECT action, COUNT(*)
            FROM public.ftp_events
            WHERE event_time >= NOW() - (%s || ' hours')::interval
            GROUP BY action;
            """,
            (hours_int,),
        )
        for action, cnt in cur.fetchall():
            sev = compute_ftp_severity(action)  # returns "low/medium/high/critical"
            bump(sev, cnt)

        # -------------------------
        # 3) NMAP (structured table)
        # -------------------------
        cur.execute(
            """
            SELECT host, port, state, service, COUNT(*)
            FROM public.nmap_findings
            WHERE scan_time >= NOW() - (%s || ' hours')::interval
            GROUP BY host, port, state, service;
            """,
            (hours_int,),
        )
        for host, port, state, service, cnt in cur.fetchall():
            sev = compute_nmap_severity(host, state, service, port)
            bump(sev, cnt)

        cur.close()
        conn.close()

        return jsonify({"window": f"{hours_int}h", "total": total, "counts": counts})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/ai/analyze", methods=["GET"])
def ai_analyze():
    try:
        hours = request.args.get("hours", "1")
        try:
            hours_int = int(hours)
        except Exception:
            hours_int = 1

        result = analyze_recent_activity(hours=hours_int)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/ai/top-correlations", methods=["GET"])
def ai_top_correlations():
    try:
        hours = request.args.get("hours", "1")
        try:
            hours_int = int(hours)
        except Exception:
            hours_int = 1

        result = analyze_recent_activity(hours=hours_int)

        return jsonify({
            "window_hours": result["window_hours"],
            "generated_at": result["generated_at"],
            "risk": result["risk"],

            # ✅ NEW STRUCTURE
            "top_activity": result["correlations"].get("top_activity_ip"),
            "top_external": result["correlations"].get("top_external_ip"),
            "top_internal": result["correlations"].get("top_internal_ip"),

            "multi_source_ips": result["correlations"].get("multi_source_ips", []),
            "correlated_ips": result["correlations"].get("correlated_ips", []),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)