#!/usr/bin/env python3
"""
alerts_engine.py
----------------
Creates "chunked" alerts from recent events and links them to underlying evidence tables.

Current supported alert sources:
- FTP brute force (ftp_events + linked logs)
- SSH brute force (ssh_events + linked logs)
- Mass delete (logs)
- Critical RMDIR (logs)
- Nmap: New Port Detected (nmap_findings)
- Web: traffic detections from apache access logs in logs ✅ NEW
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

import psycopg2
from collections import Counter

DB_CONFIG = {
    "dbname": "logdb",
    "user": "hero",
    "password": "hero",
    "host": "localhost",
    "port": 5432,
}

# -------------------------------
# Tunables
# -------------------------------
BRUTE_FORCE_WINDOW_SECONDS = 120
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_DEDUPE_MINUTES = 5

MASS_DELETE_WINDOW_SECONDS = 60
MASS_DELETE_THRESHOLD = 3

CRITICAL_RMDIR_WINDOW_SECONDS = 300

# Nmap
NMAP_DEDUPE_MINUTES = 60  # don't create same "new port" alert for same finding within this time

# -------------------------------
# Web traffic alert tunables (Option A+)
# -------------------------------
WEB_WINDOW_SECONDS = 60
WEB_DEDUPE_MINUTES = 5

WEB_BURST_THRESHOLD = 25
WEB_404_403_THRESHOLD = 10
WEB_UNIQUE_PATHS_THRESHOLD = 15

WEB_SENSITIVE_PATHS = (
    "/admin",
    "/login",
    "/signin",
    "/phpmyadmin",
    "/phppgadmin",
    "/wp-login.php",
    "/wp-admin",
    "/.env",
    "/config",
    "/backup",
)

WEB_SUSPICIOUS_METHODS = {"TRACE", "CONNECT", "PUT", "DELETE"}


# -------------------------------
# DB helpers
# -------------------------------
def _connect():
    return psycopg2.connect(**DB_CONFIG)


def alert_exists_recently(cur, title: str, ip_address: str | None) -> bool:
    """
    Dedupe by (title + ip) if ip is provided; otherwise by title only.
    Uses BRUTE_FORCE_DEDUPE_MINUTES (legacy behavior for existing rules).
    """
    if ip_address:
        cur.execute(
            """
            SELECT 1
            FROM alerts
            WHERE title = %s
              AND ip_address = %s
              AND status <> 'resolved'
              AND created_at >= NOW() - (%s || ' minutes')::interval
            LIMIT 1
            """,
            (title, ip_address, BRUTE_FORCE_DEDUPE_MINUTES),
        )
    else:
        cur.execute(
            """
            SELECT 1
            FROM alerts
            WHERE title = %s
              AND status <> 'resolved'
              AND created_at >= NOW() - (%s || ' minutes')::interval
            LIMIT 1
            """,
            (title, BRUTE_FORCE_DEDUPE_MINUTES),
        )
    return cur.fetchone() is not None


def create_alert(
    cur,
    priority: str,
    title: str,
    description: str,
    *,
    source: str = "logs",
    user_name: str | None = None,
    ip_address: str | None = None,
    file_target: str | None = None,
) -> int:
    """
    Insert into alerts table and return alert_id.
    alerts columns assumed:
      (source, priority, title, description, user_name, ip_address, file_target)
    """
    cur.execute(
        """
        INSERT INTO alerts (source, priority, title, description, user_name, ip_address, file_target)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        RETURNING id
        """,
        (source, priority, title, description, user_name, ip_address, file_target),
    )
    return cur.fetchone()[0]


def link_alert(cur, alert_id: int, log_type: str, log_id: int):
    """
    Requires unique constraint on (alert_id, log_type, log_id) for ON CONFLICT to work.
    """
    cur.execute(
        """
        INSERT INTO alert_log_links (alert_id, log_type, log_id)
        VALUES (%s, %s, %s)
        ON CONFLICT (alert_id, log_type, log_id) DO NOTHING
        """,
        (alert_id, log_type, log_id),
    )


def nmap_alert_for_finding_exists(cur, finding_id: int) -> bool:
    """
    Strong dedupe for Nmap: if there's already an ACTIVE (not resolved) alert
    linked to this exact nmap_findings row recently, don't recreate it.
    """
    cur.execute(
        """
        SELECT 1
        FROM alert_log_links allk
        JOIN alerts a ON a.id = allk.alert_id
        WHERE allk.log_type = 'nmap_findings'
          AND allk.log_id = %s
          AND a.status <> 'resolved'
          AND a.created_at >= NOW() - (%s || ' minutes')::interval
        LIMIT 1
        """,
        (finding_id, NMAP_DEDUPE_MINUTES),
    )
    return cur.fetchone() is not None


# -------------------------------
# Rule 1: FTP brute force (chunked by IP+username)
# -------------------------------
def brute_force_ftp_rule(cur):
    cur.execute(
        """
        SELECT
          ip,
          COALESCE(username, '(unknown)') AS username_bucket,
          COUNT(*) AS fail_count,
          MIN(event_time) AS first_seen,
          MAX(event_time) AS last_seen,
          array_agg(id ORDER BY event_time) AS ftp_event_ids,
          array_remove(array_agg(log_id), NULL) AS related_log_ids
        FROM ftp_events
        WHERE event_time >= NOW() - (%s || ' seconds')::interval
          AND (
            action = %s
            OR raw ILIKE %s
            OR raw ILIKE %s
          )
        GROUP BY ip, COALESCE(username, '(unknown)')
        HAVING COUNT(*) >= %s
        ORDER BY fail_count DESC
        """,
        (
            BRUTE_FORCE_WINDOW_SECONDS,
            "LOGIN_FAIL",
            "%530%",
            "%Login incorrect%",
            BRUTE_FORCE_THRESHOLD,
        ),
    )

    rows = cur.fetchall()
    for ip, username_bucket, fail_count, first_seen, last_seen, ftp_event_ids, related_log_ids in rows:
        title = "FTP Brute Force Suspected"
        if alert_exists_recently(cur, title, ip):
            continue

        description = (
            f"Multiple FTP login failures detected (possible brute force). "
            f"ip={ip}, user={username_bucket}, fails={fail_count}, "
            f"window={int(BRUTE_FORCE_WINDOW_SECONDS)}s, "
            f"first={first_seen}, last={last_seen}"
        )

        alert_id = create_alert(
            cur,
            priority="high",
            title=title,
            description=description,
            source="ftp",
            user_name=None if username_bucket == "(unknown)" else username_bucket,
            ip_address=ip,
        )

        for feid in (ftp_event_ids or []):
            link_alert(cur, alert_id, "ftp_events", int(feid))
        for lid in (related_log_ids or []):
            link_alert(cur, alert_id, "logs", int(lid))


# -------------------------------
# Rule 2: SSH brute force (chunked by IP+username)
# -------------------------------
def brute_force_ssh_rule(cur):
    cur.execute(
        """
        SELECT
          ip,
          COALESCE(username, '(unknown)') AS username_bucket,
          COUNT(*) AS fail_count,
          MIN(event_time) AS first_seen,
          MAX(event_time) AS last_seen,
          array_agg(id ORDER BY event_time) AS ssh_event_ids,
          array_remove(array_agg(log_id), NULL) AS related_log_ids
        FROM ssh_events
        WHERE event_time >= NOW() - (%s || ' seconds')::interval
          AND event_type = %s
          AND outcome = %s
        GROUP BY ip, COALESCE(username, '(unknown)')
        HAVING COUNT(*) >= %s
        ORDER BY fail_count DESC
        """,
        (
            BRUTE_FORCE_WINDOW_SECONDS,
            "login_fail",
            "fail",
            BRUTE_FORCE_THRESHOLD,
        ),
    )

    rows = cur.fetchall()
    for ip, username_bucket, fail_count, first_seen, last_seen, ssh_event_ids, related_log_ids in rows:
        title = "SSH Brute Force Suspected"
        if alert_exists_recently(cur, title, ip):
            continue

        description = (
            f"Multiple SSH login failures detected (possible brute force). "
            f"ip={ip}, user={username_bucket}, fails={fail_count}, "
            f"window={int(BRUTE_FORCE_WINDOW_SECONDS)}s, "
            f"first={first_seen}, last={last_seen}"
        )

        alert_id = create_alert(
            cur,
            priority="high",
            title=title,
            description=description,
            source="ssh",
            user_name=None if username_bucket == "(unknown)" else username_bucket,
            ip_address=ip,
        )

        for seid in (ssh_event_ids or []):
            link_alert(cur, alert_id, "ssh_events", int(seid))
        for lid in (related_log_ids or []):
            link_alert(cur, alert_id, "logs", int(lid))


# -------------------------------
# Rule 3: Mass delete (logs table)
# -------------------------------
def mass_delete_rule(cur):
    cur.execute(
        """
        SELECT array_agg(id)
        FROM logs
        WHERE message ILIKE %s
          AND log_time > NOW() - (%s || ' seconds')::interval
        HAVING COUNT(*) >= %s
        """,
        ("%DELETE%", MASS_DELETE_WINDOW_SECONDS, MASS_DELETE_THRESHOLD),
    )

    result = cur.fetchone()
    if result and result[0]:
        title = "Mass Deletion Activity"
        if alert_exists_recently(cur, title, None):
            return

        alert_id = create_alert(
            cur,
            priority="high",
            title=title,
            description="Multiple deletes detected in short time",
            source="logs",
        )
        for lid in result[0]:
            link_alert(cur, alert_id, "logs", int(lid))


# -------------------------------
# Rule 4: Critical directory removal (logs table)
# -------------------------------
def critical_rmdir_rule(cur):
    cur.execute(
        """
        SELECT array_agg(id)
        FROM logs
        WHERE (
            message ILIKE %s
            OR message ILIKE %s
        )
        AND log_time > NOW() - (%s || ' seconds')::interval
        """,
        ("%FAIL RMDIR:%", "% RMDIR %", CRITICAL_RMDIR_WINDOW_SECONDS),
    )

    result = cur.fetchone()
    if result and result[0]:
        title = "Directory Removal Detected"
        if alert_exists_recently(cur, title, None):
            return

        alert_id = create_alert(
            cur,
            priority="critical",
            title=title,
            description="Directory removal activity detected (RMDIR)",
            source="logs",
        )
        for lid in result[0]:
            link_alert(cur, alert_id, "logs", int(lid))


# -------------------------------
# Rule 5: Nmap "New Port Detected" (nmap_findings)
# -------------------------------
def nmap_new_port_rule(cur):
    """
    Creates alerts for ports that are OPEN in the latest scan but were NOT open
    in the immediately previous scan (per target+host).
    """
    cur.execute(
        """
        WITH latest AS (
            SELECT target, host, MAX(scan_time) AS latest_scan
            FROM public.nmap_findings
            GROUP BY target, host
        ),
        prev AS (
            SELECT nf.target, nf.host, MAX(nf.scan_time) AS prev_scan
            FROM public.nmap_findings nf
            JOIN latest l
              ON l.target = nf.target AND l.host = nf.host
            WHERE nf.scan_time < l.latest_scan
            GROUP BY nf.target, nf.host
        ),
        latest_rows AS (
            SELECT nf.*
            FROM public.nmap_findings nf
            JOIN latest l
              ON l.target = nf.target AND l.host = nf.host AND l.latest_scan = nf.scan_time
            WHERE nf.state = 'open'
        )
        SELECT
            lr.id, lr.scan_time, lr.agent_name, lr.target, lr.host, lr.port, lr.proto, lr.state, lr.service
        FROM latest_rows lr
        LEFT JOIN prev p
          ON p.target = lr.target AND p.host = lr.host
        WHERE NOT EXISTS (
            SELECT 1
            FROM public.nmap_findings old
            WHERE old.target = lr.target
              AND old.host   = lr.host
              AND old.port   = lr.port
              AND old.proto  = lr.proto
              AND old.state  = 'open'
              AND (
                    (p.prev_scan IS NOT NULL AND old.scan_time = p.prev_scan)
                 )
        )
        ORDER BY lr.target, lr.host, lr.port;
        """
    )

    rows = cur.fetchall()
    for finding_id, scan_time, agent_name, target, host, port, proto, state, service in rows:
        title = "Nmap: New Port Detected"

        if nmap_alert_for_finding_exists(cur, int(finding_id)):
            continue

        description = (
            f"New port detected. host={host}, port={port}/{proto}, "
            f"target={target}, state={state}, service={service}"
        )

        file_target = f"{host}:{port}/{proto}"

        alert_id = create_alert(
            cur,
            priority="high",
            title=title,
            description=description,
            source="nmap",
            user_name=None,
            ip_address=host,
            file_target=file_target,
        )

        link_alert(cur, alert_id, "nmap_findings", int(finding_id))


# -------------------------------
# Web helpers
# -------------------------------

# Example line:
# ::1 - - [22/Feb/2026:04:03:22 +0300] "GET /login HTTP/1.1" 404 432 "-" "curl/8.5.0"
_APACHE_ACCESS_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<url>\S+)'
    r'(?:\s+[^"]*)?"\s+(?P<status>\d{3})\s+\S+\s+"[^"]*"\s+"(?P<ua>[^"]*)"'
)

@dataclass
class WebHit:
    ip: str
    method: str
    path: str
    status: int
    ua: str


def _normalize_path(url: str) -> str:
    if not url:
        return "/"
    path = url.split("?", 1)[0].strip()
    if not path.startswith("/"):
        path = "/" + path
    return path


def parse_apache_access_line(line: str) -> Optional[WebHit]:
    m = _APACHE_ACCESS_RE.match(line or "")
    if not m:
        return None

    ip = (m.group("ip") or "").strip()
    method = (m.group("method") or "").strip().upper()
    url = (m.group("url") or "").strip()
    status_raw = (m.group("status") or "0").strip()
    ua = (m.group("ua") or "").strip()

    try:
        status = int(status_raw)
    except ValueError:
        status = 0

    path = _normalize_path(url)
    return WebHit(ip=ip, method=method, path=path, status=status, ua=ua)


def alert_exists_recently_web(cur, title: str, ip_address: str | None) -> bool:
    """
    Web dedupe (separate from brute-force dedupe).
    """
    if ip_address:
        cur.execute(
            """
            SELECT 1
            FROM alerts
            WHERE title = %s
              AND ip_address = %s
              AND status <> 'resolved'
              AND created_at >= NOW() - (%s || ' minutes')::interval
            LIMIT 1
            """,
            (title, ip_address, WEB_DEDUPE_MINUTES),
        )
    else:
        cur.execute(
            """
            SELECT 1
            FROM alerts
            WHERE title = %s
              AND status <> 'resolved'
              AND created_at >= NOW() - (%s || ' minutes')::interval
            LIMIT 1
            """,
            (title, WEB_DEDUPE_MINUTES),
        )
    return cur.fetchone() is not None


# -------------------------------
# Rule 6: Web traffic detection (apache access logs in public.logs)
# -------------------------------
def web_scan_rule(cur):
    """
    Creates alerts from apache access logs stored in public.logs.
    Uses UTC 'now' for correct comparison (logs.log_time is naive UTC in this project).
    Links evidence via alert_log_links(log_type='logs', log_id=<logs.id>).
    """

    cur.execute(
        """
        SELECT id, log_time, message
        FROM logs
        WHERE source LIKE %s
          AND log_time >= (NOW() AT TIME ZONE 'UTC') - (%s || ' seconds')::interval
        ORDER BY log_time DESC
        LIMIT 5000
        """,
        ("/var/log/apache2/access.log%", WEB_WINDOW_SECONDS),
    )
    rows = cur.fetchall()

    sens = tuple(p.lower() for p in WEB_SENSITIVE_PATHS)

    per_ip_total: dict[str, int] = {}
    per_ip_404_403: dict[str, int] = {}
    per_ip_evidence_ids: dict[str, list[int]] = {}

    per_ip_sensitive_hits: dict[str, list[tuple[int, str]]] = {}
    per_ip_suspicious_method_hits: dict[str, list[tuple[int, str, str, int]]] = {}

    per_ip_paths: dict[str, Counter] = {}
    per_ip_status: dict[str, Counter] = {}
    per_ip_uas: dict[str, Counter] = {}

    for log_id, _log_time, msg in rows:
        hit = parse_apache_access_line(msg or "")
        if not hit:
            continue

        ip = hit.ip
        path_l = (hit.path or "/").lower()

        per_ip_total[ip] = per_ip_total.get(ip, 0) + 1
        if hit.status in (403, 404):
            per_ip_404_403[ip] = per_ip_404_403.get(ip, 0) + 1

        per_ip_evidence_ids.setdefault(ip, []).append(int(log_id))

        per_ip_paths.setdefault(ip, Counter())[hit.path] += 1
        per_ip_status.setdefault(ip, Counter())[hit.status] += 1
        if hit.ua:
            per_ip_uas.setdefault(ip, Counter())[hit.ua[:120]] += 1

        # Sensitive path probing
        if any(path_l.startswith(s) for s in sens):
            per_ip_sensitive_hits.setdefault(ip, []).append((int(log_id), hit.path))

        # Suspicious methods
        if hit.method in WEB_SUSPICIOUS_METHODS:
            per_ip_suspicious_method_hits.setdefault(ip, []).append((int(log_id), hit.method, hit.path, hit.status))

    # 1) Sensitive path probing alerts (HIGH)
    for ip, items in per_ip_sensitive_hits.items():
        title = "Web: Sensitive Path Probing"
        if alert_exists_recently_web(cur, title, ip):
            continue

        top_paths = [f"{p}({c})" for p, c in per_ip_paths.get(ip, Counter()).most_common(5)]
        status_breakdown = [f"{s}={c}" for s, c in per_ip_status.get(ip, Counter()).most_common(5)]
        top_ua = per_ip_uas.get(ip, Counter()).most_common(1)
        top_ua = top_ua[0][0] if top_ua else ""

        example_paths = []
        for (_lid, p) in items[:6]:
            if p not in example_paths:
                example_paths.append(p)

        description = (
            f"Sensitive paths accessed in web traffic window. "
            f"ip={ip}, hits={len(items)}, window={WEB_WINDOW_SECONDS}s, "
            f"examples={example_paths}, top_paths={top_paths}, statuses={status_breakdown}, ua={top_ua}"
        )

        alert_id = create_alert(
            cur,
            priority="high",
            title=title,
            description=description,
            source="web",
            ip_address=ip,
        )

        for lid, _p in items:
            link_alert(cur, alert_id, "logs", int(lid))

    # 2) Burst scan alerts (HIGH): many requests + (many 404/403 OR many unique paths)
    for ip, total in per_ip_total.items():
        err = per_ip_404_403.get(ip, 0)
        unique_paths = len(per_ip_paths.get(ip, {}))

        if total < WEB_BURST_THRESHOLD:
            continue
        if err < WEB_404_403_THRESHOLD and unique_paths < WEB_UNIQUE_PATHS_THRESHOLD:
            continue

        title = "Web: Burst Scan Suspected"
        if alert_exists_recently_web(cur, title, ip):
            continue

        top_paths = [f"{p}({c})" for p, c in per_ip_paths.get(ip, Counter()).most_common(8)]
        status_breakdown = [f"{s}={c}" for s, c in per_ip_status.get(ip, Counter()).most_common(8)]
        top_ua = per_ip_uas.get(ip, Counter()).most_common(1)
        top_ua = top_ua[0][0] if top_ua else ""

        description = (
            f"High-rate web requests (possible scan). "
            f"ip={ip}, total={total}, unique_paths={unique_paths}, 404/403={err}, "
            f"window={WEB_WINDOW_SECONDS}s, top_paths={top_paths}, statuses={status_breakdown}, ua={top_ua}"
        )

        alert_id = create_alert(
            cur,
            priority="high",
            title=title,
            description=description,
            source="web",
            ip_address=ip,
        )

        for lid in (per_ip_evidence_ids.get(ip, [])[:200]):
            link_alert(cur, alert_id, "logs", int(lid))

    # 3) Suspicious method alerts (MEDIUM/HIGH)
    for ip, items in per_ip_suspicious_method_hits.items():
        title = "Web: Suspicious HTTP Method"
        if alert_exists_recently_web(cur, title, ip):
            continue

        methods = {m for (_lid, m, _p, _st) in items}
        sev = "medium"

        # TRACE/CONNECT is strong signal => HIGH
        if "TRACE" in methods or "CONNECT" in methods:
            sev = "high"
        else:
            # upgrade if error/deny/server error
            for (_lid, _m, _p, st) in items:
                if st in (401, 403, 404) or st >= 500:
                    sev = "high"
                    break

        examples = [f"{m} {p} ({st})" for (_lid, m, p, st) in items[:8]]

        top_paths = [f"{p}({c})" for p, c in per_ip_paths.get(ip, Counter()).most_common(5)]
        status_breakdown = [f"{s}={c}" for s, c in per_ip_status.get(ip, Counter()).most_common(5)]
        top_ua = per_ip_uas.get(ip, Counter()).most_common(1)
        top_ua = top_ua[0][0] if top_ua else ""

        description = (
            f"Suspicious HTTP methods observed. "
            f"ip={ip}, count={len(items)}, window={WEB_WINDOW_SECONDS}s, "
            f"examples={examples}, top_paths={top_paths}, statuses={status_breakdown}, ua={top_ua}"
        )

        alert_id = create_alert(
            cur,
            priority=sev,
            title=title,
            description=description,
            source="web",
            ip_address=ip,
        )

        for lid, _m, _p, _st in items:
            link_alert(cur, alert_id, "logs", int(lid))


# -------------------------------
# Run
# -------------------------------
def main():
    conn = _connect()
    try:
        with conn:
            with conn.cursor() as cur:
                brute_force_ftp_rule(cur)
                brute_force_ssh_rule(cur)

                # NEW: Web detection before filesystem rules
                web_scan_rule(cur)

                mass_delete_rule(cur)
                critical_rmdir_rule(cur)
                nmap_new_port_rule(cur)
        print("Alerts engine executed successfully")
    finally:
        conn.close()


if __name__ == "__main__":
    main()