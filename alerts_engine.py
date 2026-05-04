#!/usr/bin/env python3
"""
alerts_engine.py
----------------
Creates "chunked" alerts from recent events and links them to underlying evidence tables.

- For SSH + FTP brute force alerts, group by IP + username
- Use alerts.last_event_time to avoid re-alerting on old evidence
- 10-minute cooldown:
    - If same (title + ip + username) has an ACTIVE alert within cooldown -> append (update last_event_time + link new evidence)
    - Otherwise -> create new alert
- If there is NO newer evidence than last_event_time -> do nothing (even if alert is resolved)

Other supported alert sources:
- Mass delete (logs)
- Critical RMDIR (logs)
- Nmap: New Port Detected (nmap_findings)
- Web: traffic detections from apache access logs in logs
"""

from __future__ import annotations
from datetime import datetime, timezone
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional, List, Tuple, Dict

import psycopg2
from collections import Counter

def extract_first_ipv4(text: str) -> str | None:
    m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text or "")
    return m.group(0) if m else None

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
TSHARK_ANOMALY_WINDOW_SECONDS = 600
TSHARK_ANOMALY_DEDUPE_MINUTES = 5

#  cooldown for SSH + FTP brute force grouping
BRUTE_FORCE_COOLDOWN_MINUTES = 10

MASS_DELETE_WINDOW_SECONDS = 60
MASS_DELETE_THRESHOLD = 3

CRITICAL_RMDIR_WINDOW_SECONDS = 300

# Nmap
NMAP_DEDUPE_MINUTES = 60

# -------------------------------
# Web traffic alert tunables
# -------------------------------
WEB_WINDOW_SECONDS = 300
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
    last_event_time: datetime | None = None,
) -> int:
    """
    Insert into alerts table and return alert_id.
    NOW includes last_event_time (used for dedupe/append logic).
    """
    cur.execute(
        """
        INSERT INTO alerts (source, priority, title, description, user_name, ip_address, file_target, last_event_time)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id
        """,
        (source, priority, title, description, user_name, ip_address, file_target, last_event_time),
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


def _get_latest_alert_for_key(
    cur,
    *,
    title: str,
    source: str,
    ip_address: str,
    user_name: str,
):
    """
    Returns the most recent alert for (title + source + ip + user_name),
    regardless of status (includes resolved). That’s important for:
      - "resolved → rerun → no new evidence" => should NOT recreate.
    """
    cur.execute(
        """
        SELECT id, status, created_at, last_event_time
        FROM alerts
        WHERE title = %s
          AND source = %s
          AND ip_address = %s
          AND user_name = %s
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (title, source, ip_address, user_name),
    )
    return cur.fetchone()


def _update_alert_last_event_time(cur, alert_id: int, new_last_event_time: datetime):
    cur.execute(
        """
        UPDATE alerts
        SET last_event_time = %s
        WHERE id = %s
        """,
        (new_last_event_time, alert_id),
    )

def _update_alert_ip_if_missing(cur, alert_id: int, ip_address: str | None):
    if not ip_address:
        return

    cur.execute(
        """
        UPDATE alerts
        SET ip_address = %s
        WHERE id = %s
          AND (ip_address IS NULL OR ip_address = '')
        """,
        (ip_address, alert_id),
    )


def _append_alert_description(cur, alert_id: int, extra_line: str):
    """
    Optional: append a short note when we’re grouping into an active alert.
    Keeps UI human-readable.
    """
    cur.execute(
        """
        UPDATE alerts
        SET description = COALESCE(description, '') || %s
        WHERE id = %s
        """,
        ("\n" + extra_line, alert_id),
    )


def _new_evidence_after_last_event(last_seen: datetime, last_event_time: Optional[datetime]) -> bool:
    """
    If we have no last_event_time stored, treat it as "unknown" => allow create.
    Otherwise only act if we truly saw newer evidence.
    """
    if last_event_time is None:
        return True
    return last_seen > last_event_time


def _within_cooldown(created_at: datetime) -> bool:
    return created_at >= (datetime.utcnow() - timedelta(minutes=BRUTE_FORCE_COOLDOWN_MINUTES))


# -------------------------------
# Rule 1: FTP brute force (grouped by IP + username)
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
        if not ip:
            continue

        title = "FTP Brute Force Suspected"
        source = "ftp"
        user_key = username_bucket or "(unknown)"

        latest = _get_latest_alert_for_key(
            cur, title=title, source=source, ip_address=ip, user_name=user_key
        )

        if latest:
            alert_id, status, created_at, last_event_time = latest

            #  if no newer evidence, do nothing (even if resolved)
            if not _new_evidence_after_last_event(last_seen, last_event_time):
                continue

            # If alert is active and within cooldown, append/link instead of new alert
            if (status or "").lower() != "resolved" and _within_cooldown(created_at):
                new_count = 0
                if last_event_time is not None:
                    cur.execute(
                        """
                        SELECT COUNT(*)
                        FROM ssh_events
                        WHERE ip = %s
                        AND COALESCE(username, '(unknown)') = %s
                        AND event_type = 'login_fail'
                        AND outcome = 'fail'
                        AND event_time > %s
                        AND event_time <= %s
                        """,
                        (ip, user_key, last_event_time, last_seen),
                    )
                    new_count = int(cur.fetchone()[0] or 0)
                else:
                    new_count = int(fail_count or 0)

                _update_alert_last_event_time(cur, int(alert_id), last_seen)
                _append_alert_description(
                    cur,
                    int(alert_id),
                    f"[grouped] New FTP fails detected: +{new_count} (last_seen={last_seen})",
                )

                for feid in (ftp_event_ids or []):
                    link_alert(cur, int(alert_id), "ftp_events", int(feid))
                for lid in (related_log_ids or []):
                    link_alert(cur, int(alert_id), "logs", int(lid))

                continue

        # Otherwise, create a new alert
        description = (
            f"Multiple FTP login failures detected (possible brute force). "
            f"ip={ip}, user={user_key}, fails={fail_count}, "
            f"window={int(BRUTE_FORCE_WINDOW_SECONDS)}s, "
            f"first={first_seen}, last={last_seen}"
        )

        new_alert_id = create_alert(
            cur,
            priority="high",
            title=title,
            description=description,
            source=source,
            user_name=user_key,
            ip_address=ip,
            last_event_time=last_seen,
        )

        for feid in (ftp_event_ids or []):
            link_alert(cur, int(new_alert_id), "ftp_events", int(feid))
        for lid in (related_log_ids or []):
            link_alert(cur, int(new_alert_id), "logs", int(lid))


# -------------------------------
# Rule 2: SSH brute force (grouped by IP + username)
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
        if not ip:
            continue

        title = "SSH Brute Force Suspected"
        source = "ssh"
        user_key = username_bucket or "(unknown)"

        latest = _get_latest_alert_for_key(
            cur, title=title, source=source, ip_address=ip, user_name=user_key
        )

        if latest:
            alert_id, status, created_at, last_event_time = latest

            #  if no newer evidence, do nothing (even if resolved)
            if not _new_evidence_after_last_event(last_seen, last_event_time):
                continue

            # If alert is active and within cooldown, append/link instead of new alert
            if (status or "").lower() != "resolved" and _within_cooldown(created_at):
                new_count = 0

                if last_event_time is not None:
                    cur.execute(
                        """
                        SELECT COUNT(*)
                        FROM ssh_events
                        WHERE ip = %s
                        AND COALESCE(username, '(unknown)') = %s
                        AND event_type = 'login_fail'
                        AND outcome = 'fail'
                        AND event_time > %s
                        AND event_time <= %s
                        """,
                        (ip, user_key, last_event_time, last_seen),
                    )
                    new_count = int(cur.fetchone()[0] or 0)
                else:
                    new_count = int(fail_count or 0)

                _update_alert_last_event_time(cur, int(alert_id), last_seen)

                _append_alert_description(
                    cur,
                    int(alert_id),
                    f"[grouped] New SSH fails detected: +{new_count} (last_seen={last_seen})",
                )

                for seid in (ssh_event_ids or []):
                    link_alert(cur, int(alert_id), "ssh_events", int(seid))
                for lid in (related_log_ids or []):
                    link_alert(cur, int(alert_id), "logs", int(lid))

                continue

        # Otherwise, create a new alert
        description = (
            f"Multiple SSH login failures detected (possible brute force). "
            f"ip={ip}, user={user_key}, fails={fail_count}, "
            f"window={int(BRUTE_FORCE_WINDOW_SECONDS)}s, "
            f"first={first_seen}, last={last_seen}"
        )

        new_alert_id = create_alert(
            cur,
            priority="high",
            title=title,
            description=description,
            source=source,
            user_name=user_key,
            ip_address=ip,
            last_event_time=last_seen,
        )

        for seid in (ssh_event_ids or []):
            link_alert(cur, int(new_alert_id), "ssh_events", int(seid))
        for lid in (related_log_ids or []):
            link_alert(cur, int(new_alert_id), "logs", int(lid))


# -------------------------------
# Rule 3: Mass delete (logs table)
# -------------------------------
from datetime import datetime, timezone

# -------------------------------
# Rule 3: Mass delete (logs table)
# -------------------------------
def mass_delete_rule(cur):
    cur.execute(
        """
        SELECT
          array_agg(id) AS log_ids,
          MAX(log_time) AS last_seen
        FROM logs
        WHERE message ILIKE %s
          AND log_time >= (NOW() AT TIME ZONE 'UTC') - (%s || ' seconds')::interval
        HAVING COUNT(*) >= %s
        """,
        ("%DELETE%", MASS_DELETE_WINDOW_SECONDS, MASS_DELETE_THRESHOLD),
    )

    row = cur.fetchone()
    if row and row[0]:
        log_ids, last_seen = row[0], row[1]

        title = "Mass Deletion Activity"

        # simple dedupe: don't spam if unresolved within cooldown
        cur.execute(
            """
            SELECT 1
            FROM alerts
            WHERE title = %s
              AND status <> 'resolved'
              AND created_at >= NOW() - (%s || ' minutes')::interval
            LIMIT 1
            """,
            (title, BRUTE_FORCE_COOLDOWN_MINUTES),
        )
        if cur.fetchone():
            return

        alert_id = create_alert(
            cur,
            priority="high",
            title=title,
            description="Multiple deletes detected in short time",
            source="logs",
            last_event_time=last_seen,  #  match evidence time
        )
        for lid in log_ids:
            link_alert(cur, int(alert_id), "logs", int(lid))

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

        cur.execute(
            """
            SELECT 1
            FROM alerts
            WHERE title = %s
              AND status <> 'resolved'
              AND created_at >= NOW() - (%s || ' minutes')::interval
            LIMIT 1
            """,
            (title, BRUTE_FORCE_COOLDOWN_MINUTES),
        )
        if cur.fetchone():
            return

        alert_id = create_alert(
            cur,
            priority="critical",
            title=title,
            description="Directory removal activity detected (RMDIR)",
            source="logs",
            last_event_time=datetime.utcnow(),
        )
        for lid in result[0]:
            link_alert(cur, int(alert_id), "logs", int(lid))


# -------------------------------
# Rule 5: Nmap "New Port Detected"
# -------------------------------
def nmap_alert_for_finding_exists(cur, finding_id: int) -> bool:
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


def nmap_new_port_rule(cur):
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
            last_event_time=scan_time,
        )

        link_alert(cur, int(alert_id), "nmap_findings", int(finding_id))


# -------------------------------
# Web helpers + Rule 6 unchanged
# -------------------------------
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


def web_scan_rule(cur):
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

        if any(path_l.startswith(s) for s in sens):
            per_ip_sensitive_hits.setdefault(ip, []).append((int(log_id), hit.path))

        if hit.method in WEB_SUSPICIOUS_METHODS:
            per_ip_suspicious_method_hits.setdefault(ip, []).append((int(log_id), hit.method, hit.path, hit.status))

    # 1) Sensitive path probing
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
            last_event_time=datetime.utcnow(),
        )

        for lid, _p in items:
            link_alert(cur, int(alert_id), "logs", int(lid))

    # 2) Burst scan suspected
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
            last_event_time=datetime.utcnow(),
        )

        for lid in (per_ip_evidence_ids.get(ip, [])[:200]):
            link_alert(cur, int(alert_id), "logs", int(lid))

    # 3) Suspicious HTTP method
    for ip, items in per_ip_suspicious_method_hits.items():
        title = "Web: Suspicious HTTP Method"
        if alert_exists_recently_web(cur, title, ip):
            continue

        methods = {m for (_lid, m, _p, _st) in items}
        sev = "medium"

        if "TRACE" in methods or "CONNECT" in methods:
            sev = "high"
        else:
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
            last_event_time=datetime.utcnow(),
        )

        for lid, _m, _p, _st in items:
            link_alert(cur, int(alert_id), "logs", int(lid))


# -------------------------------
# Rule 7: TSHARK protocol anomaly alerts
# -------------------------------
def tshark_protocol_anomaly_rule(cur):
    cur.execute(
        """
        SELECT id, log_time, message, severity
        FROM logs
        WHERE agent_name = 'TSHARK'
          AND message ILIKE %s
          AND log_time >= (NOW() AT TIME ZONE 'UTC') - (%s || ' seconds')::interval
        ORDER BY log_time DESC
        LIMIT 500
        """,
        ("%[ANOMALY:%", TSHARK_ANOMALY_WINDOW_SECONDS),
    )

    rows = cur.fetchall()

    for log_id, log_time, message, severity in rows:
        msg = message or ""
        extracted_ip = extract_first_ipv4(msg)

        if "Possible ICMP sweep" in msg:
            title = "TShark: Possible ICMP Sweep"
            description = "Repeated ICMP traffic detected, indicating possible ping sweep or reconnaissance activity."
            priority = "high"

        elif "Possible DNS beaconing" in msg:
            title = "TShark: Possible DNS Beaconing"
            description = "Repeated DNS queries detected, indicating possible DNS beaconing or abnormal query burst."
            priority = "high"

        elif "Suspicious HTTP path probing" in msg:
            title = "TShark: Suspicious HTTP Path Probing"
            description = "Suspicious HTTP path request detected at packet level, such as /admin, /login, or similar probing behavior."
            priority = "high"

        else:
            title = "TShark: Network Protocol Anomaly"
            description = "A protocol-level anomaly was detected by the TShark network sensor."
            priority = severity or "medium"

        cur.execute(
            """
            SELECT 1
            FROM alert_log_links allk
            JOIN alerts a ON a.id = allk.alert_id
            WHERE allk.log_type = 'logs'
              AND allk.log_id = %s
              AND a.title = %s
            LIMIT 1
            """,
            (int(log_id), title),
        )

        if cur.fetchone():
            continue

        cur.execute(
            """
            SELECT id
            FROM alerts
            WHERE title = %s
              AND source = 'tshark'
              AND status <> 'resolved'
              AND created_at >= NOW() - (%s || ' minutes')::interval
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (title, TSHARK_ANOMALY_DEDUPE_MINUTES),
        )

        existing = cur.fetchone()

        if existing:
            alert_id = int(existing[0])
            _update_alert_last_event_time(cur, alert_id, log_time)
            _update_alert_ip_if_missing(cur, alert_id, extracted_ip)

            # Removed noisy grouped description to avoid alert spam
            pass
        else:
            alert_id = create_alert(
                cur,
                priority=priority,
                title=title,
                description=f"{description}\nEvidence: {msg}",
                source="tshark",
                user_name=None,
                ip_address=extracted_ip,
                file_target="network",
                last_event_time=log_time,
            )

        link_alert(cur, int(alert_id), "logs", int(log_id))



# -------------------------------
# Rule 8: Multi-stage Recon Correlation
# -------------------------------
# -------------------------------
# Rule 8: Multi-stage Recon Correlation
# -------------------------------
def recon_campaign_rule(cur):
    cur.execute(
        """
        SELECT id, title, created_at
        FROM alerts
        WHERE source = 'tshark'
          AND created_at >= NOW() - INTERVAL '10 minutes'
        ORDER BY created_at DESC
        """
    )

    rows = cur.fetchall()

    titles = [title for _alert_id, title, _created_at in rows]

    has_icmp = any("ICMP Sweep" in t for t in titles)
    has_dns = any("DNS Beaconing" in t for t in titles)
    has_http = any("HTTP Path" in t or "HTTP Path Probing" in t for t in titles)

    if not (has_icmp and has_dns and has_http):
        return

    title = "Reconnaissance Campaign Detected"

    cur.execute(
        """
        SELECT 1
        FROM alerts
        WHERE title = %s
          AND source = 'correlation'
          AND status <> 'resolved'
          AND created_at >= NOW() - INTERVAL '10 minutes'
        LIMIT 1
        """,
        (title,),
    )

    if cur.fetchone():
        return

    description = (
        "Multi-stage reconnaissance activity detected by the TSHARK sensor. "
        "The system observed ICMP sweep behavior, DNS query burst activity, "
        "and suspicious HTTP path probing within the same time window."
    )

    alert_id = create_alert(
        cur,
        priority="critical",
        title=title,
        description=description,
        source="correlation",
        ip_address=None,
        file_target="network",
        last_event_time=datetime.utcnow(),
    )

    for related_alert_id, related_title, _created_at in rows:
        _append_alert_description(
            cur,
            int(alert_id),
            f"[related alert] {related_title} alert_id={related_alert_id}"
        )


# -------------------------------
# Run
# -------------------------------
def main():
    conn = _connect()
    try:
        with conn:
            with conn.cursor() as cur:
                #  SSH + FTP now share the same dedupe/append logic style
                brute_force_ftp_rule(cur)
                brute_force_ssh_rule(cur)

                web_scan_rule(cur)
                tshark_protocol_anomaly_rule(cur)
                recon_campaign_rule(cur)

                mass_delete_rule(cur)
                critical_rmdir_rule(cur)
                nmap_new_port_rule(cur)

        print("Alerts engine executed successfully")
    finally:
        conn.close()


if __name__ == "__main__":
    main()