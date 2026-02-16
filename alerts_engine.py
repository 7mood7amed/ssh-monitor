#!/usr/bin/env python3
"""
alerts_engine.py
----------------
Creates "chunked" alerts from recent events and links them to underlying logs.

Key upgrades (vs old version):
- Brute-force detection is grouped by IP (+ username) using ftp_events (structured).
- Alerts store ip_address + user_name so the dashboard can filter/dedupe properly.
- Dedupe prevents repeated alerts every cron run.
- Links both:
    - ftp_events rows (log_type='ftp_events')
    - the originating logs rows via ftp_events.log_id (log_type='logs')
"""

import psycopg2
from psycopg2 import sql

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
BRUTE_FORCE_WINDOW_SECONDS = 120     # lookback window (2 minutes)
BRUTE_FORCE_THRESHOLD = 5             # >= 5 failures => alert
BRUTE_FORCE_DEDUPE_MINUTES = 5        # don't create same alert for same IP within this time

MASS_DELETE_WINDOW_SECONDS = 60       # 1 minute
MASS_DELETE_THRESHOLD = 3

CRITICAL_RMDIR_WINDOW_SECONDS = 300   # 5 minutes


# -------------------------------
# DB helpers
# -------------------------------
def _connect():
    return psycopg2.connect(**DB_CONFIG)


def alert_exists_recently(cur, title: str, ip_address: str | None) -> bool:
    """
    Dedupe: if an alert with same title + ip already exists recently and isn't resolved, skip.
    If ip_address is None, dedupe only by title.
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


def create_alert(cur, priority: str, title: str, description: str,
                 *, source: str = "logs",
                 user_name: str | None = None,
                 ip_address: str | None = None,
                 file_target: str | None = None) -> int:
    """
    Insert into alerts table and return alert_id.
    Assumes alerts has columns:
      (source, priority, title, description, user_name, ip_address, file_target)
    and created_at/status managed by defaults/triggers.
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
    cur.execute(
        """
        INSERT INTO alert_log_links (alert_id, log_type, log_id)
        VALUES (%s, %s, %s)
        ON CONFLICT (alert_id, log_type, log_id) DO NOTHING
        """,
        (alert_id, log_type, log_id),
    )


# -------------------------------
# Rule 1: FTP brute force (chunked by IP+username)
# -------------------------------
def brute_force_ftp_rule(cur):
    """
    Detect brute force bursts from ftp_events:
    - failure signals = action='LOGIN_FAIL' OR raw contains 530/Login incorrect
    - grouped by ip + username bucket
    - threshold within window seconds
    Creates ONE alert per IP chunk, stores ip/user in alerts, links related rows.
    """

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
        title = "Brute Force Suspected"

        # Dedupe by (title + ip)
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
            file_target=None,
        )

        # Link ftp_events rows
        for feid in (ftp_event_ids or []):
            link_alert(cur, alert_id, "ftp_events", int(feid))

        # Link corresponding logs rows too (keeps existing dashboard "View" working if it reads logs)
        for lid in (related_log_ids or []):
            link_alert(cur, alert_id, "logs", int(lid))


def brute_force_ssh_rule(cur):
    """
    SSH brute force detection (chunked by IP + username).
    Uses ssh_events schema: event_type/outcome/auth_method.
    """

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
            file_target=None,
        )

        for seid in (ssh_event_ids or []):
            link_alert(cur, alert_id, "ssh_events", int(seid))

        for lid in (related_log_ids or []):
            link_alert(cur, alert_id, "logs", int(lid))

# -------------------------------
# Rule 2: Mass delete (logs table)
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
# Rule 3: Critical directory removal (logs table)
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
# Run
# -------------------------------
def main():
    conn = _connect()
    try:
        with conn:
            with conn.cursor() as cur:
                brute_force_ftp_rule(cur)
                brute_force_ssh_rule(cur)
                mass_delete_rule(cur)
                critical_rmdir_rule(cur)
        print("Alerts engine executed successfully")
    finally:
        conn.close()


if __name__ == "__main__":
    main()