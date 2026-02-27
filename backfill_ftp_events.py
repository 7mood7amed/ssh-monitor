#!/usr/bin/env python3
import re
import psycopg2
import psycopg2.extras
from datetime import datetime

DB_CONFIG = dict(dbname="logdb", user="hero", password="hero", host="localhost", port=5432)
VSFTPD_PREFIX = "/var/log/vsftpd.log"

# Timestamp / user / ip
TS_RE = re.compile(r"^(?P<dow>\w+)\s+(?P<mon>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+:\d+)?")
# (kept parse_ts below; we also use db log_time primarily)

IP_RE = re.compile(r'Client\s+"::ffff:(?P<ip>[\d.]+)"')

# Match the *real* vsftpd event formats we want to store.
# Examples:
#   [hero] OK LOGIN: Client "::ffff:192.168.56.1"
#   [hero] FAIL LOGIN: Client "::ffff:127.0.0.1"
#   [hero] OK UPLOAD: Client "::ffff:192.168.56.1", "/upload/file.txt", ...
#   [hero] OK DOWNLOAD: Client "::ffff:192.168.56.1", "/upload/file.txt", ...
#   [hero] FAIL DELETE: Client "::ffff:192.168.56.1", "/file.txt"
EVENT_RE = re.compile(r"\]\s+(?P<status>OK|FAIL)\s+(?P<verb>[A-Z_]+):", re.IGNORECASE)

# Only keep these event types (what you asked for)
ALLOWED_ACTIONS = {
    "LOGIN_SUCCESS",
    "LOGIN_FAIL",
    "UPLOAD",
    "DOWNLOAD",
    "DELETE",
    "RENAME",
    "MKDIR",
    "RMDIR",
}

# Map vsftpd verbs -> our dashboard actions
VERB_TO_ACTION = {
    ("OK", "LOGIN"): "LOGIN_SUCCESS",
    ("FAIL", "LOGIN"): "LOGIN_FAIL",

    ("OK", "UPLOAD"): "UPLOAD",
    ("FAIL", "UPLOAD"): "UPLOAD",

    ("OK", "DOWNLOAD"): "DOWNLOAD",
    ("FAIL", "DOWNLOAD"): "DOWNLOAD",

    ("OK", "DELETE"): "DELETE",
    ("FAIL", "DELETE"): "DELETE",

    ("OK", "RENAME"): "RENAME",
    ("FAIL", "RENAME"): "RENAME",

    ("OK", "MKDIR"): "MKDIR",
    ("FAIL", "MKDIR"): "MKDIR",

    ("OK", "RMDIR"): "RMDIR",
    ("FAIL", "RMDIR"): "RMDIR",
}

# Extract a quoted path after Client "...", "/path"
PATH_RE = re.compile(r',\s+"(?P<path>/[^"]+)"')

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}

TS_PREFIX_RE = re.compile(
    r"^(?P<dow>\w+)\s+(?P<mon>\w+)\s+(?P<day>\d+)\s+(?P<hh>\d{2}):(?P<mm>\d{2}):(?P<ss>\d{2})\s+(?P<year>\d{4})"
)

def parse_ts(raw: str):
    m = TS_PREFIX_RE.match(raw)
    if not m:
        return None
    mon = MONTHS.get(m.group("mon"))
    if not mon:
        return None
    return datetime(
        int(m.group("year")),
        mon,
        int(m.group("day")),
        int(m.group("hh")),
        int(m.group("mm")),
        int(m.group("ss")),
    )

def parse_username(msg: str):
    # vsftpd prefix contains multiple [..] blocks: [pid ...] [hero]
    brackets = re.findall(r"\[([^\]]+)\]", msg)
    if not brackets:
        return None
    for b in reversed(brackets):
        b2 = b.strip()
        if b2.lower().startswith("pid "):
            continue
        return b2
    return None

def detect_action_and_target(msg: str):
    """
    Returns (action, file_target) or (None, None) if message is not a real event line.
    We intentionally ignore:
      - "FTP command:"
      - "FTP response:"
      - "CONNECT:"
      - "PASV", "LIST", etc.
    """
    # Hard ignore noisy lines
    up = msg.upper()
    if "FTP COMMAND:" in up or "FTP RESPONSE:" in up or "CONNECT:" in up:
        return None, None

    m = EVENT_RE.search(msg)
    if not m:
        return None, None

    status = m.group("status").upper()
    verb = m.group("verb").upper()

    action = VERB_TO_ACTION.get((status, verb))
    if not action:
        return None, None

    # Extract first quoted path after the client
    pm = PATH_RE.search(msg)
    file_target = pm.group("path") if pm else None

    # For login, target is irrelevant
    if action in {"LOGIN_SUCCESS", "LOGIN_FAIL"}:
        file_target = None

    return action, file_target

def main():
    conn = psycopg2.connect(**DB_CONFIG)
    conn.autocommit = True

    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT id, log_time, message
        FROM logs
        WHERE source LIKE %s
        ORDER BY id ASC
    """, (VSFTPD_PREFIX + "%",))
    rows = cur.fetchall()

    inserted = 0
    for r in rows:
        log_id = r["id"]
        msg = (r["message"] or "").strip()
        if not msg:
            continue

        event_time = r["log_time"] or parse_ts(msg)
        username = parse_username(msg)

        im = IP_RE.search(msg)
        ip = im.group("ip") if im else None

        action, file_target = detect_action_and_target(msg)
        if not action:
            continue
        if action not in ALLOWED_ACTIONS:
            continue

        # If it's a file operation but target is missing, skip (prevents ghost rows)
        if action in {"UPLOAD", "DOWNLOAD", "DELETE", "RENAME", "MKDIR", "RMDIR"} and not file_target:
            continue

        with conn.cursor() as cur2:
            cur2.execute("""
                INSERT INTO ftp_events (log_id, event_time, username, ip, action, file_target, raw)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (log_id) DO NOTHING
            """, (log_id, event_time, username, ip, action, file_target, msg))
            if cur2.rowcount:
                inserted += 1

    print(f"Backfill done. Inserted {inserted} rows into ftp_events.")

if __name__ == "__main__":
    main()
