#!/usr/bin/env python3
import re
import psycopg2
import psycopg2.extras
from datetime import datetime

DB_CONFIG = dict(dbname="logdb", user="hero", password="hero", host="localhost", port=5432)

VSFTPD_PREFIX = "/var/log/vsftpd.log"

# examples:
# Tue Feb 10 01:27:55 2026 [pid 5676] [hero] FTP command: Client "::ffff:192.168.56.104", "MKD testfolder"
# Tue Feb 10 01:27:39 2026 [pid 5676] [hero] FAIL DELETE: Client "::ffff:192.168.56.104", "/test.txt"
# Tue Feb 10 18:38:16 2026 [pid 2319] [lksdflsfd] FAIL LOGIN: Client "::ffff:127.0.0.1" [SEVERITY=low]

TS_RE = re.compile(r"^(?P<dow>\w+)\s+(?P<mon>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+(?P<year>\d{4})")
USER_RE = re.compile(r"\[(?P<user>[^\]]+)\]\s")
IP_RE = re.compile(r'Client\s+"::ffff:(?P<ip>[\d.]+)"')

ACTION_MAP = [
    ("FAIL LOGIN", "LOGIN_FAIL"),
    ("OK LOGIN", "LOGIN_SUCCESS"),
    ("STOR", "UPLOAD"),
    ("RETR", "DOWNLOAD"),
    ("FAIL UPLOAD", "UPLOAD"),
    ("FAIL DOWNLOAD", "DOWNLOAD"),
    ("FAIL DELETE", "DELETE"),
    ("FAIL RENAME", "RENAME"),
    ("FAIL MKDIR", "MKDIR"),
    ("FAIL RMDIR", "RMDIR"),
    ("UPLOAD", "UPLOAD"),
    ("DOWNLOAD", "DOWNLOAD"),
    ("DELE", "DELETE"),
    ("RNFR", "RENAME"),
    ("RNTO", "RENAME"),
    ("MKD", "MKDIR"),
    ("RMD", "RMDIR"),
]

PATH_RE = re.compile(r',\s+"?(/[^"]+)"?$')

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}

def parse_ts(raw: str):
    m = TS_RE.match(raw)
    if not m:
        return None
    mon = MONTHS.get(m.group("mon"))
    if not mon:
        return None
    day = int(m.group("day"))
    year = int(m.group("year"))
    hh, mm, ss = map(int, m.group("time").split(":"))
    return datetime(year, mon, day, hh, mm, ss)

def detect_action(raw: str):
    r = raw.upper()
    for needle, act in ACTION_MAP:
        if needle in r:
            return act
    return "OTHER"

def parse_file_target(raw: str):
    m = PATH_RE.search(raw)
    if m:
        return m.group(1)
    # for MKD/RMD in FTP command form: "MKD folder"
    if "MKD " in raw:
        return raw.split("MKD ", 1)[1].strip().strip('"')
    if "RMD " in raw:
        return raw.split("RMD ", 1)[1].strip().strip('"')
    return None

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
        msg = r["message"] or ""
        event_time = r["log_time"] or parse_ts(msg)

        um = USER_RE.search(msg)
        username = um.group("user") if um else None

        im = IP_RE.search(msg)
        ip = im.group("ip") if im else None

        action = detect_action(msg)
        file_target = parse_file_target(msg)

        cur2 = conn.cursor()
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