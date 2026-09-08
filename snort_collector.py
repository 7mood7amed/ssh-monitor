#!/usr/bin/env python3
"""
snort_collector.py
-------------------
Ingests Snort output into public.snort_alerts from two sources:

1. The alert_fast log (/var/log/snort/snort.alert.fast) -- one line per
   signature match (rule-based alerts: exploit signatures, SQLi, etc.).
2. The sfportscan preprocessor's own logfile (/var/log/snort/portscan.log)
   -- multi-line blocks, one per detected scan. sfportscan does NOT emit
   through the normal alert pipeline unless the (subscriber-only) GID 122
   preprocessor rule stubs are installed, which this box doesn't have, so
   its scan/sweep detections only ever show up here. Confirmed live: a test
   port scan showed up in portscan.log but never in alert_fast.

Both are cursor-based, reusing the same log_cursors table extract_logs.py
already uses for tailing auth.log/apache logs (agent_name='SNORT', keyed by
path so both files get independent cursors).

Log growth is handled separately by logrotate (see snort_logrotate.conf),
not by this script -- truncating a file this script is reading from, while
Snort might be appending to it concurrently, is a real race that can lose
alerts. logrotate's copytruncate handles that safely.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

import psycopg2

# ----------------------------
# Config (env vars)
# ----------------------------
DB_NAME = os.environ.get("DB_NAME", "logdb")
DB_USER = os.environ.get("DB_USER", "hero")
DB_PASS = os.environ.get("DB_PASS", "hero")
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = int(os.environ.get("DB_PORT", "5432"))

AGENT_NAME = os.environ.get("AGENT_NAME", "SNORT")
SNORT_ALERT_LOG = os.environ.get("SNORT_ALERT_LOG", "/var/log/snort/snort.alert.fast")
SNORT_PORTSCAN_LOG = os.environ.get("SNORT_PORTSCAN_LOG", "/var/log/snort/portscan.log")

PRIORITY_TO_SEVERITY = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}


def get_conn():
    return psycopg2.connect(
        dbname=DB_NAME, user=DB_USER, password=DB_PASS, host=DB_HOST, port=DB_PORT,
    )


# ----------------------------
# Cursor (log_cursors table, same shape extract_logs.py uses)
# ----------------------------
@dataclass(frozen=True)
class CursorState:
    inode: Optional[int]
    byte_offset: int


def load_cursor(conn, path: str) -> CursorState:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT inode, byte_offset FROM public.log_cursors
            WHERE agent_name = %s AND path = %s;
            """,
            (AGENT_NAME, path),
        )
        row = cur.fetchone()
    if not row:
        return CursorState(inode=None, byte_offset=0)
    inode, byte_offset = row
    return CursorState(inode=int(inode) if inode is not None else None, byte_offset=int(byte_offset or 0))


def save_cursor(conn, path: str, inode, byte_offset: int) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO public.log_cursors (agent_name, path, inode, byte_offset, updated_at)
            VALUES (%s, %s, %s, %s, NOW())
            ON CONFLICT (agent_name, path)
            DO UPDATE SET inode = EXCLUDED.inode, byte_offset = EXCLUDED.byte_offset, updated_at = NOW();
            """,
            (AGENT_NAME, path, inode, int(byte_offset)),
        )
    conn.commit()


def upsert_agent_heartbeat(cur, agent: str) -> None:
    cur.execute(
        """
        INSERT INTO public.agent_status (agent_name, last_heartbeat)
        VALUES (%s, NOW())
        ON CONFLICT (agent_name)
        DO UPDATE SET last_heartbeat = NOW();
        """,
        (agent,),
    )


# ----------------------------
# alert_fast line parsing
#
# Format:
#   MM/DD-HH:MM:SS.ffffff  [**] [gid:sid:rev] message [**] [Classification: c] [Priority: N] {PROTO} SRC[:PORT] -> DST[:PORT]
#
# Classification/Priority are optional (rules without a classtype/priority
# set omit them); ICMP lines have no ports.
# ----------------------------
_GID_SID_REV_RE = re.compile(r"\[(\d+):(\d+):(\d+)\]")
_CLASSIFICATION_RE = re.compile(r"\[Classification:\s*([^\]]*)\]")
_PRIORITY_RE = re.compile(r"\[Priority:\s*(\d+)\]")
_PROTO_RE = re.compile(r"\{([A-Za-z0-9]+)\}")


def _split_ip_port(token: str) -> tuple[str, Optional[int]]:
    token = token.strip()
    if ":" in token:
        ip, _, port = token.rpartition(":")
        if port.isdigit():
            return ip, int(port)
    return token, None


def parse_alert_line(line: str) -> Optional[dict]:
    line = line.strip()
    if not line or "[**]" not in line:
        return None

    parts = line.split("[**]")
    if len(parts) < 3:
        return None

    header, msg_part, rest = parts[0], parts[1], "[**]".join(parts[2:])

    gid_sid_rev = _GID_SID_REV_RE.search(header + msg_part)
    if not gid_sid_rev:
        return None
    gid, sid, rev = (int(x) for x in gid_sid_rev.groups())

    message = _GID_SID_REV_RE.sub("", msg_part).strip()

    classification_m = _CLASSIFICATION_RE.search(rest)
    classification = classification_m.group(1).strip() if classification_m else None

    priority_m = _PRIORITY_RE.search(rest)
    priority = int(priority_m.group(1)) if priority_m else 4  # default to lowest if unset

    proto_m = _PROTO_RE.search(rest)
    protocol = proto_m.group(1) if proto_m else None

    if "->" not in rest:
        return None
    endpoints = rest.rsplit("}", 1)[-1] if "}" in rest else rest
    src_raw, _, dst_raw = endpoints.partition("->")
    src_ip, src_port = _split_ip_port(src_raw)
    dst_ip, dst_port = _split_ip_port(dst_raw)

    return {
        "gid": gid, "sid": sid, "rev": rev,
        "message": message,
        "classification": classification,
        "priority": priority,
        "protocol": protocol,
        "src_ip": src_ip or None, "src_port": src_port,
        "dst_ip": dst_ip or None, "dst_port": dst_port,
        "severity": PRIORITY_TO_SEVERITY.get(priority, "LOW"),
        "raw": line,
    }


# ----------------------------
# portscan.log block parsing
#
# Format (blank-line-separated blocks):
#   Time: MM/DD-HH:MM:SS.ffffff
#   event_ref: N
#   SRC_IP -> DST_IP (portscan) TCP Portscan
#   Priority Count: N
#   Connection Count: N
#   IP Count: N
#   Scanner IP Range: X:Y
#   Port/Proto Count: N
#   Port/Proto Range: X:Y
#
# sfportscan has no rule-based priority; every block is treated as HIGH
# (matches how nmap_new_port_rule treats a freshly-discovered open port).
# ----------------------------
def parse_portscan_block(block: str) -> Optional[dict]:
    lines = [l.strip() for l in block.strip().splitlines() if l.strip()]
    endpoint_line = next((l for l in lines if "(portscan)" in l and "->" in l), None)
    if endpoint_line is None:
        return None

    src_raw, _, rest = endpoint_line.partition("->")
    dst_raw, _, type_desc = rest.partition("(portscan)")
    src_ip = src_raw.strip() or None
    dst_ip = dst_raw.strip() or None
    type_desc = type_desc.strip()
    protocol = type_desc.split()[0] if type_desc else None

    priority = 2  # HIGH
    return {
        "gid": 122, "sid": 0, "rev": 0,
        "message": f"Portscan: {type_desc}" if type_desc else "Portscan detected",
        "classification": "Network Scan Detected",
        "priority": priority,
        "protocol": protocol,
        "src_ip": src_ip, "src_port": None,
        "dst_ip": dst_ip, "dst_port": None,
        "severity": PRIORITY_TO_SEVERITY.get(priority, "LOW"),
        "raw": block.strip(),
    }


def insert_alert(cur, parsed: dict) -> None:
    cur.execute(
        """
        INSERT INTO public.snort_alerts
            (gid, sid, rev, message, classification, priority, protocol,
             src_ip, src_port, dst_ip, dst_port, severity, raw)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s);
        """,
        (
            parsed["gid"], parsed["sid"], parsed["rev"], parsed["message"],
            parsed["classification"], parsed["priority"], parsed["protocol"],
            parsed["src_ip"], parsed["src_port"], parsed["dst_ip"], parsed["dst_port"],
            parsed["severity"], parsed["raw"],
        ),
    )


def _tail_start(prev: CursorState, st: os.stat_result) -> int:
    rotated_or_truncated = (
        (prev.inode is not None and prev.inode != st.st_ino) or st.st_size < prev.byte_offset
    )
    return 0 if (prev.inode is None or rotated_or_truncated) else min(prev.byte_offset, st.st_size)


def process_alert_fast(conn) -> int:
    if not os.path.exists(SNORT_ALERT_LOG):
        return 0

    st = os.stat(SNORT_ALERT_LOG)
    prev = load_cursor(conn, SNORT_ALERT_LOG)
    start = _tail_start(prev, st)

    inserted = 0
    with open(SNORT_ALERT_LOG, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(start)
        with conn:
            with conn.cursor() as cur:
                for line in f:
                    parsed = parse_alert_line(line)
                    if parsed is None:
                        continue
                    insert_alert(cur, parsed)
                    inserted += 1
        end_offset = f.tell()

    save_cursor(conn, SNORT_ALERT_LOG, st.st_ino, end_offset)
    return inserted


def process_portscan_log(conn) -> int:
    if not os.path.exists(SNORT_PORTSCAN_LOG):
        return 0

    st = os.stat(SNORT_PORTSCAN_LOG)
    prev = load_cursor(conn, SNORT_PORTSCAN_LOG)
    start = _tail_start(prev, st)

    inserted = 0
    with open(SNORT_PORTSCAN_LOG, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(start)
        new_text = f.read()
        end_offset = f.tell()

    with conn:
        with conn.cursor() as cur:
            for block in new_text.split("\n\n"):
                parsed = parse_portscan_block(block)
                if parsed is None:
                    continue
                insert_alert(cur, parsed)
                inserted += 1

    save_cursor(conn, SNORT_PORTSCAN_LOG, st.st_ino, end_offset)
    return inserted


def main():
    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                upsert_agent_heartbeat(cur, AGENT_NAME)

        alert_count = process_alert_fast(conn)
        portscan_count = process_portscan_log(conn)

        print(f"OK: ingested {alert_count} signature alert(s), {portscan_count} portscan event(s), agent={AGENT_NAME}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
