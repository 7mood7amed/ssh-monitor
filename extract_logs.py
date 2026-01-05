# =========================================================
# (2) REPLACE collector on Raven VM
# File: /home/hero/ssh-monitor/extract_logs.py
# NOTE: cursor-based ingestion + SSH parsing (auth.log -> ssh_events)
# =========================================================
#!/usr/bin/env python3
from __future__ import annotations

import os
import re
import ipaddress
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Optional, Tuple

import psycopg2

"""
Cursor-based log collector (NO hash).

- Reads only NEW bytes via public.log_cursors(agent_name, path, inode, byte_offset)
- Inserts raw log lines into public.logs
- Parses SSH-related lines from /var/log/auth.log into public.ssh_events

Env:
  DB_NAME, DB_USER, DB_PASS, DB_HOST, DB_PORT
  AGENT_NAME (default SSH; 'raven' auto-mapped to SSH)
  LOG_DIR (default /var/log)
  LOG_LIMIT (default 20000)
  FIRST_RUN_START_AT_END (default 0)
  ON_ROTATION_START_AT_END (default 1)
"""

DB_NAME = os.environ.get("DB_NAME", "logdb")
DB_USER = os.environ.get("DB_USER", "hero")
DB_PASS = os.environ.get("DB_PASS", "hero")
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = int(os.environ.get("DB_PORT", "5432"))

AGENT_NAME = os.environ.get("AGENT_NAME", "SSH").strip()
if AGENT_NAME.lower() == "raven":
    AGENT_NAME = "SSH"

LOG_DIR = os.environ.get("LOG_DIR", "/var/log")
LOG_LIMIT = int(os.environ.get("LOG_LIMIT", "20000"))

FIRST_RUN_START_AT_END = os.environ.get("FIRST_RUN_START_AT_END", "0").strip() != "0"
ON_ROTATION_START_AT_END = os.environ.get("ON_ROTATION_START_AT_END", "1").strip() != "0"


SKIP_DIR_SUBSTRINGS = ("/var/log/journal/",)
SKIP_FILE_BASENAMES = ("wtmp", "btmp", "lastlog", "faillog")
SKIP_EXTS = (".gz", ".xz", ".zip")

ALLOW_BASENAMES = ("auth.log", "syslog", "messages", "kern.log", "access.log", "error.log")
ALLOW_EXTS = (".log",)

AUTH_LOG_PATH = os.path.join(LOG_DIR, "auth.log")

# SSH patterns (match inside stored line)
# --- SSH patterns (expanded) ---
_RE_ACCEPTED = re.compile(
    r"sshd\[\d+\]:\s+Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)",
    re.IGNORECASE,
)

_RE_FAILED_PASSWORD = re.compile(
    r"sshd\[\d+\]:\s+Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)",
    re.IGNORECASE,
)

_RE_FAILED_PUBLICKEY = re.compile(
    r"sshd\[\d+\]:\s+Failed\s+publickey\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)",
    re.IGNORECASE,
)

_RE_INVALID_USER = re.compile(
    r"sshd\[\d+\]:\s+Invalid\s+user\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)",
    re.IGNORECASE,
)

_RE_AUTH_FAILURE = re.compile(
    r"pam_unix\(sshd:auth\):\s+authentication\s+failure;.*rhost=(?P<ip>\S+).*user=(?P<user>\S*)",
    re.IGNORECASE,
)

_RE_MAX_ATTEMPTS = re.compile(
    r"sshd\[\d+\]:\s+error:\s+maximum authentication attempts exceeded for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)",
    re.IGNORECASE,
)

_RE_SESSION_OPEN = re.compile(
    r"sshd\[\d+\]:\s+pam_unix\(sshd:session\):\s+session\s+opened\s+for\s+user\s+(?P<user>\S+)",
    re.IGNORECASE,
)

_RE_SESSION_CLOSE = re.compile(
    r"sshd\[\d+\]:\s+pam_unix\(sshd:session\):\s+session\s+closed\s+for\s+user\s+(?P<user>\S+)",
    re.IGNORECASE,
)

_RE_RECEIVED_DISCONNECT = re.compile(
    r"sshd\[\d+\]:\s+Received\s+disconnect\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+):\s+(?P<reason>.*)",
    re.IGNORECASE,
)

_RE_CONN_CLOSED = re.compile(
    r"sshd\[\d+\]:\s+(?:Connection\s+closed|Disconnected\s+from)\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)",
    re.IGNORECASE,
)

_RE_NO_IDENT = re.compile(
    r"sshd\[\d+\]:\s+Did not receive identification string from\s+(?P<ip>\S+)",
    re.IGNORECASE,
)


def _normalize_user(u: str | None) -> str | None:
    if not u:
        return None
    u = u.strip()
    if "(" in u:  # hero(uid=1000) -> hero
        u = u.split("(", 1)[0].strip()
    return u or None


def parse_ssh_event(message: str) -> Optional[dict]:
    if "sshd[" not in (message or ""):
        return None

    m = _RE_ACCEPTED.search(message)
    if m:
        method = (m.group("method") or "unknown").lower()
        return {
            "event_type": "login_success",
            "outcome": "success",
            "auth_method": method,
            "username": _normalize_user(m.group("user")),
            "ip": _clean_ip(m.group("ip")),
            "port": int(m.group("port")),
        }

    m = _RE_FAILED_PASSWORD.search(message)
    if m:
        return {
            "event_type": "login_fail",
            "outcome": "fail",
            "auth_method": "password",
            "username": _normalize_user(m.group("user")),
            "ip": _clean_ip(m.group("ip")),
            "port": int(m.group("port")),
        }

    m = _RE_FAILED_PUBLICKEY.search(message)
    if m:
        return {
            "event_type": "login_fail",
            "outcome": "fail",
            "auth_method": "publickey",
            "username": _normalize_user(m.group("user")),
            "ip": _clean_ip(m.group("ip")),
            "port": int(m.group("port")),
        }

    m = _RE_INVALID_USER.search(message)
    if m:
        return {
            "event_type": "login_fail",
            "outcome": "fail",
            "auth_method": "unknown",
            "username": _normalize_user(m.group("user")),
            "ip": _clean_ip(m.group("ip")),
            "port": int(m.group("port")),
        }

    m = _RE_AUTH_FAILURE.search(message)
    if m:
        return {
            "event_type": "login_fail",
            "outcome": "fail",
            "auth_method": "unknown",
            "username": _normalize_user(m.group("user") or None),
            "ip": _clean_ip(m.group("ip")),
            "port": None,
        }

    m = _RE_MAX_ATTEMPTS.search(message)
    if m:
        return {
            "event_type": "login_fail",
            "outcome": "fail",
            "auth_method": "unknown",
            "username": _normalize_user(m.group("user")),
            "ip": _clean_ip(m.group("ip")),
            "port": int(m.group("port")),
        }

    m = _RE_SESSION_OPEN.search(message)
    if m:
        return {"event_type": "session_open", "outcome": "info", "auth_method": None, "username": _normalize_user(m.group("user")), "ip": None, "port": None}

    m = _RE_SESSION_CLOSE.search(message)
    if m:
        return {"event_type": "session_close", "outcome": "info", "auth_method": None, "username": _normalize_user(m.group("user")), "ip": None, "port": None}

    m = _RE_RECEIVED_DISCONNECT.search(message) or _RE_CONN_CLOSED.search(message)
    if m:
        return {
            "event_type": "disconnect",
            "outcome": "info",
            "auth_method": None,
            "username": None,
            "ip": _clean_ip(m.group("ip")),
            "port": int(m.group("port")),
        }

    m = _RE_NO_IDENT.search(message)
    if m:
        return {
            "event_type": "disconnect",
            "outcome": "info",
            "auth_method": None,
            "username": None,
            "ip": _clean_ip(m.group("ip")),
            "port": None,
        }

    return None



@dataclass(frozen=True)
class CursorState:
    inode: Optional[int]
    byte_offset: int


def connect_db():
    return psycopg2.connect(
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASS,
        host=DB_HOST,
        port=DB_PORT,
    )


def ensure_tables(conn) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS public.agent_status (
              agent_name TEXT PRIMARY KEY,
              last_heartbeat TIMESTAMP WITHOUT TIME ZONE,
              status TEXT
            );
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS public.log_cursors (
              agent_name  TEXT NOT NULL REFERENCES public.agent_status(agent_name) ON DELETE CASCADE,
              path        TEXT NOT NULL,
              inode       BIGINT,
              byte_offset BIGINT NOT NULL DEFAULT 0,
              updated_at  TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW(),
              PRIMARY KEY (agent_name, path)
            );
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS public.ssh_events (
              id          BIGSERIAL PRIMARY KEY,
              log_id      BIGINT REFERENCES public.logs(id) ON DELETE CASCADE,
              agent_name  TEXT NOT NULL,
              event_time  TIMESTAMP WITHOUT TIME ZONE NOT NULL,
              event_type  TEXT NOT NULL,
              outcome     TEXT,
              auth_method TEXT,
              username    TEXT,
              ip          TEXT,
              port        INTEGER,
              raw         TEXT
            );
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_ssh_events_time ON public.ssh_events(event_time DESC);")
    conn.commit()


def upsert_heartbeat(conn) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO public.agent_status (agent_name, last_heartbeat, status)
            VALUES (%s, NOW(), 'active')
            ON CONFLICT (agent_name)
            DO UPDATE SET last_heartbeat = NOW(), status = 'active';
            """,
            (AGENT_NAME,),
        )
    conn.commit()


def _allowed_file(path: str) -> bool:
    p = (path or "").lower()
    if any(s in p for s in SKIP_DIR_SUBSTRINGS):
        return False

    base = os.path.basename(p)
    if base in SKIP_FILE_BASENAMES:
        return False
    if any(p.endswith(ext) for ext in SKIP_EXTS):
        return False

    if base in ALLOW_BASENAMES:
        return True
    if any(p.endswith(ext) for ext in ALLOW_EXTS):
        return True
    return False


def iter_log_files(root_dir: str) -> Iterable[str]:
    for root, _, files in os.walk(root_dir):
        for name in files:
            path = os.path.join(root, name)
            if _allowed_file(path):
                yield path


def load_cursor(conn, path: str) -> CursorState:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT inode, byte_offset
            FROM public.log_cursors
            WHERE agent_name = %s AND path = %s;
            """,
            (AGENT_NAME, path),
        )
        row = cur.fetchone()

    if not row:
        return CursorState(inode=None, byte_offset=0)
    inode, byte_offset = row
    return CursorState(inode=int(inode) if inode is not None else None, byte_offset=int(byte_offset or 0))


def save_cursor(conn, path: str, inode: Optional[int], byte_offset: int) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO public.log_cursors (agent_name, path, inode, byte_offset, updated_at)
            VALUES (%s, %s, %s, %s, NOW())
            ON CONFLICT (agent_name, path)
            DO UPDATE SET inode = EXCLUDED.inode,
                          byte_offset = EXCLUDED.byte_offset,
                          updated_at = NOW();
            """,
            (AGENT_NAME, path, inode, int(byte_offset)),
        )
    conn.commit()


def compute_start(prev: CursorState, current_inode: Optional[int], current_size: int) -> int:
    if prev.inode is None:
        return current_size if FIRST_RUN_START_AT_END else 0

    rotated_or_truncated = (
        (current_inode is not None and prev.inode != current_inode) or current_size < prev.byte_offset
    )
    if rotated_or_truncated:
        return current_size if ON_ROTATION_START_AT_END else 0

    return min(prev.byte_offset, current_size)


def parse_syslog_time(line: str) -> datetime:
    # "Jan 05 20:45:45 ..."
    parts = (line or "").split()
    if len(parts) >= 3:
        ts_str = " ".join(parts[:3])
        try:
            return datetime.strptime(ts_str, "%b %d %H:%M:%S").replace(year=datetime.now().year)
        except ValueError:
            pass
    return datetime.now()


def insert_log_row(conn, file_path: str, log_time: datetime, message: str) -> Optional[int]:
    msg = (message or "").replace("\x00", "").strip()
    if not msg:
        return None

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO public.logs (filename, log_time, source, message, agent_name)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id;
            """,
            (os.path.basename(file_path), log_time, file_path, msg, AGENT_NAME),
        )
        return int(cur.fetchone()[0])


def _clean_ip(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    ip = raw.strip()
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        return None


def parse_ssh_event(message: str) -> Optional[dict]:
    if "sshd[" not in (message or ""):
        return None

    m = _RE_ACCEPTED.search(message)
    if m:
        method = (m.group("method") or "unknown").lower()
        return {
            "event_type": "login_success",
            "outcome": "success",
            "auth_method": method,
            "username": m.group("user"),
            "ip": _clean_ip(m.group("ip")),
            "port": int(m.group("port")),
        }

    m = _RE_FAILED.search(message)
    if m:
        return {
            "event_type": "login_fail",
            "outcome": "fail",
            "auth_method": "password",
            "username": m.group("user"),
            "ip": _clean_ip(m.group("ip")),
            "port": int(m.group("port")),
        }

    m = _RE_SESSION_OPEN.search(message)
    if m:
        return {
            "event_type": "session_open",
            "outcome": "info",
            "auth_method": None,
            "username": m.group("user"),
            "ip": None,
            "port": None,
        }

    m = _RE_SESSION_CLOSE.search(message)
    if m:
        return {
            "event_type": "session_close",
            "outcome": "info",
            "auth_method": None,
            "username": m.group("user"),
            "ip": None,
            "port": None,
        }

    m = _RE_DISCONNECT.search(message)
    if m and (m.group("ip") or m.group("user")):
        return {
            "event_type": "disconnect",
            "outcome": "info",
            "auth_method": None,
            "username": (m.group("user") or "").strip() or None,
            "ip": _clean_ip(m.group("ip")),
            "port": int(m.group("port")) if m.group("port") and m.group("port").isdigit() else None,
        }

    return None


def insert_ssh_event(conn, log_id: int, event_time: datetime, event: dict, raw: str) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO public.ssh_events
              (log_id, agent_name, event_time, event_type, outcome, auth_method, username, ip, port, raw)
            VALUES
              (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
            """,
            (
                log_id,
                AGENT_NAME,
                event_time,
                event["event_type"],
                event.get("outcome"),
                event.get("auth_method"),
                event.get("username"),
                event.get("ip"),
                event.get("port"),
                raw,
            ),
        )


def trim_logs(conn) -> None:
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM public.logs;")
        total = int(cur.fetchone()[0] or 0)
        if total <= LOG_LIMIT:
            return
        excess = total - LOG_LIMIT
        cur.execute(
            """
            DELETE FROM public.logs
            WHERE id IN (
              SELECT id FROM public.logs
              ORDER BY log_time ASC
              LIMIT %s
            );
            """,
            (excess,),
        )
    conn.commit()


def ingest_file(conn, path: str) -> int:
    try:
        st = os.stat(path)
        inode = int(st.st_ino)
        size = int(st.st_size)
    except Exception:
        return 0

    prev = load_cursor(conn, path)
    start = compute_start(prev, inode, size)

    inserted = 0
    try:
        with open(path, "r", errors="ignore") as f:
            f.seek(start)
            for line in f:
                if not line.strip():
                    continue
                log_time = parse_syslog_time(line)
                log_id = insert_log_row(conn, path, log_time, line)
                if log_id is None:
                    continue

                # SSH parsing only for auth.log
                if path == AUTH_LOG_PATH:  
                    event = parse_ssh_event(line)
                    if event:
                        insert_ssh_event(conn, log_id, log_time, event, line.strip())

                inserted += 1

            conn.commit()
            end_offset = f.tell()

        save_cursor(conn, path, inode, end_offset)
        return inserted
    except Exception:
        conn.rollback()
        return 0


def main():
    conn = connect_db()
    try:
        ensure_tables(conn)
        upsert_heartbeat(conn)

        scanned = 0
        inserted = 0
        for path in iter_log_files(LOG_DIR):
            scanned += 1
            inserted += ingest_file(conn, path)

        trim_logs(conn)
        print(f"✅ Done. agent={AGENT_NAME} scanned={scanned} inserted={inserted} db={DB_HOST}:{DB_PORT}/{DB_NAME}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
