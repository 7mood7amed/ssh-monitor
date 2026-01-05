# File: ssh-monitor/extract_logs.py
#!/usr/bin/env python3
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Optional, Tuple

import psycopg2

DB_NAME = os.environ.get("DB_NAME", "logdb")
DB_USER = os.environ.get("DB_USER", "hero")
DB_PASS = os.environ.get("DB_PASS", "hero")
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = int(os.environ.get("DB_PORT", "5432"))

# NOTE #2: default is SSH (service label), not raven (machine label)
AGENT_NAME = os.environ.get("AGENT_NAME", "SSH").strip()
if AGENT_NAME.lower() == "raven":
    AGENT_NAME = "SSH"

LOG_DIR = os.environ.get("LOG_DIR", "/var/log")
LOG_LIMIT = int(os.environ.get("LOG_LIMIT", "20000"))

FIRST_RUN_START_AT_END = os.environ.get("FIRST_RUN_START_AT_END", "0").strip() != "0"
ON_ROTATION_START_AT_END = os.environ.get("ON_ROTATION_START_AT_END", "1").strip() != "0"

SKIP_EXTS = (".gz", ".xz", ".zip", ".1", ".2", ".old")

SKIP_DIR_SUBSTRINGS = (
    "/var/log/journal/",
)
SKIP_FILE_BASENAMES = (
    "wtmp",
    "btmp",
    "lastlog",
    "faillog",
)
SKIP_FILE_PREFIXES = (
    "sa",  # /var/log/sysstat/saXX are binary
)

ALLOW_EXTS = (".log",)
ALLOW_BASENAMES = (
    "auth.log",
    "syslog",
    "messages",
    "kern.log",
)

_APACHE_TS_RE = re.compile(
    r"\[(?P<ts>\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+\-]\d{4})\]"
)


@dataclass(frozen=True)
class CursorState:
    inode: Optional[int]
    byte_offset: int


def connect_db():
    return psycopg2.connect(
        dbname=DB_NAME, user=DB_USER, password=DB_PASS, host=DB_HOST, port=DB_PORT
    )


def ensure_tables_exist(conn) -> None:
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
            CREATE INDEX IF NOT EXISTS idx_log_cursors_updated_at
            ON public.log_cursors(updated_at);
            """
        )
    conn.commit()


def update_heartbeat(conn) -> None:
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


def trim_old_logs(conn) -> None:
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


def _looks_like_apache_access(path: str) -> bool:
    p = (path or "").lower()
    return ("apache2" in p and "access" in p) or p.endswith("access.log")


def _is_binary_file(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            chunk = f.read(4096)
        return b"\x00" in chunk
    except Exception:
        return True


def _allowed_file(path: str) -> bool:
    p = (path or "").lower()

    if any(s in p for s in SKIP_DIR_SUBSTRINGS):
        return False

    base = os.path.basename(p)

    if base in SKIP_FILE_BASENAMES:
        return False

    for pref in SKIP_FILE_PREFIXES:
        if base.startswith(pref) and base[len(pref) :].isdigit():
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
            if not _allowed_file(path):
                continue
            yield path


def parse_log_line(line: str, file_path: str) -> Tuple[datetime, str]:
    raw = (line or "").strip()
    if not raw:
        return datetime.now(), ""

    if _looks_like_apache_access(file_path):
        m = _APACHE_TS_RE.search(raw)
        if m:
            try:
                ts = datetime.strptime(m.group("ts"), "%d/%b/%Y:%H:%M:%S %z")
                ts_utc = ts.astimezone(timezone.utc).replace(tzinfo=None, microsecond=0)
                return ts_utc, raw
            except ValueError:
                pass

    parts = raw.split()
    if len(parts) >= 3:
        ts_str = " ".join(parts[:3])
        try:
            t = datetime.strptime(ts_str, "%b %d %H:%M:%S").replace(year=datetime.now().year)
            return t, raw
        except ValueError:
            pass

    return datetime.now(), raw


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
    return CursorState(
        inode=int(inode) if inode is not None else None,
        byte_offset=int(byte_offset or 0),
    )


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


def compute_start_offset(prev: CursorState, current_inode: Optional[int], current_size: int) -> int:
    if prev.inode is None:
        return current_size if FIRST_RUN_START_AT_END else 0

    rotated_or_truncated = (
        (current_inode is not None and prev.inode != current_inode)
        or current_size < prev.byte_offset
    )
    if rotated_or_truncated:
        return current_size if ON_ROTATION_START_AT_END else 0

    return min(prev.byte_offset, current_size)


def insert_log_row(conn, filename: str, log_time: datetime, source: str, message: str) -> None:
    message = (message or "").replace("\x00", "")
    if not message:
        return
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO public.logs (filename, log_time, source, message, agent_name)
            VALUES (%s, %s, %s, %s, %s);
            """,
            (filename, log_time, source, message, AGENT_NAME),
        )


def ingest_file(conn, path: str) -> int:
    try:
        st = os.stat(path)
        inode = int(st.st_ino)
        size = int(st.st_size)
    except Exception:
        return 0

    if _is_binary_file(path):
        return 0

    prev = load_cursor(conn, path)
    start = compute_start_offset(prev, inode, size)

    inserted = 0
    try:
        with open(path, "r", errors="ignore") as f:
            f.seek(start)
            for line in f:
                if not line.strip():
                    continue
                log_time, msg = parse_log_line(line, path)
                if not msg:
                    continue
                insert_log_row(conn, os.path.basename(path), log_time, path, msg)
                inserted += 1

            conn.commit()
            end_offset = f.tell()

        save_cursor(conn, path, inode, end_offset)
        return inserted
    except Exception as e:
        conn.rollback()
        print(f"⚠ Error reading {path}: {e}")
        return 0


def extract_logs():
    conn = connect_db()
    try:
        ensure_tables_exist(conn)
        update_heartbeat(conn)

        total_inserted = 0
        scanned = 0
        readable = 0

        for path in iter_log_files(LOG_DIR):
            scanned += 1
            n = ingest_file(conn, path)
            readable += 1
            total_inserted += n

        trim_old_logs(conn)

        print(
            f"✅ Done. agent={AGENT_NAME} scanned={scanned} readable={readable} inserted={total_inserted} "
            f"db={DB_HOST}:{DB_PORT}/{DB_NAME}"
        )
    finally:
        conn.close()


if __name__ == "__main__":
    extract_logs()
