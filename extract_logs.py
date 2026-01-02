# =========================================
# File: ssh-monitor/extract_logs.py
# =========================================
#!/usr/bin/env python3
import os
import psycopg2
import hashlib
import re
from datetime import datetime, timezone

"""
Multi-agent ready log collector.

Run example (Raven):
  AGENT_NAME=raven python3 extract_logs.py

Run on Falcon (collector runs on Falcon but writes into Raven DB):
  AGENT_NAME=falcon DB_HOST=192.168.56.103 python3 extract_logs.py
"""

# --- Config via env (safe for multi-VM) ---
DB_NAME = os.environ.get("DB_NAME", "logdb")
DB_USER = os.environ.get("DB_USER", "hero")
DB_PASS = os.environ.get("DB_PASS", "hero")
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = int(os.environ.get("DB_PORT", "5432"))

AGENT_NAME = os.environ.get("AGENT_NAME", "raven")

LOG_DIR = os.environ.get("LOG_DIR", "/var/log")
LOG_LIMIT = int(os.environ.get("LOG_LIMIT", "20000"))

_APACHE_TS_RE = re.compile(
    r"\[(?P<ts>\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+\-]\d{4})\]"
)


def _looks_like_apache_access(file_path: str) -> bool:
    fp = (file_path or "").lower()
    return ("apache2" in fp and "access" in fp) or fp.endswith("access.log")


def connect_db():
    return psycopg2.connect(
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASS,
        host=DB_HOST,
        port=DB_PORT,
    )


def ensure_tables_exist(conn):
    with conn.cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_status (
                agent_name TEXT PRIMARY KEY,
                last_heartbeat TIMESTAMP,
                status TEXT
            );
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS logs (
                id SERIAL PRIMARY KEY,
                filename TEXT,
                log_time TIMESTAMP,
                source TEXT,
                message TEXT,
                hash TEXT UNIQUE,
                agent_name TEXT REFERENCES agent_status(agent_name) ON DELETE CASCADE
            );
            """
        )
        conn.commit()


def trim_old_logs(conn):
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM logs;")
        total = cur.fetchone()[0]
        if total <= LOG_LIMIT:
            return

        excess = total - LOG_LIMIT
        cur.execute(
            """
            DELETE FROM logs
            WHERE id IN (
                SELECT id FROM logs
                ORDER BY log_time ASC
                LIMIT %s
            );
            """,
            (excess,),
        )
        conn.commit()


def parse_log_line(line: str, file_path: str):
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
        timestamp_str = " ".join(parts[:3])
        try:
            log_time = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
            log_time = log_time.replace(year=datetime.now().year)
            return log_time, raw
        except ValueError:
            pass

    return datetime.now(), raw


def compute_hash(file_path: str, message: str):
    raw = f"{file_path}-{message}".encode("utf-8", errors="ignore")
    return hashlib.sha256(raw).hexdigest()


def update_heartbeat(conn):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO agent_status (agent_name, last_heartbeat, status)
            VALUES (%s, NOW(), 'active')
            ON CONFLICT (agent_name)
            DO UPDATE SET last_heartbeat = NOW(), status = 'active';
            """,
            (AGENT_NAME,),
        )
        conn.commit()


def extract_logs():
    conn = connect_db()
    ensure_tables_exist(conn)

    # Heartbeat first so FK insert always works
    update_heartbeat(conn)

    cursor = conn.cursor()
    for root, _, files in os.walk(LOG_DIR):
        for filename in files:
            file_path = os.path.join(root, filename)

            if file_path.endswith((".gz", ".xz", ".1", ".2", ".old")):
                continue

            try:
                with open(file_path, "r", errors="ignore") as f:
                    for line in f:
                        if not line.strip():
                            continue

                        log_time, message = parse_log_line(line, file_path)
                        log_hash = compute_hash(file_path, message)

                        cursor.execute(
                            """
                            INSERT INTO logs (filename, log_time, source, message, hash, agent_name)
                            VALUES (%s, %s, %s, %s, %s, %s)
                            ON CONFLICT (hash) DO NOTHING;
                            """,
                            (filename, log_time, file_path, message, log_hash, AGENT_NAME),
                        )
                conn.commit()
            except Exception as e:
                print(f"⚠ Error reading {file_path}: {e}")

    cursor.close()
    trim_old_logs(conn)
    conn.close()
    print(f"✅ Log import completed for agent: {AGENT_NAME}")


if __name__ == "__main__":
    extract_logs()