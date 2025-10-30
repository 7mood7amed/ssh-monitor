#!/usr/bin/env python3
import os
import psycopg2
import hashlib
from datetime import datetime

# === PostgreSQL Connection Info ===
DB_NAME = "logdb"
DB_USER = "hero"
DB_PASS = "hero"
DB_HOST = "localhost"

# === Directory to scan ===
LOG_DIR = "/var/log"

def connect_db():
    """Establish connection to PostgreSQL database."""
    return psycopg2.connect(
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASS,
        host=DB_HOST
    )

def ensure_tables_exist(conn):
    """Create tables for logs and heartbeat if they don't exist."""
    with conn.cursor() as cur:
        # Logs table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id SERIAL PRIMARY KEY,
                filename TEXT,
                log_time TIMESTAMP,
                source TEXT,
                message TEXT,
                hash TEXT UNIQUE
            );
        """)
        # Heartbeat table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS agent_status (
                agent_name TEXT PRIMARY KEY,
                last_heartbeat TIMESTAMP,
                status TEXT
            );
        """)
        conn.commit()

def parse_log_line(line):
    """Try to extract timestamp from a log line."""
    parts = line.strip().split()
    if len(parts) >= 3:
        timestamp_str = " ".join(parts[:3])
        try:
            log_time = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
            log_time = log_time.replace(year=datetime.now().year)
        except ValueError:
            log_time = datetime.now()
    else:
        log_time = datetime.now()
    return log_time, line.strip()

def compute_hash(filename, message):
    """Generate a unique hash for each log entry."""
    raw = f"{filename}-{message}".encode("utf-8", errors="ignore")
    return hashlib.sha256(raw).hexdigest()

def extract_logs():
    """Extract logs recursively and insert into the database."""
    conn = connect_db()
    ensure_tables_exist(conn)
    cur = conn.cursor()

    for root, _, files in os.walk(LOG_DIR):
        for filename in files:
            file_path = os.path.join(root, filename)

            # Skip compressed or rotated logs
            if file_path.endswith((".gz", ".xz", ".1", ".2", ".old")):
                print(f"⏭️ Skipping compressed file: {file_path}")
                continue

            # Only consider valid log files
            if not file_path.endswith(".log") and not file_path.startswith("/var/log/"):
                continue

            try:
                print(f"📄 Processing: {file_path}")
                with open(file_path, "r", errors="ignore") as f:
                    for line in f:
                        if not line.strip():
                            continue
                        log_time, message = parse_log_line(line)
                        log_hash = compute_hash(filename, message)

                        cur.execute("""
                            INSERT INTO logs (filename, log_time, source, message, hash)
                            VALUES (%s, %s, %s, %s, %s)
                            ON CONFLICT (hash) DO NOTHING;
                        """, (filename, log_time, file_path, message, log_hash))

                conn.commit()

            except Exception as e:
                print(f"⚠️ Error reading {file_path}: {e}")

    cur.close()
    conn.close()
    print("✅ Log import completed (duplicates skipped).")

def update_heartbeat():
    """Update or insert heartbeat info for this agent."""
    try:
        conn = connect_db()
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO agent_status (agent_name, last_heartbeat, status)
                VALUES (%s, NOW(), 'active')
                ON CONFLICT (agent_name)
                DO UPDATE SET last_heartbeat = NOW(), status = 'active';
            """, ('raven',))
            conn.commit()
        conn.close()
        print("💓 Heartbeat updated for agent 'raven'")
    except Exception as e:
        print(f"⚠️ Heartbeat update failed: {e}")

if __name__ == "__main__":
    extract_logs()
    update_heartbeat()
