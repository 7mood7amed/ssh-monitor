#!/usr/bin/env python3
import os
import subprocess
import time
from collections import defaultdict, deque
from datetime import datetime

import psycopg2


INTERFACE = os.environ.get("SCAN_INTERFACE", "enp0s8")
WINDOW_SECONDS = int(os.environ.get("SCAN_WINDOW_SECONDS", "20"))
PORT_THRESHOLD = int(os.environ.get("SCAN_PORT_THRESHOLD", "10"))
DEDUPE_MINUTES = int(os.environ.get("SCAN_DEDUPE_MINUTES", "10"))

DB_NAME = os.environ.get("DB_NAME", "logdb")
DB_USER = os.environ.get("DB_USER", "hero")
DB_PASS = os.environ.get("DB_PASS", "hero")
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = int(os.environ.get("DB_PORT", "5432"))

events = defaultdict(deque)


def get_conn():
    return psycopg2.connect(
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASS,
        host=DB_HOST,
        port=DB_PORT,
    )


def create_scan_alert(scanner_ip, target_ip, ports):
    ports_sorted = sorted(ports, key=lambda p: int(p) if str(p).isdigit() else 999999)
    ports_text = ", ".join(ports_sorted[:25])

    title = "Possible Port Scan Detected"
    priority = "high"
    source = "tshark"

    description = (
        f"tshark detected scan-like SYN traffic from {scanner_ip} to {target_ip}. "
        f"The source touched {len(ports_sorted)} unique destination ports within "
        f"{WINDOW_SECONDS} seconds. Observed ports: {ports_text}."
    )

    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                # Prevent duplicate alerts for the same scanner in a short time window
                cur.execute(
                    """
                    SELECT id
                    FROM alerts
                    WHERE title = %s
                      AND ip_address = %s
                      AND source = %s
                      AND status <> 'resolved'
                      AND created_at >= NOW() - (%s || ' minutes')::interval
                    LIMIT 1;
                    """,
                    (title, scanner_ip, source, DEDUPE_MINUTES),
                )

                existing = cur.fetchone()
                if existing:
                    print(
                        f"[INFO] Duplicate scan alert suppressed for scanner={scanner_ip}",
                        flush=True,
                    )
                    return

                cur.execute(
                    """
                    INSERT INTO alerts
                        (source, priority, title, description, user_name, ip_address, file_target)
                    VALUES
                        (%s, %s, %s, %s, %s, %s, %s)
                    RETURNING id;
                    """,
                    (
                        source,
                        priority,
                        title,
                        description,
                        None,
                        scanner_ip,
                        target_ip,
                    ),
                )

                alert_id = cur.fetchone()[0]
                print(
                    f"[DB] Alert inserted id={alert_id} scanner={scanner_ip} target={target_ip}",
                    flush=True,
                )
    finally:
        conn.close()


def main():
    cmd = [
        "tshark",
        "-i",
        INTERFACE,
        "-l",
        "-Y",
        "tcp.flags.syn == 1 && tcp.flags.ack == 0",
        "-T",
        "fields",
        "-e",
        "frame.time_epoch",
        "-e",
        "ip.src",
        "-e",
        "ip.dst",
        "-e",
        "tcp.dstport",
    ]

    print("[*] Raven tshark scan detector started", flush=True)
    print(f"[*] Interface: {INTERFACE}", flush=True)
    print(
        f"[*] Rule: {PORT_THRESHOLD}+ unique ports within {WINDOW_SECONDS}s",
        flush=True,
    )

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1,
    )

    for line in process.stdout:
        parts = line.strip().split()
        if len(parts) < 4:
            continue

        try:
            src_ip = parts[1]
            dst_ip = parts[2]
            dst_port = parts[3]
        except Exception:
            continue

        now = time.time()
        q = events[src_ip]
        q.append((now, dst_ip, dst_port))

        while q and now - q[0][0] > WINDOW_SECONDS:
            q.popleft()

        unique_ports = {port for _, _, port in q}
        latest_target = dst_ip

        if len(unique_ports) >= PORT_THRESHOLD:
            print(
                f"[ALERT] Possible port scan detected | "
                f"scanner={src_ip} target={latest_target} "
                f"unique_ports={len(unique_ports)} ports={sorted(unique_ports)}",
                flush=True,
            )

            create_scan_alert(src_ip, latest_target, unique_ports)

            q.clear()


if __name__ == "__main__":
    main()