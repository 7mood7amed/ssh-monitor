import re
import subprocess
from datetime import datetime, timedelta
import psycopg2

DB_CONFIG = {
    "dbname": "logdb",
    "user": "hero"
}

# Interface where Kali traffic arrives
INTERFACE = "enp0s8"

# Exclude these ports entirely — they generate constant background noise
EXCLUDED_PORTS = {"5000", "3000", "443", "8080"}

SUSPICIOUS_HTTP_PATHS = [
    "/admin",
    "/login",
    "/phpmyadmin",
    "/phppgadmin",
    "/wp-login.php",
    "/wp-admin",
    "/.env",
    "/config",
    "/backup",
    "/uploads",
    "/shell",
    "/cmd",
    "/console",
    "/server-status",
]


def is_excluded(line):
    """Skip dashboard API traffic and other known noise ports."""
    for port in EXCLUDED_PORTS:
        if f"→ {port} " in line or f"→ {port}[" in line or f" {port} →" in line:
            return True
    return False


def is_dns(line):
    upper = line.upper()
    return (
        " DNS " in upper
        or re.search(r"\b53\s*→", line)
        or re.search(r"→\s*53\b", line)
    )


def is_suspicious_http(line):
    lower = line.lower()
    if "http" not in lower and " 80 " not in lower:
        return False
    return any(path in lower for path in SUSPICIOUS_HTTP_PATHS)


def parse_packet_line(line):
    """Pull structured fields out of a tshark one-line-per-packet output row.

    Format: "<num> <time> <src> → <dst> <proto> <len> <info...>", with a
    second "<sport> → <dport>" pair inside <info> for TCP/UDP.
    """
    parts = line.strip().split()
    arrows = [i for i, p in enumerate(parts) if p in ("→", "->")]
    if not arrows or arrows[0] < 1:
        return None

    first = arrows[0]
    if first + 2 >= len(parts):
        return None

    src_ip = parts[first - 1]
    dst_ip = parts[first + 1]
    protocol = parts[first + 2]

    length = None
    if len(parts) > first + 3 and parts[first + 3].isdigit():
        length = int(parts[first + 3])

    info = " ".join(parts[first + 4:]) if len(parts) > first + 4 else ""

    src_port = dst_port = None
    if len(arrows) > 1:
        second = arrows[1]
        if (
            second > first
            and parts[second - 1].isdigit()
            and second + 1 < len(parts)
            and parts[second + 1].isdigit()
        ):
            src_port = int(parts[second - 1])
            dst_port = int(parts[second + 1])

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "length": length,
        "info": info,
    }


def classify_anomaly(line, dns_count):
    # ICMP sweep and SYN/port scan detection moved to Snort (sfportscan
    # preprocessor + ICMP rules -- more sophisticated than a raw packet
    # count, see alerts_engine.py's snort_alert_rule). Kept here: DNS
    # beaconing and the curated suspicious-HTTP-path list, which are
    # lab-specific behavior checks Snort's generic rules wouldn't flag.
    if is_dns(line) and dns_count >= 8:
        return "dns_burst", "high"
    if is_suspicious_http(line):
        return "http_probe", "high"
    return None, "low"


# Same cooldown window alerts_engine.py uses for TSHARK anomalies (TSHARK_ANOMALY_DEDUPE_MINUTES),
# so a sustained scan from one IP shows as one refreshed row instead of one row per packet.
DEDUPE_WINDOW_MINUTES = 5


def upsert_packet_event(conn, parsed, anomaly, severity, raw_line):
    now = datetime.now()
    cutoff = now - timedelta(minutes=DEDUPE_WINDOW_MINUTES)
    with conn.cursor() as cur:
        cur.execute("""
            SELECT id FROM packet_events
            WHERE src_ip = %s AND anomaly = %s AND captured_at >= %s AND status <> 'resolved'
            ORDER BY captured_at DESC
            LIMIT 1;
        """, (parsed["src_ip"], anomaly, cutoff))
        existing = cur.fetchone()

        if existing:
            cur.execute("""
                UPDATE packet_events
                SET captured_at = %s, dst_ip = %s, src_port = %s, dst_port = %s,
                    protocol = %s, length = %s, info = %s, severity = %s, raw = %s
                WHERE id = %s;
            """, (
                now, parsed["dst_ip"], parsed["src_port"], parsed["dst_port"],
                parsed["protocol"], parsed["length"], parsed["info"], severity, raw_line,
                existing[0],
            ))
        else:
            cur.execute("""
                INSERT INTO packet_events
                    (captured_at, src_ip, dst_ip, src_port, dst_port, protocol, length, info, anomaly, severity, raw)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
            """, (
                now, parsed["src_ip"], parsed["dst_ip"], parsed["src_port"], parsed["dst_port"],
                parsed["protocol"], parsed["length"], parsed["info"], anomaly, severity, raw_line,
            ))
    conn.commit()


def update_heartbeat(conn):
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO agent_status (agent_name, last_heartbeat, status)
            VALUES ('TSHARK', NOW(), 'active')
            ON CONFLICT (agent_name)
            DO UPDATE SET last_heartbeat = NOW(), status = 'active';
        """)
    conn.commit()


def insert_log(conn, message, severity):
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO logs (filename, log_time, source, message, agent_name, severity)
            VALUES (%s, %s, %s, %s, %s, %s);
        """, (
            "tshark_capture",
            datetime.now(),
            "/usr/bin/tshark",
            message,
            "TSHARK",
            severity
        ))
    conn.commit()


def main():
    while True:
        conn = psycopg2.connect(**DB_CONFIG)
        update_heartbeat(conn)

        cmd = [
            "tshark",
            "-i", INTERFACE,
            # Exclude port 5000 (Flask API) from capture entirely
            "-f", "icmp or udp port 53 or (tcp and not port 5000 and not port 3000)",
            "-a", "duration:10"
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )

        print(result.stdout)
        print(result.stderr)

        # Filter to traffic lines only, excluding known noise ports
        packet_lines = [
            line for line in result.stdout.splitlines()
            if ("→" in line or "->" in line) and not is_excluded(line)
        ]

        dns_count = sum(1 for line in packet_lines if is_dns(line))

        for line in packet_lines:
            if is_dns(line) and dns_count >= 8:
                insert_log(
                    conn,
                    f"[DNS] [ANOMALY: Possible DNS beaconing / query burst] {line.strip()}",
                    "high"
                )

            elif is_suspicious_http(line):
                insert_log(
                    conn,
                    f"[HTTP] [ANOMALY: Suspicious HTTP path probing] {line.strip()}",
                    "high"
                )

            # Normal packets are NOT stored — only anomalies are written to
            # either `logs` or `packet_events`. Keeps both tables to threats only.
            anomaly, severity = classify_anomaly(line, dns_count)
            if anomaly is None:
                continue

            parsed = parse_packet_line(line)
            if parsed is None:
                continue
            upsert_packet_event(conn, parsed, anomaly, severity, line.strip())

        conn.close()


if __name__ == "__main__":
    main()
