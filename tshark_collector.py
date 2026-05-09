import re
import subprocess
from datetime import datetime
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


def is_tcp_syn(line):
    upper = line.upper()
    return "TCP" in upper and "[SYN]" in upper and "[SYN, ACK]" not in upper


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

        icmp_count = sum(1 for line in packet_lines if "ICMP" in line.upper())
        dns_count  = sum(1 for line in packet_lines if is_dns(line))
        syn_count  = sum(1 for line in packet_lines if is_tcp_syn(line))

        for line in packet_lines:
            if "ICMP" in line.upper() and icmp_count >= 10:
                insert_log(
                    conn,
                    f"[ICMP] [ANOMALY: Possible ICMP sweep / reconnaissance] {line.strip()}",
                    "high"
                )

            elif is_dns(line) and dns_count >= 8:
                insert_log(
                    conn,
                    f"[DNS] [ANOMALY: Possible DNS beaconing / query burst] {line.strip()}",
                    "high"
                )

            elif is_tcp_syn(line) and syn_count >= 10:
                insert_log(
                    conn,
                    f"[TCP] [ANOMALY: Possible TCP SYN scan / Nmap reconnaissance] {line.strip()}",
                    "high"
                )

            elif is_suspicious_http(line):
                insert_log(
                    conn,
                    f"[HTTP] [ANOMALY: Suspicious HTTP path probing] {line.strip()}",
                    "high"
                )

            # Normal packets are NOT stored — only anomalies above are written to DB

        conn.close()


if __name__ == "__main__":
    main()