import re
import subprocess
from datetime import datetime
import psycopg2

DB_CONFIG = {
    "dbname": "logdb",
    "user": "hero"
}

# Use the interface where Kali traffic arrives
INTERFACE = "enp0s8"

SUSPICIOUS_HTTP_PATHS = [
    "/admin",
    "/login",
    "/phpmyadmin",
    "/wp-login.php",
    "/wp-admin"
]


def classify_protocol(line):
    upper = line.upper()

    if "ICMP" in upper:
        return "ICMP", "medium"

    if re.search(r"\b53\s*→", line) or re.search(r"→\s*53\b", line) or " DNS " in upper:
        return "DNS", "low"

    if re.search(r"\b80\s*→", line) or re.search(r"→\s*80\b", line) or " HTTP " in upper:
        return "HTTP", "low"

    if "SSH" in upper or re.search(r"\b22\s*→", line) or re.search(r"→\s*22\b", line):
        return "SSH", "medium"

    if "TCP" in upper:
        if "[SYN]" in upper or "[SYN, ACK]" in upper:
            return "TCP", "medium"
        return "TCP", "low"

    return "OTHER", "low"


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
    return "TCP" in upper and "[SYN]" in upper


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


def insert_packet(conn, line):
    protocol, severity = classify_protocol(line)
    message = f"[{protocol}] {line.strip()}"
    insert_log(conn, message, severity)


def main():
    while True:
        conn = psycopg2.connect(**DB_CONFIG)
        update_heartbeat(conn)

        cmd = [
            "tshark",
            "-i", INTERFACE,
            # Capture ICMP, DNS, HTTP, SSH, and general TCP scan traffic
            "-f", "icmp or udp port 53 or tcp",
            "-a", "duration:10"
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )

        print(result.stdout)
        print(result.stderr)

        packet_lines = [
            line for line in result.stdout.splitlines()
            if "→" in line or "->" in line
        ]

        icmp_count = sum(1 for line in packet_lines if "ICMP" in line.upper())
        dns_count = sum(1 for line in packet_lines if is_dns(line))
        syn_count = sum(1 for line in packet_lines if is_tcp_syn(line))

        for line in packet_lines:
            if "ICMP" in line.upper() and icmp_count >= 10:
                insert_log(
                    conn,
                    f"[ICMP] [ANOMALY: Possible ICMP sweep / reconnaissance] {line.strip()}",
                    "high"
                )

            elif is_dns(line) and dns_count >= 6:
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

            else:
                insert_packet(conn, line)

        conn.close()


if __name__ == "__main__":
    main()