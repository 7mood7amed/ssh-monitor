"""
tshark_collector.py — FIXED
============================
Problems fixed:
1. Capture filter "tcp" was capturing ALL TCP including dashboard API polls
   → Now uses specific port filters: only ICMP, DNS, SSH(22), HTTP(80), known scan ports
2. Dashboard traffic (port 5000) was being captured and stored as noise
   → Now explicitly excluded via capture filter and skip logic
3. Every packet was stored regardless of interest
   → Now only anomalies are stored; normal background packets are counted but NOT stored
4. SSH classifier matched anything containing "SSH" in TShark verbose output
   → Now only matches actual port 22 traffic
"""

import re
import subprocess
import time
from collections import defaultdict
from datetime import datetime

import psycopg2

DB_CONFIG = {
    "dbname": "logdb",
    "user": "hero",
    "password": "hero",
    "host": "localhost",
    "port": 5432,
}

# Interface where attack traffic arrives
INTERFACE = "enp0s8"

# ── Anomaly thresholds (per 10-second capture window) ────────────────────────
ICMP_SWEEP_THRESHOLD = 10    # 10+ ICMP packets → possible ping sweep
DNS_BURST_THRESHOLD  = 6     # 6+ DNS queries → possible beaconing
SYN_SCAN_THRESHOLD   = 10    # 10+ SYN packets → possible port scan

# ── IPs to ignore (your own dashboard / VM infrastructure) ───────────────────
# These generate constant background noise that is not suspicious
IGNORED_IPS = {
    "192.168.56.104",   # Raven VM itself (our machine)
    "127.0.0.1",
    "::1",
}

# Ports to ignore entirely (your own services generating noise)
IGNORED_PORTS = {
    "5000",   # Flask API — dashboard polls this constantly
    "3000",   # React dev server
}

SUSPICIOUS_HTTP_PATHS = [
    "/admin", "/login", "/phpmyadmin",
    "/wp-login.php", "/wp-admin", "/.env",
    "/config", "/backup", "/phppgadmin",
]

# ── Capture filter: ONLY the protocols we care about ─────────────────────────
# Excludes port 5000 (Flask API) to stop capturing dashboard traffic
# Excludes port 3000 (React dev server)
CAPTURE_FILTER = (
    "icmp "
    "or udp port 53 "
    "or tcp port 22 "
    "or tcp port 80 "
    "or (tcp and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0 "
    "    and not port 5000 and not port 3000)"
)


# ── DB helpers ────────────────────────────────────────────────────────────────

def get_conn():
    return psycopg2.connect(**DB_CONFIG)


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
    """Only called for anomalies and genuinely suspicious traffic."""
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
            severity.upper(),
        ))
    conn.commit()


# ── Packet classification ─────────────────────────────────────────────────────

def get_protocol(line):
    upper = line.upper()
    if "ICMP" in upper:
        return "ICMP"
    if " DNS " in upper or re.search(r"\b53\s*[→>]", line) or re.search(r"[→>]\s*53\b", line):
        return "DNS"
    # Only classify as SSH if it's actually port 22 traffic
    if re.search(r"\b22\s*[→>]", line) or re.search(r"[→>]\s*22\b", line):
        return "SSH"
    if re.search(r"\b80\s*[→>]", line) or re.search(r"[→>]\s*80\b", line) or " HTTP " in upper:
        return "HTTP"
    if "TCP" in upper and ("[SYN]" in upper or "[SYN, ACK]" in upper):
        return "TCP_SYN"
    if "TCP" in upper:
        return "TCP"
    return "OTHER"


def is_ignored(line):
    """Skip packets that are just dashboard/VM background noise."""
    # Skip if it's our own machine talking to itself
    for ip in IGNORED_IPS:
        # Only skip if BOTH src AND dst are internal (self-traffic)
        if f"{ip} →" in line and "192.168.56.104" in line:
            # But keep it if it looks like an attack (suspicious path, SYN scan etc.)
            if not any(p in line.lower() for p in SUSPICIOUS_HTTP_PATHS):
                pass  # continue checking ports

    # Skip dashboard API port traffic
    for port in IGNORED_PORTS:
        if f"→ {port} " in line or f"{port} →" in line or f"→ {port}[" in line:
            return True

    return False


def extract_src_ip(line):
    """Extract source IP from tshark verbose output line."""
    # Format: "N timestamp SRC → DST proto ..."
    parts = line.strip().split()
    for i, p in enumerate(parts):
        if p in ("→", "->") and i > 0:
            return parts[i - 1]
    return None


def is_suspicious_http(line):
    lower = line.lower()
    if "http" not in lower and " 80 " not in lower:
        return False
    return any(path in lower for path in SUSPICIOUS_HTTP_PATHS)


# ── Main loop ─────────────────────────────────────────────────────────────────

def main():
    print("[*] Raven tshark_collector started", flush=True)
    print(f"[*] Interface: {INTERFACE}", flush=True)
    print(f"[*] Capture filter: {CAPTURE_FILTER}", flush=True)
    print(f"[*] Only storing ANOMALIES — normal packets counted but not saved", flush=True)

    while True:
        conn = None
        try:
            conn = get_conn()
            update_heartbeat(conn)

            cmd = [
                "tshark",
                "-i", INTERFACE,
                "-f", CAPTURE_FILTER,
                "-a", "duration:10",
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)

            # Only process lines that have actual traffic (contain → or ->)
            packet_lines = [
                line for line in result.stdout.splitlines()
                if ("→" in line or "->" in line) and not is_ignored(line)
            ]

            if not packet_lines:
                conn.close()
                continue

            # Count per protocol for anomaly thresholds
            icmp_lines = [l for l in packet_lines if get_protocol(l) == "ICMP"]
            dns_lines  = [l for l in packet_lines if get_protocol(l) == "DNS"]
            syn_lines  = [l for l in packet_lines if get_protocol(l) == "TCP_SYN"]
            http_suspicious = [l for l in packet_lines if is_suspicious_http(l)]

            icmp_count = len(icmp_lines)
            dns_count  = len(dns_lines)
            syn_count  = len(syn_lines)

            print(
                f"[capture] packets={len(packet_lines)} "
                f"icmp={icmp_count} dns={dns_count} "
                f"syn={syn_count} http_sus={len(http_suspicious)}",
                flush=True
            )

            # ── ANOMALY STORAGE (only these get written to DB) ────────────────

            # ICMP sweep: store ONE summary row, not every packet
            if icmp_count >= ICMP_SWEEP_THRESHOLD:
                src_ips = set(filter(None, (extract_src_ip(l) for l in icmp_lines)))
                src_str = ", ".join(sorted(src_ips)) if src_ips else "unknown"
                insert_log(
                    conn,
                    f"[ICMP] [ANOMALY: Possible ICMP sweep] "
                    f"src={src_str} count={icmp_count} packets in 10s window",
                    "HIGH"
                )
                print(f"[ANOMALY] ICMP sweep: {icmp_count} packets from {src_str}", flush=True)

            # DNS burst: store ONE summary row
            if dns_count >= DNS_BURST_THRESHOLD:
                src_ips = set(filter(None, (extract_src_ip(l) for l in dns_lines)))
                src_str = ", ".join(sorted(src_ips)) if src_ips else "unknown"
                insert_log(
                    conn,
                    f"[DNS] [ANOMALY: Possible DNS beaconing] "
                    f"src={src_str} count={dns_count} queries in 10s window",
                    "HIGH"
                )
                print(f"[ANOMALY] DNS burst: {dns_count} queries from {src_str}", flush=True)

            # SYN scan: store ONE summary row
            if syn_count >= SYN_SCAN_THRESHOLD:
                src_ips = set(filter(None, (extract_src_ip(l) for l in syn_lines)))
                src_str = ", ".join(sorted(src_ips)) if src_ips else "unknown"
                insert_log(
                    conn,
                    f"[TCP] [ANOMALY: Possible TCP SYN scan] "
                    f"src={src_str} syn_count={syn_count} in 10s window",
                    "HIGH"
                )
                print(f"[ANOMALY] SYN scan: {syn_count} SYNs from {src_str}", flush=True)

            # Suspicious HTTP paths: store each one (these are always interesting)
            for line in http_suspicious:
                src_ip = extract_src_ip(line) or "unknown"
                insert_log(
                    conn,
                    f"[HTTP] [ANOMALY: Suspicious HTTP path probing] "
                    f"src={src_ip} {line.strip()}",
                    "HIGH"
                )
                print(f"[ANOMALY] HTTP probe: {src_ip}", flush=True)

            # ── NO storage for normal packets ─────────────────────────────────
            # Normal SSH connections, regular TCP, etc. are NOT stored.
            # Only anomalies above are written to the DB.
            # This keeps the logs table clean and meaningful.

        except Exception as e:
            print(f"[ERROR] tshark_collector: {e}", flush=True)
            time.sleep(3)

        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass


if __name__ == "__main__":
    main()