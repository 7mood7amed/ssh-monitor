#!/usr/bin/env python3
from __future__ import annotations

import os
import re
import ipaddress
import psycopg2

DB_NAME = os.environ.get("DB_NAME", "logdb")
DB_USER = os.environ.get("DB_USER", "hero")
DB_PASS = os.environ.get("DB_PASS", "hero")
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = int(os.environ.get("DB_PORT", "5432"))

BATCH = int(os.environ.get("BATCH", "2000"))

# --- Patterns (matches your screenshots) ---
_RE_ACCEPTED = re.compile(
    r"Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)",
    re.IGNORECASE,
)
_RE_FAILED_PASSWORD_ANY = re.compile(
    r"Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)",
    re.IGNORECASE,
)
_RE_FAILED_PUBLICKEY_ANY = re.compile(
    r"Failed\s+publickey\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)",
    re.IGNORECASE,
)
_RE_INVALID_USER_ANY = re.compile(
    r"Invalid\s+user\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)",
    re.IGNORECASE,
)
_RE_PAM_AUTH_FAIL = re.compile(
    r"pam_unix\(sshd:auth\):\s+authentication\s+failure;.*rhost=(?P<ip>\S+).*user=(?P<user>\S*)",
    re.IGNORECASE,
)
_RE_PAM_MORE_FAIL = re.compile(
    r"PAM\s+\d+\s+more\s+authentication\s+failures;.*rhost=(?P<ip>\S+).*user=(?P<user>\S*)",
    re.IGNORECASE,
)
_RE_CONN_RESET_PREAUTH = re.compile(
    r"Connection\s+reset\s+by\s+authenticating\s+user\s+(?P<user>\S+)\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)\s+\[preauth\]",
    re.IGNORECASE,
)
_RE_RECEIVED_DISCONNECT = re.compile(
    r"Received\s+disconnect\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)",
    re.IGNORECASE,
)
_RE_DISCONNECTED_FROM_USER = re.compile(
    r"Disconnected\s+from\s+user\s+(?P<user>\S+)\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)",
    re.IGNORECASE,
)
_RE_CONN_CLOSED = re.compile(
    r"(?:Connection\s+closed|Disconnected\s+from)\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)",
    re.IGNORECASE,
)
_RE_SESSION_OPEN = re.compile(
    r"pam_unix\(sshd:session\):\s+session\s+opened\s+for\s+user\s+(?P<user>\S+)",
    re.IGNORECASE,
)
_RE_SESSION_CLOSE = re.compile(
    r"pam_unix\(sshd:session\):\s+session\s+closed\s+for\s+user\s+(?P<user>\S+)",
    re.IGNORECASE,
)


def _clean_ip(raw: str | None) -> str | None:
    if not raw:
        return None
    raw = raw.strip()
    try:
        ipaddress.ip_address(raw)
        return raw
    except ValueError:
        return None


def _norm_user(u: str | None) -> str | None:
    if not u:
        return None
    u = u.strip()
    if not u:
        return None
    if "(" in u:  # hero(uid=1000) -> hero
        u = u.split("(", 1)[0].strip()
    return u or None


def parse_event(msg: str) -> dict | None:
    m = _RE_ACCEPTED.search(msg)
    if m:
        return {
            "event_type": "login_success",
            "outcome": "success",
            "auth_method": (m.group("method") or "unknown").lower(),
            "username": _norm_user(m.group("user")),
            "ip": _clean_ip(m.group("ip")),
            "port": int(m.group("port")),
        }

    m = _RE_FAILED_PASSWORD_ANY.search(msg)
    if m:
        return {
            "event_type": "login_fail",
            "outcome": "fail",
            "auth_method": "password",
            "username": _norm_user(m.group("user")),
            "ip": _clean_ip(m.group("ip")),
            "port": int(m.group("port")),
        }

    m = _RE_FAILED_PUBLICKEY_ANY.search(msg)
    if m:
        return {
            "event_type": "login_fail",
            "outcome": "fail",
            "auth_method": "publickey",
            "username": _norm_user(m.group("user")),
            "ip": _clean_ip(m.group("ip")),
            "port": int(m.group("port")),
        }

    m = _RE_INVALID_USER_ANY.search(msg)
    if m:
        return {
            "event_type": "login_fail",
            "outcome": "fail",
            "auth_method": "unknown",
            "username": _norm_user(m.group("user")),
            "ip": _clean_ip(m.group("ip")),
            "port": int(m.group("port")),
        }

    m = _RE_PAM_AUTH_FAIL.search(msg) or _RE_PAM_MORE_FAIL.search(msg)
    if m:
        return {
            "event_type": "login_fail",
            "outcome": "fail",
            "auth_method": "unknown",
            "username": _norm_user(m.group("user") or None),
            "ip": _clean_ip(m.group("ip")),
            "port": None,
        }

    m = _RE_CONN_RESET_PREAUTH.search(msg)
    if m:
        return {
            "event_type": "login_fail",
            "outcome": "fail",
            "auth_method": "unknown",
            "username": _norm_user(m.group("user")),
            "ip": _clean_ip(m.group("ip")),
            "port": int(m.group("port")),
        }

    m = _RE_DISCONNECTED_FROM_USER.search(msg)
    if m:
        return {
            "event_type": "disconnect",
            "outcome": "info",
            "auth_method": None,
            "username": _norm_user(m.group("user")),
            "ip": _clean_ip(m.group("ip")),
            "port": int(m.group("port")),
        }

    m = _RE_RECEIVED_DISCONNECT.search(msg) or _RE_CONN_CLOSED.search(msg)
    if m:
        return {
            "event_type": "disconnect",
            "outcome": "info",
            "auth_method": None,
            "username": None,
            "ip": _clean_ip(m.group("ip")),
            "port": int(m.group("port")),
        }

    m = _RE_SESSION_OPEN.search(msg)
    if m:
        return {
            "event_type": "session_open",
            "outcome": "info",
            "auth_method": None,
            "username": _norm_user(m.group("user")),
            "ip": None,
            "port": None,
        }

    m = _RE_SESSION_CLOSE.search(msg)
    if m:
        return {
            "event_type": "session_close",
            "outcome": "info",
            "auth_method": None,
            "username": _norm_user(m.group("user")),
            "ip": None,
            "port": None,
        }

    return None


def main() -> None:
    conn = psycopg2.connect(
        dbname=DB_NAME, user=DB_USER, password=DB_PASS, host=DB_HOST, port=DB_PORT
    )
    inserted = 0
    scanned = 0
    try:
        cur_sel = conn.cursor()
        cur_ins = conn.cursor()

        cur_sel.execute(
            """
            SELECT id, log_time, agent_name, message
            FROM public.logs
            WHERE source LIKE '%/var/log/auth.log%' OR filename LIKE 'auth.log%'
            ORDER BY id ASC;
            """
        )

        while True:
            batch = cur_sel.fetchmany(BATCH)
            if not batch:
                break

            for log_id, log_time, agent_name, message in batch:
                scanned += 1
                msg = (message or "").replace("\x00", "").strip()
                ev = parse_event(msg)
                if not ev:
                    continue

                cur_ins.execute(
                    """
                    INSERT INTO public.ssh_events
                      (log_id, agent_name, event_time, event_type, outcome, auth_method, username, ip, port, raw)
                    VALUES
                      (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (log_id) DO NOTHING;
                    """,
                    (
                        int(log_id),
                        (agent_name or "SSH"),
                        log_time,
                        ev["event_type"],
                        ev.get("outcome"),
                        ev.get("auth_method"),
                        ev.get("username"),
                        ev.get("ip"),
                        ev.get("port"),
                        msg,
                    ),
                )
                inserted += int(cur_ins.rowcount == 1)

            conn.commit()

        cur_sel.close()
        cur_ins.close()
        print(f"✅ Backfill done. scanned={scanned} inserted={inserted}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
