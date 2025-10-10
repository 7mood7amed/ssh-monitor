# begin

import re, sqlite3, paramiko

# ==== CONFIG ====
HOST = "192.168.56.101"
USERNAME = "hero"
PASSWORD = "hero"
REMOTE_LOG = "/home/hero/ssh.log"
DB_FILE = "remote_ssh_analysis.db"
# ================

# Join wrapped lines like:
# ... for user
# from 192.168.56.1 port 54342 ssh2
def normalize_wrapped(text: str) -> str:
    # If a new line starts with spaces then 'from ', join it to previous line
    text = re.sub(r'\n\s+(from\s+)', r' \1', text)
    return text

# Pattern A: traditional syslog
PAT_CLASSIC = re.compile(
    r'(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+'
    r'(?P<action>Accepted|Failed)\s+(?P<method>\S+)\s+for(?:\s+invalid\s+user)?\s+'
    r'(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)',
    re.IGNORECASE
)

# Pattern B: ISO-8601 timestamp (journald/rsyslog with RFC3339)
PAT_ISO = re.compile(
    r'(?P<ts>\d{4}-\d{2}-\d{2}T[0-9:.+-]+)\s+'
    r'(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+'
    r'(?P<action>Accepted|Failed)\s+(?P<method>\S+)\s+for(?:\s+invalid\s+user)?\s+'
    r'(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)',
    re.IGNORECASE
)

def ensure_db():
    con = sqlite3.connect(DB_FILE)
    con.execute("""
    CREATE TABLE IF NOT EXISTS ssh_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT,        -- ISO ts if present, else 'Mon DD HH:MM:SS'
        host TEXT,
        pid INTEGER,
        action TEXT,    -- Accepted/Failed
        method TEXT,    -- password/publickey/etc.
        user TEXT,
        ip TEXT,
        port INTEGER,
        raw TEXT
    )
    """)
    con.commit(); con.close()

def insert_row(row):
    con = sqlite3.connect(DB_FILE)
    con.execute("""INSERT INTO ssh_logs
        (ts, host, pid, action, method, user, ip, port, raw)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""", row)
    con.commit(); con.close()

def parse_and_store(text: str):
    total = 0
    matched = 0

    for line in text.splitlines():
        total += 1
        line = line.rstrip()
        if not line:
            continue

        m = PAT_ISO.search(line)
        if m:
            g = m.groupdict()
            ts = g['ts']
            row = (
                ts, g['host'], int(g['pid']),
                g['action'].capitalize(), g['method'].lower(),
                g['user'], g['ip'], int(g['port']),
                line
            )
            insert_row(row); matched += 1; continue

        m = PAT_CLASSIC.search(line)
        if m:
            g = m.groupdict()
            # reconstruct a pseudo-ts "Mon DD HH:MM:SS" (no year in classic syslog)
            ts = f"{g['month']} {g['day']} {g['time']}"
            row = (
                ts, g['host'], int(g['pid']),
                g['action'].capitalize(), g['method'].lower(),
                g['user'], g['ip'], int(g['port']),
                line
            )
            insert_row(row); matched += 1; continue

    print(f"[*] Lines read: {total}, matched (inserted): {matched}")

def main():
    print("[*] Connecting to Raven via SSH...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(HOST, username=USERNAME, password=PASSWORD)
    sftp = ssh.open_sftp()

    print("[*] Reading log file from Raven...")
    with sftp.open(REMOTE_LOG, "r") as f:
        data = f.read().decode("utf-8", errors="ignore")
    sftp.close(); ssh.close()

    data = normalize_wrapped(data)

    print("[*] Parsing and saving results...")
    ensure_db()
    parse_and_store(data)

    con = sqlite3.connect(DB_FILE)
    cur = con.cursor()
    cur.execute("SELECT action, COUNT(*) FROM ssh_logs GROUP BY action")
    print("Summary:", dict(cur.fetchall()))
    con.close()

    print("✅ Done! Data saved in", DB_FILE)

if __name__ == "__main__":
    main()
