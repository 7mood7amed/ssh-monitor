import psycopg2

DB_CONFIG = {
    "dbname": "logdb",
    "user": "hero",
    "password": "hero",
    "host": "localhost",
    "port": 5432
}

conn = psycopg2.connect(**DB_CONFIG)
cur = conn.cursor()


# ===============================
# Helper
# ===============================
def create_alert(priority, title, description, log_ids):
    cur.execute("""
        INSERT INTO alerts (source, priority, title, description)
        VALUES ('logs', %s, %s, %s)
        RETURNING id
    """, (priority, title, description))

    alert_id = cur.fetchone()[0]

    for lid in log_ids:
        cur.execute("""
            INSERT INTO alert_log_links (alert_id, log_type, log_id)
            VALUES (%s, 'logs', %s)
        """, (alert_id, lid))

    conn.commit()


# ===============================
# Rule 1: brute force (5 fails)
# ===============================
def brute_force_rule():
    cur.execute("""
        SELECT array_agg(id)
        FROM logs
        WHERE (
            message ILIKE '%FAIL LOGIN%'
            OR message ILIKE '%LOGIN FAIL%'
            OR message ILIKE '%530 Login incorrect%'
            OR message ILIKE '%Login incorrect%'
        )
        AND log_time > NOW() - interval '2 minutes'
        HAVING COUNT(*) >= 5
    """)
    result = cur.fetchone()
    if result and result[0]:
        create_alert(
            "high",
            "Brute Force Suspected",
            "Multiple FTP login failures detected (possible brute force)",
            result[0]
        )


# ===============================
# Rule 2: mass delete
# ===============================
def mass_delete_rule():
    cur.execute("""
        SELECT array_agg(id)
        FROM logs
        WHERE message ILIKE '%DELETE%'
          AND log_time > NOW() - interval '1 minute'
        HAVING COUNT(*) >= 3
    """)

    result = cur.fetchone()
    if result and result[0]:
        create_alert(
            "high",
            "Mass Deletion Activity",
            "Multiple deletes detected in short time",
            result[0]
        )


# ===============================
# Rule 3: critical directory remove
# ===============================
def critical_rmdir_rule():
    cur.execute("""
        SELECT array_agg(id)
        FROM logs
        WHERE (
            message ILIKE '%FAIL RMDIR:%'
            OR message ILIKE '% RMDIR %'
        )
        AND log_time > NOW() - interval '5 minutes'
    """)
    result = cur.fetchone()
    if result and result[0]:
        create_alert(
            "critical",
            "Directory Removal Detected",
            "Directory removal activity detected (RMDIR)",
            result[0]
        )

# ===============================
# Run
# ===============================
if __name__ == "__main__":
    brute_force_rule()
    mass_delete_rule()
    critical_rmdir_rule()

    print("Alerts engine executed successfully")