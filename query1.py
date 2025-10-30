import psycopg2

# Database connection info
conn = psycopg2.connect(
    dbname="logdb",
    user="hero",
    password="hero",
    host="localhost"
)
cur = conn.cursor()

print("Connected to PostgreSQL successfully!\n")

# Display total logs
cur.execute("SELECT COUNT(*) FROM logs;")
count = cur.fetchone()[0]
print(f"Total log entries: {count}\n")

# Show latest 10 logs
cur.execute("""
    SELECT filename, log_time, LEFT(message, 80)
    FROM logs
    ORDER BY log_time DESC
    LIMIT 10;
""")
for row in cur.fetchall():
    print(row)

# Show heartbeat
cur.execute("SELECT * FROM agent_status;")
print("\nAgent Heartbeat:")
for row in cur.fetchall():
    print(row)

cur.close()
conn.close()
