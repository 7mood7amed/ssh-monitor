#!/usr/bin/env python3
from flask import Flask, jsonify
from flask_cors import CORS
import psycopg2
import json

# === Flask App ===
app = Flask(__name__)
CORS(app)  # Allow frontend (React) access

# === PostgreSQL Connection Info ===
DB_CONFIG = {
    "dbname": "logdb",
    "user": "hero",
    "password": "hero",
    "host": "192.168.56.3",   # change if your DB host differs
    "port": 5432
}


def get_db_connection():
    """Create and return a PostgreSQL connection."""
    return psycopg2.connect(**DB_CONFIG)


# === ROUTE 1: Fetch latest 10 logs ===
@app.route("/api/logs", methods=["GET"])
def get_logs():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT log_time, source, message, agent_name
            FROM logs
            ORDER BY log_time DESC
            LIMIT 10;
        """)
        rows = cur.fetchall()
        cur.close()
        conn.close()

        def classify_severity(message):
            msg = message.lower()
            if "unauthorized" in msg or "root" in msg or "breach" in msg:
                return "High"
            elif "failed" in msg or "error" in msg or "denied" in msg:
                return "Medium"
            else:
                return "Low"

        logs = [
            {
                "timestamp": str(r[0]),
                "source": r[1],
                "message": r[2],
                "agent_name": r[3] if r[3] else "unknown",
                "severity": classify_severity(r[2])
            }
            for r in rows
        ]
        return jsonify(logs)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# === ROUTE 2: Fetch all agent statuses ===
@app.route("/api/agents", methods=["GET"])
def get_agents():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT agent_name, last_heartbeat, status
            FROM agent_status
            ORDER BY agent_name ASC;
        """)
        rows = cur.fetchall()
        cur.close()
        conn.close()

        agents = [
            {
                "agent_name": r[0],
                "last_heartbeat": str(r[1]),
                "status": r[2]
            }
            for r in rows
        ]
        return jsonify(agents)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# === ROUTE 3: Dashboard metrics ===
@app.route("/api/metrics", methods=["GET"])
def get_metrics():
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # 1️⃣ Total logs count
        cur.execute("SELECT COUNT(*) FROM logs;")
        total_logs = cur.fetchone()[0]

        # 2️⃣ Active agents
        cur.execute("SELECT COUNT(*) FROM agent_status WHERE LOWER(status) = 'active';")
        active_agents = cur.fetchone()[0]

        # 3️⃣ Anomalies (High severity logs)
        cur.execute("""
            SELECT COUNT(*)
            FROM logs
            WHERE LOWER(message) LIKE '%unauthorized%'
               OR LOWER(message) LIKE '%breach%'
               OR LOWER(message) LIKE '%root%';
        """)
        anomalies = cur.fetchone()[0]

        cur.close()
        conn.close()

        return jsonify({
            "totalLogs": total_logs,
            "activeAgents": active_agents,
            "anomalies": anomalies
        })

    except Exception as e:
        print(f"Error fetching metrics: {e}")
        return jsonify({"error": str(e)}), 500

# === ROUTE 4: Log volume over time ===
@app.route("/api/chart", methods=["GET"])
def get_chart_data():
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Group by hour (or minute if you prefer finer granularity)
        cur.execute("""
            SELECT 
                DATE_TRUNC('hour', log_time) AS hour,
                COUNT(*) AS log_count
            FROM logs
            GROUP BY hour
            ORDER BY hour DESC
            LIMIT 24;
        """)
        rows = cur.fetchall()
        cur.close()
        conn.close()

        # Convert PostgreSQL datetime to readable format
        data = [
            {"time": r[0].strftime("%H:%M"), "logs": r[1]}
            for r in reversed(rows)
        ]
        return jsonify(data)

    except Exception as e:
        print(f"Error fetching chart data: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Raven API is running", "endpoints": ["/api/logs", "/api/agents"]})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
