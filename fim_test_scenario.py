#!/usr/bin/env python3
"""
fim_test_scenario.py
---------------------
Safe, self-contained FIM smoke test.

Exercises the modified / permission_changed / CRITICAL alert paths using a
dummy file under ./fim_test_data/ -- never touches the real /etc/passwd,
/etc/shadow, /etc/sudoers, /etc/ssh/sshd_config, /etc/crontab, or the real
Apache webroot. FIM_WATCH_FILES/FIM_WATCH_DIRS/FIM_SENSITIVE_FILES are
overridden only for the subprocesses this script spawns.

Usage:
    python fim_test_scenario.py

Once you've verified the HIGH and CRITICAL alerts below fire correctly,
point the collector at your real system:
  - unset FIM_WATCH_FILES (fim_monitor.py falls back to the real default
    list: /etc/passwd,/etc/shadow,/etc/sudoers,/etc/ssh/sshd_config,/etc/crontab)
    or set it explicitly to those production paths.
  - unset FIM_WATCH_DIRS (falls back to /var/www/html) or set it to your
    real webroot.
  - unset FIM_SENSITIVE_FILES (falls back to the real passwd/shadow/sudoers
    set) -- it was only overridden here to demonstrate the CRITICAL path
    on the dummy file.
Then start fim_collector_loop.sh for production use.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time

import psycopg2

REPO_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DIR = os.path.join(REPO_DIR, "fim_test_data")
DUMMY_FILE = os.path.join(TEST_DIR, "dummy_critical_file")

DB_NAME = os.environ.get("DB_NAME", "logdb")
DB_USER = os.environ.get("DB_USER", "hero")
DB_PASS = os.environ.get("DB_PASS", "hero")
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = int(os.environ.get("DB_PORT", "5432"))

PYTHON = sys.executable


def get_conn():
    return psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASS, host=DB_HOST, port=DB_PORT)


def run(script: str, extra_env: dict, *args: str) -> None:
    env = os.environ.copy()
    env["FIM_WATCH_FILES"] = DUMMY_FILE
    env["FIM_WATCH_DIRS"] = ""  # keep the test isolated from the real webroot
    env.update(extra_env)

    cmd = [PYTHON, os.path.join(REPO_DIR, script), *args]
    print(f"$ {script} {' '.join(args)}")
    result = subprocess.run(cmd, env=env, capture_output=True, text=True)
    if result.stdout.strip():
        print(result.stdout.strip())
    if result.returncode != 0:
        print(result.stderr.strip(), file=sys.stderr)
        raise RuntimeError(f"{script} failed (exit {result.returncode})")


def latest_alert(cur, title_like: str, priority: str):
    cur.execute(
        """
        SELECT id, title, priority, created_at
        FROM alerts
        WHERE title ILIKE %s AND priority = %s AND file_target = %s
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (f"%{title_like}%", priority, DUMMY_FILE),
    )
    return cur.fetchone()


def check(label: str, found) -> bool:
    ok = found is not None
    print(f"[{'PASS' if ok else 'FAIL'}] {label}" + (f" (alert_id={found[0]})" if ok else ""))
    return ok


def main():
    os.makedirs(TEST_DIR, exist_ok=True)
    results = []

    print(f"\nUsing dummy watched file: {DUMMY_FILE}\n")

    # --- Step A: seed baseline, no alert expected ---
    print("=== Step A: seed baseline (--init) ===")
    with open(DUMMY_FILE, "w") as f:
        f.write("initial content\n")
    os.chmod(DUMMY_FILE, 0o644)  # normalize starting mode in case a prior run left it at 0600
    run("fim_monitor.py", {}, "--init")

    # --- Step B: modify content -> HIGH ---
    print("\n=== Step B: modify content (expect HIGH) ===")
    time.sleep(1)
    with open(DUMMY_FILE, "w") as f:
        f.write("tampered content\n")
    run("fim_monitor.py", {})
    run("alerts_engine.py", {})
    conn = get_conn()
    with conn.cursor() as cur:
        results.append(check("modified -> HIGH alert created", latest_alert(cur, "FIM:", "high")))
    conn.close()

    # --- Step C: permission change only -> HIGH ---
    print("\n=== Step C: permission change only (expect HIGH) ===")
    os.chmod(DUMMY_FILE, 0o600)
    run("fim_monitor.py", {})
    run("alerts_engine.py", {})
    conn = get_conn()
    with conn.cursor() as cur:
        results.append(check("permission_changed -> HIGH alert created", latest_alert(cur, "Permission Changed", "high")))
    conn.close()

    # --- Step D: treat dummy file as sensitive -> CRITICAL ---
    print("\n=== Step D: sensitive-file override + modify (expect CRITICAL) ===")
    with open(DUMMY_FILE, "w") as f:
        f.write("tampered again\n")
    sensitive_env = {"FIM_SENSITIVE_FILES": DUMMY_FILE}
    run("fim_monitor.py", sensitive_env)
    run("alerts_engine.py", sensitive_env)
    conn = get_conn()
    with conn.cursor() as cur:
        results.append(check("sensitive-file event -> CRITICAL alert created", latest_alert(cur, "Critical System File", "critical")))
    conn.close()

    print("\n=== Summary ===")
    passed = sum(1 for r in results if r)
    print(f"{passed}/{len(results)} checks passed")
    if passed != len(results):
        sys.exit(1)


if __name__ == "__main__":
    main()
