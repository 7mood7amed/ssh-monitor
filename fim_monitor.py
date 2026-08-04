#!/usr/bin/env python3
"""
fim_monitor.py
--------------
File Integrity Monitoring collector.

Snapshots a configured set of files/directories (hash, mode, uid, mtime),
compares against the last-known-good baseline in fim_baseline, logs any
deltas into fim_events, then updates the baseline to the new state so the
next run diffs against current reality.

Alerting is NOT done here (kept a pure collector, like extract_logs.py) --
alerts_engine.py reads fim_events and creates alerts on its own cadence.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import stat
import sys
from datetime import datetime

import psycopg2

# ----------------------------
# Config (env vars)
# ----------------------------
DB_NAME = os.environ.get("DB_NAME", "logdb")
DB_USER = os.environ.get("DB_USER", "hero")
DB_PASS = os.environ.get("DB_PASS", "hero")
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = int(os.environ.get("DB_PORT", "5432"))

AGENT_NAME = os.environ.get("AGENT_NAME", "FIM")

# Individually-watched files (comma-separated)
FIM_WATCH_FILES = os.environ.get(
    "FIM_WATCH_FILES",
    "/etc/passwd,/etc/shadow,/etc/sudoers,/etc/ssh/sshd_config,/etc/crontab",
)

# Directories watched recursively for new/modified/deleted files (comma-separated)
FIM_WATCH_DIRS = os.environ.get("FIM_WATCH_DIRS", "/var/www/html")

# Files that always classify as CRITICAL on any change (mirrors alerts_engine.py's rule 10).
# Env-overridable so test scenarios can safely exercise the CRITICAL path on a dummy file.
FIM_SENSITIVE_FILES = {
    p.strip() for p in os.environ.get(
        "FIM_SENSITIVE_FILES", "/etc/passwd,/etc/shadow,/etc/sudoers"
    ).split(",") if p.strip()
}

HASH_CHUNK_SIZE = 65536


def get_conn():
    return psycopg2.connect(
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASS,
        host=DB_HOST,
        port=DB_PORT,
    )


def upsert_agent_heartbeat(cur, agent: str) -> None:
    cur.execute(
        """
        INSERT INTO public.agent_status (agent_name, last_heartbeat)
        VALUES (%s, NOW())
        ON CONFLICT (agent_name)
        DO UPDATE SET last_heartbeat = NOW();
        """,
        (agent,),
    )


def parse_path_list(raw: str) -> list[str]:
    return [p.strip() for p in raw.split(",") if p.strip()]


def in_watch_scope(path: str) -> bool:
    """
    True if `path` is still covered by the *current* FIM_WATCH_FILES/FIM_WATCH_DIRS
    config. A baseline row outside current scope (e.g. the watch config was
    narrowed between runs) must never be treated as "deleted" -- it simply isn't
    being checked this run.
    """
    if path in parse_path_list(FIM_WATCH_FILES):
        return True
    for base in parse_path_list(FIM_WATCH_DIRS):
        base = base.rstrip("/")
        if base and (path == base or path.startswith(base + "/")):
            return True
    return False


def discover_paths() -> list[str]:
    """
    Individually-watched files (always included, even if currently missing --
    that's how a delete on one of them gets caught) + everything currently
    found under the watched directories (recursive). A file that shows up
    under a watched dir this run but wasn't seen before is how "added" gets
    detected.
    """
    paths: list[str] = list(parse_path_list(FIM_WATCH_FILES))

    for base in parse_path_list(FIM_WATCH_DIRS):
        if not os.path.isdir(base):
            continue
        for root, _dirs, files in os.walk(base):
            for name in files:
                paths.append(os.path.join(root, name))

    seen = set()
    unique_paths = []
    for p in paths:
        if p not in seen:
            seen.add(p)
            unique_paths.append(p)
    return unique_paths


def snapshot_file(path: str) -> dict | None:
    """
    Current state (hash, mode, uid, mtime) for path, or None if the file
    does not exist / cannot be stat'd (covers the "deleted" case).
    """
    try:
        st = os.stat(path)
    except (FileNotFoundError, PermissionError, OSError):
        return None

    if stat.S_ISDIR(st.st_mode):
        return None

    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(HASH_CHUNK_SIZE), b""):
                h.update(chunk)
        file_hash = h.hexdigest()
    except (PermissionError, OSError):
        file_hash = None

    return {
        "hash": file_hash,
        "mode": oct(stat.S_IMODE(st.st_mode)),
        "uid": st.st_uid,
        "mtime": datetime.fromtimestamp(st.st_mtime),
    }


def load_baseline(cur) -> dict[str, tuple[str | None, str | None, int | None]]:
    cur.execute(
        """
        SELECT file_path, hash, mode, uid
        FROM public.fim_baseline;
        """
    )
    return {path: (h, mode, uid) for (path, h, mode, uid) in cur.fetchall()}


def upsert_baseline(cur, path: str, state: dict | None) -> None:
    if state is None:
        # Deleted: clear hash/mode/uid but keep the row so a later re-add is detected.
        cur.execute(
            """
            INSERT INTO public.fim_baseline (file_path, hash, mode, uid, mtime, last_checked)
            VALUES (%s, NULL, NULL, NULL, NULL, NOW())
            ON CONFLICT (file_path)
            DO UPDATE SET hash=NULL, mode=NULL, uid=NULL, mtime=NULL, last_checked=NOW();
            """,
            (path,),
        )
        return

    cur.execute(
        """
        INSERT INTO public.fim_baseline (file_path, hash, mode, uid, mtime, last_checked)
        VALUES (%s, %s, %s, %s, %s, NOW())
        ON CONFLICT (file_path)
        DO UPDATE SET hash=EXCLUDED.hash, mode=EXCLUDED.mode, uid=EXCLUDED.uid,
                      mtime=EXCLUDED.mtime, last_checked=NOW();
        """,
        (path, state["hash"], state["mode"], state["uid"], state["mtime"]),
    )


def classify_severity(path: str, event_type: str) -> str:
    if path in FIM_SENSITIVE_FILES:
        return "CRITICAL"
    if event_type in ("modified", "added", "permission_changed"):
        return "HIGH"
    return "MEDIUM"


def log_event(cur, path: str, event_type: str, old: tuple | None, new: dict | None) -> int:
    old_hash, old_mode, _old_uid = old if old else (None, None, None)
    new_hash = new["hash"] if new else None
    new_mode = new["mode"] if new else None
    severity = classify_severity(path, event_type)

    cur.execute(
        """
        INSERT INTO public.fim_events
            (file_path, event_type, old_hash, new_hash, old_mode, new_mode, detected_at, severity)
        VALUES (%s, %s, %s, %s, %s, %s, NOW(), %s)
        RETURNING id;
        """,
        (path, event_type, old_hash, new_hash, old_mode, new_mode, severity),
    )
    return cur.fetchone()[0]


def main():
    parser = argparse.ArgumentParser(description="File Integrity Monitoring collector")
    parser.add_argument(
        "--init",
        action="store_true",
        help="Seed fim_baseline from current disk state without generating any events/alerts.",
    )
    args = parser.parse_args()

    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                upsert_agent_heartbeat(cur, AGENT_NAME)

                cur.execute("SELECT COUNT(*) FROM public.fim_baseline;")
                baseline_count = cur.fetchone()[0]

                paths = discover_paths()
                first_run = args.init or baseline_count == 0

                if first_run:
                    for path in paths:
                        state = snapshot_file(path)
                        upsert_baseline(cur, path, state)
                    print(f"OK: baseline initialized for {len(paths)} path(s), agent={AGENT_NAME}")
                    return

                baseline = load_baseline(cur)
                seen_paths = set(paths)
                event_count = 0

                # 1) Diff every currently-watched/discovered path against baseline
                for path in paths:
                    state = snapshot_file(path)
                    old = baseline.get(path)

                    if old is None:
                        if state is not None:
                            log_event(cur, path, "added", None, state)
                            event_count += 1
                    else:
                        old_hash, old_mode, old_uid = old
                        if state is None:
                            if old_hash is not None or old_mode is not None:
                                log_event(cur, path, "deleted", old, None)
                                event_count += 1
                        elif state["hash"] != old_hash:
                            log_event(cur, path, "modified", old, state)
                            event_count += 1
                        elif state["mode"] != old_mode or state["uid"] != old_uid:
                            log_event(cur, path, "permission_changed", old, state)
                            event_count += 1

                    upsert_baseline(cur, path, state)

                # 2) Baseline entries no longer discovered at all (e.g. a webroot file that
                #    disappeared, so os.walk no longer yields it this run) -> deleted.
                #    Only for paths still in the *current* watch scope -- a baseline row
                #    outside current FIM_WATCH_FILES/FIM_WATCH_DIRS just isn't being
                #    checked this run, it was not actually deleted.
                for path, (old_hash, old_mode, old_uid) in baseline.items():
                    if path in seen_paths:
                        continue
                    if not in_watch_scope(path):
                        continue
                    if old_hash is None and old_mode is None:
                        continue  # already recorded as deleted previously
                    log_event(cur, path, "deleted", (old_hash, old_mode, old_uid), None)
                    event_count += 1
                    upsert_baseline(cur, path, None)

        print(f"OK: checked {len(paths)} path(s), logged {event_count} event(s), agent={AGENT_NAME}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
