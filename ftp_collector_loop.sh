#!/usr/bin/env bash
set -euo pipefail

cd /home/hero/ssh-monitor

# run forever
while true; do
  /home/hero/ssh-monitor/venv/bin/python /home/hero/ssh-monitor/backfill_ftp_events.py || true
  sleep 5
done