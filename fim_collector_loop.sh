#!/usr/bin/env bash
set -euo pipefail

cd /home/hero/ssh-monitor

# run forever
while true; do
  /home/hero/ssh-monitor/venv/bin/python /home/hero/ssh-monitor/fim_monitor.py || true
  sleep 90
done
