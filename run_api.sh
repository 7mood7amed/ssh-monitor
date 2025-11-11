#!/usr/bin/env bash
cd /home/hero/ssh-monitor
source venv/bin/activate
exec /home/hero/ssh-monitor/venv/bin/python /home/hero/ssh-monitor/api_server.py
