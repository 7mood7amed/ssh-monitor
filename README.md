# SSH Monitor (Raven Agent)

A Python-based file & directory activity monitoring system using SSH, PostgreSQL, and cron automation.

## Features
- Log extraction from /var/log
- Duplicate prevention via SHA256
- PostgreSQL storage (`logdb`)
- Agent heartbeat tracking
- Cron automation (every 5 minutes)

## Setup
1. Clone repo:
   ```bash
   git clone https://github.com/7mood7amed/ssh-monitor.git
   cd ssh-monitor
