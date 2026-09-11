# Raven — Multi-Protocol Security Monitoring System

Raven is a lightweight SIEM: a set of Python collectors watch SSH, FTP, web (Apache), network (Nmap/TShark), file integrity, and Snort IDS activity on a host, normalize everything into PostgreSQL, and feed a rule-based (and optionally AI-assisted) alert engine. A Flask REST API exposes the data to a React dashboard for live monitoring, investigation, and triage.

## Architecture

```
 SSH / Apache / FTP logs ─┐
 Nmap scan results ───────┤
 TShark packet capture ───┼──▶  extract_logs.py / fim_monitor.py / nmap_scanner.py  ──▶  PostgreSQL
 File integrity hashes ───┤     tshark_collector.py / snort_collector.py                 (logdb)
 Snort alert log ─────────┘                                                                 │
                                                                                              │
                              alerts_engine.py  (rule engine)  ◀────────────────────────────┤
                              ai_engine.py      (cross-source correlation + AI narrative) ◀──┘
                                              │
                                              ▼
                                       api_server.py  (Flask REST API)
                                              │
                                              ▼
                                     dashboard/  (React frontend)
```

Collectors run periodically (cron), write into shared PostgreSQL tables, and are agnostic of each other. `alerts_engine.py` runs after them each cycle, evaluating a fixed set of detection rules against fresh rows and writing/grouping alerts. The dashboard polls `api_server.py` for logs, findings, and alerts.

## Components

| Script | Role | Writes to |
|---|---|---|
| `extract_logs.py` | Tails `/var/log/auth.log`, Apache access logs, and vsftpd logs; parses and dedupes entries (SHA256-based) | `logs`, `ssh_events`, `ftp_events` |
| `fim_monitor.py` | Hashes watched files/directories (default `/var/www/html`) and detects added/modified/removed files | `fim_events` (schema: `fim_schema.sql`) |
| `nmap_scanner.py` | Ingests Nmap scan output (XML) and tracks open ports per host over time | `nmap_findings` |
| `tshark_collector.py` | Runs packet-level heuristics (ICMP sweeps, DNS beaconing, HTTP path probing) | `packet_events`, `logs` |
| `snort_collector.py` | Tails Snort's alert log and normalizes signature matches | `snort_alerts` (schema: `snort_schema.sql`) |
| `alerts_engine.py` | Rule engine — evaluates all detection rules below and creates/groups alerts | `alerts`, `alert_log_links` |
| `ai_engine.py` | Rule-based cross-source correlation, plus optional Claude/Groq-generated narrative analysis of active alerts | `alerts` (AI-tagged), reads across all tables |
| `api_server.py` | Flask REST API serving the dashboard (logs, findings, alerts, metrics, agent heartbeats) | — |
| `dashboard/` | React single-page app (dashboard UI) | — |

Supporting scripts: `backfill_ssh_events.py` / `backfill_ftp_events.py` (one-off historical backfill into the structured event tables), `scan_detector.py` (standalone port-scan heuristic), `fim_test_scenario.py` (FIM smoke test), `query1.py` (ad-hoc DB query helper).

## Detection rules (`alerts_engine.py`)

Each rule is deduped/grouped (a burst of matching activity becomes one growing alert, not one per event) and tagged with a MITRE ATT&CK technique where applicable:

- **SSH / FTP brute force** — repeated failed logins from one IP in a short window
- **Mass deletion** / **critical directory removal** — burst of `DELETE`/`RMDIR` activity
- **Web SQLi / XSS injection** — malicious query strings in Apache access logs
- **Web scan** — probing/enumeration patterns in web traffic
- **New open port** (Nmap) — a port opens on a host that wasn't open on the previous scan
- **File integrity changes** (FIM) — new/modified/removed files under watched paths, with a dedicated high-confidence alert for new files dropped in the web root
- **Snort signature matches** — IDS alerts mapped to Raven's severity scale
- **TShark protocol anomalies** — ICMP sweep, DNS beaconing, suspicious HTTP path probing
- **Possible Web Shell Activation** *(correlation rule)* — a file dropped in the web root that is subsequently requested over HTTP: the two-stage drop-then-invoke signature of a web shell
- **Possible Compromise After Brute Force** *(correlation rule)* — a file-system change shortly after a brute-force alert, a signal the attacker may have actually gotten in rather than just attempted to

## Dashboard

React app under `dashboard/`, with pages for: Home (overview/metrics), SSH Logs, Web Traffic, FTP Logs, Nmap Logs, Network Events, Snort IDS, File Integrity, AI Insights, and Alerts (with an investigation panel showing every piece of evidence linked to an alert, sorted chronologically).

## Database

PostgreSQL (`logdb`). Most tables (`logs`, `ssh_events`, `ftp_events`, `nmap_findings`, `packet_events`, `alerts`, `alert_log_links`, `agents`) are provisioned directly against the running database rather than checked into this repo. Two feature-specific schemas are included:

- `fim_schema.sql` — file integrity monitoring tables
- `snort_schema.sql` — Snort alert tables

## Setup

1. **Clone and install Python dependencies**
   ```bash
   git clone <this-repo>
   cd ssh-monitor
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

2. **PostgreSQL**
   Create a `logdb` database and apply the included schemas:
   ```bash
   psql -U <user> -d logdb -f fim_schema.sql
   psql -U <user> -d logdb -f snort_schema.sql
   ```
   (`logs`, `ssh_events`, `ftp_events`, `nmap_findings`, `packet_events`, `alerts`, `alert_log_links`, and `agents` must exist as well — see each collector's `insert_*`/`create_alert` calls for the expected column shapes if provisioning from scratch.)

3. **Configure environment variables** (see reference table below), then run each collector once to confirm connectivity, e.g.:
   ```bash
   python extract_logs.py
   python fim_monitor.py
   python alerts_engine.py
   ```

4. **Run the API**
   ```bash
   python api_server.py
   # or, matching the reference deployment:
   ./run_api.sh
   ```

5. **Run the dashboard**
   ```bash
   cd dashboard
   npm install
   npm start
   ```

## Configuration reference

| Variable | Used by | Purpose |
|---|---|---|
| `DB_HOST`, `DB_NAME`, `DB_USER`, `DB_PASS`, `DB_PORT` | all Python scripts | PostgreSQL connection |
| `AGENT_NAME` | collectors | Overrides the agent name recorded for heartbeats/log rows |
| `FIM_WATCH_DIRS` | `fim_monitor.py` | Paths to hash/watch (default `/var/www/html`) |
| `NMAP_TARGET` / `NMAP_TARGETS`, `NMAP_XML_PATH` | `nmap_scanner.py` | Scan target(s) and where to read Nmap XML output from |
| `SCAN_INTERFACE`, `SCAN_PORT_THRESHOLD`, `SCAN_WINDOW_SECONDS` | `scan_detector.py` | Standalone port-scan heuristic tuning |
| `MONITORED_HOST_IP` | `alerts_engine.py` | Host IP used to enrich web-shell correlation with nearby packet anomalies |
| `WEBSHELL_LOOKBACK_MINUTES`, `WEBSHELL_ACTIVATION_WINDOW_MINUTES` | `alerts_engine.py` | Web-shell correlation rule windows |
| `POST_BRUTE_FORCE_FIM_LOOKBACK_MINUTES`, `POST_BRUTE_FORCE_FIM_WINDOW_MINUTES`, `POST_BRUTE_FORCE_FIM_DEDUPE_MINUTES` | `alerts_engine.py` | Post-brute-force compromise correlation rule windows |
| `NMAP_ALERT_DEDUPE_MINUTES`, `SCAN_DEDUPE_MINUTES` | `alerts_engine.py` | Alert grouping/cooldown windows |
| `ANTHROPIC_API_KEY`, `CLAUDE_MODEL` | `ai_engine.py` | Enables Claude-generated alert narrative analysis (optional) |
| `GROQ_API_KEY`, `GROQ_MODEL` | `ai_engine.py` | Alternate/fallback AI provider (optional) |

Most variables have sensible defaults in code — only DB connection settings are effectively required.

## Running in production

The reference deployment runs collectors on a schedule via cron (every few minutes: `extract_logs.py`, `fim_monitor.py`, `nmap_scanner.py`, `tshark_collector.py`, `snort_collector.py`, followed by `alerts_engine.py`), and the API as a systemd service (`raven-api.service`, invoking `run_api.sh`) so it survives reboots and restarts on failure. The dashboard is built (`npm run build`) and served as static files, or run via `npm start` for development.
