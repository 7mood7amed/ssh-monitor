#!/usr/bin/env python3
"""
ai_engine.py — Raven AI Engine
Rule-based correlation + Claude AI narrative analysis via Anthropic API.
"""
from __future__ import annotations

import os
import json
import urllib.request
import urllib.error
from datetime import datetime
from collections import defaultdict
from typing import Any, Dict, List

import psycopg2
import psycopg2.extras

DB_CONFIG = {
    "dbname":   os.environ.get("DB_NAME",  "logdb"),
    "user":     os.environ.get("DB_USER",  "hero"),
    "password": os.environ.get("DB_PASS",  "hero"),
    "host":     os.environ.get("DB_HOST",  "localhost"),
    "port":     int(os.environ.get("DB_PORT", "5432")),
}

# ── Anthropic API config ──────────────────────────────────────────────────────
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "").strip()
CLAUDE_MODEL      = os.environ.get("CLAUDE_MODEL", "claude-opus-4-5")
AI_ENABLED        = bool(ANTHROPIC_API_KEY)

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}

INTERNAL_IPS = {"192.168.56.104", "127.0.0.1", "::1"}


def get_conn():
    return psycopg2.connect(**DB_CONFIG)


def _fmt_dt(dt: Any) -> str:
    if not dt:
        return ""
    if isinstance(dt, datetime):
        return dt.replace(microsecond=0).isoformat(sep=" ")
    return str(dt)


def _safe_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default


def is_internal_ip(ip: str) -> bool:
    if not ip:
        return False
    return str(ip).strip().replace("::ffff:", "") in INTERNAL_IPS


def classify_ip_scope(ip: str) -> str:
    return "internal" if is_internal_ip(ip) else "external"


# ── Anthropic API call (pure stdlib — no SDK needed) ─────────────────────────

def _call_claude(system_prompt: str, user_message: str, max_tokens: int = 1024) -> str:
    """
    Call Claude via the Anthropic Messages API.
    Returns the text response or raises on error.
    """
    payload = json.dumps({
        "model":      CLAUDE_MODEL,
        "max_tokens": max_tokens,
        "system":     system_prompt,
        "messages":   [{"role": "user", "content": user_message}],
    }).encode("utf-8")

    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=payload,
        headers={
            "x-api-key":         ANTHROPIC_API_KEY,
            "anthropic-version": "2023-06-01",
            "content-type":      "application/json",
        },
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=30) as resp:
        body = json.loads(resp.read().decode("utf-8"))

    # content is a list of blocks; grab the first text block
    for block in body.get("content", []):
        if block.get("type") == "text":
            return block["text"].strip()

    return ""


# ── Main engine ───────────────────────────────────────────────────────────────

class RavenAIEngine:
    def __init__(self):
        self.db_config = DB_CONFIG

    # ── Public entry point ────────────────────────────────────────────────────

    def analyze_recent_activity(self, hours: int = 1) -> Dict[str, Any]:
        hours = max(1, min(int(hours), 168))

        facts        = self.collect_facts(hours=hours)
        correlations = self.cross_reference(facts)
        risk         = self.compute_risk(facts, correlations)
        report_data  = self.build_report_payload(facts, correlations, risk)

        # Try Claude AI first, fall back to rule-based summary
        ai_summary    = None
        ai_generated  = False
        ai_error      = None

        if AI_ENABLED:
            try:
                ai_summary   = self._generate_claude_summary(facts, correlations, risk, report_data)
                ai_generated = True
            except urllib.error.URLError as e:
                ai_error = f"Network error reaching Anthropic API: {e}"
            except Exception as e:
                ai_error = f"Claude API error: {e}"

        if not ai_summary:
            ai_summary = self.generate_fallback_summary(report_data)

        return {
            "window_hours":  hours,
            "generated_at":  _fmt_dt(datetime.utcnow()),
            "risk":          risk,
            "summary":       ai_summary,
            "ai_generated":  ai_generated,
            "ai_enabled":    AI_ENABLED,
            "ai_model":      CLAUDE_MODEL if AI_ENABLED else None,
            "ai_error":      ai_error,
            "facts":         facts,
            "correlations":  correlations,
            "report_data":   report_data,
        }

    # ── Claude AI narrative ───────────────────────────────────────────────────

    def _generate_claude_summary(
        self,
        facts: Dict[str, Any],
        correlations: Dict[str, Any],
        risk: Dict[str, Any],
        report_data: Dict[str, Any],
    ) -> str:
        system_prompt = (
            "You are a cybersecurity analyst assistant embedded in Raven, "
            "a multi-protocol security monitoring system. "
            "You receive structured security data collected from SSH logs, FTP logs, "
            "Apache web logs, Nmap port scans, TShark packet captures, and file integrity "
            "monitoring (FIM) of critical system files and the web root. "
            "Your job is to write a concise, professional security analysis narrative "
            "based strictly on the provided data. "
            "\n\nRules:"
            "\n- Never invent IPs, usernames, counts, file paths, event types, or events not present in the data."
            "\n- Clearly distinguish internal/trusted hosts from external/suspicious sources."
            "\n- Use professional SOC analyst language."
            "\n- Identify the most significant threats first."
            "\n- Call out multi-source correlation when the same IP appears across multiple services."
            "\n- If a file integrity change occurs shortly after a CRITICAL alert from another source, call out "
            "that sequence explicitly as a possible post-compromise indicator rather than listing it in isolation."
            "\n- End with 1-2 concrete analyst recommendations."
            "\n- Keep the response under 250 words."
            "\n- Write in flowing prose, not bullet points."
        )

        # Build a clean, compact evidence summary for the prompt
        totals  = report_data.get("totals", {})
        risk_l  = risk.get("level", "unknown").upper()
        risk_s  = risk.get("score", 0)
        reasons = risk.get("reasons", [])

        top_ext = report_data.get("top_external")
        top_int = report_data.get("top_internal")
        multi   = report_data.get("multi_source_ips", [])

        recent_alerts = [
            f"{a.get('priority','?').upper()} — {a.get('title','?')} "
            f"(source: {a.get('source','?')}, ip: {a.get('ip_address','?')})"
            for a in report_data.get("recent_alerts", [])[:8]
        ]

        attack_stages = report_data.get("attack_stages", {})
        stages = [s.get("stage", "") for s in attack_stages.get("stages", [])]

        # Top correlated IPs (external only, top 5)
        top_ips = [
            {
                "ip":       c.get("ip"),
                "scope":    c.get("ip_scope"),
                "ssh_fail": c.get("ssh_failures", 0),
                "ftp_fail": c.get("ftp_failures", 0),
                "web_hits": c.get("web_hits", 0),
                "alerts":   c.get("alert_count", 0),
                "sources":  c.get("sources", []),
                "patterns": c.get("probable_patterns", []),
            }
            for c in correlations.get("correlated_ips", [])[:5]
            if c.get("ip_scope") == "external" or c.get("activity_score", 0) > 10
        ]

        evidence = {
            "risk_score":    risk_s,
            "risk_level":    risk_l,
            "risk_reasons":  reasons,
            "window_hours":  1,
            "totals":        totals,
            "recent_alerts": recent_alerts,
            "attack_stages": stages,
            "top_ips":       top_ips,
            "fim_summary":   report_data.get("top_fim_changes", []),
            "multi_source_ips_count": len(multi),
        }

        user_message = (
            f"Here is the current security evidence from the Raven monitoring system:\n\n"
            f"{json.dumps(evidence, indent=2, default=str)}\n\n"
            f"Write a professional security analysis narrative based on this data."
        )

        return _call_claude(system_prompt, user_message, max_tokens=400)

    # ── Data collection ───────────────────────────────────────────────────────

    def collect_facts(self, hours: int = 1) -> Dict[str, Any]:
        conn = get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                facts: Dict[str, Any] = {}

                cur.execute("""
                    SELECT ip, COALESCE(username,'(unknown)') AS username,
                           COUNT(*) AS count,
                           MIN(event_time) AS first_seen, MAX(event_time) AS last_seen
                    FROM public.ssh_events
                    WHERE event_time >= NOW() - (%s || ' hours')::interval
                      AND event_type = 'login_fail' AND outcome = 'fail' AND ip IS NOT NULL
                    GROUP BY ip, COALESCE(username,'(unknown)')
                    ORDER BY count DESC LIMIT 50;
                """, (hours,))
                facts["ssh_failures"] = [dict(r) for r in cur.fetchall()]

                cur.execute("""
                    SELECT ip, COALESCE(username,'(unknown)') AS username,
                           COUNT(*) AS count, MAX(event_time) AS last_seen
                    FROM public.ssh_events
                    WHERE event_time >= NOW() - (%s || ' hours')::interval
                      AND event_type = 'login_success' AND outcome = 'success' AND ip IS NOT NULL
                    GROUP BY ip, COALESCE(username,'(unknown)')
                    ORDER BY count DESC LIMIT 50;
                """, (hours,))
                facts["ssh_successes"] = [dict(r) for r in cur.fetchall()]

                cur.execute("""
                    SELECT ip, COALESCE(username,'(unknown)') AS username,
                           COUNT(*) AS count,
                           MIN(event_time) AS first_seen, MAX(event_time) AS last_seen
                    FROM public.ftp_events
                    WHERE event_time >= NOW() - (%s || ' hours')::interval
                      AND (action = 'LOGIN_FAIL' OR raw ILIKE '%%530%%' OR raw ILIKE '%%Login incorrect%%')
                      AND ip IS NOT NULL
                    GROUP BY ip, COALESCE(username,'(unknown)')
                    ORDER BY count DESC LIMIT 50;
                """, (hours,))
                facts["ftp_failures"] = [dict(r) for r in cur.fetchall()]

                cur.execute("""
                    SELECT ip, COALESCE(username,'(unknown)') AS username,
                           COUNT(*) AS count, MAX(event_time) AS last_seen
                    FROM public.ftp_events
                    WHERE event_time >= NOW() - (%s || ' hours')::interval
                      AND action = 'LOGIN_SUCCESS' AND ip IS NOT NULL
                    GROUP BY ip, COALESCE(username,'(unknown)')
                    ORDER BY count DESC LIMIT 50;
                """, (hours,))
                facts["ftp_successes"] = [dict(r) for r in cur.fetchall()]

                cur.execute("""
                    SELECT split_part(message,' ',1) AS ip,
                           COUNT(*) AS count, MAX(log_time) AS last_seen
                    FROM public.logs
                    WHERE source LIKE '/var/log/apache2/access.log%%'
                      AND log_time >= NOW() - (%s || ' hours')::interval
                      AND (severity IN ('MEDIUM','HIGH','CRITICAL')
                           OR message ILIKE '%%/admin%%'
                           OR message ILIKE '%%/login%%'
                           OR message ILIKE '%%/phpmyadmin%%'
                           OR message ILIKE '%%/phppgadmin%%')
                    GROUP BY split_part(message,' ',1)
                    ORDER BY count DESC LIMIT 50;
                """, (hours,))
                facts["web_suspicious_ips"] = [dict(r) for r in cur.fetchall()]

                cur.execute("""
                    SELECT host, port, proto, state, service, target,
                           MAX(scan_time) AS last_seen
                    FROM public.nmap_findings
                    WHERE scan_time >= NOW() - (%s || ' hours')::interval
                    GROUP BY host, port, proto, state, service, target
                    ORDER BY last_seen DESC LIMIT 100;
                """, (hours,))
                facts["nmap_findings"] = [dict(r) for r in cur.fetchall()]

                cur.execute("""
                    SELECT file_path, event_type, severity,
                           COUNT(*) AS count, MAX(detected_at) AS last_seen
                    FROM public.fim_events
                    WHERE detected_at >= NOW() - (%s || ' hours')::interval
                    GROUP BY file_path, event_type, severity
                    ORDER BY last_seen DESC LIMIT 50;
                """, (hours,))
                facts["fim_changes"] = [dict(r) for r in cur.fetchall()]

                cur.execute("""
                    SELECT id, created_at, source, priority, title,
                           description, user_name, ip_address, file_target, status
                    FROM public.alerts
                    WHERE created_at >= NOW() - (%s || ' hours')::interval
                    ORDER BY created_at DESC LIMIT 100;
                """, (hours,))
                facts["alerts"] = [dict(r) for r in cur.fetchall()]

                cur.execute("""
                    SELECT LOWER(priority) AS priority, COUNT(*) AS count
                    FROM public.alerts
                    WHERE created_at >= NOW() - (%s || ' hours')::interval
                    GROUP BY LOWER(priority);
                """, (hours,))
                facts["alert_priority_counts"] = {
                    r["priority"]: int(r["count"]) for r in cur.fetchall()
                }

                cur.execute("SELECT agent_name, last_heartbeat FROM public.agent_status ORDER BY agent_name;")
                facts["agents"] = [dict(r) for r in cur.fetchall()]

                return facts
        finally:
            conn.close()

    # ── Cross-reference ───────────────────────────────────────────────────────

    def cross_reference(self, facts: Dict[str, Any]) -> Dict[str, Any]:
        ip_map: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "ssh_failures": 0, "ssh_successes": 0,
            "ftp_failures": 0, "ftp_successes": 0,
            "web_hits": 0, "nmap_ports": [],
            "alerts": [], "usernames": set(), "sources": set(),
        })

        for row in facts.get("ssh_failures", []):
            ip = row.get("ip")
            if not ip: continue
            ip_map[ip]["ssh_failures"] += _safe_int(row.get("count"))
            ip_map[ip]["usernames"].add(row.get("username") or "(unknown)")
            ip_map[ip]["sources"].add("ssh")

        for row in facts.get("ssh_successes", []):
            ip = row.get("ip")
            if not ip: continue
            ip_map[ip]["ssh_successes"] += _safe_int(row.get("count"))
            ip_map[ip]["usernames"].add(row.get("username") or "(unknown)")
            ip_map[ip]["sources"].add("ssh")

        for row in facts.get("ftp_failures", []):
            ip = row.get("ip")
            if not ip: continue
            ip_map[ip]["ftp_failures"] += _safe_int(row.get("count"))
            ip_map[ip]["usernames"].add(row.get("username") or "(unknown)")
            ip_map[ip]["sources"].add("ftp")

        for row in facts.get("ftp_successes", []):
            ip = row.get("ip")
            if not ip: continue
            ip_map[ip]["ftp_successes"] += _safe_int(row.get("count"))
            ip_map[ip]["usernames"].add(row.get("username") or "(unknown)")
            ip_map[ip]["sources"].add("ftp")

        for row in facts.get("web_suspicious_ips", []):
            ip = row.get("ip")
            if not ip: continue
            ip_map[ip]["web_hits"] += _safe_int(row.get("count"))
            ip_map[ip]["sources"].add("web")

        for row in facts.get("nmap_findings", []):
            ip = row.get("host")
            if not ip: continue
            ip_map[ip]["nmap_ports"].append({
                "port": row.get("port"), "proto": row.get("proto"),
                "state": row.get("state"), "service": row.get("service"),
                "target": row.get("target"),
            })
            ip_map[ip]["sources"].add("nmap")

        for row in facts.get("alerts", []):
            ip = row.get("ip_address")
            if not ip: continue
            ip_map[ip]["alerts"].append({
                "id": row.get("id"), "title": row.get("title"),
                "priority": row.get("priority"), "source": row.get("source"),
                "status": row.get("status"),
            })
            if row.get("user_name"):
                ip_map[ip]["usernames"].add(row.get("user_name"))
            if row.get("source"):
                ip_map[ip]["sources"].add(row.get("source"))

        correlated_ips = []
        for ip, data in ip_map.items():
            source_count = len(data["sources"])
            ip_scope = classify_ip_scope(ip)

            activity_score = (
                data["ssh_failures"] * 3
                + data["ftp_failures"] * 3
                + data["web_hits"] * 1
                + len(data["nmap_ports"]) * 2
                + len(data["alerts"]) * 2
            )

            probable_patterns = []
            if data["ssh_failures"] >= 5:
                probable_patterns.append("possible SSH brute force")
            if data["ftp_failures"] >= 5:
                probable_patterns.append("possible FTP brute force")
            if data["web_hits"] >= 10:
                probable_patterns.append("web probing or scanning")
            if source_count >= 2:
                probable_patterns.append("cross-source correlated activity")
            if any(p.get("state") == "open" and p.get("port") in {21, 22, 3389, 3306, 5432}
                   for p in data["nmap_ports"]):
                probable_patterns.append("sensitive exposed service")

            assessment = "trusted local Raven host" if ip_scope == "internal" else "external suspicious source"

            correlated_ips.append({
                "ip":             ip,
                "ip_scope":       ip_scope,
                "assessment":     assessment,
                "sources":        sorted(list(data["sources"])),
                "source_count":   source_count,
                "ssh_failures":   data["ssh_failures"],
                "ssh_successes":  data["ssh_successes"],
                "ftp_failures":   data["ftp_failures"],
                "ftp_successes":  data["ftp_successes"],
                "web_hits":       data["web_hits"],
                "nmap_port_count": len(data["nmap_ports"]),
                "alert_count":    len(data["alerts"]),
                "usernames":      sorted([u for u in data["usernames"] if u]),
                "activity_score": activity_score,
                "probable_patterns": probable_patterns,
            })

        correlated_ips.sort(key=lambda x: x["activity_score"], reverse=True)

        return {
            "correlated_ips":   correlated_ips[:20],
            "top_activity_ip":  correlated_ips[0] if correlated_ips else None,
            "top_external_ip":  next((x for x in correlated_ips if x["ip_scope"] == "external"), None),
            "top_internal_ip":  next((x for x in correlated_ips if x["ip_scope"] == "internal"), None),
            "multi_source_ips": [x for x in correlated_ips if x["source_count"] >= 2][:20],
        }

    # ── Risk scoring ──────────────────────────────────────────────────────────

    def compute_risk(self, facts: Dict[str, Any], correlations: Dict[str, Any]) -> Dict[str, Any]:
        score = 0
        reasons: List[str] = []
        pr = facts.get("alert_priority_counts", {})

        critical_alerts = _safe_int(pr.get("critical"))
        high_alerts     = _safe_int(pr.get("high"))
        medium_alerts   = _safe_int(pr.get("medium"))

        if critical_alerts:
            score += critical_alerts * 25
            reasons.append(f"{critical_alerts} critical alert(s)")
        if high_alerts:
            score += high_alerts * 12
            reasons.append(f"{high_alerts} high alert(s)")
        if medium_alerts:
            score += medium_alerts * 5
            reasons.append(f"{medium_alerts} medium alert(s)")

        ssh_fail_total = sum(_safe_int(x.get("count")) for x in facts.get("ssh_failures", []))
        ftp_fail_total = sum(_safe_int(x.get("count")) for x in facts.get("ftp_failures", []))
        web_hit_total  = sum(_safe_int(x.get("count")) for x in facts.get("web_suspicious_ips", []))
        sensitive_ports = sum(
            1 for r in facts.get("nmap_findings", [])
            if r.get("state") == "open" and r.get("port") in {21,22,23,3389,3306,5432,6379,27017}
        )

        if ssh_fail_total >= 5:
            score += 10; reasons.append(f"{ssh_fail_total} SSH failed login attempts")
        if ftp_fail_total >= 5:
            score += 10; reasons.append(f"{ftp_fail_total} FTP failed login attempts")
        if web_hit_total >= 20:
            score += 8;  reasons.append(f"{web_hit_total} suspicious web requests")
        if sensitive_ports > 0:
            score += sensitive_ports * 6
            reasons.append(f"{sensitive_ports} sensitive open port finding(s)")

        fim_critical_total = sum(
            _safe_int(x.get("count")) for x in facts.get("fim_changes", [])
            if str(x.get("severity") or "").upper() == "CRITICAL"
        )
        fim_total = sum(_safe_int(x.get("count")) for x in facts.get("fim_changes", []))

        if fim_critical_total > 0:
            score += fim_critical_total * 15
            reasons.append(f"{fim_critical_total} critical file integrity change(s) (passwd/shadow/sudoers)")
        if fim_total >= 3:
            score += 8; reasons.append(f"{fim_total} file integrity change(s) observed")

        multi_source_count = len(correlations.get("multi_source_ips", []))
        if multi_source_count > 0:
            score += multi_source_count * 7
            reasons.append(f"{multi_source_count} IP(s) active across multiple sources")

        alert_titles = [str(a.get("title") or "") for a in facts.get("alerts", [])]

        if any("Reconnaissance Campaign Detected" in t for t in alert_titles):
            score += 40; reasons.append("correlated reconnaissance campaign detected")
        if any("TShark: Possible ICMP Sweep" in t for t in alert_titles):
            score += 15; reasons.append("ICMP reconnaissance activity observed")
        if any("TShark: Possible DNS Beaconing" in t for t in alert_titles):
            score += 20; reasons.append("DNS beaconing-style activity observed")
        if any("TShark: Suspicious HTTP Path Probing" in t for t in alert_titles):
            score += 20; reasons.append("HTTP path probing detected")
        if any("FIM: Critical System File" in t for t in alert_titles):
            score += 20; reasons.append("critical system file (passwd/shadow/sudoers) modified")

        score = min(score, 100)
        level = "low"
        if score >= 85:   level = "critical"
        elif score >= 60: level = "high"
        elif score >= 30: level = "medium"

        return {"score": score, "level": level, "reasons": reasons[:10]}

    # ── Report payload ────────────────────────────────────────────────────────

    def build_report_payload(
        self,
        facts: Dict[str, Any],
        correlations: Dict[str, Any],
        risk: Dict[str, Any],
    ) -> Dict[str, Any]:
        top_activity = correlations.get("top_activity_ip")
        top_external = correlations.get("top_external_ip")
        top_internal = correlations.get("top_internal_ip")
        recent_alerts = facts.get("alerts", [])[:10]
        attack_stages = self.infer_attack_stages(recent_alerts)

        return {
            "risk":         risk,
            "top_activity": top_activity,
            "top_external": top_external,
            "top_internal": top_internal,
            "attack_stages": attack_stages,
            "totals": {
                "ssh_failures":          sum(_safe_int(x.get("count")) for x in facts.get("ssh_failures", [])),
                "ftp_failures":          sum(_safe_int(x.get("count")) for x in facts.get("ftp_failures", [])),
                "web_suspicious_hits":   sum(_safe_int(x.get("count")) for x in facts.get("web_suspicious_ips", [])),
                "alerts":                len(facts.get("alerts", [])),
                "nmap_findings":         len(facts.get("nmap_findings", [])),
                "fim_changes":           sum(_safe_int(x.get("count")) for x in facts.get("fim_changes", [])),
                "fim_critical_changes":  sum(
                    _safe_int(x.get("count")) for x in facts.get("fim_changes", [])
                    if str(x.get("severity") or "").upper() == "CRITICAL"
                ),
            },
            "top_ssh_failure_ips": [
                {"ip": x.get("ip"), "username": x.get("username"), "count": x.get("count")}
                for x in facts.get("ssh_failures", [])[:5]
            ],
            "top_ftp_failure_ips": [
                {"ip": x.get("ip"), "username": x.get("username"), "count": x.get("count")}
                for x in facts.get("ftp_failures", [])[:5]
            ],
            "top_web_ips": [
                {"ip": x.get("ip"), "count": x.get("count")}
                for x in facts.get("web_suspicious_ips", [])[:5]
            ],
            "top_fim_changes": [
                {
                    "file_path": x.get("file_path"), "event_type": x.get("event_type"),
                    "severity": x.get("severity"), "count": x.get("count"),
                }
                for x in facts.get("fim_changes", [])[:5]
            ],
            "multi_source_ips": correlations.get("multi_source_ips", [])[:5],
            "recent_alerts": [
                {
                    "id": x.get("id"), "source": x.get("source"),
                    "priority": x.get("priority"), "title": x.get("title"),
                    "status": x.get("status"), "ip_address": x.get("ip_address"),
                }
                for x in facts.get("alerts", [])[:10]
            ],
        }

    # ── Attack stage inference ────────────────────────────────────────────────

    def infer_attack_stages(self, recent_alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        titles = [str(a.get("title") or "") for a in recent_alerts]
        stages = []

        if any("Nmap" in t or "Port Scan" in t for t in titles):
            stages.append({"stage": "Reconnaissance", "evidence": "Port scan or service discovery observed."})
        if any("ICMP Sweep" in t for t in titles):
            stages.append({"stage": "Host Discovery", "evidence": "ICMP sweep suggests network mapping."})
        if any("DNS Beaconing" in t for t in titles):
            stages.append({"stage": "C2 Indicator", "evidence": "DNS query bursts may indicate beaconing."})
        if any("HTTP Path Probing" in t or "Sensitive Path Probing" in t for t in titles):
            stages.append({"stage": "Web Enumeration", "evidence": "Suspicious HTTP requests to sensitive paths."})
        if any("SSH Brute Force" in t or "FTP Brute Force" in t for t in titles):
            stages.append({"stage": "Initial Access Attempt", "evidence": "Repeated authentication failures."})
        if any("Reconnaissance Campaign Detected" in t for t in titles):
            stages.append({"stage": "Campaign Correlation", "evidence": "Multiple detections grouped into campaign."})
        if any("FIM:" in t for t in titles):
            stages.append({
                "stage": "File Integrity Violation",
                "evidence": "Unauthorized change detected on a watched file (possible tampering or persistence).",
            })

        confidence = "low"
        if len(stages) >= 4:   confidence = "high"
        elif len(stages) >= 2: confidence = "medium"

        return {"stage_count": len(stages), "confidence": confidence, "stages": stages}

    # ── Rule-based fallback summary ───────────────────────────────────────────

    def generate_fallback_summary(self, report_data: Dict[str, Any]) -> str:
        risk          = report_data["risk"]["level"]
        totals        = report_data["totals"]
        top_activity  = report_data.get("top_activity")
        top_external  = report_data.get("top_external")
        top_internal  = report_data.get("top_internal")
        recent_alerts = report_data.get("recent_alerts", [])
        alert_titles  = [a.get("title", "") for a in recent_alerts]

        lines = [
            f"Overall system risk is {risk.upper()}. "
            f"During the selected window, Raven observed {totals['alerts']} alert(s), "
            f"{totals['ssh_failures']} SSH failed login attempt(s), "
            f"{totals['ftp_failures']} FTP failed login attempt(s), "
            f"and {totals['web_suspicious_hits']} suspicious web request(s)."
        ]

        if top_external:
            lines.append(
                f"The most suspicious external source is {top_external['ip']}, active across "
                f"{top_external['source_count']} source(s), with patterns including "
                f"{', '.join(top_external['probable_patterns']) or 'general suspicious activity'}."
            )
        elif top_internal:
            lines.append(
                f"Top correlated source is {top_internal['ip']} (internal/test), "
                f"active across {top_internal['source_count']} source(s)."
            )

        multi = report_data.get("multi_source_ips", [])
        if multi:
            lines.append(
                f"Cross-source correlation detected for {len(multi)} IP(s) "
                f"across SSH, FTP, web, or Nmap sources."
            )

        if totals.get("fim_critical_changes"):
            lines.append(
                f"File integrity monitoring detected {totals['fim_critical_changes']} critical change(s) "
                f"to sensitive system files (passwd/shadow/sudoers), a possible indicator of privilege "
                f"escalation or persistence."
            )
        elif totals.get("fim_changes"):
            lines.append(
                f"File integrity monitoring logged {totals['fim_changes']} change(s) to watched files."
            )

        attack_stages = report_data.get("attack_stages", {})
        stages = attack_stages.get("stages", [])
        if stages:
            stage_names = " → ".join(s["stage"] for s in stages)
            lines.append(
                f"Attack chain: {attack_stages.get('stage_count', len(stages))} stage(s) "
                f"({attack_stages.get('confidence','low').upper()} confidence): {stage_names}."
            )

        if recent_alerts:
            top_titles = ", ".join(a["title"] for a in recent_alerts[:3] if a.get("title"))
            if top_titles:
                lines.append(f"Recent alerts: {top_titles}.")

        lines.append(
            "This summary is based on structured database evidence from SSH, FTP, web, Nmap, TShark, and alert records."
        )

        return " ".join(lines)


# ── Module-level entry point (called by api_server.py) ───────────────────────

def analyze_recent_activity(hours: int = 1) -> Dict[str, Any]:
    engine = RavenAIEngine()
    return engine.analyze_recent_activity(hours=hours)