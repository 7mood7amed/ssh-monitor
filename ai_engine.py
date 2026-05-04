#!/usr/bin/env python3
from __future__ import annotations

import os
import json
import ipaddress
from datetime import datetime
from collections import defaultdict
from typing import Any, Dict, List

import psycopg2
import psycopg2.extras

DB_CONFIG = {
    "dbname": os.environ.get("DB_NAME", "logdb"),
    "user": os.environ.get("DB_USER", "hero"),
    "password": os.environ.get("DB_PASS", "hero"),
    "host": os.environ.get("DB_HOST", "localhost"),
    "port": int(os.environ.get("DB_PORT", "5432")),
}

AI_ENABLE_LLM = os.environ.get("AI_ENABLE_LLM", "0").strip() == "1"
AI_MODEL = os.environ.get("AI_MODEL", "gpt-4.1-mini")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "").strip()

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


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


# =============================
# CUSTOM INTERNAL CLASSIFICATION
# =============================

# Only Raven is internal
INTERNAL_IPS = {
    "192.168.56.104",  # Raven VM
    "127.0.0.1",
    "::1",
}

DEMO_EXTERNAL_IPS = {
    # Add your Kali / attacker machine IP here if needed
    # Example: "192.168.56.105",
}

def is_internal_ip(ip: str) -> bool:
    if not ip:
        return False

    ip = str(ip).strip().replace("::ffff:", "")

    if ip in DEMO_EXTERNAL_IPS:
        return False

    return ip in INTERNAL_IPS


def classify_ip_scope(ip: str) -> str:
    return "internal" if is_internal_ip(ip) else "external"


class RavenAIEngine:
    def __init__(self):
        self.db_config = DB_CONFIG

    def analyze_recent_activity(self, hours: int = 1) -> Dict[str, Any]:
        hours = max(1, min(int(hours), 168))

        facts = self.collect_facts(hours=hours)
        correlations = self.cross_reference(facts)
        risk = self.compute_risk(facts, correlations)
        report_data = self.build_report_payload(facts, correlations, risk)

        llm_summary = None
        if AI_ENABLE_LLM and OPENAI_API_KEY:
            try:
                llm_summary = self.generate_llm_summary(report_data)
            except Exception as e:
                llm_summary = f"LLM summary unavailable: {e}"

        if not llm_summary:
            llm_summary = self.generate_fallback_summary(report_data)

        return {
            "window_hours": hours,
            "generated_at": _fmt_dt(datetime.utcnow()),
            "risk": risk,
            "summary": llm_summary,
            "facts": facts,
            "correlations": correlations,
            "report_data": report_data,
        }

    def collect_facts(self, hours: int = 1) -> Dict[str, Any]:
        conn = get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                facts: Dict[str, Any] = {}

                cur.execute(
                    """
                    SELECT ip, COALESCE(username, '(unknown)') AS username, COUNT(*) AS count,
                           MIN(event_time) AS first_seen, MAX(event_time) AS last_seen
                    FROM public.ssh_events
                    WHERE event_time >= NOW() - (%s || ' hours')::interval
                      AND event_type = 'login_fail'
                      AND outcome = 'fail'
                      AND ip IS NOT NULL
                    GROUP BY ip, COALESCE(username, '(unknown)')
                    ORDER BY count DESC
                    LIMIT 50;
                    """,
                    (hours,),
                )
                facts["ssh_failures"] = [dict(r) for r in cur.fetchall()]

                cur.execute(
                    """
                    SELECT ip, COALESCE(username, '(unknown)') AS username, COUNT(*) AS count,
                           MAX(event_time) AS last_seen
                    FROM public.ssh_events
                    WHERE event_time >= NOW() - (%s || ' hours')::interval
                      AND event_type = 'login_success'
                      AND outcome = 'success'
                      AND ip IS NOT NULL
                    GROUP BY ip, COALESCE(username, '(unknown)')
                    ORDER BY count DESC
                    LIMIT 50;
                    """,
                    (hours,),
                )
                facts["ssh_successes"] = [dict(r) for r in cur.fetchall()]

                cur.execute(
                    """
                    SELECT ip, COALESCE(username, '(unknown)') AS username, COUNT(*) AS count,
                           MIN(event_time) AS first_seen, MAX(event_time) AS last_seen
                    FROM public.ftp_events
                    WHERE event_time >= NOW() - (%s || ' hours')::interval
                      AND (
                            action = 'LOGIN_FAIL'
                            OR raw ILIKE '%%530%%'
                            OR raw ILIKE '%%Login incorrect%%'
                          )
                      AND ip IS NOT NULL
                    GROUP BY ip, COALESCE(username, '(unknown)')
                    ORDER BY count DESC
                    LIMIT 50;
                    """,
                    (hours,),
                )
                facts["ftp_failures"] = [dict(r) for r in cur.fetchall()]

                cur.execute(
                    """
                    SELECT ip, COALESCE(username, '(unknown)') AS username, COUNT(*) AS count,
                           MAX(event_time) AS last_seen
                    FROM public.ftp_events
                    WHERE event_time >= NOW() - (%s || ' hours')::interval
                      AND action = 'LOGIN_SUCCESS'
                      AND ip IS NOT NULL
                    GROUP BY ip, COALESCE(username, '(unknown)')
                    ORDER BY count DESC
                    LIMIT 50;
                    """,
                    (hours,),
                )
                facts["ftp_successes"] = [dict(r) for r in cur.fetchall()]

                cur.execute(
                    """
                    SELECT
                        split_part(message, ' ', 1) AS ip,
                        COUNT(*) AS count,
                        MAX(log_time) AS last_seen
                    FROM public.logs
                    WHERE source LIKE '/var/log/apache2/access.log%%'
                      AND log_time >= NOW() - (%s || ' hours')::interval
                      AND (
                            severity IN ('MEDIUM', 'HIGH', 'CRITICAL')
                            OR message ILIKE '%%/admin%%'
                            OR message ILIKE '%%/login%%'
                            OR message ILIKE '%%/phpmyadmin%%'
                            OR message ILIKE '%%/phppgadmin%%'
                          )
                    GROUP BY split_part(message, ' ', 1)
                    ORDER BY count DESC
                    LIMIT 50;
                    """,
                    (hours,),
                )
                facts["web_suspicious_ips"] = [dict(r) for r in cur.fetchall()]

                cur.execute(
                    """
                    SELECT host, port, proto, state, service, target, MAX(scan_time) AS last_seen
                    FROM public.nmap_findings
                    WHERE scan_time >= NOW() - (%s || ' hours')::interval
                    GROUP BY host, port, proto, state, service, target
                    ORDER BY last_seen DESC
                    LIMIT 100;
                    """,
                    (hours,),
                )
                facts["nmap_findings"] = [dict(r) for r in cur.fetchall()]

                cur.execute(
                    """
                    SELECT id, created_at, source, priority, title, description,
                           user_name, ip_address, file_target, status
                    FROM public.alerts
                    WHERE created_at >= NOW() - (%s || ' hours')::interval
                    ORDER BY created_at DESC
                    LIMIT 100;
                    """,
                    (hours,),
                )
                facts["alerts"] = [dict(r) for r in cur.fetchall()]

                cur.execute(
                    """
                    SELECT LOWER(priority) AS priority, COUNT(*) AS count
                    FROM public.alerts
                    WHERE created_at >= NOW() - (%s || ' hours')::interval
                    GROUP BY LOWER(priority);
                    """,
                    (hours,),
                )
                facts["alert_priority_counts"] = {r["priority"]: int(r["count"]) for r in cur.fetchall()}

                cur.execute(
                    """
                    SELECT agent_name, last_heartbeat
                    FROM public.agent_status
                    ORDER BY agent_name;
                    """
                )
                facts["agents"] = [dict(r) for r in cur.fetchall()]

                return facts
        finally:
            conn.close()

    def cross_reference(self, facts: Dict[str, Any]) -> Dict[str, Any]:
        ip_map: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "ssh_failures": 0,
            "ssh_successes": 0,
            "ftp_failures": 0,
            "ftp_successes": 0,
            "web_hits": 0,
            "nmap_ports": [],
            "alerts": [],
            "usernames": set(),
            "sources": set(),
        })

        for row in facts.get("ssh_failures", []):
            ip = row.get("ip")
            if not ip:
                continue
            ip_map[ip]["ssh_failures"] += _safe_int(row.get("count"))
            ip_map[ip]["usernames"].add(row.get("username") or "(unknown)")
            ip_map[ip]["sources"].add("ssh")

        for row in facts.get("ssh_successes", []):
            ip = row.get("ip")
            if not ip:
                continue
            ip_map[ip]["ssh_successes"] += _safe_int(row.get("count"))
            ip_map[ip]["usernames"].add(row.get("username") or "(unknown)")
            ip_map[ip]["sources"].add("ssh")

        for row in facts.get("ftp_failures", []):
            ip = row.get("ip")
            if not ip:
                continue
            ip_map[ip]["ftp_failures"] += _safe_int(row.get("count"))
            ip_map[ip]["usernames"].add(row.get("username") or "(unknown)")
            ip_map[ip]["sources"].add("ftp")

        for row in facts.get("ftp_successes", []):
            ip = row.get("ip")
            if not ip:
                continue
            ip_map[ip]["ftp_successes"] += _safe_int(row.get("count"))
            ip_map[ip]["usernames"].add(row.get("username") or "(unknown)")
            ip_map[ip]["sources"].add("ftp")

        for row in facts.get("web_suspicious_ips", []):
            ip = row.get("ip")
            if not ip:
                continue
            ip_map[ip]["web_hits"] += _safe_int(row.get("count"))
            ip_map[ip]["sources"].add("web")

        for row in facts.get("nmap_findings", []):
            ip = row.get("host")
            if not ip:
                continue
            ip_map[ip]["nmap_ports"].append({
                "port": row.get("port"),
                "proto": row.get("proto"),
                "state": row.get("state"),
                "service": row.get("service"),
                "target": row.get("target"),
            })
            ip_map[ip]["sources"].add("nmap")

        for row in facts.get("alerts", []):
            ip = row.get("ip_address")
            if not ip:
                continue
            ip_map[ip]["alerts"].append({
                "id": row.get("id"),
                "title": row.get("title"),
                "priority": row.get("priority"),
                "source": row.get("source"),
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
            if any((p.get("state") == "open" and p.get("port") in {21, 22, 3389, 3306, 5432}) for p in data["nmap_ports"]):
                probable_patterns.append("sensitive exposed service")

            if ip_scope == "internal":
                assessment = "trusted local Raven host"
            else:
                assessment = "external suspicious source"

            correlated_ips.append({
                "ip": ip,
                "ip_scope": ip_scope,
                "assessment": assessment,
                "sources": sorted(list(data["sources"])),
                "source_count": source_count,
                "ssh_failures": data["ssh_failures"],
                "ssh_successes": data["ssh_successes"],
                "ftp_failures": data["ftp_failures"],
                "ftp_successes": data["ftp_successes"],
                "web_hits": data["web_hits"],
                "nmap_port_count": len(data["nmap_ports"]),
                "alert_count": len(data["alerts"]),
                "usernames": sorted([u for u in data["usernames"] if u]),
                "activity_score": activity_score,
                "probable_patterns": probable_patterns,
            })

        correlated_ips.sort(key=lambda x: x["activity_score"], reverse=True)

        top_external = next((x for x in correlated_ips if x["ip_scope"] == "external"), None)
        top_internal = next((x for x in correlated_ips if x["ip_scope"] == "internal"), None)
        top_overall = correlated_ips[0] if correlated_ips else None

        return {
            "correlated_ips": correlated_ips[:20],
            "top_activity_ip": top_overall,
            "top_external_ip": top_external,
            "top_internal_ip": top_internal,
            "multi_source_ips": [x for x in correlated_ips if x["source_count"] >= 2][:20],
        }

    def compute_risk(self, facts: Dict[str, Any], correlations: Dict[str, Any]) -> Dict[str, Any]:
        score = 0
        reasons: List[str] = []
        pr = facts.get("alert_priority_counts", {})
        critical_alerts = _safe_int(pr.get("critical"))
        high_alerts = _safe_int(pr.get("high"))
        medium_alerts = _safe_int(pr.get("medium"))

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
        web_hit_total = sum(_safe_int(x.get("count")) for x in facts.get("web_suspicious_ips", []))
        sensitive_open_ports = 0

        for row in facts.get("nmap_findings", []):
            if row.get("state") == "open" and row.get("port") in {21, 22, 23, 3389, 3306, 5432, 6379, 27017}:
                sensitive_open_ports += 1

        if ssh_fail_total >= 5:
            score += 10
            reasons.append(f"{ssh_fail_total} SSH failed login attempts")
        if ftp_fail_total >= 5:
            score += 10
            reasons.append(f"{ftp_fail_total} FTP failed login attempts")
        if web_hit_total >= 20:
            score += 8
            reasons.append(f"{web_hit_total} suspicious web requests")
        if sensitive_open_ports > 0:
            score += sensitive_open_ports * 6
            reasons.append(f"{sensitive_open_ports} sensitive open port finding(s)")

        multi_source_count = len(correlations.get("multi_source_ips", []))
        if multi_source_count > 0:
            score += multi_source_count * 7
            reasons.append(f"{multi_source_count} IP(s) active across multiple sources")

        # TSHARK + correlation intelligence
        alert_titles = [str(a.get("title") or "") for a in facts.get("alerts", [])]

        if any("Reconnaissance Campaign Detected" in t for t in alert_titles):
            score += 40
            reasons.append("correlated reconnaissance campaign detected")

        if any("TShark: Possible ICMP Sweep" in t for t in alert_titles):
            score += 15
            reasons.append("ICMP reconnaissance activity observed")

        if any("TShark: Possible DNS Beaconing" in t for t in alert_titles):
            score += 20
            reasons.append("DNS beaconing-style activity observed")

        if any("TShark: Suspicious HTTP Path Probing" in t for t in alert_titles):
            score += 20
            reasons.append("HTTP path probing detected")

        # Keep score readable
        score = min(score, 100)

        level = "low"
        if score >= 85:
            level = "critical"
        elif score >= 60:
            level = "high"
        elif score >= 30:
            level = "medium"

        return {
            "score": score,
            "level": level,
            "reasons": reasons[:10],
        }

    def build_report_payload(self, facts: Dict[str, Any], correlations: Dict[str, Any], risk: Dict[str, Any]) -> Dict[str, Any]:
        top_activity = correlations.get("top_activity_ip")
        top_external = correlations.get("top_external_ip")
        top_internal = correlations.get("top_internal_ip")
        recent_alerts = facts.get("alerts", [])[:10]
        attack_stages = self.infer_attack_stages(recent_alerts)
        return {
            "risk": risk,
            "top_activity": top_activity,
            "top_external": top_external,
            "top_internal": top_internal,
            "attack_stages": attack_stages,
            "totals": {
                "ssh_failures": sum(_safe_int(x.get("count")) for x in facts.get("ssh_failures", [])),
                "ftp_failures": sum(_safe_int(x.get("count")) for x in facts.get("ftp_failures", [])),
                "web_suspicious_hits": sum(_safe_int(x.get("count")) for x in facts.get("web_suspicious_ips", [])),
                "alerts": len(facts.get("alerts", [])),
                "nmap_findings": len(facts.get("nmap_findings", [])),
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
            "multi_source_ips": correlations.get("multi_source_ips", [])[:5],
            "recent_alerts": [
                {
                    "id": x.get("id"),
                    "source": x.get("source"),
                    "priority": x.get("priority"),
                    "title": x.get("title"),
                    "status": x.get("status"),
                    "ip_address": x.get("ip_address"),
                }
                for x in facts.get("alerts", [])[:10]
            ],
        }
    

    def infer_attack_stages(self, recent_alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        titles = [str(a.get("title") or "") for a in recent_alerts]

        stages = []

        if any("Nmap" in t or "Port Scan" in t for t in titles):
            stages.append({
                "stage": "Reconnaissance",
                "evidence": "Port scan or exposed-service discovery activity was observed.",
            })

        if any("ICMP Sweep" in t for t in titles):
            stages.append({
                "stage": "Host Discovery",
                "evidence": "ICMP sweep behavior suggests host discovery or network mapping.",
            })

        if any("DNS Beaconing" in t for t in titles):
            stages.append({
                "stage": "Command-and-Control Indicator",
                "evidence": "DNS query bursts may indicate beaconing-style or abnormal lookup behavior.",
            })

        if any("HTTP Path Probing" in t or "Sensitive Path Probing" in t for t in titles):
            stages.append({
                "stage": "Web Enumeration",
                "evidence": "Suspicious HTTP requests to sensitive paths were detected.",
            })

        if any("SSH Brute Force" in t or "FTP Brute Force" in t for t in titles):
            stages.append({
                "stage": "Initial Access Attempt",
                "evidence": "Repeated authentication failures suggest brute-force login attempts.",
            })

        if any("Reconnaissance Campaign Detected" in t for t in titles):
            stages.append({
                "stage": "Campaign Correlation",
                "evidence": "Multiple detections were grouped into a reconnaissance campaign.",
            })

        confidence = "low"
        if len(stages) >= 4:
            confidence = "high"
        elif len(stages) >= 2:
            confidence = "medium"

        return {
            "stage_count": len(stages),
            "confidence": confidence,
            "stages": stages,
        }

    def generate_fallback_summary(self, report_data: Dict[str, Any]) -> str:
        risk = report_data["risk"]["level"]
        totals = report_data["totals"]
        top_activity = report_data.get("top_activity")
        top_external = report_data.get("top_external")
        top_internal = report_data.get("top_internal")

        recent_alerts = report_data.get("recent_alerts", [])
        alert_titles = [a.get("title", "") for a in recent_alerts]

        lines = [
            f"Overall system risk is {risk.upper()}.",
            f"During the selected window, Raven observed {totals['alerts']} alert(s), "
            f"{totals['ssh_failures']} SSH failed login attempt(s), "
            f"{totals['ftp_failures']} FTP failed login attempt(s), "
            f"and {totals['web_suspicious_hits']} suspicious web request(s).",
        ]

        if top_external:
            lines.append(
                f"The most suspicious external source is {top_external['ip']}, active across "
                f"{top_external['source_count']} source(s), with patterns including "
                f"{', '.join(top_external['probable_patterns']) or 'general suspicious activity'}."
            )
        elif top_internal:
            lines.append(
                f"The most active correlated source is {top_internal['ip']}, identified as internal/test activity, "
                f"active across {top_internal['source_count']} source(s), with patterns including "
                f"{', '.join(top_internal['probable_patterns']) or 'general suspicious activity'}."
            )
        elif top_activity:
            lines.append(
                f"The most active correlated source is {top_activity['ip']} with assessment "
                f"{top_activity.get('assessment', 'suspicious activity')}."
            )

        multi = report_data.get("multi_source_ips", [])
        if multi:
            lines.append(
                f"Cross-source correlation was detected for {len(multi)} IP(s), indicating repeated activity across "
                f"multiple services such as SSH, FTP, web, or Nmap."
            )

        has_campaign = any("Reconnaissance Campaign Detected" in t for t in alert_titles)
        has_icmp = any("ICMP Sweep" in t for t in alert_titles)
        has_dns = any("DNS Beaconing" in t for t in alert_titles)
        has_http = any("HTTP Path Probing" in t for t in alert_titles)

        if has_campaign or (has_icmp and has_dns and has_http):
            chain_steps = []

            if has_icmp:
                chain_steps.append("ICMP sweep activity suggests reconnaissance or host discovery")
            if has_dns:
                chain_steps.append("DNS query bursts suggest beaconing-style or abnormal lookup behavior")
            if has_http:
                chain_steps.append("HTTP path probing suggests web discovery against sensitive paths")
            if has_campaign:
                chain_steps.append("the correlation engine grouped these indicators into a reconnaissance campaign")

            lines.append(
                "Attack-chain hypothesis: "
                + " -> ".join(chain_steps)
                + "."
            )

        attack_stages = report_data.get("attack_stages", {})
        stages = attack_stages.get("stages", [])

        if stages:
            stage_names = " -> ".join([s["stage"] for s in stages])
            lines.append(
                f"Campaign assessment: {attack_stages.get('stage_count', len(stages))} attack stage(s) were observed "
                f"with {attack_stages.get('confidence', 'low').upper()} confidence: {stage_names}."
            )

        if recent_alerts:
            top_titles = ", ".join(
                [a["title"] for a in recent_alerts[:3] if a.get("title")]
            )
            if top_titles:
                lines.append(f"Recent alerts include: {top_titles}.")

        lines.append(
            "This summary is based on structured database evidence from SSH, FTP, web, Nmap, TSHARK packet events, and alert records."
        )

        return " ".join(lines)

    def generate_llm_summary(self, report_data: Dict[str, Any]) -> str:
        prompt = {
            "role": "system",
            "content": (
                "You are a cybersecurity analysis assistant for Raven. "
                "You MUST summarize only the supplied structured facts. "
                "Do not invent IPs, counts, or alerts. "
                "Distinguish clearly between internal/test activity and external suspicious sources. "
                "Focus on cross-source correlation, possible brute force activity, suspicious patterns, and short recommendations."
            ),
        }

        user_payload = {
            "role": "user",
            "content": json.dumps(report_data, default=str),
        }

        return self.generate_fallback_summary(report_data)


def analyze_recent_activity(hours: int = 1) -> Dict[str, Any]:
    engine = RavenAIEngine()
    return engine.analyze_recent_activity(hours=hours)