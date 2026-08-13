#!/usr/bin/env python3
"""Extrae sesiones interesantes del honeypot y las envía a your-server como JSON.
Solo extrae TEXTO (comandos, logs HTTP, user-agents). NUNCA binarios ni malware."""
import json, os, sys
from collections import defaultdict
from datetime import datetime, timedelta
import urllib.request

SHOGUN_URL = os.environ.get("HONEYPOT_SYNC_URL", "https://your-server.example.com/api/cases")
SHOGUN_TOKEN = os.environ.get("HONEYPOT_SYNC_TOKEN", "your-token-here")

def extract_cowrie_sessions():
    """Extrae sesiones de Cowrie con login success + comandos."""
    sessions = defaultdict(list)
    log_path = "/opt/cowrie/var/log/cowrie/cowrie.json"
    if not os.path.exists(log_path):
        return []
    with open(log_path) as f:
        for line in f:
            try:
                evt = json.loads(line)
                sid = evt.get("session", "")
                if not sid:
                    continue
                eid = evt.get("eventid", "")
                if eid in ("cowrie.login.success", "cowrie.login.failed",
                           "cowrie.command.input", "cowrie.session.closed"):
                    sessions[sid].append(evt)
            except:
                pass

    cases = []
    for sid, events in sessions.items():
        has_success = any(e["eventid"] == "cowrie.login.success" for e in events)
        cmds = [e for e in events if e["eventid"] == "cowrie.command.input"]
        if not has_success or len(cmds) < 2:
            continue

        lines = []
        src_ip = ""
        for e in events:
            ts = e.get("timestamp", "")
            ip = e.get("src_ip", "")
            if ip and not src_ip:
                src_ip = ip
            eid = e["eventid"]
            if eid == "cowrie.login.failed":
                lines.append(f"[{ts}] LOGIN FAILED: {e.get('username','')}/{e.get('password','')} from {ip}")
            elif eid == "cowrie.login.success":
                lines.append(f"[{ts}] LOGIN SUCCESS: {e.get('username','')}/{e.get('password','')} from {ip}")
            elif eid == "cowrie.command.input":
                cmd = e.get("input", "")[:500]
                lines.append(f"[{ts}] CMD: {cmd}")
            elif eid == "cowrie.session.closed":
                dur = e.get("duration_ms", 0)
                lines.append(f"[{ts}] SESSION CLOSED ({dur}ms)")

        if len(lines) < 4:
            continue

        cases.append({
            "source": "cowrie",
            "session_id": sid,
            "src_ip": src_ip,
            "timestamp": events[0].get("timestamp", ""),
            "sample": "\n".join(lines),
            "category": "ssh_log_analysis",
        })
    return cases

def extract_wp_attacks():
    """Extrae ataques web del honeypot WordPress (nginx logs)."""
    log_path = "/var/log/nginx/wp-honeypot-access.log"
    if not os.path.exists(log_path):
        return []

    suspicious = ["wp-login", "wp-admin", "xmlrpc", "boaform", "..%2F", "..\\",
                  "etc/passwd", "cmd=", "exec", "eval", "shell", "SELECT ",
                  "UNION ", "../..", "%00", "curl", "wget", "bash", "nc ",
                  "CVE-", "zgrab", "masscan", "nmap", "SET ", "DROP ", "INSERT ",
                  "script>", "<svg", "onload=", "onerror=", "javascript:"]

    cases = []
    current_ip = None
    ip_lines = []
    ip_timestamp = None

    with open(log_path) as f:
        for line in f:
            parts = line.strip().split(" - - [")
            if len(parts) < 2:
                continue
            ip = parts[0]

            is_suspicious = any(s.lower() in line.lower() for s in suspicious)
            if not is_suspicious:
                continue

            if ip != current_ip:
                if current_ip and len(ip_lines) >= 3:
                    cases.append({
                        "source": "wordpress_honeypot",
                        "session_id": f"wp-{current_ip}-{ip_timestamp}",
                        "src_ip": current_ip,
                        "timestamp": ip_timestamp,
                        "sample": "\n".join(ip_lines),
                        "category": "web_attack_analysis",
                    })
                current_ip = ip
                ip_lines = []
                rest = "[" + parts[1]
                ts_start = rest.find("[")
                ts_end = rest.find("]")
                if ts_start >= 0 and ts_end > ts_start:
                    ip_timestamp = rest[ts_start+1:ts_end]
                else:
                    ip_timestamp = ""

            ip_lines.append(line.strip())

    if current_ip and len(ip_lines) >= 3:
        cases.append({
            "source": "wordpress_honeypot",
            "session_id": f"wp-{current_ip}-{ip_timestamp}",
            "src_ip": current_ip,
            "timestamp": ip_timestamp,
            "sample": "\n".join(ip_lines),
            "category": "web_attack_analysis",
        })
    return cases

def send_cases(cases):
    """Envía casos a your-server."""
    if not cases:
        print("No cases to send")
        return
    data = json.dumps({"cases": cases, "token": SHOGUN_TOKEN}).encode()
    req = urllib.request.Request(SHOGUN_URL, data=data,
                                 headers={"Content-Type": "application/json"})
    try:
        resp = urllib.request.urlopen(req, timeout=30)
        result = json.loads(resp.read())
        print(f"Sent {len(cases)} cases: {result}")
    except Exception as e:
        print(f"Error sending cases: {e}", file=sys.stderr)

if __name__ == "__main__":
    cowrie_cases = extract_cowrie_sessions()
    wp_cases = extract_wp_attacks()
    all_cases = cowrie_cases + wp_cases
    print(f"Found {len(cowrie_cases)} Cowrie cases, {len(wp_cases)} WordPress cases")
    send_cases(all_cases)
