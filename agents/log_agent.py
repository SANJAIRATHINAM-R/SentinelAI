#!/usr/bin/env python3
"""
SentinelAI Log Agent - install on any Linux server
Monitors SSH auth, web logs, syslog, sends to backend

Usage:
  pip install requests
  SENTINEL_HOST=http://your-server:8000 python3 log_agent.py
"""
import os, time, re, socket, requests
from pathlib import Path

SENTINEL_HOST = os.getenv("SENTINEL_HOST", "http://localhost:8000")
HOSTNAME      = socket.gethostname()
POLL_INTERVAL = 5

LOG_SOURCES = [
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/nginx/access.log",
    "/var/log/apache2/access.log",
]

file_positions = {}

PATTERNS = [
    (re.compile(r"Failed password|authentication failure|Invalid user"), "auth_failure"),
    (re.compile(r"SELECT.*FROM|UNION.*SELECT|DROP TABLE", re.I), "sql_injection"),
    (re.compile(r"<script>|javascript:|onerror=", re.I), "xss_attempt"),
    (re.compile(r"powershell|cmd\.exe|\.ps1", re.I), "powershell"),
    (re.compile(r"\.encrypted|ransom", re.I), "ransomware"),
]

def send_event(event_type, details, src_ip="unknown"):
    try:
        requests.post(f"{SENTINEL_HOST}/api/ingest", json={
            "host": HOSTNAME, "type": event_type,
            "src_ip": src_ip, "details": details,
        }, timeout=3)
        print(f"[agent] sent {event_type} from {src_ip}")
    except Exception as e:
        print(f"[agent] error: {e}")

def extract_ip(line):
    m = re.search(r'\b(\d{1,3}\.){3}\d{1,3}\b', line)
    return m.group(0) if m else "unknown"

def tail_log(filepath):
    path = Path(filepath)
    if not path.exists():
        return
    size = path.stat().st_size
    pos  = file_positions.get(filepath, size)
    if size < pos: pos = 0
    if size == pos: return
    with open(filepath, "r", errors="ignore") as f:
        f.seek(pos)
        lines = f.readlines()
        file_positions[filepath] = f.tell()
    for line in lines:
        for pattern, etype in PATTERNS:
            if pattern.search(line):
                send_event(etype, line.strip()[:200], extract_ip(line))
                break

def main():
    print(f"[SentinelAI Agent] host={HOSTNAME}  server={SENTINEL_HOST}")
    while True:
        for log in LOG_SOURCES:
            tail_log(log)
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
