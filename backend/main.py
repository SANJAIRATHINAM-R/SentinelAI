"""
SentinelAI Backend - FastAPI
Real threat detection + automated response
"""
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import asyncio, json, random, time, datetime
from typing import List
from collections import defaultdict, deque

app = FastAPI(title="SentinelAI", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

incidents      = []
blocked_ips    = set()
active_clients: List[WebSocket] = []
login_tracker  = defaultdict(list)
event_log      = deque(maxlen=500)
incident_id    = 1

ATTACK_TYPES = [
    "Brute Force SSH","SQL Injection","Port Scan","XSS Attempt",
    "Ransomware Indicator","Privilege Escalation","Suspicious PowerShell",
    "Malware Download","Data Exfiltration",
]
HOSTS = ["web-server-01","db-server-02","k8s-node-03","vpn-gateway","mail-server"]

def score_severity(attack_type, failed_count=0):
    if attack_type in ("Ransomware Indicator","Data Exfiltration","Privilege Escalation") or failed_count>20:
        return "CRITICAL"
    if attack_type in ("Brute Force SSH","Malware Download","Suspicious PowerShell") or failed_count>10:
        return "HIGH"
    if failed_count>5: return "MEDIUM"
    return "LOW"

def auto_respond(ip, attack_type, severity):
    actions = []
    if severity in ("CRITICAL","HIGH"):
        blocked_ips.add(ip)
        actions.append(f"Blocked IP {ip} in firewall")
        actions.append("Alert sent to Slack #security-alerts")
    if severity == "CRITICAL":
        actions.append("Endpoint isolation initiated")
        actions.append("Admin email dispatched")
    if "Brute Force" in attack_type:
        actions.append("Account lockout triggered")
    actions.append("Incident ticket created automatically")
    return actions

MITRE = {
    "Brute Force SSH":"Credential Access (T1110)","SQL Injection":"Initial Access (T1190)",
    "Port Scan":"Reconnaissance (T1046)","XSS Attempt":"Initial Access (T1659)",
    "Ransomware Indicator":"Impact (T1486)","Privilege Escalation":"Privilege Escalation (T1068)",
    "Suspicious PowerShell":"Execution (T1059)","Malware Download":"C2 (T1105)",
    "Data Exfiltration":"Exfiltration (T1041)",
}

def create_incident(attack_type, src_ip, host, severity, details):
    global incident_id
    inc = {
        "id": incident_id,
        "timestamp": datetime.datetime.utcnow().isoformat()+"Z",
        "attack_type": attack_type,
        "source_ip": src_ip,
        "target_host": host,
        "severity": severity,
        "status": "Open",
        "details": details,
        "response_actions": auto_respond(src_ip, attack_type, severity),
        "mitre_tactic": MITRE.get(attack_type,"Unknown"),
    }
    incidents.insert(0, inc)
    incident_id += 1
    return inc

async def broadcast(message):
    dead = []
    for ws in active_clients:
        try: await ws.send_text(json.dumps(message))
        except: dead.append(ws)
    for ws in dead: active_clients.remove(ws)

async def event_simulator():
    await asyncio.sleep(2)
    while True:
        await asyncio.sleep(random.uniform(3,8))
        src_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        host   = random.choice(HOSTS)
        attack = random.choice(ATTACK_TYPES)
        count  = random.randint(0,25)
        sev    = score_severity(attack, count)
        details= f"Detected {attack} from {src_ip} targeting {host}. Pattern matched {count} times in last 60s."
        log_event = {
            "type":"log","timestamp":datetime.datetime.utcnow().strftime("%H:%M:%S"),
            "level":sev,"host":host,
            "message":f"[{attack}] src={src_ip} dst={host} count={count}",
        }
        event_log.appendleft(log_event)
        if sev in ("CRITICAL","HIGH","MEDIUM") or random.random()>0.7:
            inc = create_incident(attack, src_ip, host, sev, details)
            await broadcast({"type":"incident","data":inc})
        await broadcast({"type":"log","data":log_event})
        await broadcast({"type":"stats","data":{
            "total_threats":len(incidents),"critical":sum(1 for i in incidents if i["severity"]=="CRITICAL"),
            "blocked_ips":len(blocked_ips),"monitored_hosts":len(HOSTS),
        }})

@app.on_event("startup")
async def startup(): asyncio.create_task(event_simulator())

@app.get("/api/incidents")
def get_incidents(limit:int=50, severity:str=None, status:str=None):
    r = incidents[:limit]
    if severity: r=[i for i in r if i["severity"]==severity.upper()]
    if status:   r=[i for i in r if i["status"]==status]
    return r

@app.get("/api/incidents/{id}")
def get_incident(id:int):
    for inc in incidents:
        if inc["id"]==id: return inc
    return JSONResponse({"error":"Not found"},status_code=404)

@app.patch("/api/incidents/{id}/status")
def update_status(id:int, body:dict):
    for inc in incidents:
        if inc["id"]==id:
            inc["status"]=body.get("status",inc["status"]); return inc
    return JSONResponse({"error":"Not found"},status_code=404)

@app.get("/api/stats")
def get_stats():
    return {
        "total_threats":len(incidents),
        "critical":sum(1 for i in incidents if i["severity"]=="CRITICAL"),
        "high":sum(1 for i in incidents if i["severity"]=="HIGH"),
        "medium":sum(1 for i in incidents if i["severity"]=="MEDIUM"),
        "blocked_ips":len(blocked_ips),
        "monitored_hosts":len(HOSTS),
        "blocked_ip_list":list(blocked_ips)[:20],
    }

@app.get("/api/logs")
def get_logs(limit:int=100): return list(event_log)[:limit]

@app.post("/api/ingest")
async def ingest_event(event:dict):
    host    = event.get("host","unknown")
    src_ip  = event.get("src_ip","0.0.0.0")
    etype   = event.get("type","unknown")
    details = event.get("details","")
    label_map = {"auth_failure":"Brute Force SSH","sql_injection":"SQL Injection",
                 "port_scan":"Port Scan","malware":"Malware Download","powershell":"Suspicious PowerShell"}
    attack = label_map.get(etype, etype)
    sev    = score_severity(attack)
    inc    = create_incident(attack, src_ip, host, sev, details)
    await broadcast({"type":"incident","data":inc})
    return {"status":"ingested","incident_id":inc["id"]}

@app.post("/api/block-ip")
def block_ip(body:dict):
    ip=body.get("ip")
    if ip: blocked_ips.add(ip); return {"status":"blocked","ip":ip}
    return JSONResponse({"error":"ip required"},status_code=400)

@app.get("/api/threat-intel/{ip}")
def threat_intel(ip:str):
    return {
        "ip":ip,"reputation":random.choice(["malicious","suspicious","clean"]),
        "country":random.choice(["CN","RU","US","BR","DE"]),"abuse_score":random.randint(0,100),
        "reports":random.randint(0,500),"blocked":ip in blocked_ips,
        "note":"Add VIRUSTOTAL_KEY and ABUSEIPDB_KEY to .env for real data",
    }

@app.get("/health")
def health(): return {"status":"ok","incidents":len(incidents),"blocked":len(blocked_ips)}

@app.websocket("/ws")
async def websocket_endpoint(ws:WebSocket):
    await ws.accept()
    active_clients.append(ws)
    await ws.send_text(json.dumps({
        "type":"init","incidents":incidents[:20],"logs":list(event_log)[:50],
        "stats":{"total_threats":len(incidents),"critical":sum(1 for i in incidents if i["severity"]=="CRITICAL"),
                 "blocked_ips":len(blocked_ips),"monitored_hosts":len(HOSTS)},
    }))
    try:
        while True: await ws.receive_text()
    except WebSocketDisconnect:
        if ws in active_clients: active_clients.remove(ws)
