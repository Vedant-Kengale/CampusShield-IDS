import asyncio
import hashlib
import hmac
import json
import logging
import time
from collections import defaultdict
from typing import Dict, List, Optional
import numpy as np
from sklearn.ensemble import IsolationForest
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ==========================================
# CONFIGURATION & LOGGING
# ==========================================
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("CampusShieldBackend")

SECRET_HMAC_KEY = b"PCCoE_CNS_Hackathon_Secret_2026"

app = FastAPI(
    title="CampusShield IDS Engine API",
    description="Backend engine providing L4/L7 threat detection, ML anomaly classification, and cryptographic log signatures.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================================
# DATA MODELS
# ==========================================
class PacketIngest(BaseModel):
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str = "TCP"
    bytes_sent: int = 500
    bytes_rcvd: int = 1200
    duration: float = 0.5

class AuthLogIngest(BaseModel):
    src_ip: str
    service: str = "SSH"
    status: str
    username: str = "admin"

class AttackSimulationRequest(BaseModel):
    attack_type: str
    target_ip: str

class VerifyLogRequest(BaseModel):
    log_data: str
    signature: str

# ==========================================
# MODULE 1: PORT SCAN DETECTOR (LAYER 4)
# ==========================================
class PortScanDetector:
    def __init__(self, time_window: int = 10, port_threshold: int = 15):
        self.time_window = time_window
        self.port_threshold = port_threshold
        self.history = defaultdict(list)

    def process(self, src_ip: str, dst_port: int) -> Optional[dict]:
        now = time.time()
        self.history[src_ip] = [(t, port) for t, port in self.history[src_ip] if now - t <= self.time_window]
        self.history[src_ip].append((now, dst_port))
        unique_ports = {port for _, port in self.history[src_ip]}
        if len(unique_ports) >= self.port_threshold:
            return {"alert": "PORT_SCAN_DETECTED", "layer": "Layer 4 (Transport)", "details": f"Probed {len(unique_ports)} unique ports in {self.time_window}s", "score_impact": 45, "severity": "HIGH"}
        return None

# ==========================================
# MODULE 2: BRUTE FORCE DETECTOR (LAYER 7)
# ==========================================
class BruteForceDetector:
    def __init__(self, failure_limit: int = 5, window_sec: int = 30):
        self.failure_limit = failure_limit
        self.window_sec = window_sec
        self.failures = defaultdict(list)

    def process(self, src_ip: str, status: str, service: str) -> Optional[dict]:
        if status.upper() != "FAILED": return None
        now = time.time()
        self.failures[src_ip] = [t for t in self.failures[src_ip] if now - t <= self.window_sec]
        self.failures[src_ip].append(now)
        if len(self.failures[src_ip]) >= self.failure_limit:
            return {"alert": "BRUTE_FORCE_ATTACK", "layer": "Layer 7 (Application)", "details": f"{len(self.failures[src_ip])} failed {service} authentication attempts in {self.window_sec}s", "score_impact": 60, "severity": "CRITICAL"}
        return None

# ==========================================
# MODULE 3: ML ANOMALY DETECTOR (ISOLATION FOREST)
# ==========================================
class MLAnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(contamination=0.03, random_state=42)
        baseline_data = np.array([[1.2, 500, 1200, 80], [0.5, 300, 800, 443], [2.0, 1500, 3000, 443], [0.1, 60, 60, 53]] * 100)
        self.model.fit(baseline_data)

    def process(self, flow: list) -> Optional[dict]:
        prediction = self.model.predict([flow])
        if prediction[0] == -1:
            return {"alert": "UNUSUAL_CONNECTION_ANOMALY", "layer": "Layer 3/4 (NetFlow Anomaly)", "details": f"Unusual volume/port pattern: Sent {flow[1]}B, Rcvd {flow[2]}B on port {flow[3]}", "score_impact": 35, "severity": "MEDIUM"}
        return None

# ==========================================
# MODULE 4: CRYPTOGRAPHIC LOG SIGNER (CNS UNIT 3)
# ==========================================
class CryptoAuditLogger:
    def __init__(self, secret_key: bytes):
        self.secret_key = secret_key
        self.audit_log: List[dict] = []

    def sign_and_store(self, src_ip: str, alert_type: str, severity: str) -> dict:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        log_payload = f"[{timestamp}] IP:{src_ip} | ALERT:{alert_type} | SEVERITY:{severity}"
        signature = hmac.new(self.secret_key, log_payload.encode('utf-8'), hashlib.sha256).hexdigest()
        entry = {"id": len(self.audit_log) + 1, "timestamp": timestamp, "raw_payload": log_payload, "signature": signature, "src_ip": src_ip, "alert": alert_type, "severity": severity}
        self.audit_log.insert(0, entry)
        return entry

    def verify(self, raw_payload: str, signature: str) -> bool:
        expected_sig = hmac.new(self.secret_key, raw_payload.encode('utf-8'), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected_sig, signature)

# ==========================================
# CENTRAL STATE & WEBSOCKET MANAGER
# ==========================================
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

port_detector = PortScanDetector()
brute_detector = BruteForceDetector()
ml_detector = MLAnomalyDetector()
crypto_logger = CryptoAuditLogger(SECRET_HMAC_KEY)
ws_manager = ConnectionManager()

device_registry: Dict[str, dict] = {
    "192.168.1.101": {"subnet": "Library WiFi", "threat_score": 0, "status": "GREEN", "blocked": False},
    "192.168.1.102": {"subnet": "CS Lab A", "threat_score": 0, "status": "GREEN", "blocked": False},
    "192.168.1.103": {"subnet": "CS Lab B", "threat_score": 0, "status": "GREEN", "blocked": False},
    "192.168.1.104": {"subnet": "Admin Dept", "threat_score": 0, "status": "GREEN", "blocked": False},
}

async def auto_purge_sweep_loop():
    while True:
        await asyncio.sleep(10)
        purged_ips = []
        for ip, info in list(device_registry.items()):
            if info["threat_score"] >= 30 and not info["blocked"]:
                info["status"] = "BLOCKED"
                info["blocked"] = True
                purged_ips.append(ip)
                logger.info(f"[AUTO-PURGE ENGINE] Device {ip} blocked during 10-second sweep.")
        if purged_ips:
            await ws_manager.broadcast({"type": "AUTO_PURGE_EXECUTION", "purged_ips": purged_ips, "timestamp": time.time(), "devices": device_registry})

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(auto_purge_sweep_loop())

@app.get("/api/devices")
async def get_devices():
    return {"status": "success", "devices": device_registry}

@app.get("/api/logs")
async def get_logs():
    return {"status": "success", "logs": crypto_logger.audit_log}

@app.post("/api/ingest/packet")
async def ingest_packet(packet: PacketIngest):
    src_ip = packet.src_ip
    if src_ip not in device_registry:
        device_registry[src_ip] = {"subnet": "Unknown Subnet", "threat_score": 0, "status": "GREEN", "blocked": False}
    alerts = []
    scan_alert = port_detector.process(src_ip, packet.dst_port)
    if scan_alert: alerts.append(scan_alert)
    flow_features = [packet.duration, packet.bytes_sent, packet.bytes_rcvd, packet.dst_port]
    ml_alert = ml_detector.process(flow_features)
    if ml_alert: alerts.append(ml_alert)
    for alert in alerts:
        device_registry[src_ip]["threat_score"] += alert["score_impact"]
        if device_registry[src_ip]["threat_score"] >= 30:
            device_registry[src_ip]["status"] = "RED"
        log_entry = crypto_logger.sign_and_store(src_ip, alert["alert"], alert["severity"])
        await ws_manager.broadcast({"type": "NEW_ALERT", "alert": alert, "log": log_entry, "device": {src_ip: device_registry[src_ip]}})
    return {"status": "processed", "alerts_triggered": len(alerts)}

@app.post("/api/ingest/auth-log")
async def ingest_auth_log(auth: AuthLogIngest):
    src_ip = auth.src_ip
    if src_ip not in device_registry:
        device_registry[src_ip] = {"subnet": "Unknown Subnet", "threat_score": 0, "status": "GREEN", "blocked": False}
    alert = brute_detector.process(src_ip, auth.status, auth.service)
    if alert:
        device_registry[src_ip]["threat_score"] += alert["score_impact"]
        if device_registry[src_ip]["threat_score"] >= 30:
            device_registry[src_ip]["status"] = "RED"
        log_entry = crypto_logger.sign_and_store(src_ip, alert["alert"], alert["severity"])
        await ws_manager.broadcast({"type": "NEW_ALERT", "alert": alert, "log": log_entry, "device": {src_ip: device_registry[src_ip]}})
        return {"status": "alert_triggered", "details": alert}
    return {"status": "logged"}

@app.post("/api/simulate-attack")
async def simulate_attack(req: AttackSimulationRequest):
    target_ip = req.target_ip
    if target_ip not in device_registry:
        device_registry[target_ip] = {"subnet": "Demo Subnet", "threat_score": 0, "status": "GREEN", "blocked": False}
    if req.attack_type == "PORT_SCAN":
        for port in range(1, 20): port_detector.process(target_ip, port)
        alert = {"alert": "PORT_SCAN_DETECTED", "layer": "Layer 4 (Transport)", "details": "Rapid TCP SYN probe burst detected across 19 ports", "score_impact": 45, "severity": "HIGH"}
    elif req.attack_type == "BRUTE_FORCE":
        for _ in range(6): brute_detector.process(target_ip, "FAILED", "SSH")
        alert = {"alert": "BRUTE_FORCE_ATTACK", "layer": "Layer 7 (Application)", "details": "6 consecutive failed SSH authentication attempts", "score_impact": 60, "severity": "CRITICAL"}
    else:
        alert = {"alert": "UNUSUAL_CONNECTION_ANOMALY", "layer": "Layer 3/4 (NetFlow Anomaly)", "details": "Exfiltration spike: 12.4 MB on non-standard port 8888", "score_impact": 35, "severity": "MEDIUM"}
    device_registry[target_ip]["threat_score"] += alert["score_impact"]
    if device_registry[target_ip]["threat_score"] >= 30:
        device_registry[target_ip]["status"] = "RED"
    log_entry = crypto_logger.sign_and_store(target_ip, alert["alert"], alert["severity"])
    await ws_manager.broadcast({"type": "NEW_ALERT", "alert": alert, "log": log_entry, "devices": device_registry})
    return {"status": "simulated", "target": target_ip, "threat_score": device_registry[target_ip]["threat_score"]}

@app.post("/api/verify-log")
async def verify_log(req: VerifyLogRequest):
    is_valid = crypto_logger.verify(req.log_data, req.signature)
    return {"status": "success", "verified": is_valid, "message": "Signature MATCH: Log is authentic and untampered." if is_valid else "Signature MISMATCH: Warning! Log payload has been altered."}

@app.post("/api/block-ip")
async def manual_block(ip: str):
    if ip in device_registry:
        device_registry[ip]["status"] = "BLOCKED"
        device_registry[ip]["blocked"] = True
        await ws_manager.broadcast({"type": "MANUAL_BLOCK", "ip": ip, "devices": device_registry})
        return {"status": "blocked", "ip": ip}
    raise HTTPException(status_code=404, detail="Device IP not found")

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        await websocket.send_json({"type": "INIT_STATE", "devices": device_registry, "logs": crypto_logger.audit_log})
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
