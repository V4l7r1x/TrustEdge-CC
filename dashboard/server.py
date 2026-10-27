"""
TrustEdge-CC: FastAPI Dashboard & Zero-Trust Orchestrator Server
Serves real-time WebSockets, REST APIs, and UI Dashboard.
"""

import os
import sys
import asyncio
import logging
from typing import Dict, Any, List

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

# Ensure project root in path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from dashboard.fl_orchestrator import FederatedOrchestrator

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [SERVER:%(levelname)s] %(message)s")
logger = logging.getLogger("DashboardServer")

app = FastAPI(title="TrustEdge-CC Orchestrator", version="1.0.0")

# Setup directories
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

orchestrator = FederatedOrchestrator()

# Connected WebSocket clients
connected_clients: List[WebSocket] = []


# --- Pydantic Data Models ---
class RegisterNodePayload(BaseModel):
    node_id: str
    node_type: str
    tee_type: str
    ta_uuid: str = ""
    public_key: str
    attestation: Dict[str, Any]
    aes_key_hex: str


class TelemetryPayload(BaseModel):
    node_id: str
    timestamp: float
    temperature: float
    humidity: float
    anomaly_score: float
    is_anomaly: bool
    tee_latency_ms: float = 0.0
    anomaly_forced: bool = False


class FlUpdatePayload(BaseModel):
    node_id: str
    round: int
    model_digest: str
    signature: str
    encrypted_model: Dict[str, Any]
    aad: str = ""
    execution_stats: Dict[str, Any] = {}


class AttackSimPayload(BaseModel):
    node_id: str
    attack_type: str = "model_poisoning"


# --- HTML Frontend Route ---
@app.get("/", response_class=HTMLResponse)
async def serve_dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


# --- REST API Endpoints ---
@app.post("/api/nodes/register")
async def register_node(payload: RegisterNodePayload):
    result = orchestrator.register_node(payload.dict())
    if not result.get("success"):
        return JSONResponse(status_code=400, content=result)
    return result


@app.post("/api/telemetry/report")
async def report_telemetry(payload: TelemetryPayload):
    result = orchestrator.record_telemetry(payload.dict())
    return result


@app.get("/api/fl/status")
async def get_fl_status():
    return {
        "current_round": orchestrator.current_round,
        "is_active": orchestrator.is_round_active,
        "active_nodes": [nid for nid, n in orchestrator.nodes.items() if (orchestrator.time_now() - n.last_seen) < 15.0]
    }


@app.post("/api/fl/start-round")
async def start_fl_round():
    result = orchestrator.start_fl_round()
    if not result.get("success"):
        return JSONResponse(status_code=400, content=result)
    return result


@app.post("/api/fl/submit-update")
async def submit_fl_update(payload: FlUpdatePayload):
    result = orchestrator.submit_fl_update(payload.dict())
    if not result.get("success"):
        return JSONResponse(status_code=400, content=result)
    return result


@app.get("/api/fl/global-model")
async def get_global_model():
    return orchestrator.global_model.to_dict()


@app.get("/api/dashboard/state")
async def get_dashboard_state():
    return orchestrator.get_dashboard_state()


@app.post("/api/attack/simulate")
async def simulate_attack(payload: AttackSimPayload):
    res = orchestrator.simulate_model_poisoning(payload.node_id)
    return res


@app.post("/api/sensor/toggle-anomaly")
async def toggle_anomaly(payload: Dict[str, Any]):
    node_id = payload.get("node_id")
    enabled = payload.get("enabled", True)
    # If the node has an active process or proxy, flag it
    orchestrator._log_audit("SENSOR_ANOMALY_TRIGGERED",
                            f"Manual sensor anomaly injection {'ENABLED' if enabled else 'DISABLED'} on node {node_id}",
                            level="WARN")
    return {"success": True, "node_id": node_id, "anomaly_forced": enabled}


# Helper for time
setattr(orchestrator, "time_now", lambda: __import__("time").time())


# --- WebSocket for Live State Synchronization ---
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)
    try:
        # Send immediate initial state
        state = orchestrator.get_dashboard_state()
        await websocket.send_json(state)

        while True:
            # Keep-alive receive
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        if websocket in connected_clients:
            connected_clients.remove(websocket)
    except Exception:
        if websocket in connected_clients:
            connected_clients.remove(websocket)


# Background task to broadcast dashboard state every 500ms
async def broadcast_state_loop():
    while True:
        await asyncio.sleep(0.5)
        if connected_clients:
            state = orchestrator.get_dashboard_state()
            disconnected = []
            for ws in connected_clients:
                try:
                    await ws.send_json(state)
                except Exception:
                    disconnected.append(ws)
            for ws in disconnected:
                if ws in connected_clients:
                    connected_clients.remove(ws)


@app.on_event("startup")
async def startup_event():
    asyncio.create_task(broadcast_state_loop())


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("dashboard.server:app", host="0.0.0.0", port=8000, reload=False)
