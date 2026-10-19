from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, List
from mythos.agent_defense import MythosAiThreatDetector, PreProdIncidentResponseEngine

app = FastAPI(title="Blackwell-Aegis Mythos AI Sandbox & Cluster Incident Response API", version="1.0.0")
detector = MythosAiThreatDetector()
ir_engine = PreProdIncidentResponseEngine()

class AgentActionRequest(BaseModel):
    agent_id: str
    tool_command: str
    sandbox_profile: Dict[str, bool]
    egress_bytes_mb: float

class IncidentRequest(BaseModel):
    node_id: str
    telemetry_alerts: List[str]

@app.get("/health")
def health():
    return {"status": "UP", "layers": "L12-L17-Mythos-AI-Sandbox-And-Cluster-IR-DR"}

@app.post("/api/v1/mythos/evaluate")
def evaluate_agent(req: AgentActionRequest):
    return detector.evaluate_agent_tool_call(
        req.agent_id, req.tool_command, req.sandbox_profile, req.egress_bytes_mb
    )

@app.post("/api/v1/incident/respond")
def respond_incident(req: IncidentRequest):
    return ir_engine.execute_ir_dr_playbook(req.node_id, req.telemetry_alerts)
