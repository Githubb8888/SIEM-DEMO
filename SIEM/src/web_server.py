#!/usr/bin/env python3
"""FastAPI web server for Fintech Mini-SIEM & SOAR Web Console."""

import json
import os
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, WebSocket, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from src.models import Alert, Incident, NormalizedEvent, PlaybookAction, Employee, Device
from src import storage
import src.soar as soar
from src.ai_hunt import parse_hunt_query

app = FastAPI(title="Fintech Mini-SIEM Web Console", version="1.0.0")

# Mount static files
STATIC_PATH = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_PATH), name="static")

@app.get("/")
async def root():
    index_path = STATIC_PATH / "index.html"
    return FileResponse(index_path)

# --- API Endpoints ---

@app.get("/api/stats")
async def get_stats():
    alerts = storage.get_alerts(db_path=storage.get_db_path())
    incidents = storage.get_incidents(db_path=storage.get_db_path())
    blocked = storage.get_blocked_ips(db_path=storage.get_db_path())
    frozen = storage.get_frozen_accounts(db_path=storage.get_db_path())

    avg_risk = sum(a.risk_score for a in alerts) / len(alerts) if alerts else 0

    # Calculate all required KPI keys
    critical_alerts = len([a for a in alerts if a.severity == "CRITICAL"])
    high_alerts = len([a for a in alerts if a.severity == "HIGH"])
    medium_alerts = len([a for a in alerts if a.severity == "MEDIUM"])
    low_alerts = len([a for a in alerts if a.severity == "LOW"])
    critical_incidents = len([i for i in incidents if i.severity == "CRITICAL" and i.resolved_at is None])
    active_incidents = len([i for i in incidents if i.resolved_at is None])

    avg_risk = sum(a.risk_score for a in alerts) / len(alerts) if alerts else 0

    return {
        "total_events": storage.get_event_count(db_path=storage.get_db_path()),
        "total_alerts": len(alerts),
        "critical_alerts": critical_alerts,
        "high_alerts": high_alerts,
        "medium_alerts": medium_alerts,
        "low_alerts": low_alerts,
        "critical_incidents": critical_incidents,
        "active_incidents": active_incidents,
        "blocked_ips": len(blocked),
        "frozen_accounts": len(frozen),
        "mean_risk_score": round(avg_risk, 2)
    }

@app.get("/api/alerts")
async def get_alerts_endpoint(severities: Optional[str] = None):
    severity_list = severities.split(',') if severities else None
    alerts = storage.get_alerts(severities=severity_list, db_path=storage.get_db_path())
    return [vars(a) for a in alerts]

@app.post("/api/triage/{alert_id}")
async def triage_alert(alert_id: str, status: str):
    from src import storage
    # Update alert status in database
    success = storage.update_alert_status(alert_id, status)
    return {"success": success, "alert_id": alert_id, "new_status": status}

@app.get("/api/fleet")
async def get_fleet():
    return storage.get_fleet_posture(db_path=storage.get_db_path())


@app.get("/favicon.ico")
async def favicon():
    return Response(status_code=204)


@app.post("/api/block-ip")
async def block_ip_endpoint(ip: str, reason: str, performed_by: str):
    from src import soar
    result = soar.execute_playbook('block_ip', ip, reason, performed_by)
    return {"success": result["success"], "ip": ip}


@app.post("/api/unblock-ip")
async def unblock_ip_endpoint(ip: str, performed_by: str):
    success = storage.unblock_ip(ip, performed_by)
    if success:
        return {"success": True, "ip": ip}
    return {"success": False, "ip": ip, "error": "IP not found"}


@app.get("/api/export")
async def export_incident(incident_id: str, format: str = "json"):
    incidents = storage.get_incidents(db_path=storage.get_db_path())
    incident = next((i for i in incidents if i.id == incident_id), None)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    if format == "json":
        return {
            "incident_id": incident.id,
            "title": incident.title,
            "severity": incident.severity,
            "created_at": incident.created_at.isoformat(),
            "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
            "summary": incident.summary,
            "alert_count": len(incident.alerts),
            "alerts": incident.alerts,
            "timeline": incident.timeline
        }
    raise HTTPException(status_code=400, detail="Unsupported format")


@app.get("/api/incidents")
async def get_incidents():
    incidents = storage.get_incidents(db_path=storage.get_db_path())
    return [vars(i) for i in incidents]

@app.get("/api/incidents")
async def get_incidents():
    incidents = storage.get_incidents(db_path=storage.get_db_path())
    return [vars(i) for i in incidents]

@app.get("/api/soar")
async def get_soar():
    return {
        "blocked_ips": storage.get_blocked_ips(db_path=storage.get_db_path()),
        "frozen_accounts": storage.get_frozen_accounts(db_path=storage.get_db_path()),
        "audit_log": storage.get_audit_log(limit=20, db_path=storage.get_db_path())
    }

class AIRequest(BaseModel):
    prompt: str
    lang: str = "en"

@app.post("/api/ai-hunt")
async def ai_hunt(req: AIRequest):
    intent = parse_hunt_query(req.prompt, req.lang)
    findings = storage.search_events(q=intent.spl_query, limit=10, db_path=storage.get_db_path())
    return {
        "spl": intent.spl_query,
        "summary": intent.summary_ru if req.lang == "ru" else intent.summary_en,
        "findings": findings,
        "actions": intent.recommended_actions
    }

@app.post("/api/simulate")
async def simulate(request: dict):
    from src.collector import generate_sample_traffic
    from src.storage import seed_realistic_environment
    scenario = request.get("scenario", "brute_force")

    if scenario == "regenerate_random_all":
        seed_realistic_environment(reset=True)
        generate_sample_traffic(1000, "sample_logs/fintech_stream.jsonl", 0.3)
    else:
        generate_sample_traffic(50, "sample_logs/simulation.jsonl")
    return {"status": "success", "scenario": scenario, "events_generated": 50}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
