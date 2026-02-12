"""
SOC AI Tool API - Multi-Agent Architecture
FastAPI backend with Google ADK agent orchestration.
"""
from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from sqlalchemy.orm import Session
from sqlalchemy import func
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime
import uuid
import json
import pathlib

from database import init_db, get_db, Alert, Incident, Action, ChatMessage, MetricsHistory, AITimeEstimate
from vector_store import vector_store
from soc_agent import run_agent, APP_NAME

# ========================= APP SETUP =========================

app = FastAPI(
    title="SOC AI Tool API",
    description="AI-Powered Security Operations Center Tool with Multi-Agent Architecture",
    version="2.0.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Paths
BACKEND_DIR = pathlib.Path(__file__).parent
PROJECT_DIR = BACKEND_DIR.parent
FRONTEND_DIR = PROJECT_DIR / "frontend"
DATA_DIR = PROJECT_DIR / "data"


# ========================= STARTUP =========================

@app.on_event("startup")
async def startup():
    init_db()
    print("=" * 60)
    print("🚀 SOC AI Tool v2.0 - Multi-Agent Architecture")
    print("=" * 60)
    print(f"✅ Database initialized")
    print(f"✅ ChromaDB stats: {vector_store.get_stats()}")
    print(f"✅ Agent system ready")
    print("=" * 60)


# ========================= MODELS =========================

class AgentRequest(BaseModel):
    """Request model for the agent endpoint"""
    message: str
    session_id: Optional[str] = None
    user_id: Optional[str] = "soc_analyst"

class AlertUpload(BaseModel):
    alerts: List[Dict[str, Any]]

class IncidentUpdateRequest(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None


# ========================= MAIN AGENT ENDPOINT =========================

@app.post("/api/v1/agent")
async def agent_endpoint(request: AgentRequest):
    """
    Main agent endpoint - all AI interactions go through here.
    The orchestrator agent will delegate to the appropriate specialist.
    
    Example messages:
    - "Analyze all alerts and create incidents"
    - "Analyze alerts with training explanations"
    - "What are the most critical threats?"
    - "Execute action 5"
    - "How many alerts do we have?"
    """
    try:
        result = await run_agent(
            message=request.message,
            user_id=request.user_id,
            session_id=request.session_id
        )
        
        if result["success"]:
            return {
                "success": True,
                "data": {
                    "response": result["response"],
                    "session_id": result["session_id"]
                }
            }
        else:
            return {
                "success": False,
                "error": result.get("error", "Unknown error")
            }
            
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


# ========================= DATA ENDPOINTS (No AI) =========================

@app.get("/api/v1/health")
async def health_check(db: Session = Depends(get_db)):
    """Health check endpoint"""
    try:
        from sqlalchemy import text
        db.execute(text("SELECT 1"))
        db_status = "connected"
    except Exception as e:
        db_status = "disconnected"
    
    # Check if Gemini API key is configured
    import os
    gemini_key = os.getenv("GEMINI_API_KEY", "")
    gemini_status = "configured" if gemini_key and len(gemini_key) > 10 else "not_configured"
    
    return {
        "status": "healthy",
        "version": "2.0.0",
        "architecture": "multi-agent",
        "gemini": gemini_status,
        "dependencies": {
            "database": db_status,
            "chromadb": "connected",
            "agent_system": "ready"
        },
        "stats": vector_store.get_stats()
    }


@app.post("/api/v1/alerts/upload")
async def upload_alerts(data: AlertUpload, db: Session = Depends(get_db)):
    """Upload alerts from parsed CSV data"""
    upload_id = str(uuid.uuid4())
    alerts_created = []
    
    for alert_data in data.alerts:
        timestamp = alert_data.get("timestamp")
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except:
                timestamp = datetime.utcnow()
        
        alert = Alert(
            timestamp=timestamp,
            severity=alert_data.get("severity", "Medium"),
            source_ip=alert_data.get("source_ip", ""),
            destination_ip=alert_data.get("destination_ip", ""),
            user=alert_data.get("user", "unknown"),
            description=alert_data.get("description", ""),
            event_type=alert_data.get("event_type", "Unknown"),
            upload_id=upload_id
        )
        db.add(alert)
        db.flush()
        alerts_created.append({
            "id": alert.id,
            "severity": alert.severity,
            "source_ip": alert.source_ip,
            "destination_ip": alert.destination_ip,
            "user": alert.user,
            "description": alert.description,
            "event_type": alert.event_type,
            "timestamp": str(alert.timestamp)
        })
    
    db.commit()
    
    # Index in ChromaDB
    indexed = vector_store.add_alerts(alerts_created)
    
    return {
        "success": True,
        "data": {
            "upload_id": upload_id,
            "count": len(alerts_created),
            "indexed_in_chromadb": indexed
        }
    }


@app.get("/api/v1/alerts")
async def get_alerts(
    limit: int = Query(50, ge=1, le=500),
    severity: Optional[str] = None,
    source_ip: Optional[str] = None,
    event_type: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Get alerts with optional filters"""
    query = db.query(Alert)
    
    if severity:
        query = query.filter(Alert.severity == severity)
    if source_ip:
        query = query.filter(Alert.source_ip.contains(source_ip))
    if event_type:
        query = query.filter(Alert.event_type == event_type)
    
    total = query.count()
    alerts = query.order_by(Alert.timestamp.desc()).limit(limit).all()
    
    return {
        "success": True,
        "data": {
            "total": total,
            "alerts": [
                {
                    "id": a.id,
                    "timestamp": str(a.timestamp),
                    "severity": a.severity,
                    "source_ip": a.source_ip,
                    "destination_ip": a.destination_ip,
                    "user": a.user,
                    "description": a.description,
                    "event_type": a.event_type
                }
                for a in alerts
            ]
        }
    }


@app.get("/api/v1/incidents")
async def get_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Get all incidents with optional filters"""
    query = db.query(Incident)
    
    if status:
        query = query.filter(Incident.status == status)
    if severity:
        query = query.filter(Incident.severity == severity)
    
    incidents = query.order_by(Incident.created_at.desc()).all()
    
    result = []
    for inc in incidents:
        actions = db.query(Action).filter(Action.incident_id == inc.id).all()
        
        training = None
        if inc.training_explanation:
            try:
                training = json.loads(inc.training_explanation)
            except:
                training = None
        
        result.append({
            "id": inc.id,
            "title": inc.title,
            "summary": inc.summary,
            "severity": inc.severity,
            "alert_count": inc.alert_count,
            "alert_ids": json.loads(inc.alert_ids) if inc.alert_ids else [],
            "status": inc.status,
            "assigned_to": inc.assigned_to,
            "confidence": inc.confidence,
            "attack_stage": inc.attack_stage,
            "training": training,
            "created_at": str(inc.created_at),
            "updated_at": str(inc.updated_at),
            "actions": [
                {
                    "id": a.id,
                    "title": a.title,
                    "description": a.description,
                    "urgency": a.urgency,
                    "executed": a.executed
                }
                for a in actions
            ]
        })
    
    return {"success": True, "data": {"incidents": result}}


@app.get("/api/v1/incidents/{incident_id}")
async def get_incident(incident_id: int, db: Session = Depends(get_db)):
    """Get a specific incident with its alerts"""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    alert_ids = json.loads(incident.alert_ids) if incident.alert_ids else []
    alerts = db.query(Alert).filter(Alert.id.in_(alert_ids)).order_by(Alert.timestamp).all()
    actions = db.query(Action).filter(Action.incident_id == incident_id).all()
    
    training = None
    if incident.training_explanation:
        try:
            training = json.loads(incident.training_explanation)
        except:
            training = None
    
    return {
        "success": True,
        "data": {
            "id": incident.id,
            "title": incident.title,
            "summary": incident.summary,
            "severity": incident.severity,
            "alert_count": incident.alert_count,
            "status": incident.status,
            "assigned_to": incident.assigned_to,
            "confidence": incident.confidence,
            "attack_stage": incident.attack_stage,
            "training": training,
            "created_at": str(incident.created_at),
            "updated_at": str(incident.updated_at),
            "alerts": [
                {
                    "id": a.id,
                    "timestamp": str(a.timestamp),
                    "severity": a.severity,
                    "source_ip": a.source_ip,
                    "destination_ip": a.destination_ip,
                    "user": a.user,
                    "description": a.description,
                    "event_type": a.event_type
                }
                for a in alerts
            ],
            "actions": [
                {
                    "id": a.id,
                    "title": a.title,
                    "description": a.description,
                    "urgency": a.urgency,
                    "action_type": a.action_type,
                    "executed": a.executed,
                    "executed_at": str(a.executed_at) if a.executed_at else None,
                    "executed_by": a.executed_by,
                    "result": a.result
                }
                for a in actions
            ]
        }
    }


@app.patch("/api/v1/incidents/{incident_id}")
async def update_incident(
    incident_id: int,
    request: IncidentUpdateRequest,
    db: Session = Depends(get_db)
):
    """Update incident status or assignment"""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    if request.status:
        incident.status = request.status
    if request.assigned_to is not None:
        incident.assigned_to = request.assigned_to
    
    incident.updated_at = datetime.utcnow()
    db.commit()
    
    return {
        "success": True,
        "data": {
            "id": incident.id,
            "status": incident.status,
            "assigned_to": incident.assigned_to,
            "updated_at": str(incident.updated_at)
        }
    }


@app.get("/api/v1/chat/history")
async def get_chat_history(limit: int = 50, db: Session = Depends(get_db)):
    """Get chat history"""
    messages = db.query(ChatMessage).order_by(ChatMessage.created_at.desc()).limit(limit).all()
    
    return {
        "success": True,
        "data": {
            "messages": [
                {
                    "id": m.id,
                    "sender": m.sender,
                    "message": m.message,
                    "sources": json.loads(m.sources) if m.sources else [],
                    "created_at": str(m.created_at)
                }
                for m in reversed(messages)
            ]
        }
    }


@app.get("/api/v1/metrics/dashboard")
async def get_dashboard_metrics(db: Session = Depends(get_db)):
    """Get dashboard metrics"""
    total_alerts = db.query(Alert).count()
    active_incidents = db.query(Incident).filter(Incident.status == "active").count()
    total_incidents = db.query(Incident).count()
    actions_executed = db.query(Action).filter(Action.executed == True).count()
    total_actions = db.query(Action).count()
    
    # Get latest AI time estimate
    latest_estimate = db.query(AITimeEstimate).order_by(AITimeEstimate.created_at.desc()).first()
    
    if latest_estimate:
        time_saved = latest_estimate.time_saved_minutes
        manual_time = latest_estimate.manual_review_minutes
        ai_time = latest_estimate.ai_assisted_minutes
        time_explanation = latest_estimate.explanation
    else:
        manual_time = total_alerts * 15
        ai_time = total_incidents * 3
        time_saved = max(0, manual_time - ai_time)
        time_explanation = "Fallback estimate: 15 min/alert manual, 3 min/incident with AI"
    
    severity_counts = dict(
        db.query(Alert.severity, func.count(Alert.id))
        .group_by(Alert.severity)
        .all()
    )
    
    return {
        "success": True,
        "data": {
            "total_alerts": total_alerts,
            "active_incidents": active_incidents,
            "total_incidents": total_incidents,
            "actions_executed": actions_executed,
            "total_actions": total_actions,
            "time_saved_minutes": time_saved,
            "time_saved_hours": round(time_saved / 60, 1),
            "manual_review_minutes": manual_time,
            "ai_assisted_minutes": ai_time,
            "time_explanation": time_explanation,
            "severity_breakdown": severity_counts,
            "reduction_percentage": round((1 - ai_time / max(1, manual_time)) * 100, 1) if manual_time > 0 else 0,
            "chromadb_stats": vector_store.get_stats()
        }
    }


@app.delete("/api/v1/data/reset")
async def reset_data(db: Session = Depends(get_db)):
    """Reset all data"""
    db.query(ChatMessage).delete()
    db.query(Action).delete()
    db.query(Incident).delete()
    db.query(Alert).delete()
    db.query(MetricsHistory).delete()
    db.query(AITimeEstimate).delete()
    db.commit()
    
    vector_store.clear_all()
    
    return {"success": True, "message": "All data reset successfully"}


# ========================= STATIC FILES =========================

@app.get("/api/v1/sample_alerts.csv")
async def get_sample_alerts():
    """Serve the sample alerts CSV file"""
    csv_path = DATA_DIR / "sample_alerts.csv"
    if not csv_path.exists():
        raise HTTPException(status_code=404, detail=f"Sample alerts file not found")
    
    with open(csv_path, "r") as f:
        content = f.read()
    
    return Response(
        content=content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=sample_alerts.csv"}
    )


@app.get("/")
async def serve_index():
    """Serve the main index.html"""
    index_path = FRONTEND_DIR / "index.html"
    if not index_path.exists():
        return {"error": f"Frontend not found at {FRONTEND_DIR}", "hint": "Place frontend files in ../frontend/"}
    return FileResponse(str(index_path))


@app.get("/{filename:path}")
async def serve_static(filename: str):
    """Serve static files from frontend folder"""
    if filename.startswith("api/"):
        raise HTTPException(status_code=404, detail="Not found")
    
    file_path = FRONTEND_DIR / filename
    if file_path.exists() and file_path.is_file():
        return FileResponse(str(file_path))
    
    index_path = FRONTEND_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    
    raise HTTPException(status_code=404, detail="Not found")


# ========================= RUN =========================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
