"""
SOC AI Tool API - Multi-Agent Architecture
FastAPI backend with Google ADK agent orchestration.

FIXED VERSION - Includes:
- Proper imports for threat_intel_agent, action_agent
- run_agent_task function for calling specific agents
- All Threat Center endpoints
- Proper model imports
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
import asyncio

# Database imports - include ALL models
from database import (
    init_db, get_db, SessionLocal,
    Alert, Incident, Action, ChatMessage, MetricsHistory, AITimeEstimate,
    ThreatIntel, DetectionRule, Hunt, HuntResult, PendingAction
)
from vector_store import vector_store

# Agent imports
from soc_agent import run_agent, APP_NAME
from soc_agent.threat_intel_agent import threat_intel_agent
from soc_agent.action_agent import action_agent

# Try to import hunting agent if it exists
try:
    from soc_agent.threat_hunt_agent import threat_hunt_agent
    HUNT_AGENT_AVAILABLE = True
except ImportError:
    threat_hunt_agent = None
    HUNT_AGENT_AVAILABLE = False
    print("⚠️ threat_hunt_agent not available - hunting features limited")

from ingestion import ingestion_router, auto_triage_manager
from siem_simulator.router import router as simulator_router

# Google ADK imports for running agents directly
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types


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

# Include routers
app.include_router(ingestion_router)
app.include_router(simulator_router)

# Paths
BACKEND_DIR = pathlib.Path(__file__).parent
PROJECT_DIR = BACKEND_DIR.parent
FRONTEND_DIR = PROJECT_DIR / "frontend"
DATA_DIR = PROJECT_DIR / "data"

# Session service for agent runs
session_service = InMemorySessionService()


# ========================= AGENT TASK RUNNER =========================

async def run_agent_task(agent, message: str, user_id: str = "system") -> dict:
    """
    Run a specific agent with a message and return the result.
    
    This is used to call individual agents (threat_intel_agent, action_agent, etc.)
    directly from API endpoints without going through the orchestrator.
    
    Args:
        agent: The ADK agent to run
        message: The task/message for the agent
        user_id: User identifier for the session
    
    Returns:
        dict with 'success', 'response', and optional 'error'
    """
    try:
        # Create a unique session for this task
        session_id = f"task_{agent.name}_{datetime.now().timestamp()}"
        
        # Create session
        session = session_service.create_session(
            app_name=APP_NAME,
            user_id=user_id,
            session_id=session_id
        )
        
        # Create runner for the agent
        runner = Runner(
            agent=agent,
            app_name=APP_NAME,
            session_service=session_service
        )
        
        # Create the user message
        user_message = types.Content(
            role="user",
            parts=[types.Part(text=message)]
        )
        
        # Run the agent
        response_text = ""
        async for event in runner.run_async(
            user_id=user_id,
            session_id=session_id,
            new_message=user_message
        ):
            if hasattr(event, 'content') and event.content:
                if hasattr(event.content, 'parts'):
                    for part in event.content.parts:
                        if hasattr(part, 'text') and part.text:
                            response_text += part.text
        
        return {
            "success": True,
            "response": response_text,
            "agent": agent.name,
            "session_id": session_id
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "agent": agent.name if agent else "unknown"
        }


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
    print(f"✅ Threat Intel Agent: loaded")
    print(f"✅ Action Agent: loaded")
    print(f"✅ Hunt Agent: {'loaded' if HUNT_AGENT_AVAILABLE else 'not available'}")
    print(f"✅ Ingestion endpoints active")
    print(f"✅ SIEM Simulator available")
    print(f"✅ Threat Center endpoints active")
    print("=" * 60)
    
    # Start auto-triage time-based triggers
    await auto_triage_manager.start_time_based_triggers()


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

class ApprovalRequest(BaseModel):
    approver: str = "analyst"

class RejectRequest(BaseModel):
    reason: str = "Not applicable"


# ========================= MAIN AGENT ENDPOINT =========================

@app.post("/api/v1/agent")
async def agent_endpoint(request: AgentRequest):
    """
    Main agent endpoint - all AI interactions go through here.
    The orchestrator agent will delegate to the appropriate specialist.
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


# ========================= HEALTH & DATA ENDPOINTS =========================

@app.get("/api/v1/health")
async def health_check(db: Session = Depends(get_db)):
    """Health check endpoint"""
    import os
    
    try:
        from sqlalchemy import text
        db.execute(text("SELECT 1"))
        db_status = "connected"
    except Exception as e:
        db_status = "disconnected"
    
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
        "stats": vector_store.get_stats(),
        "auto_triage": auto_triage_manager.get_status()
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
    limit: int = 50,
    db: Session = Depends(get_db)
):
    """Get all incidents"""
    query = db.query(Incident)
    if status:
        query = query.filter(Incident.status == status)
    
    incidents = query.order_by(Incident.created_at.desc()).limit(limit).all()
    
    return {
        "success": True,
        "data": {
            "total": len(incidents),
            "incidents": [
                {
                    "id": i.id,
                    "title": i.title,
                    "summary": i.summary,
                    "severity": i.severity,
                    "status": i.status,
                    "alert_count": i.alert_count,
                    "alert_ids": json.loads(i.alert_ids) if i.alert_ids else [],  # ADDED for grouped alerts
                    "confidence": i.confidence,
                    "attack_stage": i.attack_stage,
                    "indicators": json.loads(i.indicators) if i.indicators else [],  # ADDED
                    "recommended_actions": json.loads(i.recommended_actions) if i.recommended_actions else [],  # ADDED
                    "training": json.loads(i.training_explanation) if i.training_explanation else None,  # ADDED for training mode
                    "assigned_to": i.assigned_to,
                    "created_at": str(i.created_at)
                }
                for i in incidents
            ]
        }
    }


@app.get("/api/v1/incidents/{incident_id}")
async def get_incident_detail(incident_id: int, db: Session = Depends(get_db)):
    """Get incident detail with actions"""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    # Get related alerts
    alert_ids = json.loads(incident.alert_ids) if incident.alert_ids else []
    alerts = db.query(Alert).filter(Alert.id.in_(alert_ids)).all() if alert_ids else []
    
    # Get actions
    actions = db.query(Action).filter(Action.incident_id == incident_id).all()
    
    return {
        "success": True,
        "data": {
            "id": incident.id,
            "title": incident.title,
            "summary": incident.summary,
            "severity": incident.severity,
            "status": incident.status,
            "alert_count": incident.alert_count,
            "confidence": incident.confidence,
            "attack_stage": incident.attack_stage,
            "assigned_to": incident.assigned_to,
            "training_explanation": json.loads(incident.training_explanation) if incident.training_explanation else None,
            "created_at": str(incident.created_at),
            "alerts": [
                {
                    "id": a.id,
                    "severity": a.severity,
                    "description": a.description,
                    "source_ip": a.source_ip,
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
    # Also reset Threat Center data
    db.query(HuntResult).delete()
    db.query(Hunt).delete()
    db.query(PendingAction).delete()
    db.query(DetectionRule).delete()
    db.query(ThreatIntel).delete()
    db.commit()
    
    vector_store.clear_all()
    
    return {"success": True, "message": "All data reset successfully"}


# ========================= THREAT INTEL ENDPOINTS =========================

@app.post('/api/v1/threat-intel/refresh')
async def refresh_threat_intel():
    """Refresh threat intelligence from CISA KEV"""
    try:
        result = await run_agent_task(
            threat_intel_agent,
            'Fetch new CISA KEVs and check exposure for the most critical vulnerabilities.'
        )
        return {'success': result.get('success', False), 'result': result}
    except Exception as e:
        return {'success': False, 'error': str(e)}


@app.get('/api/v1/threat-intel/kevs')
async def get_kevs(limit: int = 20, db: Session = Depends(get_db)):
    """Get stored CISA KEV threats"""
    threats = db.query(ThreatIntel).order_by(ThreatIntel.date_added.desc()).limit(limit).all()
    return {
        'success': True,
        'count': len(threats),
        'threats': [
            {
                'id': t.id,
                'cve_id': t.cve_id,
                'vendor': t.vendor,
                'product': t.product,
                'vulnerability_name': t.vulnerability_name,
                'description': t.description,
                'severity': t.severity,
                'date_added': str(t.date_added) if t.date_added else None,
                'due_date': str(t.due_date) if t.due_date else None,
                'ransomware_use': t.ransomware_use,
                'status': t.status,
                'created_at': str(t.created_at)
            }
            for t in threats
        ]
    }


# ========================= DETECTION RULES ENDPOINTS =========================

@app.get('/api/v1/rules')
async def get_detection_rules(
    status: Optional[str] = None,
    limit: int = 20,
    db: Session = Depends(get_db)
):
    """Get detection rules"""
    query = db.query(DetectionRule)
    if status:
        query = query.filter(DetectionRule.status == status)
    rules = query.order_by(DetectionRule.created_at.desc()).limit(limit).all()
    
    return {
        'success': True,
        'count': len(rules),
        'rules': [
            {
                'id': r.id,
                'title': r.title,
                'description': r.description,
                'severity': r.severity,
                'mitre_techniques': json.loads(r.mitre_techniques) if r.mitre_techniques else [],
                'source_cve': r.source_cve,
                'sigma_rule': r.sigma_rule,
                'kql_query': r.kql_query,
                'siem_platform': r.siem_platform,
                'status': r.status,
                'approved_by': r.approved_by,
                'approved_at': str(r.approved_at) if r.approved_at else None,
                'deployed_at': str(r.deployed_at) if r.deployed_at else None,
                'sentinel_rule_id': r.sentinel_rule_id,
                'created_at': str(r.created_at)
            }
            for r in rules
        ]
    }


@app.post('/api/v1/rules/{rule_id}/approve')
async def approve_rule(rule_id: int, request: ApprovalRequest, db: Session = Depends(get_db)):
    """Approve a detection rule"""
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if not rule:
        raise HTTPException(404, 'Rule not found')
    if rule.status != 'pending':
        raise HTTPException(400, f'Cannot approve. Current status: {rule.status}')
    
    rule.status = 'approved'
    rule.approved_by = request.approver
    rule.approved_at = datetime.utcnow()
    db.commit()
    
    return {'success': True, 'rule_id': rule_id, 'status': 'approved'}


@app.post('/api/v1/rules/{rule_id}/reject')
async def reject_rule(rule_id: int, request: RejectRequest, db: Session = Depends(get_db)):
    """Reject a detection rule"""
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if not rule:
        raise HTTPException(404, 'Rule not found')
    
    rule.status = 'rejected'
    rule.rejected_reason = request.reason
    db.commit()
    
    return {'success': True, 'rule_id': rule_id, 'status': 'rejected'}


@app.post('/api/v1/rules/{rule_id}/deploy')
async def deploy_rule(rule_id: int, db: Session = Depends(get_db)):
    """Deploy an approved rule to Sentinel"""
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if not rule:
        raise HTTPException(404, 'Rule not found')
    if rule.status != 'approved':
        raise HTTPException(400, f'Rule must be approved first. Current status: {rule.status}')
    
    # Call action agent to deploy
    result = await run_agent_task(
        action_agent,
        f'Deploy detection rule {rule_id} to Sentinel'
    )
    
    if result.get('success'):
        rule.status = 'deployed'
        rule.deployed_at = datetime.utcnow()
        rule.sentinel_rule_id = f'soc-ai-rule-{rule_id}'
        db.commit()
    
    return {'success': result.get('success', False), 'result': result}


# ========================= HUNT ENDPOINTS =========================

@app.get('/api/v1/hunts')
async def get_hunts(
    status: Optional[str] = None,
    limit: int = 20,
    db: Session = Depends(get_db)
):
    """Get threat hunts"""
    query = db.query(Hunt)
    if status:
        query = query.filter(Hunt.status == status)
    hunts = query.order_by(Hunt.created_at.desc()).limit(limit).all()
    
    return {
        'success': True,
        'count': len(hunts),
        'hunts': [
            {
                'id': h.id,
                'title': h.title,
                'hypothesis': h.hypothesis,
                'rationale': h.rationale,
                'mitre_technique': h.mitre_technique,
                'hunt_query': h.hunt_query,
                'data_sources': json.loads(h.data_sources) if h.data_sources else [],
                'priority': h.priority,
                'status': h.status,
                'approved_by': h.approved_by,
                'approved_at': str(h.approved_at) if h.approved_at else None,
                'related_cve': h.related_cve,
                'created_at': str(h.created_at)
            }
            for h in hunts
        ]
    }


@app.post('/api/v1/hunts/{hunt_id}/approve')
async def approve_hunt(hunt_id: int, request: ApprovalRequest, db: Session = Depends(get_db)):
    """Approve a threat hunt"""
    hunt = db.query(Hunt).filter(Hunt.id == hunt_id).first()
    if not hunt:
        raise HTTPException(404, 'Hunt not found')
    if hunt.status != 'pending':
        raise HTTPException(400, f'Cannot approve. Current status: {hunt.status}')
    
    hunt.status = 'approved'
    hunt.approved_by = request.approver
    hunt.approved_at = datetime.utcnow()
    db.commit()
    
    return {'success': True, 'hunt_id': hunt_id, 'status': 'approved'}


@app.post('/api/v1/hunts/{hunt_id}/reject')
async def reject_hunt(hunt_id: int, request: RejectRequest, db: Session = Depends(get_db)):
    """Reject a threat hunt"""
    hunt = db.query(Hunt).filter(Hunt.id == hunt_id).first()
    if not hunt:
        raise HTTPException(404, 'Hunt not found')
    
    hunt.status = 'rejected'
    hunt.rejected_reason = request.reason
    db.commit()
    
    return {'success': True, 'hunt_id': hunt_id, 'status': 'rejected'}


@app.post('/api/v1/hunts/{hunt_id}/execute')
async def execute_hunt(hunt_id: int, db: Session = Depends(get_db)):
    """Execute an approved hunt"""
    hunt = db.query(Hunt).filter(Hunt.id == hunt_id).first()
    if not hunt:
        raise HTTPException(404, 'Hunt not found')
    if hunt.status != 'approved':
        raise HTTPException(400, f'Hunt must be approved first. Current status: {hunt.status}')
    if not hunt.approved_by:
        raise HTTPException(400, 'No approver recorded - cannot execute')
    
    # Call action agent to execute
    result = await run_agent_task(
        action_agent,
        f'Execute approved hunt {hunt_id}'
    )
    
    if result.get('success'):
        hunt.status = 'executing'
        hunt.executed_at = datetime.utcnow()
        db.commit()
        
        # Simulate results (in production, this would be actual SIEM query results)
        hunt_result = HuntResult(
            hunt_id=hunt_id,
            findings_count=5,  # Simulated
            findings_summary="Found suspicious activity matching hunt criteria",
            malicious_ips=json.dumps(['10.0.0.100', '192.168.1.50']),
            affected_hosts=json.dumps(['web-server-01'])
        )
        db.add(hunt_result)
        
        hunt.status = 'completed'
        hunt.completed_at = datetime.utcnow()
        db.commit()
    
    return {'success': result.get('success', False), 'result': result}


@app.get('/api/v1/hunts/{hunt_id}/results')
async def get_hunt_results(hunt_id: int, db: Session = Depends(get_db)):
    """Get results for a hunt"""
    hunt = db.query(Hunt).filter(Hunt.id == hunt_id).first()
    if not hunt:
        raise HTTPException(404, 'Hunt not found')
    
    results = db.query(HuntResult).filter(HuntResult.hunt_id == hunt_id).all()
    
    return {
        'success': True,
        'hunt_id': hunt_id,
        'hunt_title': hunt.title,
        'hunt_status': hunt.status,
        'results': [
            {
                'id': r.id,
                'findings_count': r.findings_count,
                'findings_summary': r.findings_summary,
                'malicious_ips': json.loads(r.malicious_ips) if r.malicious_ips else [],
                'affected_hosts': json.loads(r.affected_hosts) if r.affected_hosts else [],
                'escalated': r.escalated,
                'incident_id': r.incident_id,
                'executed_at': str(r.executed_at)
            }
            for r in results
        ]
    }


# ========================= PENDING ACTIONS ENDPOINTS =========================

@app.get('/api/v1/actions/pending')
async def get_pending_actions(db: Session = Depends(get_db)):
    """Get all pending actions awaiting approval"""
    actions = db.query(PendingAction).filter(PendingAction.status == 'pending').all()
    
    return {
        'success': True,
        'count': len(actions),
        'actions': [
            {
                'id': a.id,
                'action_type': a.action_type,
                'title': a.title,
                'description': a.description,
                'payload': json.loads(a.payload) if a.payload else {},
                'source_type': a.source_type,
                'source_id': a.source_id,
                'priority': a.priority,
                'status': a.status,
                'created_at': str(a.created_at)
            }
            for a in actions
        ]
    }


@app.post('/api/v1/actions/{action_id}/approve')
async def approve_pending_action(action_id: int, request: ApprovalRequest, db: Session = Depends(get_db)):
    """Approve a pending action"""
    action = db.query(PendingAction).filter(PendingAction.id == action_id).first()
    if not action:
        raise HTTPException(404, 'Action not found')
    if action.status != 'pending':
        raise HTTPException(400, f'Cannot approve. Current status: {action.status}')
    
    action.status = 'approved'
    action.approved_by = request.approver
    action.approved_at = datetime.utcnow()
    db.commit()
    
    return {'success': True, 'action_id': action_id, 'status': 'approved'}


@app.post('/api/v1/actions/{action_id}/reject')
async def reject_pending_action(action_id: int, request: RejectRequest, db: Session = Depends(get_db)):
    """Reject a pending action"""
    action = db.query(PendingAction).filter(PendingAction.id == action_id).first()
    if not action:
        raise HTTPException(404, 'Action not found')
    
    action.status = 'rejected'
    action.rejected_reason = request.reason
    db.commit()
    
    return {'success': True, 'action_id': action_id, 'status': 'rejected'}


@app.post('/api/v1/actions/{action_id}/execute')
async def execute_pending_action(action_id: int, db: Session = Depends(get_db)):
    """Execute an approved action"""
    action = db.query(PendingAction).filter(PendingAction.id == action_id).first()
    if not action:
        raise HTTPException(404, 'Action not found')
    if action.status != 'approved':
        raise HTTPException(400, f'Action must be approved first. Current status: {action.status}')
    if not action.approved_by:
        raise HTTPException(400, 'No approver recorded - cannot execute')
    
    # Call action agent to execute
    result = await run_agent_task(
        action_agent,
        f'Execute approved action {action_id}: {action.title}'
    )
    
    if result.get('success'):
        action.status = 'completed'
        action.executed_at = datetime.utcnow()
        action.execution_result = json.dumps(result)
        db.commit()
    
    return {'success': result.get('success', False), 'result': result}


# ========================= THREAT CENTER STATS =========================

@app.get('/api/v1/threat-center/stats')
async def get_threat_center_stats(db: Session = Depends(get_db)):
    """Get all stats for the Threat Center dashboard"""
    # Detection Rules stats
    pending_rules = db.query(DetectionRule).filter(DetectionRule.status == 'pending').count()
    approved_rules = db.query(DetectionRule).filter(DetectionRule.status == 'approved').count()
    deployed_rules = db.query(DetectionRule).filter(DetectionRule.status == 'deployed').count()
    
    # Hunt stats
    pending_hunts = db.query(Hunt).filter(Hunt.status == 'pending').count()
    approved_hunts = db.query(Hunt).filter(Hunt.status == 'approved').count()
    completed_hunts = db.query(Hunt).filter(Hunt.status == 'completed').count()
    
    # Results with findings
    hunts_with_findings = db.query(HuntResult).filter(HuntResult.findings_count > 0).count()
    
    # Pending actions
    pending_actions = db.query(PendingAction).filter(PendingAction.status == 'pending').count()
    
    # Threat intel
    new_threats = db.query(ThreatIntel).filter(ThreatIntel.status == 'new').count()
    
    return {
        'success': True,
        'rules': {
            'pending': pending_rules,
            'approved': approved_rules,
            'deployed': deployed_rules
        },
        'hunts': {
            'pending': pending_hunts,
            'approved': approved_hunts,
            'completed': completed_hunts,
            'with_findings': hunts_with_findings
        },
        'threats': {
            'new': new_threats
        },
        'pending_actions': pending_actions,
        'total_pending': pending_rules + pending_hunts + pending_actions
    }


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
