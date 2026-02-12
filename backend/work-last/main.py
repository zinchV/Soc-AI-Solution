"""
SOC AI Tool API - Multi-Agent Architecture
FastAPI backend with Google ADK agent orchestration.
Complete version with Threat Center, Asset Inventory, and Sentinel Integration.
"""
from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from sqlalchemy.orm import Session
from sqlalchemy import func, Column, Integer, String, Text, Boolean, DateTime, Float
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime
import uuid
import json
import pathlib
import httpx

# Import ALL models from database.py (they are already defined there)
from database import (
    init_db, get_db, Base, engine, SessionLocal,
    Alert, Incident, Action, ChatMessage, MetricsHistory, AITimeEstimate,
    ThreatIntel, DetectionRule, Hunt, HuntResult, PendingAction
)
from vector_store import vector_store
from soc_agent import run_agent, APP_NAME
from ingestion import ingestion_router, auto_triage_manager
from siem_simulator.router import router as simulator_router


# ========================= APP SETUP =========================

app = FastAPI(title="SOC AI Tool API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ingestion_router)
app.include_router(simulator_router)

BACKEND_DIR = pathlib.Path(__file__).parent
PROJECT_DIR = BACKEND_DIR.parent
FRONTEND_DIR = PROJECT_DIR / "frontend"
DATA_DIR = PROJECT_DIR / "data"


# ========================= ASSET INVENTORY =========================

SIMULATED_ASSETS = [
    {"id": 1, "hostname": "WEB-PROD-01", "ip_address": "10.0.1.10", "asset_type": "server", "os": "Ubuntu 22.04", "software": ["nginx", "nodejs", "openssl"], "criticality": "critical", "owner": "Web Team"},
    {"id": 2, "hostname": "APP-SERVER-01", "ip_address": "10.0.2.20", "asset_type": "server", "os": "RHEL 8", "software": ["tomcat", "java", "elasticsearch"], "criticality": "critical", "owner": "App Team"},
    {"id": 3, "hostname": "DB-POSTGRES-01", "ip_address": "10.0.5.50", "asset_type": "server", "os": "Ubuntu 22.04", "software": ["postgresql", "pgbouncer"], "criticality": "critical", "owner": "DBA Team"},
    {"id": 4, "hostname": "FORTINET-FW-01", "ip_address": "10.0.0.1", "asset_type": "network", "os": "FortiOS 7.2", "software": ["fortios", "fortigate"], "criticality": "critical", "owner": "Security"},
    {"id": 5, "hostname": "PALOALTO-FW-01", "ip_address": "10.0.0.20", "asset_type": "security", "os": "PAN-OS 10.2", "software": ["panos", "paloalto"], "criticality": "critical", "owner": "Security"},
    {"id": 6, "hostname": "SONICWALL-VPN-01", "ip_address": "10.0.0.5", "asset_type": "security", "os": "SonicOS 7.0", "software": ["sonicwall", "sma1000"], "criticality": "critical", "owner": "Security"},
    {"id": 7, "hostname": "WORKSTATION-HR-001", "ip_address": "10.10.1.101", "asset_type": "workstation", "os": "Windows 11", "software": ["office", "chrome"], "criticality": "medium", "owner": "HR"},
    {"id": 8, "hostname": "DC-PRIMARY-01", "ip_address": "10.0.10.10", "asset_type": "server", "os": "Windows Server 2022", "software": ["windows", "active-directory"], "criticality": "critical", "owner": "IT Ops"},
]

PRODUCT_SOFTWARE_MAP = {
    'fortios': ['fortios', 'fortigate'], 'fortigate': ['fortios', 'fortigate'],
    'panos': ['panos', 'paloalto'], 'palo alto': ['panos', 'paloalto'],
    'sonicwall': ['sonicwall', 'sma1000'], 'nginx': ['nginx'], 'windows': ['windows'],
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
    print("=" * 60)
    await auto_triage_manager.start_time_based_triggers()


# ========================= MODELS =========================

class AgentRequest(BaseModel):
    message: str
    session_id: Optional[str] = None
    user_id: Optional[str] = "soc_analyst"

class AlertUpload(BaseModel):
    alerts: List[Dict[str, Any]]

class IncidentUpdateRequest(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None


# ========================= AGENT ENDPOINT =========================

@app.post("/api/v1/agent")
async def agent_endpoint(request: AgentRequest):
    try:
        result = await run_agent(message=request.message, user_id=request.user_id, session_id=request.session_id)
        if result["success"]:
            return {"success": True, "data": {"response": result["response"], "session_id": result["session_id"]}}
        return {"success": False, "error": result.get("error", "Unknown")}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ========================= HEALTH =========================

@app.get("/api/v1/health")
async def health_check(db: Session = Depends(get_db)):
    import os
    try:
        from sqlalchemy import text
        db.execute(text("SELECT 1"))
        db_status = "connected"
    except:
        db_status = "disconnected"
    
    gemini_key = os.getenv("GEMINI_API_KEY", "")
    gemini_status = "configured" if gemini_key and len(gemini_key) > 10 else "not_configured"
    
    return {
        "status": "healthy", "version": "2.0.0", "gemini": gemini_status,
        "dependencies": {"database": db_status, "chromadb": "connected"},
        "stats": vector_store.get_stats(), "auto_triage": auto_triage_manager.get_status()
    }


# ========================= ALERTS =========================

@app.post("/api/v1/alerts/upload")
async def upload_alerts(data: AlertUpload, db: Session = Depends(get_db)):
    upload_id = str(uuid.uuid4())
    alerts_created = []
    for alert_data in data.alerts:
        timestamp = alert_data.get("timestamp")
        if isinstance(timestamp, str):
            try: timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except: timestamp = datetime.utcnow()
        alert = Alert(timestamp=timestamp, severity=alert_data.get("severity", "Medium"),
            source_ip=alert_data.get("source_ip", ""), destination_ip=alert_data.get("destination_ip", ""),
            user=alert_data.get("user", "unknown"), description=alert_data.get("description", ""),
            event_type=alert_data.get("event_type", "Unknown"), upload_id=upload_id)
        db.add(alert)
        db.flush()
        alerts_created.append({"id": alert.id, "severity": alert.severity, "source_ip": alert.source_ip,
            "destination_ip": alert.destination_ip, "user": alert.user, "description": alert.description,
            "event_type": alert.event_type, "timestamp": str(alert.timestamp)})
    db.commit()
    indexed = vector_store.add_alerts(alerts_created)
    return {"success": True, "data": {"upload_id": upload_id, "count": len(alerts_created), "indexed_in_chromadb": indexed}}


@app.get("/api/v1/alerts")
async def get_alerts(limit: int = 50, severity: Optional[str] = None, event_type: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(Alert)
    if severity: query = query.filter(Alert.severity == severity)
    if event_type: query = query.filter(Alert.event_type == event_type)
    total = query.count()
    alerts = query.order_by(Alert.timestamp.desc()).limit(limit).all()
    return {"success": True, "data": {"total": total, "alerts": [
        {"id": a.id, "timestamp": str(a.timestamp), "severity": a.severity, "source_ip": a.source_ip,
         "destination_ip": a.destination_ip, "user": a.user, "description": a.description, "event_type": a.event_type}
        for a in alerts]}}


# ========================= INCIDENTS =========================

@app.get("/api/v1/incidents")
async def get_incidents(status: Optional[str] = None, limit: int = 50, db: Session = Depends(get_db)):
    query = db.query(Incident)
    if status: query = query.filter(Incident.status == status)
    total = query.count()
    incidents = query.order_by(Incident.created_at.desc()).limit(limit).all()
    return {"success": True, "data": {"total": total, "incidents": [
        {"id": i.id, "title": i.title, "summary": i.summary, "severity": i.severity, "status": i.status,
         "alert_count": i.alert_count, "alert_ids": json.loads(i.alert_ids) if i.alert_ids else [],
         "confidence": i.confidence, "attack_stage": i.attack_stage, "assigned_to": i.assigned_to,
         "training_explanation": json.loads(i.training_explanation) if i.training_explanation else None,
         "created_at": str(i.created_at), "updated_at": str(i.updated_at)}
        for i in incidents]}}


@app.put("/api/v1/incidents/{incident_id}")
async def update_incident(incident_id: int, request: IncidentUpdateRequest, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident: raise HTTPException(404, "Incident not found")
    if request.status: incident.status = request.status
    if request.assigned_to: incident.assigned_to = request.assigned_to
    incident.updated_at = datetime.utcnow()
    db.commit()
    return {"success": True, "data": {"id": incident.id, "status": incident.status}}


# ========================= CHAT =========================

@app.get("/api/v1/chat/history")
async def get_chat_history(limit: int = 50, db: Session = Depends(get_db)):
    messages = db.query(ChatMessage).order_by(ChatMessage.created_at.desc()).limit(limit).all()
    return {"success": True, "data": {"messages": [
        {"id": m.id, "sender": m.sender, "message": m.message, "sources": json.loads(m.sources) if m.sources else [], "created_at": str(m.created_at)}
        for m in reversed(messages)]}}


# ========================= METRICS =========================

@app.get("/api/v1/metrics/dashboard")
async def get_dashboard_metrics(db: Session = Depends(get_db)):
    total_alerts = db.query(Alert).count()
    active_incidents = db.query(Incident).filter(Incident.status == "active").count()
    total_incidents = db.query(Incident).count()
    actions_executed = db.query(Action).filter(Action.executed == True).count()
    latest_estimate = db.query(AITimeEstimate).order_by(AITimeEstimate.created_at.desc()).first()
    if latest_estimate:
        time_saved = latest_estimate.time_saved_minutes
        manual_time = latest_estimate.manual_review_minutes
    else:
        manual_time = total_alerts * 15
        time_saved = max(0, manual_time - total_incidents * 3)
    severity_counts = dict(db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all())
    return {"success": True, "data": {
        "total_alerts": total_alerts, "active_incidents": active_incidents, "total_incidents": total_incidents,
        "actions_executed": actions_executed, "time_saved_minutes": time_saved, "time_saved_hours": round(time_saved / 60, 1),
        "severity_breakdown": severity_counts, "chromadb_stats": vector_store.get_stats()}}


@app.delete("/api/v1/data/reset")
async def reset_data(db: Session = Depends(get_db)):
    for model in [ChatMessage, Action, Incident, Alert, MetricsHistory, AITimeEstimate, ThreatIntel, PendingAction, DetectionRule, Hunt, HuntResult]:
        try: db.query(model).delete()
        except: pass
    db.commit()
    vector_store.clear_all()
    return {"success": True, "message": "All data reset"}


# ========================= THREAT INTEL =========================

@app.post('/api/v1/threat-intel/refresh')
async def refresh_threat_intel(db: Session = Depends(get_db)):
    try:
        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
            response = await client.get('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json')
            data = response.json()
        vulnerabilities = data.get('vulnerabilities', [])[:20]
        saved_count = 0
        for vuln in vulnerabilities:
            cve_id = vuln.get('cveID')
            if not cve_id: continue
            if db.query(ThreatIntel).filter(ThreatIntel.cve_id == cve_id).first(): continue
            try: date_added = datetime.strptime(vuln.get('dateAdded', ''), '%Y-%m-%d')
            except: date_added = None
            try: due_date = datetime.strptime(vuln.get('dueDate', ''), '%Y-%m-%d')
            except: due_date = None
            threat = ThreatIntel(source='cisa_kev', cve_id=cve_id, vendor=vuln.get('vendorProject', 'Unknown'),
                product=vuln.get('product', 'Unknown'), description=vuln.get('shortDescription', ''),
                severity='critical', date_added=date_added, due_date=due_date,
                ransomware_use=vuln.get('knownRansomwareCampaignUse', '') == 'Known', status='new')
            db.add(threat)
            saved_count += 1
        db.commit()
        return {'success': True, 'message': f'Saved {saved_count} new CVEs', 'new_count': saved_count}
    except Exception as e:
        return {'success': False, 'error': str(e)}


@app.get('/api/v1/threat-intel/kevs')
async def get_kevs(limit: int = 20, db: Session = Depends(get_db)):
    threats = db.query(ThreatIntel).order_by(ThreatIntel.date_added.desc()).limit(limit).all()
    return {'success': True, 'count': len(threats), 'threats': [
        {'id': t.id, 'cve_id': t.cve_id, 'vendor': t.vendor, 'product': t.product, 'description': t.description,
         'severity': t.severity, 'date_added': str(t.date_added) if t.date_added else None,
         'due_date': str(t.due_date) if t.due_date else None, 'ransomware_use': t.ransomware_use, 'status': t.status}
        for t in threats]}


@app.get('/api/v1/threat-intel/exposure')
async def check_exposure(vendor: str = '', product: str = '', cve_id: str = ''):
    search_terms = []
    for key, values in PRODUCT_SOFTWARE_MAP.items():
        if key in vendor.lower() or key in product.lower():
            search_terms.extend(values)
    if not search_terms: search_terms = [vendor.lower(), product.lower()]
    exposed = []
    for asset in SIMULATED_ASSETS:
        for term in search_terms:
            if any(term in sw.lower() for sw in asset.get('software', [])):
                exposed.append({**asset, 'matching_software': term})
                break
    return {'success': True, 'is_exposed': len(exposed) > 0, 'exposed_count': len(exposed), 'assets': exposed}


# ========================= DETECTION RULES =========================

@app.get('/api/v1/rules')
async def get_rules(status: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(DetectionRule)
    if status: query = query.filter(DetectionRule.status == status)
    rules = query.order_by(DetectionRule.created_at.desc()).all()
    return {'success': True, 'count': len(rules), 'rules': [
        {'id': r.id, 'title': r.title, 'description': r.description, 'source_cve': r.source_cve, 'severity': r.severity,
         'sigma_rule': r.sigma_rule, 'kql_query': r.kql_query, 'mitre_techniques': json.loads(r.mitre_techniques) if r.mitre_techniques else [],
         'status': r.status, 'approved_by': r.approved_by, 'sentinel_rule_id': r.sentinel_rule_id, 'created_at': str(r.created_at)}
        for r in rules]}


@app.get('/api/v1/rules/{rule_id}')
async def get_rule(rule_id: int, db: Session = Depends(get_db)):
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if not rule: raise HTTPException(404, 'Rule not found')
    return {'success': True, 'rule': {'id': rule.id, 'title': rule.title, 'description': rule.description,
        'source_cve': rule.source_cve, 'severity': rule.severity, 'sigma_rule': rule.sigma_rule, 'kql_query': rule.kql_query,
        'mitre_techniques': json.loads(rule.mitre_techniques) if rule.mitre_techniques else [], 'status': rule.status}}


@app.post('/api/v1/threat-intel/{cve_id}/create-rule')
async def create_detection_rule(cve_id: str, db: Session = Depends(get_db)):
    threat = db.query(ThreatIntel).filter(ThreatIntel.cve_id == cve_id).first()
    if not threat: raise HTTPException(404, f'CVE {cve_id} not found')
    if db.query(DetectionRule).filter(DetectionRule.source_cve == cve_id).first():
        return {'success': False, 'error': f'Rule already exists for {cve_id}'}
    
    sigma = f"""title: Detect {cve_id} - {threat.vendor} {threat.product}
status: experimental
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|contains: '{threat.product.lower()}'
  condition: selection
level: high"""
    
    kql = f"""// Detection for {cve_id}
SecurityEvent | where TimeGenerated > ago(24h)
| where EventID in (4688, 4624)
| where CommandLine has_any ("{threat.product.lower()}", "exploit")
| project TimeGenerated, Computer, Account, CommandLine"""
    
    rule = DetectionRule(title=f"Detect {cve_id} - {threat.vendor} {threat.product}",
        description=f"Detection for {threat.description[:200]}", source_cve=cve_id, severity='high',
        sigma_rule=sigma, kql_query=kql, mitre_techniques=json.dumps(['T1190']), status='pending')
    db.add(rule)
    db.commit()
    return {'success': True, 'message': f'Rule created for {cve_id}', 'rule_id': rule.id}


@app.post('/api/v1/rules/{rule_id}/approve')
async def approve_rule(rule_id: int, analyst: str = 'soc_analyst', db: Session = Depends(get_db)):
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if not rule: raise HTTPException(404, 'Rule not found')
    rule.status = 'approved'
    rule.approved_by = analyst
    rule.approved_at = datetime.utcnow()
    db.commit()
    return {'success': True, 'message': f'Rule {rule_id} approved'}


@app.post('/api/v1/rules/{rule_id}/reject')
async def reject_rule(rule_id: int, db: Session = Depends(get_db)):
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if not rule: raise HTTPException(404, 'Rule not found')
    rule.status = 'rejected'
    db.commit()
    return {'success': True}


@app.post('/api/v1/rules/{rule_id}/deploy')
async def deploy_rule(rule_id: int, db: Session = Depends(get_db)):
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if not rule: raise HTTPException(404, 'Rule not found')
    if rule.status != 'approved': raise HTTPException(400, 'Rule must be approved first')
    try:
        from sentinel_integration import SentinelRuleDeployer
        deployer = SentinelRuleDeployer()
        result = deployer.deploy_scheduled_rule(rule_name=f"soc-ai-rule-{rule_id}",
            display_name=f"[SOC-AI] {rule.title[:80]}", query=rule.kql_query, severity=rule.severity or "High",
            description=rule.description, tactics=["InitialAccess"], techniques=["T1190"], enabled=True)
        if result.get('success'):
            rule.status = 'deployed'
            rule.deployed_at = datetime.utcnow()
            rule.sentinel_rule_id = result.get('rule_id')
            db.commit()
            return {'success': True, 'sentinel_rule_id': rule.sentinel_rule_id}
        return {'success': False, 'error': result.get('error')}
    except ImportError:
        rule.status = 'deployed'
        rule.deployed_at = datetime.utcnow()
        rule.sentinel_rule_id = f'soc-ai-rule-{rule_id}-simulated'
        db.commit()
        return {'success': True, 'sentinel_rule_id': rule.sentinel_rule_id, 'simulated': True}
    except Exception as e:
        return {'success': False, 'error': str(e)}


# ========================= PENDING ACTIONS =========================

@app.get('/api/v1/actions/pending')
async def get_pending_actions(db: Session = Depends(get_db)):
    actions = db.query(PendingAction).filter(PendingAction.status == 'pending').all()
    return {'success': True, 'count': len(actions), 'actions': [
        {'id': a.id, 'action_type': a.action_type, 'title': a.title, 'description': a.description,
         'priority': a.priority, 'source_type': a.source_type, 'source_id': a.source_id, 'status': a.status}
        for a in actions]}

@app.post('/api/v1/actions/{action_id}/approve')
async def approve_action(action_id: int, analyst: str = 'soc_analyst', db: Session = Depends(get_db)):
    action = db.query(PendingAction).filter(PendingAction.id == action_id).first()
    if not action: raise HTTPException(404, 'Action not found')
    action.status = 'approved'
    action.approved_by = analyst
    db.commit()
    return {'success': True}

@app.post('/api/v1/actions/{action_id}/reject')
async def reject_action(action_id: int, db: Session = Depends(get_db)):
    action = db.query(PendingAction).filter(PendingAction.id == action_id).first()
    if not action: raise HTTPException(404, 'Action not found')
    action.status = 'rejected'
    db.commit()
    return {'success': True}

@app.post('/api/v1/actions/{action_id}/execute')
async def execute_action(action_id: int):
    return {'success': True, 'message': f'Action {action_id} executed'}


# ========================= HUNTS =========================

@app.get('/api/v1/hunts')
async def get_hunts(status: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(Hunt)
    if status: query = query.filter(Hunt.status == status)
    hunts = query.all()
    return {'success': True, 'count': len(hunts), 'hunts': [
        {'id': h.id, 'title': h.title, 'description': h.description, 'status': h.status, 'priority': h.priority}
        for h in hunts]}

@app.post('/api/v1/hunts/generate')
async def generate_hunts(db: Session = Depends(get_db)):
    threats = db.query(ThreatIntel).limit(5).all()
    created = []
    for t in threats:
        if not db.query(Hunt).filter(Hunt.title.contains(t.cve_id)).first():
            hunt = Hunt(title=f"Hunt for {t.cve_id}", description=f"Hunt for {t.vendor} {t.product}",
                hypothesis=f"Check for {t.cve_id} exploitation", hunt_query=f"SecurityEvent | where CommandLine has '{t.product}'",
                mitre_technique='T1190', status='pending', priority='high' if t.ransomware_use else 'medium')
            db.add(hunt)
            created.append(t.cve_id)
    db.commit()
    return {'success': True, 'hunts_created': created}

@app.get('/api/v1/hunts/results')
async def get_hunt_results(db: Session = Depends(get_db)):
    results = db.query(HuntResult).all()
    return {'success': True, 'count': len(results), 'results': [
        {'id': r.id, 'hunt_id': r.hunt_id, 'finding': r.finding, 'severity': r.severity, 'status': r.status}
        for r in results]}


# ========================= STATIC FILES =========================

@app.get("/")
async def serve_index():
    index_path = FRONTEND_DIR / "index.html"
    if not index_path.exists(): return {"error": "Frontend not found"}
    return FileResponse(str(index_path))

@app.get("/{filename:path}")
async def serve_static(filename: str):
    if filename.startswith("api/"): raise HTTPException(404)
    file_path = FRONTEND_DIR / filename
    if file_path.exists(): return FileResponse(str(file_path))
    return FileResponse(str(FRONTEND_DIR / "index.html"))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
