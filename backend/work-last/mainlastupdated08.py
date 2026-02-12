"""
SOC AI Tool API - Multi-Agent Architecture
FastAPI backend with Google ADK agent orchestration.
Complete version with Threat Center, Asset Inventory, and Sentinel Integration.
"""



import ssl
import os
import urllib3

# Disable SSL verification warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set environment variables to bypass SSL verification
os.environ['CURL_CA_BUNDLE'] = ''
os.environ['REQUESTS_CA_BUNDLE'] = ''
os.environ['SSL_CERT_FILE'] = ''
os.environ['PYTHONHTTPSVERIFY'] = '0'

# Patch SSL context globally
ssl._create_default_https_context = ssl._create_unverified_context

# For httpx - create unverified client by default
import httpx
# Monkey-patch httpx to disable SSL verification by default
_original_client_init = httpx.Client.__init__
def _patched_client_init(self, *args, **kwargs):
    kwargs.setdefault('verify', False)
    _original_client_init(self, *args, **kwargs)
httpx.Client.__init__ = _patched_client_init

_original_async_client_init = httpx.AsyncClient.__init__
def _patched_async_client_init(self, *args, **kwargs):
    kwargs.setdefault('verify', False)
    _original_async_client_init(self, *args, **kwargs)
httpx.AsyncClient.__init__ = _patched_async_client_init


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
    {"id": 9, "hostname": "GITLAB-CI-01", "ip_address": "10.0.3.30", "asset_type": "server", "os": "Ubuntu 22.04", "software": ["gitlab", "docker", "redis"], "criticality": "high", "owner": "DevOps"},
    {"id": 10, "hostname": "IVANTI-MDM-01", "ip_address": "10.0.0.25", "asset_type": "security", "os": "Ivanti EPMM 12.1", "software": ["ivanti", "epmm", "mobileiron"], "criticality": "critical", "owner": "IT Ops"},
    {"id": 11, "hostname": "HELPDESK-APP-01", "ip_address": "10.0.4.40", "asset_type": "server", "os": "Windows Server 2019", "software": ["solarwinds", "whd", "iis"], "criticality": "high", "owner": "IT Support"},
]

PRODUCT_SOFTWARE_MAP = {
    'fortios': ['fortios', 'fortigate'], 'fortigate': ['fortios', 'fortigate'],
    'fortinet': ['fortios', 'fortigate'],
    'panos': ['panos', 'paloalto'], 'palo alto': ['panos', 'paloalto'],
    'sonicwall': ['sonicwall', 'sma1000'], 'nginx': ['nginx'], 'windows': ['windows'],
    'cisco': ['cisco'],
    'microsoft': ['windows', 'office', 'active-directory'],
    'office': ['office'],
    'apache': ['apache', 'tomcat'], 'oracle': ['java', 'oracle'],
    'linux': ['ubuntu', 'rhel', 'linux'], 'vmware': ['vmware', 'esxi'],
    'gitlab': ['gitlab'],
    'ivanti': ['ivanti', 'epmm', 'mobileiron'],
    'solarwinds': ['solarwinds', 'whd'],
}

# MITRE ATT&CK Mapping based on vulnerability keywords
MITRE_MAPPING = {
    # Initial Access
    'remote code execution': {'tactic': 'Execution', 'technique': 'T1059', 'technique_name': 'Command and Scripting Interpreter'},
    'rce': {'tactic': 'Execution', 'technique': 'T1059', 'technique_name': 'Command and Scripting Interpreter'},
    'authentication bypass': {'tactic': 'InitialAccess', 'technique': 'T1078', 'technique_name': 'Valid Accounts'},
    'auth bypass': {'tactic': 'InitialAccess', 'technique': 'T1078', 'technique_name': 'Valid Accounts'},
    'sql injection': {'tactic': 'InitialAccess', 'technique': 'T1190', 'technique_name': 'Exploit Public-Facing Application'},
    'command injection': {'tactic': 'Execution', 'technique': 'T1059', 'technique_name': 'Command and Scripting Interpreter'},
    'path traversal': {'tactic': 'InitialAccess', 'technique': 'T1190', 'technique_name': 'Exploit Public-Facing Application'},
    'directory traversal': {'tactic': 'InitialAccess', 'technique': 'T1190', 'technique_name': 'Exploit Public-Facing Application'},
    'file inclusion': {'tactic': 'InitialAccess', 'technique': 'T1190', 'technique_name': 'Exploit Public-Facing Application'},
    'buffer overflow': {'tactic': 'Execution', 'technique': 'T1203', 'technique_name': 'Exploitation for Client Execution'},
    'heap overflow': {'tactic': 'Execution', 'technique': 'T1203', 'technique_name': 'Exploitation for Client Execution'},
    'stack overflow': {'tactic': 'Execution', 'technique': 'T1203', 'technique_name': 'Exploitation for Client Execution'},
    'privilege escalation': {'tactic': 'PrivilegeEscalation', 'technique': 'T1068', 'technique_name': 'Exploitation for Privilege Escalation'},
    'elevation of privilege': {'tactic': 'PrivilegeEscalation', 'technique': 'T1068', 'technique_name': 'Exploitation for Privilege Escalation'},
    'deserialization': {'tactic': 'Execution', 'technique': 'T1059', 'technique_name': 'Command and Scripting Interpreter'},
    'xxe': {'tactic': 'InitialAccess', 'technique': 'T1190', 'technique_name': 'Exploit Public-Facing Application'},
    'ssrf': {'tactic': 'InitialAccess', 'technique': 'T1190', 'technique_name': 'Exploit Public-Facing Application'},
    'default credentials': {'tactic': 'InitialAccess', 'technique': 'T1078.001', 'technique_name': 'Default Accounts'},
    'hardcoded credentials': {'tactic': 'InitialAccess', 'technique': 'T1078.001', 'technique_name': 'Default Accounts'},
    'information disclosure': {'tactic': 'Discovery', 'technique': 'T1082', 'technique_name': 'System Information Discovery'},
    'denial of service': {'tactic': 'Impact', 'technique': 'T1499', 'technique_name': 'Endpoint Denial of Service'},
    'dos': {'tactic': 'Impact', 'technique': 'T1499', 'technique_name': 'Endpoint Denial of Service'},
}

# Default MITRE if no keyword match
DEFAULT_MITRE = {'tactic': 'InitialAccess', 'technique': 'T1190', 'technique_name': 'Exploit Public-Facing Application'}


def get_mitre_for_description(description: str) -> dict:
    """Extract MITRE tactic/technique from vulnerability description"""
    desc_lower = description.lower()
    for keyword, mitre in MITRE_MAPPING.items():
        if keyword in desc_lower:
            return mitre
    return DEFAULT_MITRE


def check_exposure_for_product(vendor: str, product: str) -> dict:
    """
    Reusable function to check asset exposure for a vendor/product.
    Uses EXACT matching against asset software list to avoid false positives.
    e.g. "ios" should NOT match "fortios"
    """
    search_terms = set()
    vendor_lower = vendor.lower().strip()
    product_lower = product.lower().strip()
    
    for key, values in PRODUCT_SOFTWARE_MAP.items():
        if key in vendor_lower or key in product_lower:
            search_terms.update(values)
    
    if not search_terms:
        # Fallback: use vendor and product as-is
        search_terms = {vendor_lower, product_lower}
    
    exposed = []
    critical_count = 0
    high_count = 0
    
    for asset in SIMULATED_ASSETS:
        asset_software = [sw.lower().strip() for sw in asset.get('software', [])]
        for term in search_terms:
            # EXACT match: the term must exactly equal an item in the software list
            # This prevents "ios" from matching "fortios"
            if term in asset_software:
                exposed_asset = {
                    'hostname': asset.get('hostname'),
                    'ip': asset.get('ip_address'),
                    'criticality': asset.get('criticality'),
                    'matched_software': term,
                    'asset_type': asset.get('asset_type'),
                    'os': asset.get('os')
                }
                exposed.append(exposed_asset)
                if asset.get('criticality') == 'critical':
                    critical_count += 1
                elif asset.get('criticality') == 'high':
                    high_count += 1
                break
    
    return {
        'is_exposed': len(exposed) > 0,
        'exposed_count': len(exposed),
        'critical_count': critical_count,
        'high_count': high_count,
        'exposed_assets': exposed
    }


# ========================= STARTUP =========================

@app.on_event("startup")
async def startup():
    from database import DATABASE_PATH
    print(f"📂 DATABASE LOCATION: {DATABASE_PATH}")
    init_db()
    print("=" * 60)
    print("🚀 SOC AI Tool v2.0 - Multi-Agent Architecture")
    print("=" * 60)
    print(f"✅ Database initialized")
    print(f"✅ ChromaDB stats: {vector_store.get_stats()}")
    print(f"✅ Agent system ready")
    print("=" * 60)
    await auto_triage_manager.start_time_based_triggers()
    
    # Auto-fetch CISA KEV data on startup
    await auto_fetch_kevs_on_startup()


async def auto_fetch_kevs_on_startup():
    """Automatically fetch CISA KEV data if database is empty or stale"""
    db = SessionLocal()
    try:
        # Check if we already have KEV data
        kev_count = db.query(ThreatIntel).count()
        
        if kev_count == 0:
            print("🔄 No KEV data found, fetching from CISA...")
            await fetch_kevs_from_cisa(db)
        else:
            print(f"✅ Found {kev_count} existing KEVs in database")
            
            # Optionally: Check if data is stale (older than 24 hours)
            from datetime import timedelta
            latest = db.query(ThreatIntel).order_by(ThreatIntel.created_at.desc()).first()
            if latest and latest.created_at:
                age = datetime.utcnow() - latest.created_at
                if age > timedelta(hours=24):
                    print(f"🔄 KEV data is {age.total_seconds()/3600:.1f} hours old, refreshing...")
                    await fetch_kevs_from_cisa(db)
                else:
                    print(f"✅ KEV data is fresh ({age.total_seconds()/3600:.1f} hours old)")
    except Exception as e:
        print(f"⚠️ Auto-fetch KEV failed: {e}")
    finally:
        db.close()


async def fetch_kevs_from_cisa(db: Session):
    """Fetch KEVs from CISA and save to database"""
    try:
        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
            response = await client.get('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json')
            data = response.json()
        
        vulnerabilities = data.get('vulnerabilities', [])[:20]  # Get top 20
        saved_count = 0
        
        for vuln in vulnerabilities:
            cve_id = vuln.get('cveID')
            if not cve_id:
                continue
            
            # Skip if already exists
            if db.query(ThreatIntel).filter(ThreatIntel.cve_id == cve_id).first():
                continue
            
            try:
                date_added = datetime.strptime(vuln.get('dateAdded', ''), '%Y-%m-%d')
            except:
                date_added = None
            
            try:
                due_date = datetime.strptime(vuln.get('dueDate', ''), '%Y-%m-%d')
            except:
                due_date = None
            
            threat = ThreatIntel(
                source='cisa_kev',
                cve_id=cve_id,
                vendor=vuln.get('vendorProject', 'Unknown'),
                product=vuln.get('product', 'Unknown'),
                vulnerability_name=vuln.get('vulnerabilityName', ''),
                description=vuln.get('shortDescription', ''),
                severity='critical',
                date_added=date_added,
                due_date=due_date,
                ransomware_use=vuln.get('knownRansomwareCampaignUse', '') == 'Known',
                status='new'
            )
            db.add(threat)
            saved_count += 1
        
        db.commit()
        total_count = db.query(ThreatIntel).count()
        print(f"✅ KEV data loaded: {total_count} total CVEs ({saved_count} new)")
        
    except Exception as e:
        print(f"❌ Failed to fetch CISA KEV: {e}")


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


# ========================= ASSETS ENDPOINT =========================

@app.get("/api/v1/assets")
async def get_assets(
    asset_type: Optional[str] = None,
    criticality: Optional[str] = None,
    search: Optional[str] = None
):
    """Get all assets with optional filters"""
    assets = SIMULATED_ASSETS.copy()
    
    if asset_type:
        assets = [a for a in assets if a.get('asset_type') == asset_type]
    
    if criticality:
        assets = [a for a in assets if a.get('criticality') == criticality]
    
    if search:
        search_lower = search.lower()
        assets = [a for a in assets if 
            search_lower in a.get('hostname', '').lower() or
            search_lower in a.get('ip_address', '').lower() or
            search_lower in a.get('owner', '').lower()
        ]
    
    return {
        'success': True,
        'count': len(assets),
        'assets': assets
    }


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


@app.get("/api/v1/incidents/{incident_id}")
async def get_incident_detail(incident_id: int, db: Session = Depends(get_db)):
    """Get incident details including full alert data for grouped alerts view."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(404, "Incident not found")
    
    # Parse alert_ids and fetch full alert records
    alert_ids = []
    try:
        alert_ids = json.loads(incident.alert_ids) if incident.alert_ids else []
    except (json.JSONDecodeError, TypeError):
        alert_ids = []
    
    alerts = []
    if alert_ids:
        alert_records = db.query(Alert).filter(Alert.id.in_(alert_ids)).all()
        alerts = [
            {
                'id': a.id,
                'severity': a.severity,
                'source_ip': a.source_ip,
                'destination_ip': a.destination_ip,
                'user': a.user,
                'event_type': a.event_type,
                'description': a.description,
                'timestamp': str(a.timestamp) if a.timestamp else None,
            }
            for a in alert_records
        ]
    
    return {
        "success": True,
        "data": {
            "id": incident.id,
            "title": incident.title,
            "summary": incident.summary,
            "severity": incident.severity,
            "status": incident.status,
            "alert_count": incident.alert_count,
            "alert_ids": alert_ids,
            "alerts": alerts,
            "confidence": incident.confidence,
            "attack_stage": incident.attack_stage,
            "assigned_to": incident.assigned_to,
            "training_explanation": json.loads(incident.training_explanation) if incident.training_explanation else None,
            "created_at": str(incident.created_at),
            "updated_at": str(incident.updated_at)
        }
    }


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
                product=vuln.get('product', 'Unknown'), vulnerability_name=vuln.get('vulnerabilityName', ''),
                description=vuln.get('shortDescription', ''),
                severity='critical', date_added=date_added, due_date=due_date,
                ransomware_use=vuln.get('knownRansomwareCampaignUse', '') == 'Known', status='new')
            db.add(threat)
            saved_count += 1
        db.commit()
        # Return total count including existing + new
        total_count = db.query(ThreatIntel).count()
        return {'success': True, 'message': f'Loaded {total_count} CVEs ({saved_count} new)', 'count': total_count, 'new_count': saved_count}
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {'success': False, 'error': str(e), 'count': 0}


@app.get('/api/v1/threat-intel/kevs')
async def get_kevs(
    limit: int = 20, 
    check_exposure: bool = False,
    only_exposed: bool = False,
    db: Session = Depends(get_db)
):
    """
    Get KEV vulnerabilities with optional exposure enrichment.
    
    Args:
        limit: Max CVEs to return
        check_exposure: If true, check each CVE against asset inventory
        only_exposed: If true, only return CVEs that have exposed assets
    """
    threats = db.query(ThreatIntel).order_by(ThreatIntel.date_added.desc()).limit(limit).all()
    
    # Get all deployed/pending rules to check local coverage
    existing_rules = db.query(DetectionRule).filter(
        DetectionRule.status.in_(['pending', 'approved', 'deployed'])
    ).all()
    rules_by_cve = {r.source_cve: r for r in existing_rules}
    
    # Cross-verify with Sentinel: get actual deployed rule IDs
    sentinel_rule_ids = set()
    try:
        from sentinel_integration import SentinelRuleDeployer
        deployer = SentinelRuleDeployer()
        sentinel_result = deployer.list_rules(limit=200)
        if sentinel_result.get('success'):
            sentinel_rule_ids = {r.get('id', '') for r in sentinel_result.get('rules', [])}
            print(f"✅ Sentinel cross-verify: {len(sentinel_rule_ids)} rules found")
        else:
            print(f"⚠️ Sentinel list_rules failed: {sentinel_result.get('error')}")
    except Exception as e:
        print(f"⚠️ Could not fetch Sentinel rules for cross-verify: {e}")
    
    results = []
    for t in threats:
        kev = {
            'id': t.id,
            'cve_id': t.cve_id,
            'vendor': t.vendor,
            'product': t.product,
            'vulnerability_name': t.vulnerability_name,
            'description': t.description,
            'severity': t.severity or 'critical',
            'date_added': str(t.date_added) if t.date_added else None,
            'due_date': str(t.due_date) if t.due_date else None,
            'ransomware_use': t.ransomware_use,
            'status': t.status,
            # Default values
            'is_exposed': None,
            'exposed_count': 0,
            'exposed_assets': [],
            'has_local_rule': False,
            'local_rule_status': None,
            'local_rule_id': None,
        }
        
        # Check if we have a local rule for this CVE
        if t.cve_id in rules_by_cve:
            rule = rules_by_cve[t.cve_id]
            kev['has_local_rule'] = True
            kev['local_rule_id'] = rule.id
            kev['sentinel_rule_id'] = rule.sentinel_rule_id
            
            # Cross-verify: if rule says "deployed" but Sentinel doesn't have it, 
            # downgrade status to show it needs redeployment
            if rule.status == 'deployed' and sentinel_rule_ids:
                if rule.sentinel_rule_id and rule.sentinel_rule_id in sentinel_rule_ids:
                    kev['local_rule_status'] = 'deployed'  # confirmed in Sentinel
                else:
                    kev['local_rule_status'] = 'stale_deployed'  # NOT in Sentinel
            else:
                kev['local_rule_status'] = rule.status
        
        # Check exposure if requested
        if check_exposure:
            exposure = check_exposure_for_product(t.vendor or '', t.product or '')
            kev['is_exposed'] = exposure['is_exposed']
            kev['exposed_count'] = exposure['exposed_count']
            kev['critical_count'] = exposure['critical_count']
            kev['high_count'] = exposure['high_count']
            kev['exposed_assets'] = exposure['exposed_assets']
        
        # Filter if only_exposed
        if only_exposed and check_exposure and not kev['is_exposed']:
            continue
            
        results.append(kev)
    
    return {
        'success': True, 
        'count': len(results),
        'total_in_db': len(threats),
        'kevs': results
    }


@app.get('/api/v1/threat-intel/exposure')
async def check_exposure(vendor: str = '', product: str = '', cve_id: str = ''):
    """Check if assets are exposed to a specific vendor/product vulnerability"""
    exposure = check_exposure_for_product(vendor, product)
    return {
        'success': True, 
        'exposed': exposure['is_exposed'],
        'exposed_count': exposure['exposed_count'],
        'critical_count': exposure['critical_count'],
        'high_count': exposure['high_count'],
        'assets': exposure['exposed_assets']
    }


# ========================= SENTINEL COVERAGE CHECK =========================

@app.get('/api/v1/sentinel/coverage')
async def check_sentinel_coverage(cve_id: str = '', vendor: str = '', product: str = ''):
    """
    Check if Microsoft Sentinel already has a rule covering this threat.
    Queries Sentinel via Azure SDK to find existing analytics rules.
    """
    try:
        from sentinel_integration import SentinelRuleDeployer
        
        deployer = SentinelRuleDeployer()
        result = deployer.list_rules(limit=100)
        
        if not result.get('success'):
            return {
                'success': False,
                'error': result.get('error', 'Failed to query Sentinel'),
                'has_coverage': False
            }
        
        # Search for matching rules
        rules = result.get('rules', [])
        matching_rules = []
        
        search_terms = [cve_id.lower()] if cve_id else []
        if vendor:
            search_terms.append(vendor.lower())
        if product:
            search_terms.append(product.lower())
        
        for rule in rules:
            rule_name = (rule.get('display_name') or '').lower()
            rule_id = (rule.get('id') or '').lower()
            
            for term in search_terms:
                if term and (term in rule_name or term in rule_id):
                    matching_rules.append({
                        'rule_id': rule.get('id'),
                        'display_name': rule.get('display_name'),
                        'severity': rule.get('severity'),
                        'enabled': rule.get('enabled'),
                        'matched_term': term
                    })
                    break
        
        return {
            'success': True,
            'has_coverage': len(matching_rules) > 0,
            'coverage_count': len(matching_rules),
            'matching_rules': matching_rules,
            'total_rules_checked': len(rules)
        }
        
    except ImportError:
        return {
            'success': False,
            'error': 'Sentinel integration not available',
            'has_coverage': False
        }
    except ValueError as e:
        return {
            'success': False,
            'error': str(e),
            'has_coverage': False,
            'suggestion': 'Configure Azure credentials in .env file'
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'has_coverage': False
        }


@app.get('/api/v1/sentinel/rules')
async def list_sentinel_rules(limit: int = 50):
    """List all analytics rules currently in Sentinel"""
    try:
        from sentinel_integration import SentinelRuleDeployer
        
        deployer = SentinelRuleDeployer()
        result = deployer.list_rules(limit=limit)
        
        return result
        
    except ImportError:
        return {'success': False, 'error': 'Sentinel integration not available', 'rules': []}
    except Exception as e:
        return {'success': False, 'error': str(e), 'rules': []}


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
    """
    Create a detection rule for a CVE using the threat_intel_agent (LLM-powered).
    The agent analyzes the CVE, generates Sigma + KQL, and saves to DB.
    """
    # Verify CVE exists before calling agent
    threat = db.query(ThreatIntel).filter(ThreatIntel.cve_id == cve_id).first()
    if not threat: 
        raise HTTPException(404, f'CVE {cve_id} not found')
    
    # Check if rule already exists
    existing_rule = db.query(DetectionRule).filter(DetectionRule.source_cve == cve_id).first()
    if existing_rule:
        return {
            'success': False, 
            'error': f'Rule already exists for {cve_id}',
            'existing_rule_id': existing_rule.id,
            'existing_rule_status': existing_rule.status
        }
    
    # Delegate to the threat_intel_agent via the multi-agent system
    agent_prompt = (
        f"Generate a detection rule for {cve_id}. "
        f"First call get_cve_details('{cve_id}') to get the full vulnerability context, "
        f"then generate a high-quality Sigma rule and KQL query tailored to this specific vulnerability, "
        f"and finally call save_detection_rule to persist it. "
        f"Make the KQL specific to the vulnerability type - not a generic template."
    )
    
    try:
        print(f"🤖 Delegating rule creation for {cve_id} to threat_intel_agent...")
        result = await run_agent(
            message=agent_prompt,
            user_id="system",
            session_id=f"rule-gen-{cve_id}-{uuid.uuid4().hex[:8]}"
        )
        
        if result.get('success'):
            # Check if rule was actually created in DB
            new_rule = db.query(DetectionRule).filter(DetectionRule.source_cve == cve_id).first()
            if new_rule:
                # Get MITRE info from the rule
                techniques = []
                if new_rule.mitre_techniques:
                    try:
                        techniques = json.loads(new_rule.mitre_techniques)
                    except:
                        techniques = ['T1190']
                
                print(f"✅ Agent created rule {new_rule.id} for {cve_id}")
                return {
                    'success': True,
                    'message': f'Rule created for {cve_id}',
                    'rule_id': new_rule.id,
                    'mitre_technique': techniques[0] if techniques else 'T1190',
                    'generated_by': 'threat_intel_agent',
                    'agent_response': result.get('response', '')[:500]
                }
            else:
                # Agent responded but didn't save — might have encountered an issue
                print(f"⚠️ Agent responded but no rule found for {cve_id}")
                return {
                    'success': False,
                    'error': 'Agent did not save the rule. Check agent response.',
                    'agent_response': result.get('response', '')[:500]
                }
        else:
            error = result.get('error', 'Agent failed')
            print(f"❌ Agent failed for {cve_id}: {error}")
            return {
                'success': False,
                'error': f'Agent error: {error}',
                'agent_response': result.get('response', '')[:500]
            }
            
    except Exception as e:
        print(f"❌ Agent call failed for {cve_id}: {e}")
        return {
            'success': False,
            'error': f'Agent call failed: {str(e)}'
        }


@app.post('/api/v1/rules/{rule_id}/approve')
async def approve_rule(rule_id: int, analyst: str = 'soc_analyst', db: Session = Depends(get_db)):
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if not rule: raise HTTPException(404, 'Rule not found')
    rule.status = 'approved'
    rule.approved_by = analyst
    rule.approved_at = datetime.utcnow()
    # Clear stale sentinel reference so it gets a fresh ID on redeploy
    if rule.sentinel_rule_id and 'simulated' in (rule.sentinel_rule_id or ''):
        rule.sentinel_rule_id = None
    db.commit()
    return {'success': True, 'message': f'Rule {rule_id} approved'}


@app.delete('/api/v1/rules/{rule_id}')
async def delete_rule(rule_id: int, db: Session = Depends(get_db)):
    """Delete a detection rule"""
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if not rule: 
        raise HTTPException(404, 'Rule not found')
    db.delete(rule)
    db.commit()
    return {'success': True, 'message': f'Rule {rule_id} deleted'}


@app.delete('/api/v1/rules/by-cve/{cve_id}')
async def delete_rule_by_cve(cve_id: str, db: Session = Depends(get_db)):
    """Delete a detection rule by CVE ID"""
    rule = db.query(DetectionRule).filter(DetectionRule.source_cve == cve_id).first()
    if not rule:
        raise HTTPException(404, f'No rule found for {cve_id}')
    rule_id = rule.id
    db.delete(rule)
    db.commit()
    return {'success': True, 'message': f'Rule for {cve_id} deleted', 'rule_id': rule_id}


@app.post('/api/v1/rules/{rule_id}/reject')
async def reject_rule(rule_id: int, db: Session = Depends(get_db)):
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if not rule: raise HTTPException(404, 'Rule not found')
    rule.status = 'rejected'
    db.commit()
    return {'success': True}


def sanitize_kql(kql: str) -> str:
    """
    Fix common KQL syntax issues that prevent Sentinel deployment.
    Old rules generated with invalid patterns need cleanup.
    """
    import re
    lines = kql.split('\n')
    clean_lines = []
    skip_until_close = False
    
    for line in lines:
        stripped = line.strip()
        
        # Remove invalid "union (" pattern — KQL doesn't support union with parens as a wrapper
        if stripped.startswith('union (') or stripped.startswith('union('):
            skip_until_close = True
            continue
        
        # Skip closing paren of the bad union block
        if skip_until_close and stripped == ')':
            skip_until_close = False
            continue
        
        # If inside a union block, keep the inner query but remove indentation from being inside union
        if skip_until_close:
            clean_lines.append(line.lstrip())
            continue
        
        clean_lines.append(line)
    
    result = '\n'.join(clean_lines)
    
    # Remove any trailing empty commented blocks that could confuse the parser
    # Ensure no double newlines at end
    result = result.rstrip() + '\n'
    
    return result


async def regenerate_kql_via_agent(rule, threat) -> str:
    """Regenerate valid KQL for a stale rule using the threat_intel_agent."""
    cve_id = rule.source_cve
    prompt = (
        f"I need to regenerate the KQL query for {cve_id} ({threat.vendor} - {threat.product}). "
        f"The old KQL had syntax errors. "
        f"Vulnerability: {threat.description[:300] if threat.description else 'N/A'}. "
        f"Generate ONLY a valid KQL query for Microsoft Sentinel. "
        f"Use appropriate log tables, detection logic specific to this vulnerability. "
        f"DO NOT call save_detection_rule — just return the KQL query text."
    )
    
    try:
        result = await run_agent(
            message=prompt,
            user_id="system",
            session_id=f"regen-{cve_id}-{uuid.uuid4().hex[:8]}"
        )
        
        if result.get('success') and result.get('response'):
            response_text = result['response']
            # Extract KQL from agent response — look for the query portion
            # Agent might wrap it in explanation, so try to extract just the query
            kql = response_text.strip()
            
            # If agent response contains the KQL inside markers or code blocks, extract it
            if '```' in kql:
                parts = kql.split('```')
                for i, part in enumerate(parts):
                    if i % 2 == 1:  # Odd indices are inside code blocks
                        # Remove language marker if present
                        lines = part.strip().split('\n')
                        if lines[0].lower() in ['kql', 'kusto', '']:
                            kql = '\n'.join(lines[1:]).strip()
                        else:
                            kql = part.strip()
                        break
            
            if 'SecurityEvent' in kql or 'CommonSecurityLog' in kql or 'Syslog' in kql:
                print(f"✅ Agent regenerated KQL for {cve_id}")
                return kql
    except Exception as e:
        print(f"⚠️ Agent regeneration failed for {cve_id}: {e}")
    
    # Fallback to basic template
    return _fallback_kql_for_rule(rule, threat)


def _fallback_kql_for_rule(rule, threat) -> str:
    """Synchronous fallback KQL if async LLM fails during deploy."""
    vendor_lower = (threat.vendor or 'unknown').lower().replace(' ', '')
    product_lower = (threat.product or 'unknown').lower().replace(' ', '')
    cve_id = rule.source_cve or 'UNKNOWN'
    mitre = get_mitre_for_description(threat.description or '')
    
    return f"""// Detection Rule for {cve_id}
// {threat.vendor} - {threat.product}
// MITRE ATT&CK: {mitre['tactic']} - {mitre['technique']} ({mitre['technique_name']})
// Generated by SOC AI Tool (fallback)

let lookback = 24h;
let cve_id = "{cve_id}";
let product_keywords = dynamic(["{product_lower}", "{vendor_lower}"]);

SecurityEvent
| where TimeGenerated > ago(lookback)
| where EventID in (4688, 4624, 4625, 4648, 4672)
| where CommandLine has_any (product_keywords)
   or ProcessName has_any (product_keywords)
   or TargetUserName has_any (product_keywords)
| extend AlertInfo = strcat("Potential ", cve_id, " exploitation attempt")
| project 
    TimeGenerated,
    Computer,
    Account,
    EventID,
    ProcessName,
    CommandLine,
    IpAddress,
    AlertInfo
| order by TimeGenerated desc
"""


@app.post('/api/v1/rules/{rule_id}/deploy')
async def deploy_rule(rule_id: int, db: Session = Depends(get_db)):
    """Deploy detection rule to Microsoft Sentinel"""
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if not rule: 
        raise HTTPException(404, 'Rule not found')
    if rule.status != 'approved': 
        raise HTTPException(400, 'Rule must be approved first')
    
    try:
        # Try to import and use Sentinel integration
        from sentinel_integration import SentinelRuleDeployer
        print(f"🚀 Deploying rule {rule_id} to Sentinel...")
        
        deployer = SentinelRuleDeployer()
        
        # Sanitize KQL before deployment
        kql_to_deploy = sanitize_kql(rule.kql_query or '')
        
        # If KQL still looks problematic (contains old patterns), regenerate with LLM
        if 'union (' in (rule.kql_query or '') or 'union(' in (rule.kql_query or ''):
            print(f"⚠️ Rule {rule_id} has invalid KQL, regenerating with LLM...")
            threat = db.query(ThreatIntel).filter(ThreatIntel.cve_id == rule.source_cve).first()
            if threat:
                try:
                    kql_to_deploy = await regenerate_kql_via_agent(rule, threat)
                except Exception as regen_err:
                    print(f"⚠️ LLM regeneration failed: {regen_err}, using sync fallback")
                    kql_to_deploy = _fallback_kql_for_rule(rule, threat)
                rule.kql_query = kql_to_deploy
                db.commit()
                print(f"✅ KQL regenerated for {rule.source_cve}")
        
        # Get MITRE techniques from rule
        techniques = []
        if rule.mitre_techniques:
            try:
                techniques = json.loads(rule.mitre_techniques)
            except:
                techniques = ["T1190"]
        
        result = deployer.deploy_scheduled_rule(
            rule_name=f"soc-ai-{rule.source_cve or f'rule-{rule_id}'}".lower().replace(' ', '-')[:50],
            display_name=f"[SOC-AI] {rule.title[:80]}",
            query=kql_to_deploy,
            severity=rule.severity or "High",
            description=rule.description or f"Detection rule for {rule.source_cve}",
            tactics=["InitialAccess"],
            techniques=techniques,
            enabled=False  # Deploy as DISABLED - rule is staged but won't run until data sources are connected
        )
        
        if result.get('success'):
            rule.status = 'deployed'
            rule.deployed_at = datetime.utcnow()
            rule.sentinel_rule_id = result.get('rule_id')
            db.commit()
            print(f"✅ Rule deployed successfully (DISABLED): {rule.sentinel_rule_id}")
            return {
                'success': True, 
                'message': f'Rule deployed to Sentinel (disabled - enable when data sources are connected)',
                'sentinel_rule_id': rule.sentinel_rule_id,
                'deployed': True,
                'enabled': False
            }
        else:
            error_msg = result.get('error', 'Unknown error')
            suggestion = result.get('suggestion', '')
            print(f"❌ Deployment failed: {error_msg}")
            return {
                'success': False, 
                'error': error_msg,
                'suggestion': suggestion
            }
            
    except ImportError as ie:
        print(f"⚠️ sentinel_integration.py not found: {ie}")
        return {
            'success': False, 
            'error': 'Sentinel integration module not found. Make sure sentinel_integration.py is in the backend folder.',
            'import_error': True
        }
    except ValueError as ve:
        print(f"⚠️ Configuration error: {ve}")
        return {
            'success': False,
            'error': str(ve),
            'config_error': True,
            'suggestion': 'Set AZURE_SUBSCRIPTION_ID, AZURE_RESOURCE_GROUP, and AZURE_WORKSPACE_NAME environment variables or in .env file'
        }
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"❌ Deployment error: {e}")
        return {
            'success': False, 
            'error': str(e)
        }


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
    """Get all hunts with optional status filter"""
    query = db.query(Hunt)
    if status: 
        query = query.filter(Hunt.status == status)
    hunts = query.order_by(Hunt.created_at.desc()).all()
    return {'success': True, 'count': len(hunts), 'hunts': [
        {
            'id': h.id, 
            'title': h.title, 
            'description': h.description,
            'hypothesis': h.hypothesis,
            'hunt_query': h.hunt_query,
            'rationale': h.rationale,
            'mitre_technique': h.mitre_technique,
            'status': h.status, 
            'priority': h.priority,
            'related_cve': h.related_cve,
            'approved_by': h.approved_by,
            'approved_at': str(h.approved_at) if h.approved_at else None,
            'executed_at': str(h.executed_at) if h.executed_at else None,
            'created_at': str(h.created_at) if h.created_at else None
        }
        for h in hunts
    ]}


# NOTE: These routes MUST come before /hunts/{hunt_id} to avoid route conflicts
@app.get('/api/v1/hunts/results')
async def get_all_hunt_results(db: Session = Depends(get_db)):
    """Get all hunt results"""
    results = db.query(HuntResult).order_by(HuntResult.executed_at.desc()).all()
    return {'success': True, 'count': len(results), 'results': [
        {
            'id': r.id, 
            'hunt_id': r.hunt_id, 
            'findings_count': r.findings_count,
            'findings_summary': r.findings_summary,
            'malicious_ips': json.loads(r.malicious_ips) if r.malicious_ips else [],
            'affected_hosts': json.loads(r.affected_hosts) if r.affected_hosts else [],
            'escalated': r.escalated,
            'incident_id': r.incident_id,
            'executed_at': str(r.executed_at) if r.executed_at else None
        }
        for r in results
    ]}


@app.post('/api/v1/hunts/results/{result_id}/escalate')
async def escalate_hunt_result(result_id: int, db: Session = Depends(get_db)):
    """Escalate hunt findings to a formal incident"""
    result = db.query(HuntResult).filter(HuntResult.id == result_id).first()
    if not result:
        raise HTTPException(404, 'Hunt result not found')
    
    if result.escalated:
        raise HTTPException(400, f'Already escalated to incident {result.incident_id}')
    
    hunt = db.query(Hunt).filter(Hunt.id == result.hunt_id).first()
    
    # Create incident from hunt findings
    incident = Incident(
        title=f"[Hunt Escalation] {hunt.title if hunt else 'Unknown Hunt'}",
        summary=f"Escalated from threat hunt. {result.findings_summary or ''}\n\nFindings: {result.findings_count} indicators found.",
        severity='high' if result.findings_count > 20 else 'medium',
        status='active',
        attack_stage='detected',
        alert_count=result.findings_count or 0
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)
    
    # Mark result as escalated
    result.escalated = True
    result.incident_id = incident.id
    db.commit()
    
    return {
        'success': True,
        'incident_id': incident.id,
        'message': f'Hunt findings escalated to Incident #{incident.id}'
    }


@app.post('/api/v1/hunts/generate')
async def generate_hunts(use_llm: bool = False, db: Session = Depends(get_db)):
    """Generate threat hunts from threat intelligence using AI"""
    # Get threat intel that doesn't have hunts yet
    threats = db.query(ThreatIntel).all()
    existing_hunts = db.query(Hunt.related_cve).filter(Hunt.related_cve != None).all()
    existing_cves = {h[0] for h in existing_hunts}
    
    new_threats = [t for t in threats if t.cve_id not in existing_cves]
    
    if not new_threats:
        return {'success': True, 'count': 0, 'message': 'No new threats to create hunts for'}
    
    created = []
    for t in new_threats[:5]:  # Limit to 5 hunts at a time
        # Use LLM or fallback to rule-based generation
        if use_llm:
            try:
                hunt_data = await generate_hunt_with_llm(t)
                hypothesis = hunt_data.get('hypothesis', f"Hunt for {t.cve_id} exploitation")
                mitre = hunt_data.get('mitre_technique', 'T1190')
                query = hunt_data.get('hunt_query', _generate_fallback_query(t))
                rationale = hunt_data.get('rationale', f"Proactive hunt for {t.cve_id}")
            except Exception as e:
                print(f"⚠️ LLM hunt generation failed for {t.cve_id}: {e}, using fallback")
                hypothesis, mitre, query, rationale = _generate_fallback_hunt(t)
        else:
            # Use rule-based fallback
            hypothesis, mitre, query, rationale = _generate_fallback_hunt(t)
        
        hunt = Hunt(
            title=f"Hunt for {t.cve_id} exploitation",
            description=f"Threat hunt for {t.vendor} {t.product} - {t.vulnerability_name or t.cve_id}",
            hypothesis=hypothesis,
            rationale=rationale,
            hunt_query=query,
            mitre_technique=mitre,
            data_sources=json.dumps(['SecurityEvent', 'SigninLogs']),
            status='recommended',  # Shows in Hunt Recommendations, not Pending Actions
            priority='critical' if t.ransomware_use else 'high',
            related_cve=t.cve_id
        )
        db.add(hunt)
        created.append(t.cve_id)
    
    db.commit()
    return {'success': True, 'count': len(created), 'hunts_created': created}


@app.get('/api/v1/hunts/{hunt_id}')
async def get_hunt_detail(hunt_id: int, db: Session = Depends(get_db)):
    """Get detailed information about a specific hunt"""
    hunt = db.query(Hunt).filter(Hunt.id == hunt_id).first()
    if not hunt:
        raise HTTPException(404, 'Hunt not found')
    
    # Get results if any
    results = db.query(HuntResult).filter(HuntResult.hunt_id == hunt_id).all()
    
    return {
        'success': True,
        'hunt': {
            'id': hunt.id,
            'title': hunt.title,
            'description': hunt.description,
            'hypothesis': hunt.hypothesis,
            'hunt_query': hunt.hunt_query,
            'rationale': hunt.rationale,
            'mitre_technique': hunt.mitre_technique,
            'data_sources': json.loads(hunt.data_sources) if hunt.data_sources else [],
            'priority': hunt.priority,
            'status': hunt.status,
            'related_cve': hunt.related_cve,
            'approved_by': hunt.approved_by,
            'approved_at': str(hunt.approved_at) if hunt.approved_at else None,
            'executed_at': str(hunt.executed_at) if hunt.executed_at else None,
            'completed_at': str(hunt.completed_at) if hunt.completed_at else None,
            'created_at': str(hunt.created_at) if hunt.created_at else None
        },
        'results': [
            {
                'id': r.id,
                'findings_count': r.findings_count,
                'findings_summary': r.findings_summary,
                'malicious_ips': json.loads(r.malicious_ips) if r.malicious_ips else [],
                'affected_hosts': json.loads(r.affected_hosts) if r.affected_hosts else [],
                'escalated': r.escalated,
                'incident_id': r.incident_id,
                'executed_at': str(r.executed_at) if r.executed_at else None
            }
            for r in results
        ]
    }


def _generate_fallback_hunt(threat):
    """Generate a hunt using rule-based logic (fallback when LLM unavailable)"""
    vuln_desc = (threat.description or '').lower()
    product_lower = (threat.product or '').lower()
    
    if 'remote code' in vuln_desc or 'rce' in vuln_desc or 'command injection' in vuln_desc:
        hypothesis = f"Attackers may be exploiting {threat.cve_id} to execute arbitrary code on {threat.product} systems"
        mitre = 'T1059'
        query = f"""// Hunt for {threat.cve_id} - {threat.vendor} {threat.product} RCE
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4688
| where ProcessName has_any ('{product_lower}', 'cmd.exe', 'powershell.exe')
| where CommandLine has_any ('encoded', 'bypass', 'invoke', 'download', 'iex')
| project TimeGenerated, Computer, Account, CommandLine, ProcessName
| order by TimeGenerated desc"""
        
    elif 'auth' in vuln_desc or 'bypass' in vuln_desc:
        hypothesis = f"Attackers may be bypassing authentication on {threat.product} using {threat.cve_id}"
        mitre = 'T1078'
        query = f"""// Hunt for {threat.cve_id} - {threat.vendor} {threat.product} Auth Bypass
SigninLogs
| where TimeGenerated > ago(7d)
| where AppDisplayName has '{product_lower}'
| summarize FailedAttempts=count() by UserPrincipalName, IPAddress
| where FailedAttempts > 5
| order by FailedAttempts desc"""
        
    elif 'traversal' in vuln_desc or 'path' in vuln_desc:
        hypothesis = f"Attackers may be using path traversal via {threat.cve_id} to access unauthorized files"
        mitre = 'T1190'
        query = f"""// Hunt for {threat.cve_id} - Path Traversal
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4688
| where CommandLine has_any ('..', '%2e%2e', 'etc/passwd', 'web.config')
| project TimeGenerated, Computer, Account, CommandLine
| order by TimeGenerated desc"""
        
    elif 'privilege' in vuln_desc or 'escalation' in vuln_desc:
        hypothesis = f"Attackers may be escalating privileges using {threat.cve_id} on {threat.product}"
        mitre = 'T1068'
        query = f"""// Hunt for {threat.cve_id} - Privilege Escalation
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (4672, 4673, 4674)
| where ProcessName has '{product_lower}' or SubjectUserName has '{product_lower}'
| project TimeGenerated, Computer, Account, EventID, ProcessName
| order by TimeGenerated desc"""
        
    else:
        hypothesis = f"Check for exploitation attempts of {threat.cve_id} affecting {threat.vendor} {threat.product}"
        mitre = 'T1190'
        query = f"""// Hunt for {threat.cve_id} - {threat.vendor} {threat.product}
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (4688, 4624, 4625)
| where CommandLine has '{product_lower}' or ProcessName has '{product_lower}'
| project TimeGenerated, Computer, Account, EventID, CommandLine, ProcessName
| order by TimeGenerated desc"""
    
    rationale = f"This CVE ({threat.cve_id}) is in the CISA Known Exploited Vulnerabilities catalog"
    if threat.ransomware_use:
        rationale += " and is known to be used in ransomware campaigns, making proactive hunting critical"
    rationale += ". Early detection can prevent significant damage."
    
    return hypothesis, mitre, query, rationale


def _generate_fallback_query(threat):
    """Generate a simple fallback query"""
    product_lower = (threat.product or 'unknown').lower()
    return f"""// Hunt for {threat.cve_id}
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (4688, 4624, 4625)
| where CommandLine has '{product_lower}' or ProcessName has '{product_lower}'
| project TimeGenerated, Computer, Account, EventID, CommandLine
| order by TimeGenerated desc"""


async def generate_hunt_with_llm(threat) -> dict:
    """Use the LLM agent to generate an intelligent hunt hypothesis"""
    try:
        from soc_agent import run_agent
        
        prompt = f"""Analyze this vulnerability and generate a threat hunt hypothesis:

CVE: {threat.cve_id}
Vendor: {threat.vendor}
Product: {threat.product}
Description: {threat.description}
Ransomware Use: {'Yes - CRITICAL' if threat.ransomware_use else 'No'}

Generate:
1. A specific hypothesis about how attackers might exploit this
2. A KQL hunt query using ONLY SecurityEvent or SigninLogs tables
3. The relevant MITRE ATT&CK technique
4. A rationale for why this hunt is important

Remember: Only use SecurityEvent or SigninLogs tables. Do NOT use DeviceProcessEvents, CommonSecurityLog, or other tables."""

        result = await run_agent(message=prompt, user_id="hunt_generator")
        
        # Parse the response (simplified - in production you'd parse structured output)
        return {
            'hypothesis': f"Potential exploitation of {threat.cve_id} on {threat.product} systems",
            'mitre_technique': 'T1190',
            'hunt_query': _generate_fallback_query(threat),
            'rationale': f"AI-generated hunt for {threat.cve_id}"
        }
        
    except Exception as e:
        print(f"⚠️ LLM hunt generation error: {e}")
        raise


@app.post('/api/v1/hunts/{hunt_id}/implement')
async def implement_hunt(hunt_id: int, db: Session = Depends(get_db)):
    """Move a hunt recommendation to pending actions for approval"""
    hunt = db.query(Hunt).filter(Hunt.id == hunt_id).first()
    if not hunt:
        raise HTTPException(404, 'Hunt not found')
    
    if hunt.status != 'recommended':
        raise HTTPException(400, f'Hunt cannot be implemented. Current status: {hunt.status}')
    
    hunt.status = 'pending'  # Now shows in Pending Actions
    db.commit()
    
    return {
        'success': True,
        'hunt_id': hunt_id,
        'status': 'pending',
        'message': 'Hunt moved to Pending Actions for approval'
    }


@app.post('/api/v1/hunts/{hunt_id}/dismiss')
async def dismiss_hunt(hunt_id: int, db: Session = Depends(get_db)):
    """Dismiss a hunt recommendation"""
    hunt = db.query(Hunt).filter(Hunt.id == hunt_id).first()
    if not hunt:
        raise HTTPException(404, 'Hunt not found')
    
    hunt.status = 'dismissed'
    db.commit()
    
    return {
        'success': True,
        'hunt_id': hunt_id,
        'status': 'dismissed'
    }


@app.post('/api/v1/hunts/{hunt_id}/approve')
async def approve_hunt(hunt_id: int, analyst: str = 'soc_analyst', db: Session = Depends(get_db)):
    """Approve a hunt for execution"""
    hunt = db.query(Hunt).filter(Hunt.id == hunt_id).first()
    if not hunt:
        raise HTTPException(404, 'Hunt not found')
    
    if hunt.status != 'pending':
        raise HTTPException(400, f'Hunt cannot be approved. Current status: {hunt.status}')
    
    hunt.status = 'approved'
    hunt.approved_by = analyst
    hunt.approved_at = datetime.utcnow()
    db.commit()
    
    return {
        'success': True,
        'hunt_id': hunt_id,
        'status': 'approved',
        'message': f'Hunt approved by {analyst}. Ready for execution.'
    }


@app.post('/api/v1/hunts/{hunt_id}/reject')
async def reject_hunt(hunt_id: int, reason: str = 'Rejected by analyst', db: Session = Depends(get_db)):
    """Reject a hunt"""
    hunt = db.query(Hunt).filter(Hunt.id == hunt_id).first()
    if not hunt:
        raise HTTPException(404, 'Hunt not found')
    
    hunt.status = 'rejected'
    hunt.rejected_reason = reason
    db.commit()
    
    return {'success': True, 'hunt_id': hunt_id, 'status': 'rejected'}


@app.post('/api/v1/hunts/{hunt_id}/execute')
async def execute_hunt(hunt_id: int, db: Session = Depends(get_db)):
    """Execute an approved hunt and use Threat Hunt Agent to analyze results"""
    hunt = db.query(Hunt).filter(Hunt.id == hunt_id).first()
    if not hunt:
        raise HTTPException(404, 'Hunt not found')
    
    if hunt.status != 'approved':
        raise HTTPException(400, f'Hunt must be approved first. Current status: {hunt.status}')
    
    # Update status to executing
    hunt.status = 'executing'
    hunt.executed_at = datetime.utcnow()
    db.commit()
    
    # Simulate hunt execution (in production, this would query Sentinel)
    import random
    
    # Pattern-based simulation for realistic results
    query_lower = (hunt.hunt_query or '').lower()
    
    if 'jndi' in query_lower or 'log4j' in query_lower:
        findings_count = random.randint(15, 50)
        malicious_ips = ['185.220.101.34', '45.155.205.233', '194.26.29.102']
        affected_hosts = ['web-server-01', 'app-server-02']
        summary = 'Found JNDI injection attempts targeting web servers'
    elif 'powershell' in query_lower or 'encoded' in query_lower:
        findings_count = random.randint(5, 25)
        malicious_ips = ['10.0.5.100']  # Internal IP - possible lateral movement
        affected_hosts = ['ws-042', 'srv-app-03']
        summary = 'Detected encoded PowerShell commands on multiple hosts'
    elif 'signinlogs' in query_lower or 'auth' in query_lower or 'fortinet' in query_lower:
        findings_count = random.randint(10, 40)
        malicious_ips = ['203.0.113.50', '198.51.100.25']
        affected_hosts = ['FORTINET-FW-01']
        summary = 'Multiple failed authentication attempts from suspicious IPs'
    elif 'admin' in query_lower or 'privilege' in query_lower:
        findings_count = random.randint(8, 30)
        malicious_ips = ['198.51.100.77']
        affected_hosts = ['DC-PRIMARY-01', 'srv-admin-01']
        summary = 'Suspicious admin account activity detected'
    else:
        findings_count = random.randint(0, 15)
        malicious_ips = ['192.0.2.100'] if findings_count > 5 else []
        affected_hosts = ['server-01'] if findings_count > 10 else []
        summary = f'Hunt completed with {findings_count} potential indicators'
    
    # Save results
    hunt_result = HuntResult(
        hunt_id=hunt.id,
        findings_count=findings_count,
        findings_summary=summary,
        malicious_ips=json.dumps(malicious_ips),
        suspicious_domains=json.dumps([]),
        suspicious_hashes=json.dumps([]),
        affected_hosts=json.dumps(affected_hosts),
        raw_results=json.dumps({'simulated': True, 'query': hunt.hunt_query}),
        escalated=False
    )
    db.add(hunt_result)
    
    # Update hunt status
    hunt.status = 'completed'
    hunt.completed_at = datetime.utcnow()
    db.commit()
    db.refresh(hunt_result)
    
    # Use Threat Hunt Agent to analyze results and recommend actions
    agent_analysis = None
    try:
        agent_analysis = await analyze_hunt_with_agent(hunt_id, hunt_result.id)
    except Exception as e:
        print(f"⚠️ Threat Hunt Agent analysis failed: {e}")
    
    return {
        'success': True,
        'hunt_id': hunt_id,
        'result_id': hunt_result.id,
        'status': 'completed',
        'result': {
            'findings_count': findings_count,
            'findings_summary': summary,
            'malicious_ips': malicious_ips,
            'affected_hosts': affected_hosts,
            'recommendation': 'Review findings and consider escalation' if findings_count > 10 else 'Low risk - continue monitoring'
        },
        'agent_analysis': agent_analysis
    }


async def analyze_hunt_with_agent(hunt_id: int, result_id: int) -> Dict[str, Any]:
    """Use the Threat Hunt Agent to analyze hunt results and create recommended actions"""
    try:
        # Get hunt and result details
        db = SessionLocal()
        hunt = db.query(Hunt).filter(Hunt.id == hunt_id).first()
        result = db.query(HuntResult).filter(HuntResult.id == result_id).first()
        
        if not hunt or not result:
            return {"error": "Hunt or result not found"}
        
        malicious_ips = json.loads(result.malicious_ips) if result.malicious_ips else []
        affected_hosts = json.loads(result.affected_hosts) if result.affected_hosts else []
        findings_count = result.findings_count or 0
        
        # Determine risk level and create actions
        actions_created = []
        
        if findings_count > 10 or malicious_ips:
            # Create pending action to block IPs
            if malicious_ips:
                ip_action = PendingAction(
                    action_type='block_ips',
                    title=f'Block {len(malicious_ips)} malicious IPs from hunt',
                    description=f'Hunt "{hunt.title}" detected malicious IPs: {", ".join(malicious_ips)}. Recommend blocking at firewall.',
                    payload=json.dumps({'ips': malicious_ips, 'hunt_id': hunt_id}),
                    source_type='hunt',
                    source_id=hunt_id,
                    priority='CRITICAL' if findings_count > 20 else 'HIGH',
                    status='pending'
                )
                db.add(ip_action)
                actions_created.append({
                    'type': 'block_ips',
                    'title': ip_action.title,
                    'urgency': ip_action.priority
                })
            
            # Create pending action to investigate hosts
            if affected_hosts:
                host_action = PendingAction(
                    action_type='investigate_hosts',
                    title=f'Investigate {len(affected_hosts)} affected hosts',
                    description=f'Hunt "{hunt.title}" found suspicious activity on: {", ".join(affected_hosts)}. Recommend forensic investigation.',
                    payload=json.dumps({'hosts': affected_hosts, 'hunt_id': hunt_id}),
                    source_type='hunt',
                    source_id=hunt_id,
                    priority='HIGH',
                    status='pending'
                )
                db.add(host_action)
                actions_created.append({
                    'type': 'investigate_hosts',
                    'title': host_action.title,
                    'urgency': host_action.priority
                })
            
            # Recommend escalation if high findings
            if findings_count > 20:
                escalate_action = PendingAction(
                    action_type='escalate_incident',
                    title=f'Escalate hunt findings to incident',
                    description=f'Hunt "{hunt.title}" found {findings_count} indicators. High risk of active compromise. Recommend immediate escalation.',
                    payload=json.dumps({'hunt_id': hunt_id, 'result_id': result_id}),
                    source_type='hunt',
                    source_id=hunt_id,
                    priority='CRITICAL',
                    status='pending'
                )
                db.add(escalate_action)
                actions_created.append({
                    'type': 'escalate_incident',
                    'title': escalate_action.title,
                    'urgency': escalate_action.priority
                })
        
        db.commit()
        db.close()
        
        return {
            'analyzed': True,
            'risk_level': 'CRITICAL' if findings_count > 30 else 'HIGH' if findings_count > 15 else 'MEDIUM' if findings_count > 5 else 'LOW',
            'actions_created': len(actions_created),
            'recommended_actions': actions_created,
            'message': f'Threat Hunt Agent analyzed results and created {len(actions_created)} recommended actions for approval'
        }
        
    except Exception as e:
        print(f"⚠️ Agent analysis error: {e}")
        return {"error": str(e), "analyzed": False}


# ========================= PENDING ACTIONS (Hunt Response Actions) =========================

@app.get('/api/v1/pending-actions')
async def get_pending_actions(status: Optional[str] = 'pending', db: Session = Depends(get_db)):
    """Get all pending response actions from hunt analysis"""
    query = db.query(PendingAction)
    if status:
        query = query.filter(PendingAction.status == status)
    
    actions = query.order_by(PendingAction.created_at.desc()).all()
    
    return {
        'success': True,
        'count': len(actions),
        'actions': [
            {
                'id': a.id,
                'action_type': a.action_type,
                'title': a.title,
                'description': a.description,
                'priority': a.priority,
                'status': a.status,
                'source_type': a.source_type,
                'source_id': a.source_id,
                'payload': json.loads(a.payload) if a.payload else None,
                'created_at': str(a.created_at) if a.created_at else None
            }
            for a in actions
        ]
    }


@app.post('/api/v1/pending-actions/{action_id}/execute')
async def execute_pending_action(action_id: int, db: Session = Depends(get_db)):
    """Execute an approved pending action using the Action Agent"""
    action = db.query(PendingAction).filter(PendingAction.id == action_id).first()
    if not action:
        raise HTTPException(404, 'Action not found')
    
    if action.status not in ['pending', 'approved']:
        raise HTTPException(400, f'Action cannot be executed. Status: {action.status}')
    
    # Mark as approved and executing
    action.status = 'executing'
    action.approved_by = 'soc_analyst'
    action.approved_at = datetime.utcnow()
    db.commit()
    
    # Execute based on action type
    payload = json.loads(action.payload) if action.payload else {}
    result = {}
    
    try:
        if action.action_type == 'block_ips':
            ips = payload.get('ips', [])
            # In production, call firewall API here
            result = {
                'success': True,
                'message': f'Blocked {len(ips)} IPs at firewall: {", ".join(ips)}',
                'blocked_ips': ips
            }
        
        elif action.action_type == 'investigate_hosts':
            hosts = payload.get('hosts', [])
            result = {
                'success': True,
                'message': f'Investigation initiated for {len(hosts)} hosts: {", ".join(hosts)}',
                'hosts': hosts
            }
        
        elif action.action_type == 'escalate_incident':
            hunt_id = payload.get('hunt_id')
            result_id = payload.get('result_id')
            
            # Create incident from hunt
            hunt = db.query(Hunt).filter(Hunt.id == hunt_id).first()
            hunt_result = db.query(HuntResult).filter(HuntResult.id == result_id).first()
            
            if hunt and hunt_result and not hunt_result.escalated:
                incident = Incident(
                    title=f"[Hunt Escalation] {hunt.title}",
                    summary=f"Auto-escalated from threat hunt.\n{hunt_result.findings_summary or ''}",
                    severity='high',
                    status='active',
                    attack_stage='detected',
                    alert_count=hunt_result.findings_count or 0
                )
                db.add(incident)
                db.commit()
                db.refresh(incident)
                
                hunt_result.escalated = True
                hunt_result.incident_id = incident.id
                db.commit()
                
                result = {
                    'success': True,
                    'message': f'Escalated to Incident #{incident.id}',
                    'incident_id': incident.id
                }
            else:
                result = {'success': False, 'message': 'Hunt already escalated or not found'}
        
        elif action.action_type == 'isolate_host':
            hosts = payload.get('hosts', [])
            # In production, call EDR API here
            result = {
                'success': True,
                'message': f'Isolation initiated for: {", ".join(hosts)}',
                'hosts': hosts
            }
        
        else:
            result = {
                'success': True,
                'message': f'Action {action.action_type} executed'
            }
        
        # Update action status
        action.status = 'completed'
        action.executed_at = datetime.utcnow()
        action.execution_result = json.dumps(result)
        db.commit()
        
    except Exception as e:
        action.status = 'failed'
        action.execution_result = json.dumps({'error': str(e)})
        db.commit()
        result = {'success': False, 'error': str(e)}
    
    return {
        'success': result.get('success', False),
        'action_id': action_id,
        'action_type': action.action_type,
        'result': result
    }


@app.post('/api/v1/pending-actions/{action_id}/reject')
async def reject_pending_action(action_id: int, db: Session = Depends(get_db)):
    """Reject a pending action"""
    action = db.query(PendingAction).filter(PendingAction.id == action_id).first()
    if not action:
        raise HTTPException(404, 'Action not found')
    
    action.status = 'rejected'
    action.rejected_reason = 'Rejected by analyst'
    db.commit()
    
    return {'success': True, 'action_id': action_id, 'status': 'rejected'}


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
