"""
Ingestion Router
Handles incoming alerts from various SIEM formats.
Auto-triggers triage on every alert.
"""
from fastapi import APIRouter, HTTPException, Header, Depends
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from datetime import datetime
import json

from database import get_db, Alert
from sqlalchemy.orm import Session
from vector_store import vector_store
from .normalizer import AlertNormalizer
from .auto_triage import auto_triage_manager

router = APIRouter(prefix="/api/v1/ingest", tags=["Ingestion"])

# Initialize normalizer
normalizer = AlertNormalizer()


# ============================================
# PYDANTIC MODELS
# ============================================

class GenericAlert(BaseModel):
    """Generic alert format"""
    timestamp: Optional[str] = None
    severity: str = "Medium"
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    user: Optional[str] = None
    description: str
    event_type: Optional[str] = "Unknown"


class BatchAlerts(BaseModel):
    """Batch alert ingestion"""
    siem_type: str = "generic"
    alerts: List[Dict[str, Any]]


# ============================================
# TRIAGE CALLBACK SETUP
# ============================================

async def run_triage_callback():
    """Callback function to run triage agent"""
    try:
        from soc_agent import run_agent
        result = await run_agent(
            message="Analyze all unprocessed alerts and create incidents. Group related alerts, assign severity, identify attack stages, and recommend response actions.",
            user_id="auto_triage_system"
        )
        return result
    except Exception as e:
        print(f"Triage callback error: {e}")
        return {"success": False, "error": str(e)}

# Set the callback
auto_triage_manager.set_triage_callback(run_triage_callback)


# ============================================
# HELPER FUNCTIONS
# ============================================

async def save_alert_to_db(alert_data: Dict[str, Any], db: Session) -> Dict[str, Any]:
    """Save normalized alert to database"""
    
    # Parse timestamp
    timestamp = alert_data.get("timestamp")
    if isinstance(timestamp, str):
        try:
            timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except:
            timestamp = datetime.utcnow()
    elif timestamp is None:
        timestamp = datetime.utcnow()
    
    # Create alert record
    alert = Alert(
        timestamp=timestamp,
        severity=alert_data.get("severity", "Medium"),
        source_ip=alert_data.get("source_ip", ""),
        destination_ip=alert_data.get("destination_ip", ""),
        user=alert_data.get("user", "unknown"),
        description=alert_data.get("description", ""),
        event_type=alert_data.get("event_type", "Unknown")
    )
    
    db.add(alert)
    db.commit()
    db.refresh(alert)
    
    # Prepare alert dict for indexing
    alert_dict = {
        "id": alert.id,
        "timestamp": str(alert.timestamp),
        "severity": alert.severity,
        "source_ip": alert.source_ip,
        "destination_ip": alert.destination_ip,
        "user": alert.user,
        "description": alert.description,
        "event_type": alert.event_type
    }
    
    # Index in ChromaDB
    vector_store.add_alerts([alert_dict])
    
    return alert_dict


# ============================================
# INGESTION ENDPOINTS
# ============================================

@router.post("/alert")
async def ingest_generic_alert(
    alert: GenericAlert,
    db: Session = Depends(get_db)
):
    """
    Ingest a single alert in generic format.
    Auto-triggers triage after saving.
    """
    alert_data = alert.dict()
    
    # Save to database
    saved_alert = await save_alert_to_db(alert_data, db)
    
    # Trigger auto-triage
    triage_result = await auto_triage_manager.on_alert_received(saved_alert)
    
    return {
        "success": True,
        "alert_id": saved_alert["id"],
        "severity": saved_alert["severity"],
        "auto_triage": triage_result
    }


@router.post("/alerts")
async def ingest_batch_alerts(
    data: BatchAlerts,
    db: Session = Depends(get_db)
):
    """
    Ingest multiple alerts in batch.
    Auto-triggers triage after saving all.
    """
    saved_alerts = []
    
    for alert_data in data.alerts:
        # Normalize based on SIEM type
        normalized = normalizer.normalize(data.siem_type, alert_data)
        saved_alert = await save_alert_to_db(normalized, db)
        saved_alerts.append(saved_alert)
    
    # Trigger auto-triage for the batch (only trigger once for the batch)
    if saved_alerts:
        # Get highest severity alert for triage decision
        severities = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
        highest_severity_alert = max(saved_alerts, key=lambda x: severities.get(x["severity"], 0))
        triage_result = await auto_triage_manager.on_alert_received(highest_severity_alert)
    else:
        triage_result = {"triggered": False, "reason": "no_alerts"}
    
    return {
        "success": True,
        "count": len(saved_alerts),
        "alerts": saved_alerts,
        "auto_triage": triage_result
    }


@router.post("/splunk")
async def ingest_splunk_alert(
    data: Dict[str, Any],
    db: Session = Depends(get_db)
):
    """
    Ingest alert from Splunk Enterprise Security.
    Expects Splunk webhook format.
    """
    # Normalize Splunk format
    normalized = normalizer.normalize("splunk", data)
    
    # Save to database
    saved_alert = await save_alert_to_db(normalized, db)
    
    # Trigger auto-triage
    triage_result = await auto_triage_manager.on_alert_received(saved_alert)
    
    return {
        "success": True,
        "source": "splunk",
        "alert_id": saved_alert["id"],
        "severity": saved_alert["severity"],
        "auto_triage": triage_result
    }


@router.post("/qradar")
async def ingest_qradar_offense(
    data: Dict[str, Any],
    db: Session = Depends(get_db)
):
    """
    Ingest offense from IBM QRadar.
    Expects QRadar API format.
    """
    # Normalize QRadar format
    normalized = normalizer.normalize("qradar", data)
    
    # Save to database
    saved_alert = await save_alert_to_db(normalized, db)
    
    # Trigger auto-triage
    triage_result = await auto_triage_manager.on_alert_received(saved_alert)
    
    return {
        "success": True,
        "source": "qradar",
        "alert_id": saved_alert["id"],
        "severity": saved_alert["severity"],
        "auto_triage": triage_result
    }


@router.post("/elastic")
async def ingest_elastic_alert(
    data: Dict[str, Any],
    db: Session = Depends(get_db)
):
    """
    Ingest alert from Elastic SIEM.
    Expects ECS (Elastic Common Schema) format.
    """
    # Normalize Elastic format
    normalized = normalizer.normalize("elastic", data)
    
    # Save to database
    saved_alert = await save_alert_to_db(normalized, db)
    
    # Trigger auto-triage
    triage_result = await auto_triage_manager.on_alert_received(saved_alert)
    
    return {
        "success": True,
        "source": "elastic",
        "alert_id": saved_alert["id"],
        "severity": saved_alert["severity"],
        "auto_triage": triage_result
    }


@router.post("/sentinel")
async def ingest_sentinel_incident(
    data: Dict[str, Any],
    db: Session = Depends(get_db)
):
    """
    Ingest incident from Microsoft Sentinel.
    Expects Sentinel incident format.
    """
    # Normalize Sentinel format
    normalized = normalizer.normalize("sentinel", data)
    
    # Save to database
    saved_alert = await save_alert_to_db(normalized, db)
    
    # Trigger auto-triage
    triage_result = await auto_triage_manager.on_alert_received(saved_alert)
    
    return {
        "success": True,
        "source": "sentinel",
        "alert_id": saved_alert["id"],
        "severity": saved_alert["severity"],
        "auto_triage": triage_result
    }


@router.post("/cef")
async def ingest_cef_event(
    data: Dict[str, Any],
    db: Session = Depends(get_db)
):
    """
    Ingest event in Common Event Format (CEF).
    Used by many SIEM and security tools.
    """
    # Normalize CEF format
    normalized = normalizer.normalize("cef", data)
    
    # Save to database
    saved_alert = await save_alert_to_db(normalized, db)
    
    # Trigger auto-triage
    triage_result = await auto_triage_manager.on_alert_received(saved_alert)
    
    return {
        "success": True,
        "source": "cef",
        "alert_id": saved_alert["id"],
        "severity": saved_alert["severity"],
        "auto_triage": triage_result
    }


# ============================================
# STATUS & CONTROL ENDPOINTS
# ============================================

@router.get("/status")
async def get_ingestion_status():
    """Get ingestion and auto-triage status"""
    return {
        "success": True,
        "supported_formats": ["generic", "splunk", "qradar", "elastic", "sentinel", "cef"],
        "auto_triage": auto_triage_manager.get_status()
    }


@router.get("/auto-triage/status")
async def get_auto_triage_status():
    """Get auto-triage status"""
    return auto_triage_manager.get_status()


@router.post("/auto-triage/trigger")
async def trigger_manual_triage():
    """Manually trigger triage"""
    result = await auto_triage_manager.trigger_manual()
    return {
        "success": True,
        "message": "Manual triage triggered",
        "result": result
    }


# Export router and manager
ingestion_router = router
