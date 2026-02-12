"""
Ingestion API Router
Webhook endpoints for receiving alerts from various SIEM systems.
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime

from ingestion.auth import optional_api_key, require_api_key, list_api_keys, generate_api_key, DEFAULT_API_KEY
from ingestion.normalizer import normalize_alert, normalize_alerts, NORMALIZERS
from ingestion.auto_triage import auto_triage_manager

from database import SessionLocal, Alert
from vector_store import vector_store


# Create router
router = APIRouter(prefix="/api/v1/ingest", tags=["Ingestion"])


# Wire up auto-triage callback
async def run_triage_callback() -> dict:
    """Callback function for auto-triage - runs the triage agent"""
    try:
        from soc_agent import run_agent
        result = await run_agent(
            message="Analyze all alerts and create incidents",
            user_id="auto_triage_system",
            session_id=None
        )
        return result
    except Exception as e:
        return {"success": False, "error": str(e)}

# Set the callback
auto_triage_manager.set_triage_callback(run_triage_callback)


# Request/Response Models
class SingleAlertRequest(BaseModel):
    """Request model for single alert ingestion"""
    timestamp: Optional[str] = None
    severity: Optional[str] = "Medium"
    source_ip: Optional[str] = "unknown"
    destination_ip: Optional[str] = "unknown"
    user: Optional[str] = "unknown"
    description: Optional[str] = ""
    event_type: Optional[str] = "Unknown"
    
    class Config:
        extra = "allow"


class BatchAlertRequest(BaseModel):
    """Request model for batch alert ingestion"""
    alerts: List[Dict[str, Any]]
    siem_type: Optional[str] = "generic"


class IngestionResponse(BaseModel):
    """Response model for ingestion endpoints"""
    success: bool
    message: str
    alerts_ingested: int = 0
    alert_ids: List[int] = []
    auto_triage_triggered: bool = False
    triage_result: Optional[Dict[str, Any]] = None


# Helper function to save alerts
async def save_alerts_to_db(normalized_alerts: List[Dict[str, Any]]) -> List[int]:
    """Save normalized alerts to database and vector store"""
    db = SessionLocal()
    created_ids = []
    
    try:
        for alert_data in normalized_alerts:
            timestamp_str = alert_data.get("timestamp")
            if timestamp_str:
                try:
                    timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                except:
                    timestamp = datetime.utcnow()
            else:
                timestamp = datetime.utcnow()
            
            alert = Alert(
                timestamp=timestamp,
                severity=alert_data.get("severity", "Medium"),
                source_ip=alert_data.get("source_ip", "unknown"),
                destination_ip=alert_data.get("destination_ip", "unknown"),
                user=alert_data.get("user", "unknown"),
                description=alert_data.get("description", ""),
                event_type=alert_data.get("event_type", "Unknown")
            )
            db.add(alert)
            db.flush()
            created_ids.append(alert.id)
            alert_data["id"] = alert.id
        
        db.commit()
        
        # Index in vector store
        vector_store.add_alerts(normalized_alerts)
        
        return created_ids
        
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()


# ============== ENDPOINTS ==============

@router.post("/alert", response_model=IngestionResponse)
async def ingest_single_alert(
    alert: SingleAlertRequest,
    background_tasks: BackgroundTasks,
    auth: dict = Depends(optional_api_key)
):
    """
    Ingest a single alert in generic format.
    """
    try:
        alert_dict = alert.dict()
        normalized = normalize_alert(alert_dict, "generic")
        alert_ids = await save_alerts_to_db([normalized])
        triage_result = await auto_triage_manager.on_alert_ingested(normalized)
        
        return IngestionResponse(
            success=True,
            message="Alert ingested successfully",
            alerts_ingested=1,
            alert_ids=alert_ids,
            auto_triage_triggered=triage_result is not None,
            triage_result=triage_result
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/alerts", response_model=IngestionResponse)
async def ingest_batch_alerts(
    request: BatchAlertRequest,
    background_tasks: BackgroundTasks,
    auth: dict = Depends(optional_api_key)
):
    """
    Ingest multiple alerts in batch.
    
    Supports: generic, splunk, qradar, elastic, sentinel, cef
    """
    try:
        normalized = normalize_alerts(request.alerts, request.siem_type)
        alert_ids = await save_alerts_to_db(normalized)
        triage_result = await auto_triage_manager.on_batch_ingested(normalized)
        
        return IngestionResponse(
            success=True,
            message=f"Batch of {len(alert_ids)} alerts ingested successfully",
            alerts_ingested=len(alert_ids),
            alert_ids=alert_ids,
            auto_triage_triggered=triage_result is not None,
            triage_result=triage_result
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/splunk", response_model=IngestionResponse)
async def ingest_splunk_alert(
    alert: Dict[str, Any],
    background_tasks: BackgroundTasks,
    auth: dict = Depends(optional_api_key)
):
    """Ingest alert from Splunk."""
    try:
        normalized = normalize_alert(alert, "splunk")
        alert_ids = await save_alerts_to_db([normalized])
        triage_result = await auto_triage_manager.on_alert_ingested(normalized)
        
        return IngestionResponse(
            success=True,
            message="Splunk alert ingested successfully",
            alerts_ingested=1,
            alert_ids=alert_ids,
            auto_triage_triggered=triage_result is not None,
            triage_result=triage_result
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/qradar", response_model=IngestionResponse)
async def ingest_qradar_offense(
    offense: Dict[str, Any],
    background_tasks: BackgroundTasks,
    auth: dict = Depends(optional_api_key)
):
    """Ingest offense from IBM QRadar."""
    try:
        normalized = normalize_alert(offense, "qradar")
        alert_ids = await save_alerts_to_db([normalized])
        triage_result = await auto_triage_manager.on_alert_ingested(normalized)
        
        return IngestionResponse(
            success=True,
            message="QRadar offense ingested successfully",
            alerts_ingested=1,
            alert_ids=alert_ids,
            auto_triage_triggered=triage_result is not None,
            triage_result=triage_result
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/elastic", response_model=IngestionResponse)
async def ingest_elastic_alert(
    alert: Dict[str, Any],
    background_tasks: BackgroundTasks,
    auth: dict = Depends(optional_api_key)
):
    """Ingest alert from Elastic SIEM (ECS format)."""
    try:
        normalized = normalize_alert(alert, "elastic")
        alert_ids = await save_alerts_to_db([normalized])
        triage_result = await auto_triage_manager.on_alert_ingested(normalized)
        
        return IngestionResponse(
            success=True,
            message="Elastic alert ingested successfully",
            alerts_ingested=1,
            alert_ids=alert_ids,
            auto_triage_triggered=triage_result is not None,
            triage_result=triage_result
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/sentinel", response_model=IngestionResponse)
async def ingest_sentinel_incident(
    incident: Dict[str, Any],
    background_tasks: BackgroundTasks,
    auth: dict = Depends(optional_api_key)
):
    """Ingest incident from Microsoft Sentinel."""
    try:
        normalized = normalize_alert(incident, "sentinel")
        alert_ids = await save_alerts_to_db([normalized])
        triage_result = await auto_triage_manager.on_alert_ingested(normalized)
        
        return IngestionResponse(
            success=True,
            message="Sentinel incident ingested successfully",
            alerts_ingested=1,
            alert_ids=alert_ids,
            auto_triage_triggered=triage_result is not None,
            triage_result=triage_result
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/cef", response_model=IngestionResponse)
async def ingest_cef_event(
    event: Dict[str, Any],
    background_tasks: BackgroundTasks,
    auth: dict = Depends(optional_api_key)
):
    """Ingest event in Common Event Format (CEF)."""
    try:
        normalized = normalize_alert(event, "cef")
        alert_ids = await save_alerts_to_db([normalized])
        triage_result = await auto_triage_manager.on_alert_ingested(normalized)
        
        return IngestionResponse(
            success=True,
            message="CEF event ingested successfully",
            alerts_ingested=1,
            alert_ids=alert_ids,
            auto_triage_triggered=triage_result is not None,
            triage_result=triage_result
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============== STATUS & CONFIG ENDPOINTS ==============

@router.get("/status")
async def get_ingestion_status():
    """Get status of the ingestion system"""
    return {
        "status": "active",
        "supported_formats": list(NORMALIZERS.keys()),
        "auto_triage": auto_triage_manager.get_status(),
        "endpoints": {
            "single": "/api/v1/ingest/alert",
            "batch": "/api/v1/ingest/alerts",
            "splunk": "/api/v1/ingest/splunk",
            "qradar": "/api/v1/ingest/qradar",
            "elastic": "/api/v1/ingest/elastic",
            "sentinel": "/api/v1/ingest/sentinel",
            "cef": "/api/v1/ingest/cef"
        }
    }


@router.get("/auto-triage/status")
async def get_auto_triage_status():
    """Get auto-triage system status"""
    return auto_triage_manager.get_status()


@router.post("/auto-triage/trigger")
async def trigger_manual_triage(
    auth: dict = Depends(optional_api_key)
):
    """Manually trigger triage analysis"""
    result = await auto_triage_manager.trigger_manual()
    return {
        "success": True,
        "message": "Manual triage triggered",
        "result": result
    }


@router.put("/auto-triage/config")
async def update_auto_triage_config(
    enabled: Optional[bool] = None,
    count_threshold: Optional[int] = None,
    time_interval_minutes: Optional[int] = None,
    trigger_on_critical: Optional[bool] = None,
    cooldown_seconds: Optional[int] = None,
    auth: dict = Depends(require_api_key)
):
    """Update auto-triage configuration (requires API key)"""
    auto_triage_manager.update_config(
        enabled=enabled,
        count_threshold=count_threshold,
        time_interval_minutes=time_interval_minutes,
        trigger_on_critical=trigger_on_critical,
        cooldown_seconds=cooldown_seconds
    )
    
    return {
        "success": True,
        "message": "Auto-triage configuration updated",
        "config": auto_triage_manager.get_status()["config"]
    }


# ============== API KEY MANAGEMENT ==============

@router.get("/keys", dependencies=[Depends(require_api_key)])
async def list_ingestion_keys():
    """List all API keys (requires authentication)"""
    return {"keys": list_api_keys()}


@router.post("/keys", dependencies=[Depends(require_api_key)])
async def create_ingestion_key(name: str, permissions: List[str] = ["ingest"]):
    """Create a new API key (requires authentication)"""
    new_key = generate_api_key(name, permissions)
    return {
        "success": True,
        "message": "API key created. Save this key - it won't be shown again!",
        "api_key": new_key
    }
