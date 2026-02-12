"""
SIEM Simulator API Router
Endpoints for controlling the SIEM simulator.
"""
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import asyncio

from siem_simulator import (
    simulator,
    generate_demo_data,
    list_scenarios,
    FORMAT_GENERATORS
)


# Create router
router = APIRouter(prefix="/api/v1/simulator", tags=["SIEM Simulator"])


# Request/Response Models
class SimulatorConfig(BaseModel):
    """Configuration for continuous simulation"""
    interval_seconds: int = 30
    alerts_per_interval: int = 1
    siem_format: str = "generic"


class ScenarioRequest(BaseModel):
    """Request to generate a specific scenario"""
    scenario_name: Optional[str] = None  # None = random
    siem_format: str = "generic"
    send_to_ingestion: bool = True


class DemoDataRequest(BaseModel):
    """Request to generate demo data"""
    num_scenarios: int = 5
    siem_format: str = "generic"
    send_to_ingestion: bool = True


# Store for background task
_simulation_task: Optional[asyncio.Task] = None


# ============== ENDPOINTS ==============

@router.get("/status")
async def get_simulator_status():
    """Get current status of the SIEM simulator"""
    return {
        "running": simulator.running,
        "target_url": simulator.target_url,
        "available_scenarios": list_scenarios(),
        "available_formats": list(FORMAT_GENERATORS.keys())
    }


@router.get("/scenarios")
async def get_available_scenarios():
    """List all available attack scenarios"""
    return {
        "scenarios": list_scenarios()
    }


@router.get("/formats")
async def get_available_formats():
    """List all available SIEM output formats"""
    return {
        "formats": list(FORMAT_GENERATORS.keys()),
        "descriptions": {
            "generic": "Standard SOC AI Tool format",
            "splunk": "Splunk Enterprise Security alert format",
            "qradar": "IBM QRadar offense format",
            "elastic": "Elastic SIEM (ECS) format",
            "sentinel": "Microsoft Sentinel incident format",
            "cef": "Common Event Format (CEF)"
        }
    }


@router.post("/generate/scenario")
async def generate_scenario(
    request: ScenarioRequest,
    background_tasks: BackgroundTasks
):
    """
    Generate alerts for a specific attack scenario.
    
    If scenario_name is not provided, a random scenario is selected.
    """
    try:
        alerts = simulator.generate_scenario_alerts(
            scenario_name=request.scenario_name,
            siem_format=request.siem_format
        )
        
        result = {
            "success": True,
            "scenario": request.scenario_name or "random",
            "format": request.siem_format,
            "alerts_generated": len(alerts),
            "alerts": alerts
        }
        
        # Send to ingestion if requested
        if request.send_to_ingestion:
            send_result = await simulator.send_batch(alerts)
            result["ingestion_result"] = send_result
        
        return result
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/generate/random")
async def generate_random_alerts(
    count: int = 5,
    siem_format: str = "generic",
    send_to_ingestion: bool = True
):
    """Generate random individual alerts"""
    try:
        alerts = [
            simulator.generate_random_alert(siem_format)
            for _ in range(count)
        ]
        
        result = {
            "success": True,
            "format": siem_format,
            "alerts_generated": len(alerts),
            "alerts": alerts
        }
        
        if send_to_ingestion:
            send_result = await simulator.send_batch(alerts)
            result["ingestion_result"] = send_result
        
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/generate/demo")
async def generate_demo_alerts(request: DemoDataRequest):
    """
    Generate comprehensive demo data with multiple attack scenarios.
    
    Useful for demonstrations and testing.
    """
    try:
        alerts = generate_demo_data(
            num_scenarios=request.num_scenarios,
            siem_format=request.siem_format
        )
        
        result = {
            "success": True,
            "num_scenarios": request.num_scenarios,
            "format": request.siem_format,
            "alerts_generated": len(alerts),
            "alerts": alerts
        }
        
        if request.send_to_ingestion:
            send_result = await simulator.send_batch(alerts)
            result["ingestion_result"] = send_result
        
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/start")
async def start_continuous_simulation(
    config: SimulatorConfig,
    background_tasks: BackgroundTasks
):
    """
    Start continuous alert generation in the background.
    
    Alerts will be generated and sent to the ingestion API at regular intervals.
    """
    global _simulation_task
    
    if simulator.running:
        raise HTTPException(status_code=400, detail="Simulation already running")
    
    # Start simulation in background
    _simulation_task = asyncio.create_task(
        simulator.run_continuous(
            interval_seconds=config.interval_seconds,
            alerts_per_interval=config.alerts_per_interval,
            siem_format=config.siem_format
        )
    )
    
    return {
        "success": True,
        "message": "Continuous simulation started",
        "config": config.dict()
    }


@router.post("/stop")
async def stop_continuous_simulation():
    """Stop continuous alert generation"""
    global _simulation_task
    
    if not simulator.running:
        raise HTTPException(status_code=400, detail="Simulation not running")
    
    simulator.stop()
    
    if _simulation_task:
        _simulation_task.cancel()
        try:
            await _simulation_task
        except asyncio.CancelledError:
            pass
        _simulation_task = None
    
    return {
        "success": True,
        "message": "Continuous simulation stopped"
    }


@router.put("/config")
async def update_simulator_config(
    target_url: Optional[str] = None,
    api_key: Optional[str] = None
):
    """Update simulator configuration"""
    if target_url:
        simulator.target_url = target_url.rstrip("/")
    if api_key:
        simulator.api_key = api_key
    
    return {
        "success": True,
        "config": {
            "target_url": simulator.target_url,
            "api_key_set": bool(simulator.api_key)
        }
    }
