"""
Tools for the Triage Agent.
Handles alert retrieval, incident creation, and time estimates.
These are plain Python functions that ADK will use as tools.
"""
import json
from datetime import datetime
from typing import Dict, List, Any

import sys
sys.path.insert(0, '..')

from database import SessionLocal, Alert, Incident, Action, AITimeEstimate
from vector_store import vector_store



def get_all_alerts(limit: int = 100) -> Dict[str, Any]:
    """
    Retrieve all security alerts from the database for analysis.
    
    Args:
        limit: Maximum number of alerts to retrieve (default 100)
    
    Returns:
        Dictionary with alerts list and count
    """
    db = SessionLocal()
    try:
        alerts = db.query(Alert).order_by(Alert.timestamp.desc()).limit(limit).all()
        
        alerts_data = [
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
        
        return {
            "success": True,
            "total_alerts": len(alerts_data),
            "alerts": alerts_data
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        db.close()


def create_incident(
    title: str,
    summary: str,
    severity: str,
    alert_ids: List[int],
    confidence: float,
    attack_stage: str,
    recommended_actions: List[str]
) -> Dict[str, Any]:
    """
    Create a new security incident from correlated alerts.
    
    Args:
        title: Brief descriptive title for the incident
        summary: 2-3 sentence summary of what happened
        severity: Severity level (Critical, High, Medium, Low)
        alert_ids: List of alert IDs that belong to this incident
        confidence: Confidence score between 0 and 1
        attack_stage: MITRE ATT&CK stage (e.g., Initial Access, Lateral Movement)
        recommended_actions: List of recommended response actions
    
    Returns:
        Dictionary with created incident details
    """
    db = SessionLocal()
    try:
        incident = Incident(
            title=title,
            summary=summary,
            severity=severity,
            alert_count=len(alert_ids),
            alert_ids=json.dumps(alert_ids),
            confidence=confidence,
            attack_stage=attack_stage,
            status="active"
        )
        db.add(incident)
        db.flush()
        
        created_actions = []
        for action_text in recommended_actions:
            action = Action(
                incident_id=incident.id,
                action_type="AI Recommended",
                title=action_text,
                description=f"AI-recommended action for incident: {title}",
                urgency="Immediate" if severity == "Critical" else "Soon"
            )
            db.add(action)
            created_actions.append(action_text)
        
        db.commit()
        
        return {
            "success": True,
            "incident": {
                "id": incident.id,
                "title": incident.title,
                "severity": incident.severity,
                "alert_count": incident.alert_count,
                "alert_ids": alert_ids,
                "confidence": confidence,
                "attack_stage": attack_stage,
                "recommended_actions": created_actions
            }
        }
    except Exception as e:
        db.rollback()
        return {"success": False, "error": str(e)}
    finally:
        db.close()

        


def save_time_estimate(
    total_alerts: int,
    total_incidents: int,
    manual_review_minutes: int,
    ai_assisted_minutes: int,
    explanation: str
) -> Dict[str, Any]:
    """
    Save the AI's estimate of time saved by automated analysis.
    
    Args:
        total_alerts: Number of alerts analyzed
        total_incidents: Number of incidents created
        manual_review_minutes: Estimated time for manual review
        ai_assisted_minutes: Estimated time with AI assistance
        explanation: Explanation of how time was calculated
    
    Returns:
        Dictionary with saved estimate details
    """
    db = SessionLocal()
    try:
        time_saved = manual_review_minutes - ai_assisted_minutes
        
        estimate = AITimeEstimate(
            total_alerts=total_alerts,
            total_incidents=total_incidents,
            manual_review_minutes=manual_review_minutes,
            ai_assisted_minutes=ai_assisted_minutes,
            time_saved_minutes=time_saved,
            explanation=explanation
        )
        db.add(estimate)
        db.commit()
        
        return {
            "success": True,
            "time_analysis": {
                "total_alerts": total_alerts,
                "total_incidents": total_incidents,
                "manual_review_minutes": manual_review_minutes,
                "ai_assisted_minutes": ai_assisted_minutes,
                "time_saved_minutes": time_saved,
                "explanation": explanation
            }
        }
    except Exception as e:
        db.rollback()
        return {"success": False, "error": str(e)}
    finally:
        db.close()


def clear_previous_analysis() -> Dict[str, Any]:
    """
    Clear previous incidents and actions before running new analysis.
    This ensures fresh analysis results.
    
    Returns:
        Dictionary confirming cleanup
    """
    db = SessionLocal()
    try:
        db.query(Action).delete()
        db.query(Incident).delete()
        db.query(AITimeEstimate).delete()
        db.commit()
        
        return {
            "success": True,
            "message": "Previous analysis cleared"
        }
    except Exception as e:
        db.rollback()
        return {"success": False, "error": str(e)}
    finally:
        db.close()


def index_incidents_in_vectorstore(incident_ids: str) -> Dict[str, Any]:
    """
    Index all incidents in ChromaDB for semantic search.
    Call this after creating incidents.
    
    Args:
        incident_ids: Comma-separated incident IDs to index (e.g., "1,2,3") or "all" for all incidents
    
    Returns:
        Dictionary with indexing result
    """
    try:
        db = SessionLocal()
        
        if incident_ids.lower() == "all":
            incidents = db.query(Incident).all()
        else:
            ids = [int(id.strip()) for id in incident_ids.split(",")]
            incidents = db.query(Incident).filter(Incident.id.in_(ids)).all()
        
        incidents_data = [
            {
                "id": inc.id,
                "title": inc.title,
                "summary": inc.summary,
                "severity": inc.severity,
                "attack_stage": inc.attack_stage
            }
            for inc in incidents
        ]
        
        db.close()
        
        count = vector_store.add_incidents(incidents_data)
        return {
            "success": True,
            "indexed_count": count
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


