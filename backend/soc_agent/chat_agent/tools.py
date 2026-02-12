"""
Tools for the Chat Agent.
Handles searching and retrieving security data for answering questions.
"""
import json
from typing import Dict, Any, Optional

from database import SessionLocal, Alert, Incident, Action, ChatMessage
from vector_store import vector_store

def search_alerts(query: str, limit: int = 20) -> Dict[str, Any]:
    """
    Search for alerts using semantic search.
    
    Args:
        query: Search query (e.g., "brute force attacks", "IP 192.168.1.105")
        limit: Maximum number of results (default 20)
    
    Returns:
        Dictionary with matching alerts and relevance scores
    """
    try:
        results = vector_store.search_alerts(query, n_results=limit)
        
        return {
            "success": True,
            "query": query,
            "result_count": len(results),
            "results": results
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def get_alerts_by_severity(severity: str) -> Dict[str, Any]:
    """
    Get all alerts with a specific severity level.
    
    Args:
        severity: Severity level to filter by (Critical, High, Medium, Low)
    
    Returns:
        Dictionary with alerts matching the severity
    """
    db = SessionLocal()
    try:
        # Case-insensitive search
        alerts = db.query(Alert).filter(
            Alert.severity.ilike(severity)
        ).order_by(Alert.timestamp.desc()).all()
        
        return {
            "success": True,
            "severity": severity,
            "alert_count": len(alerts),
            "alerts": [
                {
                    "id": a.id,
                    "timestamp": str(a.timestamp),
                    "severity": a.severity,
                    "source_ip": a.source_ip,
                    "destination_ip": a.destination_ip,
                    "user": a.user,
                    "event_type": a.event_type,
                    "description": a.description
                }
                for a in alerts
            ]
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        db.close()

def search_incidents(query: str, limit: int = 10) -> Dict[str, Any]:
    """
    Search for incidents using semantic search.
    
    Args:
        query: Search query (e.g., "ransomware", "lateral movement")
        limit: Maximum number of results (default 10)
    
    Returns:
        Dictionary with matching incidents and relevance scores
    """
    try:
        results = vector_store.search_incidents(query, n_results=limit)
        
        return {
            "success": True,
            "query": query,
            "result_count": len(results),
            "results": results
        }
    except Exception as e:
        return {"success": False, "error": str(e)}



def get_incidents_by_severity(severity: str) -> Dict[str, Any]:
    """
    Get all incidents with a specific severity level.
    
    Args:
        severity: Severity level to filter by (Critical, High, Medium, Low)
    
    Returns:
        Dictionary with incidents matching the severity
    """
    db = SessionLocal()
    try:
        incidents = db.query(Incident).filter(
            Incident.severity.ilike(severity)
        ).order_by(Incident.created_at.desc()).all()
        
        return {
            "success": True,
            "severity": severity,
            "incident_count": len(incidents),
            "incidents": [
                {
                    "id": inc.id,
                    "title": inc.title,
                    "summary": inc.summary,
                    "severity": inc.severity,
                    "attack_stage": inc.attack_stage,
                    "confidence": inc.confidence,
                    "alert_count": inc.alert_count,
                    "status": inc.status
                }
                for inc in incidents
            ]
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        db.close()


def get_all_incidents() -> Dict[str, Any]:
    """
    Get all incidents from the database.
    
    Returns:
        Dictionary with all incidents
    """
    db = SessionLocal()
    try:
        incidents = db.query(Incident).order_by(Incident.created_at.desc()).all()
        
        return {
            "success": True,
            "incident_count": len(incidents),
            "incidents": [
                {
                    "id": inc.id,
                    "title": inc.title,
                    "summary": inc.summary,
                    "severity": inc.severity,
                    "attack_stage": inc.attack_stage,
                    "confidence": inc.confidence,
                    "alert_count": inc.alert_count,
                    "status": inc.status
                }
                for inc in incidents
            ]
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        db.close()

def get_database_stats() -> Dict[str, Any]:
    """
    Get statistics about alerts, incidents, and actions in the database.
    Use this for questions about counts or totals.
    
    Returns:
        Dictionary with database statistics
    """
    db = SessionLocal()
    try:
        total_alerts = db.query(Alert).count()
        total_incidents = db.query(Incident).count()
        active_incidents = db.query(Incident).filter(Incident.status == "active").count()
        total_actions = db.query(Action).count()
        executed_actions = db.query(Action).filter(Action.executed == True).count()
        
        from sqlalchemy import func
        severity_counts = dict(
            db.query(Alert.severity, func.count(Alert.id))
            .group_by(Alert.severity)
            .all()
        )
        
        return {
            "success": True,
            "stats": {
                "total_alerts": total_alerts,
                "total_incidents": total_incidents,
                "active_incidents": active_incidents,
                "total_actions": total_actions,
                "executed_actions": executed_actions,
                "severity_breakdown": severity_counts
            }
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        db.close()


def get_alert_details(alert_id: int) -> Dict[str, Any]:
    """
    Get detailed information about a specific alert.
    
    Args:
        alert_id: The ID of the alert to retrieve
    
    Returns:
        Dictionary with alert details
    """
    db = SessionLocal()
    try:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        
        if not alert:
            return {"success": False, "error": f"Alert {alert_id} not found"}
        
        return {
            "success": True,
            "alert": {
                "id": alert.id,
                "timestamp": str(alert.timestamp),
                "severity": alert.severity,
                "source_ip": alert.source_ip,
                "destination_ip": alert.destination_ip,
                "user": alert.user,
                "description": alert.description,
                "event_type": alert.event_type
            }
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        db.close()


def get_incident_details(incident_id: int) -> Dict[str, Any]:
    """
    Get detailed information about a specific incident including its alerts.
    
    Args:
        incident_id: The ID of the incident to retrieve
    
    Returns:
        Dictionary with incident details and associated alerts
    """
    db = SessionLocal()
    try:
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        
        if not incident:
            return {"success": False, "error": f"Incident {incident_id} not found"}
        
        alert_ids = json.loads(incident.alert_ids) if incident.alert_ids else []
        alerts = db.query(Alert).filter(Alert.id.in_(alert_ids)).all()
        actions = db.query(Action).filter(Action.incident_id == incident_id).all()
        
        return {
            "success": True,
            "incident": {
                "id": incident.id,
                "title": incident.title,
                "summary": incident.summary,
                "severity": incident.severity,
                "status": incident.status,
                "confidence": incident.confidence,
                "attack_stage": incident.attack_stage,
                "assigned_to": incident.assigned_to,
                "created_at": str(incident.created_at),
                "alerts": [
                    {
                        "id": a.id,
                        "severity": a.severity,
                        "source_ip": a.source_ip,
                        "event_type": a.event_type,
                        "description": a.description
                    }
                    for a in alerts
                ],
                "actions": [
                    {
                        "id": a.id,
                        "title": a.title,
                        "urgency": a.urgency,
                        "executed": a.executed
                    }
                    for a in actions
                ]
            }
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        db.close()


def get_alerts_by_ip(ip_address: str) -> Dict[str, Any]:
    """
    Get all alerts related to a specific IP address (source or destination).
    
    Args:
        ip_address: IP address to search for
    
    Returns:
        Dictionary with alerts involving this IP
    """
    db = SessionLocal()
    try:
        alerts = db.query(Alert).filter(
            (Alert.source_ip.contains(ip_address)) | 
            (Alert.destination_ip.contains(ip_address))
        ).all()
        
        return {
            "success": True,
            "ip_address": ip_address,
            "alert_count": len(alerts),
            "alerts": [
                {
                    "id": a.id,
                    "timestamp": str(a.timestamp),
                    "severity": a.severity,
                    "source_ip": a.source_ip,
                    "destination_ip": a.destination_ip,
                    "event_type": a.event_type,
                    "description": a.description
                }
                for a in alerts
            ]
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        db.close()


def get_alerts_by_user(username: str) -> Dict[str, Any]:
    """
    Get all alerts related to a specific user.
    
    Args:
        username: Username to search for
    
    Returns:
        Dictionary with alerts involving this user
    """
    db = SessionLocal()
    try:
        alerts = db.query(Alert).filter(Alert.user.contains(username)).all()
        
        return {
            "success": True,
            "username": username,
            "alert_count": len(alerts),
            "alerts": [
                {
                    "id": a.id,
                    "timestamp": str(a.timestamp),
                    "severity": a.severity,
                    "source_ip": a.source_ip,
                    "event_type": a.event_type,
                    "description": a.description
                }
                for a in alerts
            ]
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        db.close()
