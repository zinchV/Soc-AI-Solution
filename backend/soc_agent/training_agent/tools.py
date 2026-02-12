"""
Tools for the Training Agent.
Handles generating training content, MITRE mappings, and quiz questions.
"""
import json
from typing import Dict, Any, List

from database import SessionLocal, Incident, Alert, Action


def get_incident_for_training(incident_id: int) -> Dict[str, Any]:
    """
    Get detailed incident information for generating training content.
    
    Args:
        incident_id: The ID of the incident
    
    Returns:
        Dictionary with incident details, alerts, and actions
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
                "attack_stage": incident.attack_stage,
                "confidence": incident.confidence
            },
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
            ],
            "actions": [
                {"title": a.title, "urgency": a.urgency}
                for a in actions
            ]
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        db.close()


def get_all_incidents_for_training() -> Dict[str, Any]:
    """
    Get all incidents that need training content generated.
    
    Returns:
        Dictionary with list of incidents
    """
    db = SessionLocal()
    try:
        incidents = db.query(Incident).all()
        
        incidents_data = []
        for inc in incidents:
            alert_ids = json.loads(inc.alert_ids) if inc.alert_ids else []
            alerts = db.query(Alert).filter(Alert.id.in_(alert_ids)).all()
            actions = db.query(Action).filter(Action.incident_id == inc.id).all()
            
            incidents_data.append({
                "id": inc.id,
                "title": inc.title,
                "summary": inc.summary,
                "severity": inc.severity,
                "attack_stage": inc.attack_stage,
                "confidence": inc.confidence,
                "alerts": [
                    {
                        "id": a.id,
                        "severity": a.severity,
                        "source_ip": a.source_ip,
                        "destination_ip": a.destination_ip,
                        "user": a.user,
                        "event_type": a.event_type,
                        "description": a.description
                    }
                    for a in alerts
                ],
                "actions": [a.title for a in actions]
            })
        
        return {
            "success": True,
            "incident_count": len(incidents_data),
            "incidents": incidents_data
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        db.close()


def save_training_content(
    incident_id: int,
    correlation_reasoning: str,
    severity_reasoning: str,
    mitre_mappings: List[Dict[str, str]],
    recommended_actions_reasoning: str,
    learning_points: List[str],
    quiz_question: str,
    quiz_options: List[str],
    quiz_answer: int
) -> Dict[str, Any]:
    """
    Save generated training content for an incident.
    
    Args:
        incident_id: The ID of the incident
        correlation_reasoning: Explanation of why alerts were grouped together
        severity_reasoning: Explanation of why this severity was chosen
        mitre_mappings: List of MITRE ATT&CK technique mappings
        recommended_actions_reasoning: Explanation of why actions are important
        learning_points: Key takeaways for junior analysts
        quiz_question: Question to test understanding
        quiz_options: Multiple choice options (4 options)
        quiz_answer: Index of correct answer (0-3)
    
    Returns:
        Dictionary confirming training content saved
    """
    db = SessionLocal()
    try:
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        
        if not incident:
            return {"success": False, "error": f"Incident {incident_id} not found"}
        
        training_data = {
            "correlation_reasoning": correlation_reasoning,
            "severity_reasoning": severity_reasoning,
            "mitre_mapping": mitre_mappings,
            "recommended_actions_reasoning": recommended_actions_reasoning,
            "learning_points": learning_points,
            "quiz_question": quiz_question,
            "quiz_options": quiz_options,
            "quiz_answer": quiz_answer
        }
        
        incident.training_explanation = json.dumps(training_data)
        db.commit()
        
        return {
            "success": True,
            "incident_id": incident_id,
            "training_saved": True
        }
    except Exception as e:
        db.rollback()
        return {"success": False, "error": str(e)}
    finally:
        db.close()
