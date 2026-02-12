"""
Tools for the Action Agent.
Handles executing security response actions like blocking IPs, isolating hosts, etc.
"""
import json
from datetime import datetime
from typing import Dict, Any, List

from database import SessionLocal, PendingAction, Incident, Hunt, HuntResult


def execute_block_ips(action_id: int = None, ips: List[str] = None) -> Dict[str, Any]:
    """
    Block malicious IPs at the firewall.
    
    Args:
        action_id: Optional - ID of the pending action to execute
        ips: List of IP addresses to block (if not using action_id)
    
    Returns:
        Dictionary with execution result
    """
    db = SessionLocal()
    try:
        blocked_ips = []
        
        # If action_id provided, get IPs from the action payload
        if action_id:
            action = db.query(PendingAction).filter(PendingAction.id == action_id).first()
            if not action:
                return {"success": False, "error": f"Action {action_id} not found"}
            
            if action.status not in ['pending', 'approved']:
                return {"success": False, "error": f"Action not approved. Status: {action.status}"}
            
            payload = json.loads(action.payload) if action.payload else {}
            blocked_ips = payload.get('ips', [])
            
            # Update action status
            action.status = 'completed'
            action.executed_at = datetime.utcnow()
            action.execution_result = json.dumps({
                'blocked_ips': blocked_ips,
                'timestamp': str(datetime.utcnow())
            })
            db.commit()
        elif ips:
            blocked_ips = ips
        else:
            return {"success": False, "error": "No IPs provided"}
        
        # In production, this would call your firewall API:
        # - Palo Alto: pan-python or pan-os-python SDK
        # - Fortinet: fortigate-api
        # - Cisco: requests to Firepower API
        # - Azure: Network Security Group rules
        
        # Simulated firewall response
        firewall_result = {
            "firewall": "FORTINET-FW-01",
            "rule_name": f"BLOCK-HUNT-{datetime.now().strftime('%Y%m%d%H%M')}",
            "action": "deny",
            "ips_added": blocked_ips,
            "status": "active"
        }
        
        return {
            "success": True,
            "action": "block_ips",
            "blocked_count": len(blocked_ips),
            "blocked_ips": blocked_ips,
            "firewall_result": firewall_result,
            "message": f"Successfully blocked {len(blocked_ips)} IPs at firewall"
        }
        
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        db.close()


def execute_isolate_host(action_id: int = None, hostname: str = None, hostnames: List[str] = None) -> Dict[str, Any]:
    """
    Isolate a compromised host from the network via EDR.
    
    Args:
        action_id: Optional - ID of the pending action to execute
        hostname: Single hostname to isolate
        hostnames: List of hostnames to isolate
    
    Returns:
        Dictionary with execution result
    """
    db = SessionLocal()
    try:
        hosts_to_isolate = []
        
        if action_id:
            action = db.query(PendingAction).filter(PendingAction.id == action_id).first()
            if not action:
                return {"success": False, "error": f"Action {action_id} not found"}
            
            if action.status not in ['pending', 'approved']:
                return {"success": False, "error": f"Action not approved. Status: {action.status}"}
            
            payload = json.loads(action.payload) if action.payload else {}
            hosts_to_isolate = payload.get('hosts', [])
            
            action.status = 'completed'
            action.executed_at = datetime.utcnow()
            action.execution_result = json.dumps({
                'isolated_hosts': hosts_to_isolate,
                'timestamp': str(datetime.utcnow())
            })
            db.commit()
        elif hostnames:
            hosts_to_isolate = hostnames
        elif hostname:
            hosts_to_isolate = [hostname]
        else:
            return {"success": False, "error": "No hostname provided"}
        
        # In production, this would call your EDR API:
        # - CrowdStrike: falconpy SDK
        # - Microsoft Defender: Microsoft Graph API
        # - SentinelOne: SentinelOne API
        # - Carbon Black: cbapi
        
        # Simulated EDR response
        isolation_results = []
        for host in hosts_to_isolate:
            isolation_results.append({
                "hostname": host,
                "status": "isolated",
                "isolation_type": "full",
                "network_access": "blocked",
                "can_communicate_with": ["security_tools", "dns"]
            })
        
        return {
            "success": True,
            "action": "isolate_host",
            "isolated_count": len(hosts_to_isolate),
            "isolated_hosts": hosts_to_isolate,
            "edr_results": isolation_results,
            "message": f"Successfully isolated {len(hosts_to_isolate)} hosts from network"
        }
        
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        db.close()


def execute_collect_forensics(action_id: int = None, hostname: str = None) -> Dict[str, Any]:
    """
    Collect forensic evidence from a host.
    
    Args:
        action_id: Optional - ID of the pending action to execute
        hostname: Hostname to collect forensics from
    
    Returns:
        Dictionary with execution result
    """
    db = SessionLocal()
    try:
        target_host = None
        
        if action_id:
            action = db.query(PendingAction).filter(PendingAction.id == action_id).first()
            if not action:
                return {"success": False, "error": f"Action {action_id} not found"}
            
            payload = json.loads(action.payload) if action.payload else {}
            hosts = payload.get('hosts', [])
            target_host = hosts[0] if hosts else None
            
            action.status = 'completed'
            action.executed_at = datetime.utcnow()
            db.commit()
        elif hostname:
            target_host = hostname
        else:
            return {"success": False, "error": "No hostname provided"}
        
        # In production, this would:
        # - Trigger memory dump collection
        # - Collect event logs
        # - Capture running processes
        # - Collect network connections
        # - Package and store artifacts
        
        # Simulated forensic collection
        forensic_result = {
            "hostname": target_host,
            "collection_id": f"FORENSIC-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "artifacts_collected": [
                "memory_dump.raw",
                "security_events.evtx",
                "system_events.evtx",
                "running_processes.json",
                "network_connections.json",
                "scheduled_tasks.json",
                "registry_hives.zip"
            ],
            "storage_location": f"/forensics/{target_host}/{datetime.now().strftime('%Y%m%d')}",
            "status": "collected"
        }
        
        return {
            "success": True,
            "action": "collect_forensics",
            "hostname": target_host,
            "forensic_result": forensic_result,
            "message": f"Forensic evidence collected from {target_host}"
        }
        
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        db.close()


def create_incident_from_hunt(
    hunt_id: int,
    title: str = None,
    severity: str = "high"
) -> Dict[str, Any]:
    """
    Create a formal incident from hunt findings.
    
    Args:
        hunt_id: ID of the hunt to escalate
        title: Optional custom title for the incident
        severity: Incident severity (critical, high, medium, low)
    
    Returns:
        Dictionary with created incident details
    """
    db = SessionLocal()
    try:
        hunt = db.query(Hunt).filter(Hunt.id == hunt_id).first()
        if not hunt:
            return {"success": False, "error": f"Hunt {hunt_id} not found"}
        
        # Get hunt results
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
        
        # Create incident
        incident = Incident(
            title=title or f"[Hunt Escalation] {hunt.title}",
            summary=summary,
            severity=severity,
            status='active',
            attack_stage='detected',
            alert_count=result.findings_count or 0
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
            "action": "create_incident",
            "incident_id": incident.id,
            "incident_title": incident.title,
            "severity": severity,
            "hunt_id": hunt_id,
            "message": f"Created Incident #{incident.id} from hunt findings"
        }
        
    except Exception as e:
        db.rollback()
        return {"success": False, "error": str(e)}
    finally:
        db.close()


def get_action_status(action_id: int) -> Dict[str, Any]:
    """
    Get the status of a pending action.
    
    Args:
        action_id: ID of the action to check
    
    Returns:
        Dictionary with action status
    """
    db = SessionLocal()
    try:
        action = db.query(PendingAction).filter(PendingAction.id == action_id).first()
        
        if not action:
            return {"success": False, "error": f"Action {action_id} not found"}
        
        return {
            "success": True,
            "action": {
                "id": action.id,
                "action_type": action.action_type,
                "title": action.title,
                "status": action.status,
                "priority": action.priority,
                "approved_by": action.approved_by,
                "approved_at": str(action.approved_at) if action.approved_at else None,
                "executed_at": str(action.executed_at) if action.executed_at else None,
                "can_execute": action.status in ['pending', 'approved']
            }
        }
        
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        db.close()


def get_pending_actions_summary() -> Dict[str, Any]:
    """
    Get summary of all pending actions.
    
    Returns:
        Dictionary with pending actions summary
    """
    db = SessionLocal()
    try:
        pending = db.query(PendingAction).filter(PendingAction.status == 'pending').all()
        approved = db.query(PendingAction).filter(PendingAction.status == 'approved').all()
        
        # Group by type
        by_type = {}
        for action in pending + approved:
            action_type = action.action_type
            if action_type not in by_type:
                by_type[action_type] = []
            by_type[action_type].append({
                "id": action.id,
                "title": action.title,
                "priority": action.priority,
                "status": action.status
            })
        
        return {
            "success": True,
            "summary": {
                "total_pending": len(pending),
                "total_approved": len(approved),
                "by_type": by_type,
                "critical_count": len([a for a in pending if a.priority == 'CRITICAL']),
                "high_count": len([a for a in pending if a.priority == 'HIGH'])
            }
        }
        
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        db.close()


# Export all functions
__all__ = [
    'execute_block_ips',
    'execute_isolate_host',
    'execute_collect_forensics',
    'create_incident_from_hunt',
    'get_action_status',
    'get_pending_actions_summary'
]
