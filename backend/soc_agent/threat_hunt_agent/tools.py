"""
Tools for the Threat Hunt Agent.
Handles analyzing hunt results and creating response actions.
"""
import json
from datetime import datetime
from typing import Dict, Any, List, Optional

from database import SessionLocal, Hunt, HuntResult, Incident, PendingAction


def get_hunt_details(hunt_id: int) -> Dict[str, Any]:
    """
    Get full details of a hunt including its context and query.
    
    Args:
        hunt_id: The ID of the hunt
    
    Returns:
        Dictionary with hunt details
    """
    db = SessionLocal()
    try:
        hunt = db.query(Hunt).filter(Hunt.id == hunt_id).first()
        
        if not hunt:
            return {"success": False, "error": f"Hunt {hunt_id} not found"}
        
        return {
            "success": True,
            "hunt": {
                "id": hunt.id,
                "title": hunt.title,
                "hypothesis": hunt.hypothesis,
                "rationale": hunt.rationale,
                "hunt_query": hunt.hunt_query,
                "mitre_technique": hunt.mitre_technique,
                "related_cve": hunt.related_cve,
                "priority": hunt.priority,
                "status": hunt.status,
                "data_sources": json.loads(hunt.data_sources) if hunt.data_sources else [],
                "created_at": str(hunt.created_at) if hunt.created_at else None,
                "executed_at": str(hunt.executed_at) if hunt.executed_at else None
            }
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        db.close()


def analyze_hunt_results(hunt_id: int) -> Dict[str, Any]:
    """
    Analyze the results of an executed hunt and provide threat assessment.
    
    Args:
        hunt_id: ID of the hunt to analyze
    
    Returns:
        Dictionary with analysis including IOCs, affected assets, and risk level
    """
    db = SessionLocal()
    try:
        hunt = db.query(Hunt).filter(Hunt.id == hunt_id).first()
        if not hunt:
            return {"success": False, "error": f"Hunt {hunt_id} not found"}
        
        # Get the latest result for this hunt
        result = db.query(HuntResult).filter(
            HuntResult.hunt_id == hunt_id
        ).order_by(HuntResult.executed_at.desc()).first()
        
        if not result:
            return {
                "success": False,
                "error": f"No results found for hunt {hunt_id}",
                "hint": "Hunt may not have been executed yet"
            }
        
        # Parse IOCs
        malicious_ips = json.loads(result.malicious_ips) if result.malicious_ips else []
        suspicious_domains = json.loads(result.suspicious_domains) if result.suspicious_domains else []
        suspicious_hashes = json.loads(result.suspicious_hashes) if result.suspicious_hashes else []
        affected_hosts = json.loads(result.affected_hosts) if result.affected_hosts else []
        
        # Calculate risk level
        findings_count = result.findings_count or 0
        
        if findings_count == 0:
            risk_level = "NONE"
            risk_summary = "No suspicious activity detected"
        elif findings_count < 5 and len(malicious_ips) == 0:
            risk_level = "LOW"
            risk_summary = "Minor anomalies detected, likely false positives"
        elif findings_count < 15 or len(malicious_ips) < 3:
            risk_level = "MEDIUM"
            risk_summary = "Suspicious activity detected, investigation recommended"
        elif findings_count < 50 or len(affected_hosts) < 5:
            risk_level = "HIGH"
            risk_summary = "Likely compromise detected, immediate response needed"
        else:
            risk_level = "CRITICAL"
            risk_summary = "Active threat detected, containment required immediately"
        
        # Generate recommended actions based on findings
        recommended_actions = []
        
        if malicious_ips:
            recommended_actions.append({
                "action": f"Block {len(malicious_ips)} malicious IPs at firewall",
                "urgency": "CRITICAL" if risk_level in ["HIGH", "CRITICAL"] else "HIGH",
                "ips": malicious_ips
            })
        
        if affected_hosts:
            recommended_actions.append({
                "action": f"Investigate {len(affected_hosts)} affected hosts",
                "urgency": "HIGH",
                "hosts": affected_hosts
            })
            
            if risk_level in ["HIGH", "CRITICAL"]:
                recommended_actions.append({
                    "action": f"Isolate affected hosts from network",
                    "urgency": "CRITICAL",
                    "hosts": affected_hosts
                })
        
        if suspicious_domains:
            recommended_actions.append({
                "action": f"Block {len(suspicious_domains)} suspicious domains",
                "urgency": "HIGH",
                "domains": suspicious_domains
            })
        
        if risk_level in ["HIGH", "CRITICAL"]:
            recommended_actions.append({
                "action": "Escalate to security incident",
                "urgency": "CRITICAL"
            })
            recommended_actions.append({
                "action": "Collect forensic evidence from affected hosts",
                "urgency": "HIGH"
            })
        
        return {
            "success": True,
            "hunt_id": hunt_id,
            "hunt_title": hunt.title,
            "related_cve": hunt.related_cve,
            "analysis": {
                "risk_level": risk_level,
                "risk_summary": risk_summary,
                "findings_count": findings_count,
                "findings_summary": result.findings_summary
            },
            "iocs": {
                "malicious_ips": malicious_ips,
                "suspicious_domains": suspicious_domains,
                "suspicious_hashes": suspicious_hashes
            },
            "affected_assets": {
                "hosts": affected_hosts,
                "host_count": len(affected_hosts)
            },
            "recommended_actions": recommended_actions,
            "already_escalated": result.escalated,
            "incident_id": result.incident_id if result.escalated else None
        }
        
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        db.close()


def create_hunt_action(
    hunt_id: int,
    action_type: str,
    title: str,
    description: str,
    urgency: str = "HIGH",
    payload: Dict = None
) -> Dict[str, Any]:
    """
    Create a pending action based on hunt findings for human approval.
    
    Args:
        hunt_id: The hunt that triggered this action
        action_type: Type of action (block_ips, isolate_host, investigate, collect_forensics)
        title: Brief action title
        description: Detailed description of what to do
        urgency: CRITICAL, HIGH, MEDIUM, LOW
        payload: Additional data (IPs to block, hosts to isolate, etc.)
    
    Returns:
        Dictionary with created action details
    """
    db = SessionLocal()
    try:
        # Validate hunt exists
        hunt = db.query(Hunt).filter(Hunt.id == hunt_id).first()
        if not hunt:
            return {"success": False, "error": f"Hunt {hunt_id} not found"}
        
        # Create pending action
        action = PendingAction(
            action_type=action_type,
            title=title,
            description=description,
            payload=json.dumps(payload) if payload else None,
            source_type='hunt',
            source_id=hunt_id,
            priority=urgency,
            status='pending'
        )
        
        db.add(action)
        db.commit()
        db.refresh(action)
        
        return {
            "success": True,
            "action_id": action.id,
            "action_type": action_type,
            "title": title,
            "urgency": urgency,
            "status": "pending",
            "message": "Action created and awaiting human approval"
        }
        
    except Exception as e:
        db.rollback()
        return {"success": False, "error": str(e)}
    finally:
        db.close()


def escalate_to_incident(
    hunt_id: int,
    title: str,
    severity: str = "high",
    summary: str = None,
    attack_stage: str = "detected"
) -> Dict[str, Any]:
    """
    Escalate hunt findings to a formal security incident.
    
    Args:
        hunt_id: ID of the hunt with findings
        title: Incident title
        severity: critical, high, medium, low
        summary: Incident summary (auto-generated if not provided)
        attack_stage: Stage of attack (initial_access, execution, persistence, etc.)
    
    Returns:
        Dictionary with created incident details
    """
    db = SessionLocal()
    try:
        hunt = db.query(Hunt).filter(Hunt.id == hunt_id).first()
        if not hunt:
            return {"success": False, "error": f"Hunt {hunt_id} not found"}
        
        # Get hunt results
        result = db.query(HuntResult).filter(HuntResult.hunt_id == hunt_id).first()
        if not result:
            return {"success": False, "error": "No hunt results to escalate"}
        
        if result.escalated:
            return {
                "success": False,
                "error": f"Hunt already escalated to Incident #{result.incident_id}"
            }
        
        # Parse findings for incident summary
        malicious_ips = json.loads(result.malicious_ips) if result.malicious_ips else []
        affected_hosts = json.loads(result.affected_hosts) if result.affected_hosts else []
        
        # Auto-generate summary if not provided
        if not summary:
            summary = f"Escalated from threat hunt: {hunt.title}\n\n"
            summary += f"Findings: {result.findings_count or 0} indicators detected.\n"
            summary += f"{result.findings_summary or ''}\n\n"
            if malicious_ips:
                summary += f"Malicious IPs: {', '.join(malicious_ips[:5])}\n"
            if affected_hosts:
                summary += f"Affected Hosts: {', '.join(affected_hosts[:5])}\n"
            if hunt.related_cve:
                summary += f"\nRelated CVE: {hunt.related_cve}"
        
        # Create incident
        incident = Incident(
            title=title,
            summary=summary,
            severity=severity,
            status='active',
            attack_stage=attack_stage,
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
            "incident_id": incident.id,
            "incident_title": title,
            "severity": severity,
            "status": "active",
            "message": f"Hunt findings escalated to Incident #{incident.id}",
            "hunt_id": hunt_id
        }
        
    except Exception as e:
        db.rollback()
        return {"success": False, "error": str(e)}
    finally:
        db.close()


def get_hunt_statistics() -> Dict[str, Any]:
    """
    Get overall threat hunt statistics.
    
    Returns:
        Dictionary with hunt statistics
    """
    db = SessionLocal()
    try:
        total_hunts = db.query(Hunt).count()
        pending_hunts = db.query(Hunt).filter(Hunt.status == 'pending').count()
        completed_hunts = db.query(Hunt).filter(Hunt.status == 'completed').count()
        
        total_results = db.query(HuntResult).count()
        escalated_results = db.query(HuntResult).filter(HuntResult.escalated == True).count()
        
        # Get total findings
        results = db.query(HuntResult).all()
        total_findings = sum(r.findings_count or 0 for r in results)
        total_malicious_ips = sum(
            len(json.loads(r.malicious_ips)) if r.malicious_ips else 0 
            for r in results
        )
        
        return {
            "success": True,
            "statistics": {
                "total_hunts": total_hunts,
                "pending_hunts": pending_hunts,
                "completed_hunts": completed_hunts,
                "total_results": total_results,
                "escalated_to_incidents": escalated_results,
                "total_findings": total_findings,
                "total_malicious_ips_found": total_malicious_ips
            }
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        db.close()


# Export all functions
__all__ = [
    'get_hunt_details',
    'analyze_hunt_results',
    'create_hunt_action',
    'escalate_to_incident',
    'get_hunt_statistics'
]
