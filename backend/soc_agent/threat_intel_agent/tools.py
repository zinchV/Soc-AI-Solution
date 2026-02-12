"""Threat Intelligence Tools - Agent-driven rule generation"""
from google.adk.tools import FunctionTool
from datetime import datetime
import json
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_cisa_kevs() -> dict:
    """Fetch the latest CISA Known Exploited Vulnerabilities catalog."""
    try:
        try:
            response = requests.get(CISA_KEV_URL, timeout=30)
        except requests.exceptions.SSLError:
            response = requests.get(CISA_KEV_URL, timeout=30, verify=False)
        
        response.raise_for_status()
        data = response.json()
        
        vulns = []
        for v in data.get('vulnerabilities', [])[:20]:
            vulns.append({
                'cve_id': v.get('cveID', ''),
                'vendor': v.get('vendorProject', ''),
                'product': v.get('product', ''),
                'name': v.get('vulnerabilityName', ''),
                'description': v.get('shortDescription', ''),
                'date_added': v.get('dateAdded', ''),
                'due_date': v.get('dueDate', ''),
                'ransomware_use': v.get('knownRansomwareCampaignUse', 'Unknown') == 'Known',
            })
        
        return {'success': True, 'count': len(vulns), 'vulnerabilities': vulns}
    except Exception as e:
        return {'success': False, 'error': str(e), 'count': 0, 'vulnerabilities': []}


def check_asset_exposure(vendor: str, product: str) -> dict:
    """Check if environment has assets affected by a vulnerability.
    Calls the main API to use the centralized asset inventory."""
    try:
        resp = requests.get(
            f"http://localhost:8080/api/v1/threat-intel/exposure",
            params={'vendor': vendor, 'product': product},
            timeout=10
        )
        return resp.json()
    except Exception as e:
        return {'success': False, 'error': str(e)}


def get_cve_details(cve_id: str) -> dict:
    """Get full CVE details from the local database including exposure and existing rule info.
    Use this BEFORE generating a detection rule to understand the vulnerability context."""
    try:
        from database import SessionLocal, ThreatIntel, DetectionRule
        db = SessionLocal()
        try:
            threat = db.query(ThreatIntel).filter(ThreatIntel.cve_id == cve_id).first()
            if not threat:
                return {'success': False, 'error': f'CVE {cve_id} not found in database'}
            
            existing_rule = db.query(DetectionRule).filter(DetectionRule.source_cve == cve_id).first()
            
            return {
                'success': True,
                'cve_id': threat.cve_id,
                'vendor': threat.vendor,
                'product': threat.product,
                'vulnerability_name': threat.vulnerability_name,
                'description': threat.description,
                'severity': threat.severity,
                'date_added': str(threat.date_added) if threat.date_added else None,
                'due_date': str(threat.due_date) if threat.due_date else None,
                'ransomware_use': threat.ransomware_use,
                'has_existing_rule': existing_rule is not None,
                'existing_rule_id': existing_rule.id if existing_rule else None,
                'existing_rule_status': existing_rule.status if existing_rule else None,
            }
        finally:
            db.close()
    except Exception as e:
        return {'success': False, 'error': str(e)}


def save_detection_rule(
    cve_id: str,
    title: str,
    description: str,
    sigma_rule: str,
    kql_query: str,
    severity: str = 'high',
    mitre_tactic: str = 'InitialAccess',
    mitre_technique: str = 'T1190'
) -> dict:
    """Save a detection rule to the database. 
    The agent should generate the sigma_rule and kql_query content, then call this tool to persist it.
    
    Args:
        cve_id: The CVE identifier (e.g. CVE-2026-24858)
        title: Human-readable rule title
        description: What the rule detects
        sigma_rule: Complete Sigma rule in YAML format
        kql_query: Complete KQL query for Microsoft Sentinel. MUST be valid KQL syntax.
        severity: Rule severity (critical, high, medium, low)
        mitre_tactic: MITRE ATT&CK tactic name
        mitre_technique: MITRE ATT&CK technique ID (e.g. T1190)
    
    Returns:
        dict with success status and rule_id
    """
    try:
        from database import SessionLocal, DetectionRule, ThreatIntel
        import json
        
        db = SessionLocal()
        try:
            # Verify CVE exists
            threat = db.query(ThreatIntel).filter(ThreatIntel.cve_id == cve_id).first()
            if not threat:
                return {'success': False, 'error': f'CVE {cve_id} not found in database'}
            
            # Check for existing rule
            existing = db.query(DetectionRule).filter(DetectionRule.source_cve == cve_id).first()
            if existing:
                return {
                    'success': False, 
                    'error': f'Rule already exists for {cve_id}',
                    'existing_rule_id': existing.id,
                    'existing_rule_status': existing.status
                }
            
            rule = DetectionRule(
                title=title[:200],
                description=description[:500],
                source_cve=cve_id,
                severity=severity.lower() if severity else 'high',
                sigma_rule=sigma_rule,
                kql_query=kql_query,
                mitre_techniques=json.dumps([mitre_technique]),
                status='pending'
            )
            db.add(rule)
            db.commit()
            
            return {
                'success': True,
                'message': f'Detection rule created for {cve_id}',
                'rule_id': rule.id,
                'status': 'pending',
                'mitre_tactic': mitre_tactic,
                'mitre_technique': mitre_technique
            }
        finally:
            db.close()
    except Exception as e:
        return {'success': False, 'error': str(e)}


fetch_cisa_kevs_tool = FunctionTool(fetch_cisa_kevs)
check_asset_exposure_tool = FunctionTool(check_asset_exposure)
get_cve_details_tool = FunctionTool(get_cve_details)
save_detection_rule_tool = FunctionTool(save_detection_rule)

__all__ = [
    'fetch_cisa_kevs_tool', 
    'check_asset_exposure_tool', 
    'get_cve_details_tool',
    'save_detection_rule_tool'
]
