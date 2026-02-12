# soc_agent/threat_intel_agent/tools.py
"""
Threat Intelligence Tools for SOC Agent
CORRECTED VERSION - Tested imports that actually work

YOUR PROJECT STRUCTURE:
soc_adk_tool_new/
├── backend/
│   ├── main.py
│   ├── soc_agent/
│   │   ├── __init__.py
│   │   ├── agent.py
│   │   ├── threat_intel_agent/    <-- NEW
│   │   │   ├── __init__.py
│   │   │   ├── agent.py
│   │   │   └── tools.py           <-- THIS FILE
"""

from google.adk.tools import FunctionTool
from datetime import datetime
import json
import os

# ============================================================
# IMPORTS FOR CISA KEV
# We use requests directly to handle SSL certificate issues
# ============================================================
import requests
import urllib3

# Disable SSL warnings for corporate environments with proxy/firewall issues
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# CISA KEV URL
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


# ============================================================
# TOOL 1: Fetch CISA KEV Vulnerabilities
# ============================================================
def fetch_cisa_kevs() -> dict:
    """
    Fetch the latest CISA Known Exploited Vulnerabilities catalog.
    
    Handles SSL certificate errors that occur in corporate environments.
    
    Returns:
        dict with 'count' and 'vulnerabilities' list
    """
    try:
        # Try with SSL verification first
        try:
            response = requests.get(CISA_KEV_URL, timeout=30)
        except requests.exceptions.SSLError:
            # If SSL fails (corporate proxy, etc.), try without verification
            # NOTE: In production, fix the root cause (install proper certs)
            response = requests.get(CISA_KEV_URL, timeout=30, verify=False)
        
        response.raise_for_status()
        data = response.json()
        
        # Parse the vulnerabilities
        vulns = []
        vulnerabilities = data.get('vulnerabilities', [])
        
        # Get most recent 20 (they're sorted newest first in the JSON)
        for v in vulnerabilities[:20]:
            vulns.append({
                'cve_id': v.get('cveID', ''),
                'vendor': v.get('vendorProject', ''),
                'product': v.get('product', ''),
                'name': v.get('vulnerabilityName', ''),
                'description': v.get('shortDescription', ''),
                'date_added': v.get('dateAdded', ''),
                'due_date': v.get('dueDate', ''),
                'ransomware_use': v.get('knownRansomwareCampaignUse', 'Unknown') == 'Known',
                'notes': v.get('notes', '')
            })
        
        return {
            'success': True,
            'count': len(vulns),
            'total_in_catalog': len(vulnerabilities),
            'vulnerabilities': vulns,
            'catalog_version': data.get('catalogVersion', ''),
            'date_released': data.get('dateReleased', '')
        }
        
    except requests.exceptions.RequestException as e:
        return {
            'success': False,
            'error': f'Network error: {str(e)}',
            'count': 0,
            'vulnerabilities': [],
            'suggestion': 'Check your network connection or proxy settings'
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'count': 0,
            'vulnerabilities': []
        }


# ============================================================
# TOOL 2: Check Asset Exposure (uses sample data for POC)
# ============================================================
def check_asset_exposure(vendor: str, product: str) -> dict:
    """
    Check if our environment has assets that might be affected by a vulnerability.
    
    For POC: Uses a sample assets file. In production, connect to your CMDB.
    
    Args:
        vendor: Vendor name (e.g., 'Apache', 'Microsoft')
        product: Product name (e.g., 'Log4j', 'Exchange')
    
    Returns:
        dict with exposure assessment
    """
    # Sample assets for POC - in production, query your CMDB
    sample_assets = [
        {"hostname": "web-server-01", "ip": "10.0.0.5", "software": ["nginx", "tomcat-9.0", "java-11"], "criticality": "high"},
        {"hostname": "app-server-02", "ip": "10.0.0.8", "software": ["elasticsearch-7.17", "java-11", "kibana"], "criticality": "critical"},
        {"hostname": "jenkins-01", "ip": "10.0.0.15", "software": ["jenkins-2.426", "java-17"], "criticality": "high"},
        {"hostname": "db-server-01", "ip": "10.0.0.20", "software": ["postgresql-14"], "criticality": "critical"},
        {"hostname": "kafka-01", "ip": "10.0.0.25", "software": ["kafka-3.5", "java-11", "zookeeper"], "criticality": "critical"},
    ]
    
    # Map products to applications that include them
    product_map = {
        'log4j': ['java', 'tomcat', 'elasticsearch', 'kafka', 'jenkins', 'solr'],
        'java': ['java', 'openjdk', 'tomcat', 'elasticsearch', 'jenkins'],
        'apache': ['httpd', 'apache2', 'tomcat'],
        'openssl': ['openssl', 'nginx', 'apache'],
        'spring': ['spring', 'java', 'tomcat'],
    }
    
    # Find matching applications
    search_terms = product_map.get(product.lower(), [product.lower()])
    
    exposed_assets = []
    for asset in sample_assets:
        for software in asset['software']:
            if any(term in software.lower() for term in search_terms):
                exposed_assets.append({
                    'hostname': asset['hostname'],
                    'ip': asset['ip'],
                    'matched_software': software,
                    'criticality': asset['criticality'],
                    'exposure_confidence': 'likely'  # CMDB = likely, scanner = confirmed
                })
                break  # Don't double-count same asset
    
    return {
        'vendor': vendor,
        'product': product,
        'exposed': len(exposed_assets) > 0,
        'exposed_count': len(exposed_assets),
        'assets': exposed_assets,
        'note': 'Based on CMDB application data. Run vulnerability scanner for confirmation.'
    }


# ============================================================
# TOOL 3: Create Detection Rule (generates Sigma + SIEM query)
# ============================================================
def create_detection_rule(
    cve_id: str,
    attack_pattern: str,
    description: str,
    log_source: str = 'webserver',
    siem_format: str = 'elastic'
) -> dict:
    """
    Generate a detection rule in Sigma format with SIEM-specific query.
    
    Args:
        cve_id: The CVE identifier (e.g., 'CVE-2021-44228')
        attack_pattern: The pattern to detect (e.g., '${jndi:')
        description: Human-readable description
        log_source: Type of logs to search (webserver, windows, network)
        siem_format: Target SIEM (elastic, splunk, sentinel)
    
    Returns:
        dict with sigma_yaml and siem_query
    """
    # Generate Sigma rule
    sigma_yaml = f"""title: Detection for {cve_id}
id: auto-generated-{cve_id.lower().replace('-', '')}
status: experimental
description: |
    {description}
    Auto-generated by SOC AI Tool.
author: SOC AI Tool
date: {datetime.now().strftime('%Y/%m/%d')}
references:
    - https://nvd.nist.gov/vuln/detail/{cve_id}
tags:
    - attack.initial_access
    - attack.t1190
    - cve.{cve_id.lower()}
logsource:
    category: {log_source}
detection:
    selection:
        cs-uri-query|contains: '{attack_pattern}'
    selection_ua:
        cs-user-agent|contains: '{attack_pattern}'
    condition: selection or selection_ua
fields:
    - cs-uri-query
    - cs-user-agent
    - c-ip
    - cs-host
falsepositives:
    - Unlikely in production environments
level: critical
"""
    
    # Generate SIEM-specific query
    if siem_format == 'elastic':
        siem_query = f'(url.query:*{attack_pattern}* OR user_agent.original:*{attack_pattern}*)'
    elif siem_format == 'splunk':
        siem_query = f'index=web (uri_query="*{attack_pattern}*" OR user_agent="*{attack_pattern}*")'
    elif siem_format == 'sentinel':
        siem_query = f'WebLogs | where Uri contains "{attack_pattern}" or UserAgent contains "{attack_pattern}"'
    else:
        siem_query = f'Search for pattern: {attack_pattern}'
    
    return {
        'cve_id': cve_id,
        'sigma_yaml': sigma_yaml,
        'siem_format': siem_format,
        'siem_query': siem_query,
        'status': 'generated',
        'message': 'Rule generated. Review and deploy to SIEM.'
    }


# ============================================================
# TOOL 4: Search Sigma Rules (semantic search using ChromaDB)
# ============================================================
def find_sigma_rules(search_query: str, limit: int = 5) -> dict:
    """
    Search existing Sigma rules using semantic search.
    
    Args:
        search_query: What to search for (e.g., 'log4j exploitation', 'credential theft')
        limit: Maximum number of results
    
    Returns:
        dict with matching rules
    """
    try:
        # Try to import your existing ChromaDB setup
        # Adjust the import path based on your project structure
        try:
            from soc_agent.shared.chroma_store import get_collection
            collection = get_collection('sigma_rules')
        except ImportError:
            # Fallback: return sample data for demo
            return {
                'search_query': search_query,
                'found': 2,
                'rules': [
                    {
                        'title': 'Log4j RCE Exploitation Attempt',
                        'description': 'Detects Log4j exploitation patterns in web logs',
                        'mitre_techniques': ['T1190'],
                        'level': 'critical'
                    },
                    {
                        'title': 'JNDI Injection Attempt',
                        'description': 'Detects JNDI lookup patterns indicating exploitation',
                        'mitre_techniques': ['T1190', 'T1059'],
                        'level': 'high'
                    }
                ],
                'note': 'Using sample data. Index Sigma rules in ChromaDB for full functionality.'
            }
        
        # Query ChromaDB
        results = collection.query(
            query_texts=[search_query],
            n_results=limit,
            include=['documents', 'metadatas']
        )
        
        rules = []
        for i, doc in enumerate(results['documents'][0]):
            meta = results['metadatas'][0][i] if results['metadatas'] else {}
            rules.append({
                'title': meta.get('title', 'Unknown'),
                'description': doc[:300] if doc else '',
                'mitre_techniques': meta.get('mitre_techniques', []),
                'level': meta.get('level', 'medium')
            })
        
        return {
            'search_query': search_query,
            'found': len(rules),
            'rules': rules
        }
        
    except Exception as e:
        return {
            'search_query': search_query,
            'found': 0,
            'rules': [],
            'error': str(e)
        }


# ============================================================
# CREATE ADK FUNCTION TOOLS
# ============================================================
fetch_cisa_kevs_tool = FunctionTool(fetch_cisa_kevs)
check_asset_exposure_tool = FunctionTool(check_asset_exposure)
create_detection_rule_tool = FunctionTool(create_detection_rule)
find_sigma_rules_tool = FunctionTool(find_sigma_rules)

# Export all tools
__all__ = [
    'fetch_cisa_kevs_tool',
    'check_asset_exposure_tool', 
    'create_detection_rule_tool',
    'find_sigma_rules_tool'
]