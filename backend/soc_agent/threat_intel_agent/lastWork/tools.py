# soc_agent/threat_intel_agent/tools.py
"""
Threat Intelligence Agent Tools
- Fetch CISA KEVs
- Check Asset Exposure (with SIMULATED assets for demo)
- Create Detection Rules
- Find Sigma Rules
"""

import urllib.request
import urllib.error
import json
import ssl
from google.adk.tools import FunctionTool

# ============================================================
# CONFIGURATION
# ============================================================

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# ============================================================
# SIMULATED ASSET INVENTORY (CMDB)
# In production, this would query your actual CMDB/Asset Management
# ============================================================

SIMULATED_ASSETS = [
    {
        "hostname": "WEB-PROD-01",
        "ip_address": "10.0.1.10",
        "os": "Ubuntu 22.04 LTS",
        "software": ["nginx-1.24", "nodejs-18", "openssl-3.0"],
        "criticality": "critical",
        "owner": "Web Team",
        "department": "Engineering",
        "location": "DC-Primary"
    },
    {
        "hostname": "WEB-PROD-02",
        "ip_address": "10.0.1.11",
        "os": "Ubuntu 22.04 LTS",
        "software": ["apache-2.4", "php-8.1", "mysql-client"],
        "criticality": "critical",
        "owner": "Web Team",
        "department": "Engineering",
        "location": "DC-Primary"
    },
    {
        "hostname": "APP-SERVER-01",
        "ip_address": "10.0.2.20",
        "os": "Windows Server 2022",
        "software": ["tomcat-9.0", "java-11", "elasticsearch-7.17"],
        "criticality": "critical",
        "owner": "Application Team",
        "department": "Engineering",
        "location": "DC-Primary"
    },
    {
        "hostname": "APP-SERVER-02",
        "ip_address": "10.0.2.21",
        "os": "Windows Server 2022",
        "software": ["dotnet-6.0", "iis-10", "mssql-client"],
        "criticality": "high",
        "owner": "Application Team",
        "department": "Engineering",
        "location": "DC-Secondary"
    },
    {
        "hostname": "JENKINS-CI-01",
        "ip_address": "10.0.3.30",
        "os": "Ubuntu 20.04 LTS",
        "software": ["jenkins-2.426", "java-17", "docker-24.0", "git"],
        "criticality": "high",
        "owner": "DevOps Team",
        "department": "Engineering",
        "location": "DC-Primary"
    },
    {
        "hostname": "KAFKA-PROD-01",
        "ip_address": "10.0.4.40",
        "os": "RHEL 8",
        "software": ["kafka-3.5", "java-11", "zookeeper-3.8"],
        "criticality": "critical",
        "owner": "Data Platform",
        "department": "Engineering",
        "location": "DC-Primary"
    },
    {
        "hostname": "DB-POSTGRES-01",
        "ip_address": "10.0.5.50",
        "os": "Ubuntu 22.04 LTS",
        "software": ["postgresql-15", "pgbouncer"],
        "criticality": "critical",
        "owner": "DBA Team",
        "department": "Engineering",
        "location": "DC-Primary"
    },
    {
        "hostname": "DB-MONGO-01",
        "ip_address": "10.0.5.51",
        "os": "Ubuntu 22.04 LTS",
        "software": ["mongodb-6.0", "mongosh"],
        "criticality": "critical",
        "owner": "DBA Team",
        "department": "Engineering",
        "location": "DC-Primary"
    },
    {
        "hostname": "MAIL-EXCHANGE-01",
        "ip_address": "10.0.6.60",
        "os": "Windows Server 2019",
        "software": ["exchange-2019", "outlook-web", "iis-10"],
        "criticality": "critical",
        "owner": "IT Operations",
        "department": "IT",
        "location": "DC-Primary"
    },
    {
        "hostname": "FILE-SERVER-01",
        "ip_address": "10.0.7.70",
        "os": "Windows Server 2022",
        "software": ["smb-3.0", "dfs"],
        "criticality": "high",
        "owner": "IT Operations",
        "department": "IT",
        "location": "DC-Primary"
    },
    {
        "hostname": "FORTINET-FW-01",
        "ip_address": "10.0.0.1",
        "os": "FortiOS 7.2",
        "software": ["fortios-7.2", "fortigate", "fortinet"],
        "criticality": "critical",
        "owner": "Network Security",
        "department": "Security",
        "location": "DC-Primary"
    },
    {
        "hostname": "CISCO-ROUTER-01",
        "ip_address": "10.0.0.2",
        "os": "Cisco IOS XE",
        "software": ["cisco-ios-xe", "cisco-asa"],
        "criticality": "critical",
        "owner": "Network Team",
        "department": "IT",
        "location": "DC-Primary"
    },
    {
        "hostname": "SPLUNK-INDEXER-01",
        "ip_address": "10.0.8.80",
        "os": "RHEL 8",
        "software": ["splunk-9.1", "java-11"],
        "criticality": "high",
        "owner": "SOC Team",
        "department": "Security",
        "location": "DC-Primary"
    },
    {
        "hostname": "WORKSTATION-HR-001",
        "ip_address": "10.10.1.101",
        "os": "Windows 11 Pro",
        "software": ["office-365", "chrome", "adobe-reader", "winrar"],
        "criticality": "medium",
        "owner": "HR Department",
        "department": "HR",
        "location": "Office-HQ"
    },
    {
        "hostname": "WORKSTATION-FIN-001",
        "ip_address": "10.10.2.101",
        "os": "Windows 11 Pro",
        "software": ["office-365", "sap-client", "chrome", "7zip"],
        "criticality": "high",
        "owner": "Finance Department",
        "department": "Finance",
        "location": "Office-HQ"
    },
    {
        "hostname": "DEV-LAPTOP-001",
        "ip_address": "10.20.1.50",
        "os": "macOS Sonoma",
        "software": ["vscode", "docker", "nodejs-20", "python-3.11", "git"],
        "criticality": "medium",
        "owner": "Dev Team",
        "department": "Engineering",
        "location": "Remote"
    },
    {
        "hostname": "GOGS-SERVER-01",
        "ip_address": "10.0.9.90",
        "os": "Ubuntu 22.04 LTS",
        "software": ["gogs-0.13", "git", "sqlite"],
        "criticality": "high",
        "owner": "DevOps Team",
        "department": "Engineering",
        "location": "DC-Primary"
    },
    {
        "hostname": "SONICWALL-VPN-01",
        "ip_address": "10.0.0.5",
        "os": "SonicOS 7.0",
        "software": ["sonicwall-sma1000", "sonicwall-vpn"],
        "criticality": "critical",
        "owner": "Network Security",
        "department": "Security",
        "location": "DC-Primary"
    },
    {
        "hostname": "WATCHGUARD-FW-01",
        "ip_address": "10.0.0.6",
        "os": "Fireware OS 12.10",
        "software": ["watchguard-firebox", "fireware"],
        "criticality": "critical",
        "owner": "Network Security",
        "department": "Security",
        "location": "DC-Secondary"
    },
    {
        "hostname": "DLINK-ROUTER-BRANCH",
        "ip_address": "192.168.1.1",
        "os": "D-Link Firmware",
        "software": ["dlink-router", "dlink-dir"],
        "criticality": "medium",
        "owner": "Branch IT",
        "department": "IT",
        "location": "Branch-Office"
    }
]

# ============================================================
# PRODUCT TO SOFTWARE MAPPING
# Maps CVE product names to software that might be affected
# ============================================================

PRODUCT_SOFTWARE_MAP = {
    # Operating Systems
    'windows': ['windows', 'win11', 'win10', 'windows-server'],
    'linux': ['ubuntu', 'rhel', 'centos', 'debian'],
    'macos': ['macos', 'osx'],
    
    # Web/App Servers
    'apache': ['apache', 'httpd'],
    'nginx': ['nginx'],
    'tomcat': ['tomcat', 'java'],
    'iis': ['iis'],
    
    # Programming/Runtime
    'java': ['java', 'openjdk', 'jdk', 'jre', 'tomcat', 'elasticsearch', 'kafka', 'jenkins'],
    'log4j': ['java', 'tomcat', 'elasticsearch', 'kafka', 'jenkins', 'log4j'],
    'python': ['python'],
    'nodejs': ['nodejs', 'node'],
    '.net': ['dotnet', '.net'],
    
    # Databases
    'postgresql': ['postgresql', 'postgres'],
    'mysql': ['mysql', 'mariadb'],
    'mongodb': ['mongodb', 'mongo'],
    'oracle': ['oracle'],
    'mssql': ['mssql', 'sql-server'],
    
    # Security/Network Devices
    'fortinet': ['fortios', 'fortigate', 'fortinet'],
    'fortigate': ['fortios', 'fortigate', 'fortinet'],
    'fortios': ['fortios', 'fortigate', 'fortinet'],
    'cisco': ['cisco', 'ios-xe', 'asa'],
    'sonicwall': ['sonicwall', 'sma1000', 'sonicwall-vpn'],
    'sma1000': ['sonicwall', 'sma1000'],
    'watchguard': ['watchguard', 'firebox', 'fireware'],
    'firebox': ['watchguard', 'firebox', 'fireware'],
    'd-link': ['dlink', 'd-link', 'dlink-router', 'dlink-dir'],
    'dlink': ['dlink', 'd-link', 'dlink-router'],
    
    # Applications
    'exchange': ['exchange', 'outlook-web', 'owa'],
    'office': ['office', 'office-365', 'word', 'excel', 'powerpoint'],
    'chrome': ['chrome', 'chromium'],
    'firefox': ['firefox'],
    'adobe': ['adobe', 'acrobat', 'reader'],
    'winrar': ['winrar', 'rar'],
    '7-zip': ['7zip', '7-zip'],
    
    # DevOps/Infrastructure
    'jenkins': ['jenkins'],
    'docker': ['docker'],
    'kubernetes': ['kubernetes', 'k8s'],
    'elasticsearch': ['elasticsearch', 'elastic'],
    'kafka': ['kafka'],
    'splunk': ['splunk'],
    'gogs': ['gogs'],
    'git': ['git', 'gogs', 'gitlab', 'github'],
    
    # Messaging
    'outlook': ['outlook', 'exchange', 'office-365'],
}


# ============================================================
# HELPER: Secure HTTPS Request
# ============================================================

def _make_secure_request(url: str, timeout: int = 30) -> dict:
    """Make a secure HTTPS request to a .gov endpoint"""
    ctx = ssl.create_default_context()
    
    req = urllib.request.Request(
        url,
        headers={'User-Agent': 'SOC-AI-Tool/2.0 (Threat Intel Agent)'}
    )
    
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
        return json.loads(response.read().decode('utf-8'))


# ============================================================
# TOOL 1: Fetch CISA KEVs
# ============================================================

def fetch_cisa_kevs(limit: int = 20) -> dict:
    """
    Fetch Known Exploited Vulnerabilities from CISA's official catalog.
    
    SECURE: Uses direct HTTPS call to official CISA .gov endpoint.
    No third-party Python packages required.
    
    Args:
        limit: Maximum number of vulnerabilities to return (default 20)
    
    Returns:
        dict with 'success', 'count', and 'vulnerabilities' list
    """
    try:
        data = _make_secure_request(CISA_KEV_URL)
        
        all_vulns = data.get('vulnerabilities', [])
        
        # Sort by date added (newest first)
        sorted_vulns = sorted(
            all_vulns,
            key=lambda x: x.get('dateAdded', ''),
            reverse=True
        )[:limit]
        
        vulns = []
        for v in sorted_vulns:
            vulns.append({
                'cve_id': v.get('cveID'),
                'vendor': v.get('vendorProject'),
                'product': v.get('product'),
                'name': v.get('vulnerabilityName'),
                'description': v.get('shortDescription'),
                'date_added': v.get('dateAdded'),
                'due_date': v.get('dueDate'),
                'ransomware_use': v.get('knownRansomwareCampaignUse') == 'Known',
                'required_action': v.get('requiredAction'),
                'notes': v.get('notes')
            })
        
        return {
            'success': True,
            'count': len(vulns),
            'total_in_catalog': len(all_vulns),
            'catalog_version': data.get('catalogVersion'),
            'vulnerabilities': vulns,
            'source': 'CISA Official API (cisa.gov)'
        }
        
    except urllib.error.URLError as e:
        return {
            'success': False,
            'error': f'Network error: {str(e)}',
            'count': 0,
            'vulnerabilities': []
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'count': 0,
            'vulnerabilities': []
        }


# ============================================================
# TOOL 2: Check Asset Exposure (SIMULATED for Demo)
# ============================================================

def check_asset_exposure(vendor: str, product: str) -> dict:
    """
    Check if our organization's assets are exposed to a vulnerability.
    
    FOR DEMO: Uses simulated asset inventory.
    IN PRODUCTION: Would query actual CMDB, ServiceNow, or asset management system.
    
    Args:
        vendor: Vendor name from CVE (e.g., 'Microsoft', 'Apache', 'Fortinet')
        product: Product name from CVE (e.g., 'Windows', 'Log4j', 'FortiOS')
    
    Returns:
        dict with exposure assessment and affected assets
    """
    vendor_lower = vendor.lower().strip() if vendor else ''
    product_lower = product.lower().strip() if product else ''
    
    # Build search terms from product mapping
    search_terms = set()
    
    # Add direct product name
    search_terms.add(product_lower)
    
    # Add vendor name
    if vendor_lower:
        search_terms.add(vendor_lower)
    
    # Add mapped software names
    for key, values in PRODUCT_SOFTWARE_MAP.items():
        if key in product_lower or product_lower in key:
            search_terms.update(values)
        if vendor_lower and (key in vendor_lower or vendor_lower in key):
            search_terms.update(values)
    
    # Remove empty strings
    search_terms.discard('')
    
    # Find exposed assets
    exposed_assets = []
    
    for asset in SIMULATED_ASSETS:
        matched_software = []
        
        for software in asset.get('software', []):
            software_lower = software.lower()
            
            # Check if any search term matches this software
            for term in search_terms:
                if term in software_lower or software_lower in term:
                    matched_software.append(software)
                    break
        
        if matched_software:
            exposed_assets.append({
                'hostname': asset['hostname'],
                'ip_address': asset['ip_address'],
                'os': asset['os'],
                'criticality': asset['criticality'],
                'owner': asset['owner'],
                'department': asset['department'],
                'location': asset['location'],
                'matched_software': list(set(matched_software)),
                'exposure_confidence': 'high' if product_lower in ' '.join(matched_software).lower() else 'medium'
            })
    
    # Sort by criticality (critical first)
    criticality_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    exposed_assets.sort(key=lambda x: criticality_order.get(x['criticality'], 99))
    
    # Calculate summary stats
    critical_count = sum(1 for a in exposed_assets if a['criticality'] == 'critical')
    high_count = sum(1 for a in exposed_assets if a['criticality'] == 'high')
    
    # Generate recommendation
    if critical_count > 0:
        recommendation = f"🚨 URGENT: {critical_count} critical assets exposed! Immediate patching required."
        risk_level = "CRITICAL"
    elif high_count > 0:
        recommendation = f"⚠️ HIGH RISK: {high_count} high-priority assets exposed. Patch within 48 hours."
        risk_level = "HIGH"
    elif len(exposed_assets) > 0:
        recommendation = f"📋 {len(exposed_assets)} assets potentially exposed. Schedule patching."
        risk_level = "MEDIUM"
    else:
        recommendation = "✅ No exposed assets found in inventory."
        risk_level = "LOW"
    
    return {
        'success': True,
        'vendor': vendor,
        'product': product,
        'search_terms_used': list(search_terms),
        'is_exposed': len(exposed_assets) > 0,
        'exposed_count': len(exposed_assets),
        'critical_count': critical_count,
        'high_count': high_count,
        'risk_level': risk_level,
        'assets': exposed_assets,
        'recommendation': recommendation,
        'note': 'Based on simulated CMDB data. In production, connect to actual asset management system.'
    }


# ============================================================
# TOOL 3: Create Detection Rule
# ============================================================

def create_detection_rule(
    cve_id: str,
    rule_type: str = "sigma",
    severity: str = "high"
) -> dict:
    """
    Generate a detection rule for a CVE.
    
    Args:
        cve_id: The CVE identifier (e.g., 'CVE-2024-1234')
        rule_type: Type of rule - 'sigma', 'kql', or 'splunk'
        severity: Rule severity - 'critical', 'high', 'medium', 'low'
    
    Returns:
        dict with generated detection rule
    """
    # Generate a Sigma rule template
    sigma_rule = f"""title: Detect {cve_id} Exploitation Attempt
id: {cve_id.lower().replace('-', '_')}_detection
status: experimental
description: Detects potential exploitation attempts of {cve_id}
author: SOC AI Tool
date: 2025/01/22
references:
    - https://nvd.nist.gov/vuln/detail/{cve_id}
    - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
tags:
    - attack.initial_access
    - attack.t1190
    - cve.{cve_id.lower()}
logsource:
    category: webserver
    product: apache
detection:
    selection:
        cs-uri-query|contains:
            - '../'
            - '..%2f'
            - '%2e%2e/'
    condition: selection
falsepositives:
    - Legitimate path traversal in some applications
level: {severity}
"""

    # Generate KQL equivalent
    kql_rule = f"""// Detection for {cve_id}
// Deploy to Microsoft Sentinel
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID in (4688, 1) // Process creation
| where CommandLine has_any ("../", "..\\\\", "%2e%2e")
| project TimeGenerated, Computer, Account, CommandLine, ParentProcessName
| extend CVE = "{cve_id}"
"""

    # Generate Splunk SPL
    splunk_rule = f"""| tstats count from datamodel=Web where Web.url="*../*" OR Web.url="*%2e%2e*" by Web.src, Web.dest, Web.url
| rename Web.* as *
| eval cve="{cve_id}"
| where count > 5
"""

    rules = {
        'sigma': sigma_rule,
        'kql': kql_rule,
        'splunk': splunk_rule
    }

    return {
        'success': True,
        'cve_id': cve_id,
        'rule_type': rule_type,
        'severity': severity,
        'rule_content': rules.get(rule_type, sigma_rule),
        'all_formats': rules,
        'deployment_note': f'Rule generated for {cve_id}. Review and customize before deployment.',
        'requires_approval': True
    }


# ============================================================
# TOOL 4: Find Existing Sigma Rules
# ============================================================

def find_sigma_rules(search_query: str, limit: int = 5) -> dict:
    """
    Search for existing Sigma rules related to a threat.
    
    FOR DEMO: Returns sample rules.
    IN PRODUCTION: Would search SigmaHQ repository or your rule database.
    
    Args:
        search_query: Search term (CVE ID, technique, product name)
        limit: Maximum results to return
    
    Returns:
        dict with matching rules
    """
    # Simulated Sigma rules database
    sample_rules = [
        {
            'title': 'Web Shell Detection',
            'id': 'rule_webshell_001',
            'description': 'Detects common web shell patterns in HTTP requests',
            'mitre_techniques': ['T1505.003'],
            'severity': 'high',
            'author': 'SigmaHQ'
        },
        {
            'title': 'Suspicious PowerShell Execution',
            'id': 'rule_powershell_001',
            'description': 'Detects encoded PowerShell commands often used in attacks',
            'mitre_techniques': ['T1059.001'],
            'severity': 'high',
            'author': 'SigmaHQ'
        },
        {
            'title': 'Log4j Exploitation Attempt',
            'id': 'rule_log4j_001',
            'description': 'Detects Log4j/Log4Shell exploitation patterns',
            'mitre_techniques': ['T1190'],
            'severity': 'critical',
            'author': 'SigmaHQ'
        },
        {
            'title': 'Path Traversal Attack',
            'id': 'rule_pathtraversal_001',
            'description': 'Detects directory traversal attempts in web requests',
            'mitre_techniques': ['T1083'],
            'severity': 'medium',
            'author': 'SigmaHQ'
        },
        {
            'title': 'Brute Force Authentication',
            'id': 'rule_bruteforce_001',
            'description': 'Detects multiple failed authentication attempts',
            'mitre_techniques': ['T1110'],
            'severity': 'medium',
            'author': 'SigmaHQ'
        }
    ]
    
    # Filter by search query
    query_lower = search_query.lower()
    matching = [
        rule for rule in sample_rules
        if query_lower in rule['title'].lower() 
        or query_lower in rule['description'].lower()
        or any(query_lower in t.lower() for t in rule['mitre_techniques'])
    ]
    
    return {
        'success': True,
        'search_query': search_query,
        'found_count': len(matching[:limit]),
        'rules': matching[:limit],
        'source': 'Simulated rule database (Demo). In production, searches SigmaHQ/internal rules.'
    }


# ============================================================
# CREATE ADK FUNCTION TOOLS
# ============================================================

fetch_cisa_kevs_tool = FunctionTool(fetch_cisa_kevs)
check_asset_exposure_tool = FunctionTool(check_asset_exposure)
create_detection_rule_tool = FunctionTool(create_detection_rule)
find_sigma_rules_tool = FunctionTool(find_sigma_rules)


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    'fetch_cisa_kevs',
    'check_asset_exposure',
    'create_detection_rule',
    'find_sigma_rules',
    'fetch_cisa_kevs_tool',
    'check_asset_exposure_tool',
    'create_detection_rule_tool',
    'find_sigma_rules_tool',
    'SIMULATED_ASSETS',
    'PRODUCT_SOFTWARE_MAP'
]
