"""
VMG Agent Tools - Vulnerability Management Functions
Handles vulnerability scanning simulation, risk scoring, and remediation tracking.
"""
import json
import random
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any

# Import database components (will be available when running with main.py)
try:
    from database import SessionLocal, Vulnerability
except ImportError:
    SessionLocal = None
    Vulnerability = None


# ========================= SIMULATED TENABLE SCANNER DATA =========================

# Simulated vulnerability findings that match your asset inventory
SIMULATED_SCANNER_FINDINGS = [
    # Critical - On critical assets, in KEV
    {
        "cve_id": "CVE-2024-21762",
        "plugin_id": "189234",
        "plugin_name": "FortiOS Out-of-Bounds Write RCE",
        "severity": "Critical",
        "cvss_score": 9.8,
        "ip_address": "10.0.0.1",
        "hostname": "FORTINET-FW-01",
        "port": 443,
        "protocol": "HTTPS",
        "description": "FortiOS out-of-bounds write vulnerability allowing remote code execution via crafted HTTP requests.",
        "solution": "Upgrade FortiOS to version 7.4.3 or later. Apply vendor patch immediately.",
        "exploit_available": True,
        "in_cisa_kev": True,
        "epss_score": 0.92,
        "first_discovered": "2024-02-01",
        "vendor": "Fortinet",
        "product": "FortiOS"
    },
    {
        "cve_id": "CVE-2024-3400",
        "plugin_id": "193456",
        "plugin_name": "Palo Alto PAN-OS Command Injection",
        "severity": "Critical",
        "cvss_score": 10.0,
        "ip_address": "10.0.0.20",
        "hostname": "PALOALTO-FW-01",
        "port": 443,
        "protocol": "HTTPS",
        "description": "Command injection vulnerability in GlobalProtect feature of PAN-OS allowing unauthenticated RCE.",
        "solution": "Apply Palo Alto hotfix or upgrade to PAN-OS 10.2.9 or later.",
        "exploit_available": True,
        "in_cisa_kev": True,
        "epss_score": 0.97,
        "first_discovered": "2024-04-12",
        "vendor": "Palo Alto",
        "product": "PAN-OS"
    },
    {
        "cve_id": "CVE-2024-40711",
        "plugin_id": "195678",
        "plugin_name": "SonicWall SMA1000 Deserialization RCE",
        "severity": "Critical",
        "cvss_score": 9.8,
        "ip_address": "10.0.0.5",
        "hostname": "SONICWALL-VPN-01",
        "port": 443,
        "protocol": "HTTPS",
        "description": "Deserialization of untrusted data in SonicWall SMA1000 allows unauthenticated remote code execution.",
        "solution": "Upgrade to SMA1000 firmware 12.4.3-02854 or later.",
        "exploit_available": True,
        "in_cisa_kev": True,
        "epss_score": 0.89,
        "first_discovered": "2024-09-05",
        "vendor": "SonicWall",
        "product": "SMA1000"
    },
    # Critical - On DC, high value target
    {
        "cve_id": "CVE-2024-30088",
        "plugin_id": "198234",
        "plugin_name": "Windows Kernel Elevation of Privilege",
        "severity": "Critical",
        "cvss_score": 8.8,
        "ip_address": "10.0.10.10",
        "hostname": "DC-PRIMARY-01",
        "port": 445,
        "protocol": "SMB",
        "description": "Windows kernel vulnerability allowing local privilege escalation to SYSTEM.",
        "solution": "Apply Microsoft Security Update KB5039212.",
        "exploit_available": True,
        "in_cisa_kev": True,
        "epss_score": 0.78,
        "first_discovered": "2024-06-11",
        "vendor": "Microsoft",
        "product": "Windows Server 2022"
    },
    # High - On production server
    {
        "cve_id": "CVE-2024-38077",
        "plugin_id": "199345",
        "plugin_name": "Windows Remote Desktop Licensing Service RCE",
        "severity": "High",
        "cvss_score": 9.8,
        "ip_address": "10.0.10.10",
        "hostname": "DC-PRIMARY-01",
        "port": 3389,
        "protocol": "RDP",
        "description": "Remote code execution vulnerability in Windows Remote Desktop Licensing Service.",
        "solution": "Apply Microsoft Security Update KB5040442.",
        "exploit_available": True,
        "in_cisa_kev": False,
        "epss_score": 0.65,
        "first_discovered": "2024-07-09",
        "vendor": "Microsoft",
        "product": "Windows Server 2022"
    },
    # High - GitLab vulnerability
    {
        "cve_id": "CVE-2024-45409",
        "plugin_id": "201456",
        "plugin_name": "GitLab SAML Authentication Bypass",
        "severity": "Critical",
        "cvss_score": 10.0,
        "ip_address": "10.0.3.30",
        "hostname": "GITLAB-CI-01",
        "port": 443,
        "protocol": "HTTPS",
        "description": "SAML authentication bypass in GitLab allowing account takeover.",
        "solution": "Upgrade GitLab to version 17.3.3, 17.2.7, or 17.1.8.",
        "exploit_available": True,
        "in_cisa_kev": True,
        "epss_score": 0.85,
        "first_discovered": "2024-09-17",
        "vendor": "GitLab",
        "product": "GitLab CE/EE"
    },
    # High - Web server
    {
        "cve_id": "CVE-2024-5535",
        "plugin_id": "202567",
        "plugin_name": "OpenSSL SSL_select_next_proto Buffer Overread",
        "severity": "High",
        "cvss_score": 7.5,
        "ip_address": "10.0.1.10",
        "hostname": "WEB-PROD-01",
        "port": 443,
        "protocol": "HTTPS",
        "description": "Buffer over-read vulnerability in OpenSSL affecting ALPN protocol negotiation.",
        "solution": "Upgrade OpenSSL to version 3.3.2, 3.2.3, 3.1.7, or 3.0.15.",
        "exploit_available": False,
        "in_cisa_kev": False,
        "epss_score": 0.35,
        "first_discovered": "2024-06-27",
        "vendor": "OpenSSL",
        "product": "OpenSSL"
    },
    # Medium - On production but lower risk
    {
        "cve_id": "CVE-2024-37371",
        "plugin_id": "203678",
        "plugin_name": "MIT Kerberos Invalid Memory Read",
        "severity": "Medium",
        "cvss_score": 6.5,
        "ip_address": "10.0.10.10",
        "hostname": "DC-PRIMARY-01",
        "port": 88,
        "protocol": "Kerberos",
        "description": "Invalid memory read in MIT Kerberos when processing GSS message tokens.",
        "solution": "Upgrade MIT Kerberos to version 1.21.3.",
        "exploit_available": False,
        "in_cisa_kev": False,
        "epss_score": 0.15,
        "first_discovered": "2024-06-28",
        "vendor": "MIT",
        "product": "Kerberos"
    },
    # Medium - Database server
    {
        "cve_id": "CVE-2024-7348",
        "plugin_id": "204789",
        "plugin_name": "PostgreSQL pg_dump Arbitrary SQL Execution",
        "severity": "High",
        "cvss_score": 7.5,
        "ip_address": "10.0.5.50",
        "hostname": "DB-POSTGRES-01",
        "port": 5432,
        "protocol": "PostgreSQL",
        "description": "Arbitrary SQL execution vulnerability during pg_dump operations.",
        "solution": "Upgrade PostgreSQL to version 16.4, 15.8, 14.13, 13.16, or 12.20.",
        "exploit_available": False,
        "in_cisa_kev": False,
        "epss_score": 0.25,
        "first_discovered": "2024-08-08",
        "vendor": "PostgreSQL",
        "product": "PostgreSQL"
    },
    # High - Ivanti MDM (matches asset)
    {
        "cve_id": "CVE-2024-7593",
        "plugin_id": "205890",
        "plugin_name": "Ivanti vTM Authentication Bypass",
        "severity": "Critical",
        "cvss_score": 9.8,
        "ip_address": "10.0.0.25",
        "hostname": "IVANTI-MDM-01",
        "port": 9644,
        "protocol": "HTTPS",
        "description": "Authentication bypass in Ivanti Virtual Traffic Manager allows admin access.",
        "solution": "Apply Ivanti security patch or upgrade to latest version.",
        "exploit_available": True,
        "in_cisa_kev": True,
        "epss_score": 0.88,
        "first_discovered": "2024-08-13",
        "vendor": "Ivanti",
        "product": "vTM"
    },
    # Medium - Elasticsearch on app server
    {
        "cve_id": "CVE-2024-23450",
        "plugin_id": "206901",
        "plugin_name": "Elasticsearch Stack Overflow DoS",
        "severity": "Medium",
        "cvss_score": 4.9,
        "ip_address": "10.0.2.20",
        "hostname": "APP-SERVER-01",
        "port": 9200,
        "protocol": "HTTP",
        "description": "Stack overflow leading to denial of service via deeply nested queries.",
        "solution": "Upgrade Elasticsearch to version 8.13.2 or later.",
        "exploit_available": False,
        "in_cisa_kev": False,
        "epss_score": 0.08,
        "first_discovered": "2024-03-27",
        "vendor": "Elastic",
        "product": "Elasticsearch"
    },
    # Low - On workstation
    {
        "cve_id": "CVE-2024-5274",
        "plugin_id": "207012",
        "plugin_name": "Google Chrome V8 Type Confusion",
        "severity": "High",
        "cvss_score": 8.8,
        "ip_address": "10.10.1.101",
        "hostname": "WORKSTATION-HR-001",
        "port": 0,
        "protocol": "Local",
        "description": "Type confusion vulnerability in Chrome V8 engine allowing RCE via crafted webpage.",
        "solution": "Update Google Chrome to version 125.0.6422.112 or later.",
        "exploit_available": True,
        "in_cisa_kev": True,
        "epss_score": 0.72,
        "first_discovered": "2024-05-23",
        "vendor": "Google",
        "product": "Chrome"
    },
    # SolarWinds - matches helpdesk asset
    {
        "cve_id": "CVE-2024-28986",
        "plugin_id": "208123",
        "plugin_name": "SolarWinds Web Help Desk Java Deserialization RCE",
        "severity": "Critical",
        "cvss_score": 9.8,
        "ip_address": "10.0.4.40",
        "hostname": "HELPDESK-APP-01",
        "port": 8443,
        "protocol": "HTTPS",
        "description": "Java deserialization vulnerability in SolarWinds WHD allowing unauthenticated RCE.",
        "solution": "Apply SolarWinds Web Help Desk hotfix or upgrade to version 12.8.3 HF2.",
        "exploit_available": True,
        "in_cisa_kev": True,
        "epss_score": 0.94,
        "first_discovered": "2024-08-13",
        "vendor": "SolarWinds",
        "product": "Web Help Desk"
    },
]

# Asset criticality weights
CRITICALITY_WEIGHTS = {
    "critical": 2.0,
    "high": 1.5,
    "medium": 1.0,
    "low": 0.5
}

# Asset type weights (some asset types are more valuable targets)
ASSET_TYPE_WEIGHTS = {
    "network": 2.0,      # Firewalls, routers
    "security": 1.8,     # Security appliances
    "server": 1.5,       # Production servers
    "workstation": 0.8   # Endpoints
}


def get_db_session():
    """Get database session"""
    if SessionLocal:
        return SessionLocal()
    return None


def simulate_tenable_scan() -> Dict[str, Any]:
    """
    Simulate a Tenable vulnerability scan.
    Returns scan results as if from a real scanner.
    """
    scan_id = f"SCAN-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    scan_time = datetime.now().isoformat()
    
    # Add some randomness to make it feel like a real scan
    findings = []
    for vuln in SIMULATED_SCANNER_FINDINGS:
        # Randomly adjust some values slightly
        finding = vuln.copy()
        finding["scan_id"] = scan_id
        finding["scan_time"] = scan_time
        finding["last_seen"] = scan_time
        findings.append(finding)
    
    return {
        "success": True,
        "scan_id": scan_id,
        "scan_time": scan_time,
        "scanner": "Tenable.io",
        "scan_policy": "Full Network Scan",
        "total_hosts_scanned": 11,
        "total_vulnerabilities": len(findings),
        "findings": findings,
        "summary": {
            "critical": len([f for f in findings if f["severity"] == "Critical"]),
            "high": len([f for f in findings if f["severity"] == "High"]),
            "medium": len([f for f in findings if f["severity"] == "Medium"]),
            "low": len([f for f in findings if f["severity"] == "Low"])
        }
    }


def calculate_ai_risk_score(
    cvss_score: float,
    asset_criticality: str,
    asset_type: str,
    in_cisa_kev: bool,
    exploit_available: bool,
    epss_score: float
) -> Dict[str, Any]:
    """
    Calculate AI-powered risk score based on multiple factors.
    
    Formula:
    AI Risk Score = Base CVSS × Asset Factor × Threat Factor
    
    Where:
    - Asset Factor = Criticality Weight × Asset Type Weight
    - Threat Factor = KEV Multiplier × Exploit Multiplier × EPSS Factor
    """
    # Base score from CVSS (normalized to 0-10)
    base_score = cvss_score
    
    # Asset factor
    criticality_weight = CRITICALITY_WEIGHTS.get(asset_criticality.lower(), 1.0)
    asset_type_weight = ASSET_TYPE_WEIGHTS.get(asset_type.lower(), 1.0)
    asset_factor = (criticality_weight + asset_type_weight) / 2
    
    # Threat factor
    kev_multiplier = 1.5 if in_cisa_kev else 1.0
    exploit_multiplier = 1.3 if exploit_available else 1.0
    epss_factor = 1.0 + (epss_score * 0.5)  # EPSS adds up to 50% boost
    threat_factor = kev_multiplier * exploit_multiplier * epss_factor
    
    # Calculate final score (cap at 100)
    raw_score = base_score * asset_factor * threat_factor
    ai_risk_score = min(100, raw_score * 10)  # Scale to 0-100
    
    # Determine priority
    if ai_risk_score >= 80:
        priority = "FIX NOW"
        priority_order = 1
    elif ai_risk_score >= 60:
        priority = "Fix This Week"
        priority_order = 2
    elif ai_risk_score >= 40:
        priority = "Fix This Month"
        priority_order = 3
    else:
        priority = "Scheduled"
        priority_order = 4
    
    return {
        "ai_risk_score": round(ai_risk_score, 1),
        "priority": priority,
        "priority_order": priority_order,
        "factors": {
            "base_cvss": cvss_score,
            "asset_criticality": asset_criticality,
            "asset_criticality_weight": criticality_weight,
            "asset_type": asset_type,
            "asset_type_weight": asset_type_weight,
            "asset_factor": round(asset_factor, 2),
            "in_cisa_kev": in_cisa_kev,
            "kev_multiplier": kev_multiplier,
            "exploit_available": exploit_available,
            "exploit_multiplier": exploit_multiplier,
            "epss_score": epss_score,
            "epss_factor": round(epss_factor, 2),
            "threat_factor": round(threat_factor, 2)
        },
        "reasoning": _generate_risk_reasoning(
            cvss_score, asset_criticality, in_cisa_kev, 
            exploit_available, epss_score, ai_risk_score
        )
    }


def _generate_risk_reasoning(
    cvss_score: float, 
    asset_criticality: str, 
    in_cisa_kev: bool,
    exploit_available: bool,
    epss_score: float,
    ai_risk_score: float
) -> str:
    """Generate human-readable reasoning for the risk score"""
    reasons = []
    
    if cvss_score >= 9.0:
        reasons.append(f"Critical CVSS score of {cvss_score}")
    elif cvss_score >= 7.0:
        reasons.append(f"High CVSS score of {cvss_score}")
    
    if asset_criticality.lower() == "critical":
        reasons.append("Asset is business-critical")
    elif asset_criticality.lower() == "high":
        reasons.append("Asset has high business importance")
    
    if in_cisa_kev:
        reasons.append("⚠️ ACTIVELY EXPLOITED - Listed in CISA KEV")
    
    if exploit_available:
        reasons.append("Public exploit code available")
    
    if epss_score >= 0.7:
        reasons.append(f"High exploitation probability (EPSS: {epss_score:.0%})")
    elif epss_score >= 0.4:
        reasons.append(f"Moderate exploitation probability (EPSS: {epss_score:.0%})")
    
    if not reasons:
        reasons.append("Standard vulnerability requiring routine patching")
    
    return "; ".join(reasons)


def get_remediation_guidance(cve_id: str, vendor: str, product: str) -> Dict[str, Any]:
    """
    Generate AI-powered remediation guidance for a vulnerability.
    """
    # Find the vulnerability in our simulated data
    vuln = next((v for v in SIMULATED_SCANNER_FINDINGS if v["cve_id"] == cve_id), None)
    
    if not vuln:
        return {
            "success": False,
            "error": f"CVE {cve_id} not found"
        }
    
    # Generate detailed remediation steps
    steps = [
        {
            "step": 1,
            "action": "Verify Vulnerability",
            "details": f"Confirm {cve_id} affects {vuln['hostname']} ({vuln['ip_address']}) by reviewing scan results and validating the installed version of {product}."
        },
        {
            "step": 2,
            "action": "Assess Impact",
            "details": f"This is a {vuln['severity']} severity vulnerability. Exploitation could lead to: {_get_impact_description(vuln['description'])}"
        },
        {
            "step": 3,
            "action": "Apply Remediation",
            "details": vuln["solution"]
        },
        {
            "step": 4,
            "action": "Verify Fix",
            "details": "After patching, run a targeted vulnerability scan to confirm the vulnerability is resolved."
        },
        {
            "step": 5,
            "action": "Document",
            "details": "Update the remediation ticket with patch date, version changes, and verification results."
        }
    ]
    
    # Add workaround if available
    workaround = _get_workaround(vuln)
    
    return {
        "success": True,
        "cve_id": cve_id,
        "vendor": vendor,
        "product": product,
        "severity": vuln["severity"],
        "solution_summary": vuln["solution"],
        "steps": steps,
        "workaround": workaround,
        "references": [
            f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
        ],
        "estimated_time": "30-60 minutes" if vuln["severity"] in ["Critical", "High"] else "15-30 minutes"
    }


def _get_impact_description(description: str) -> str:
    """Extract impact from vulnerability description"""
    desc_lower = description.lower()
    if "remote code execution" in desc_lower or "rce" in desc_lower:
        return "Remote code execution allowing attacker to run arbitrary commands"
    elif "privilege escalation" in desc_lower:
        return "Privilege escalation to administrator/root access"
    elif "authentication bypass" in desc_lower:
        return "Bypassing authentication controls to gain unauthorized access"
    elif "denial of service" in desc_lower:
        return "Service disruption affecting availability"
    elif "information disclosure" in desc_lower:
        return "Exposure of sensitive data"
    else:
        return "System compromise and potential data breach"


def _get_workaround(vuln: Dict) -> Optional[str]:
    """Get workaround if patching isn't immediately possible"""
    if vuln.get("in_cisa_kev"):
        return "⚠️ This vulnerability is actively exploited. If patching is not immediately possible: 1) Isolate the affected system 2) Implement network-level blocking 3) Enable enhanced monitoring 4) Patch within 24 hours"
    elif vuln.get("exploit_available"):
        return "If immediate patching is not possible, consider: 1) Network segmentation 2) Web application firewall rules 3) Enhanced logging and monitoring"
    return None


def get_vmg_dashboard_stats(vulnerabilities: List[Dict]) -> Dict[str, Any]:
    """
    Calculate dashboard statistics for vulnerability management.
    """
    if not vulnerabilities:
        return {
            "total_vulnerabilities": 0,
            "by_severity": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
            "by_priority": {},
            "kev_count": 0,
            "exploit_available_count": 0,
            "mean_risk_score": 0,
            "assets_affected": 0,
            "fix_now_count": 0
        }
    
    by_severity = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    by_priority = {"FIX NOW": 0, "Fix This Week": 0, "Fix This Month": 0, "Scheduled": 0}
    kev_count = 0
    exploit_count = 0
    total_risk_score = 0
    affected_assets = set()
    
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "Medium")
        by_severity[severity] = by_severity.get(severity, 0) + 1
        
        priority = vuln.get("priority", "Scheduled")
        by_priority[priority] = by_priority.get(priority, 0) + 1
        
        if vuln.get("in_cisa_kev"):
            kev_count += 1
        if vuln.get("exploit_available"):
            exploit_count += 1
        
        total_risk_score += vuln.get("ai_risk_score", 0)
        affected_assets.add(vuln.get("hostname", ""))
    
    return {
        "total_vulnerabilities": len(vulnerabilities),
        "by_severity": by_severity,
        "by_priority": by_priority,
        "kev_count": kev_count,
        "exploit_available_count": exploit_count,
        "mean_risk_score": round(total_risk_score / len(vulnerabilities), 1),
        "assets_affected": len(affected_assets),
        "fix_now_count": by_priority.get("FIX NOW", 0)
    }


def prioritize_vulnerabilities(vulnerabilities: List[Dict]) -> List[Dict]:
    """
    Sort vulnerabilities by AI risk score (descending).
    """
    return sorted(vulnerabilities, key=lambda x: x.get("ai_risk_score", 0), reverse=True)
