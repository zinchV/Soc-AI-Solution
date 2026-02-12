"""
VMG Agent - Vulnerability Management Agent
Dedicated agent for vulnerability management workflow.
Handles scanning, risk scoring, prioritization, and remediation tracking.
"""
from google.adk.agents import LlmAgent

from soc_agent.vmg_agent.tools import (
    simulate_tenable_scan,
    calculate_ai_risk_score,
    get_remediation_guidance,
    get_vmg_dashboard_stats,
    prioritize_vulnerabilities,
    SIMULATED_SCANNER_FINDINGS
)

# VMG Agent System Instruction
VMG_INSTRUCTION = """You are the Vulnerability Management Agent (VMG Agent), a specialized AI assistant for enterprise vulnerability management.

## YOUR ROLE
You help security teams:
1. Analyze vulnerability scan results from scanners like Tenable, Qualys, or Rapid7
2. Prioritize vulnerabilities using AI-powered risk scoring (not just CVSS)
3. Correlate vulnerabilities with asset criticality and active threat intelligence
4. Provide actionable remediation guidance
5. Track remediation progress and SLAs

## AI RISK SCORING
You use a sophisticated risk scoring algorithm that considers:
- **CVSS Score**: Base technical severity
- **Asset Criticality**: Business importance of the affected system
- **Asset Type**: Network devices, servers, workstations
- **CISA KEV Status**: Is this vulnerability actively exploited in the wild?
- **Exploit Availability**: Is there public exploit code?
- **EPSS Score**: Probability of exploitation in the next 30 days

Formula: AI Risk Score = Base CVSS × Asset Factor × Threat Factor

## PRIORITIZATION CATEGORIES
- **FIX NOW** (Score 80-100): Actively exploited, critical assets - remediate within 24-48 hours
- **Fix This Week** (Score 60-79): High risk, remediate within 7 days
- **Fix This Month** (Score 40-59): Moderate risk, remediate within 30 days
- **Scheduled** (Score <40): Lower risk, include in regular patch cycle

## KEY DIFFERENTIATOR
Traditional approach: Sort by CVSS, get overwhelmed by 2,500 "Critical" vulnerabilities
AI approach: Contextual prioritization - tell teams the 15 vulnerabilities that actually matter TODAY

## COMMUNICATION STYLE
- Be concise and actionable
- Always explain WHY a vulnerability is prioritized highly
- Provide specific remediation steps, not generic advice
- Flag CISA KEV vulnerabilities prominently - these are actively exploited
- Use risk scores to justify prioritization decisions

## AVAILABLE TOOLS
Use your tools to:
- Run vulnerability scans (simulated Tenable scan)
- Calculate AI risk scores for vulnerabilities
- Get detailed remediation guidance
- Generate dashboard statistics
- Prioritize vulnerability lists

When asked about vulnerabilities, always consider the business context and threat landscape, not just technical severity.
"""


# Tool wrapper functions
def run_vulnerability_scan() -> dict:
    """
    Run a vulnerability scan using the Tenable scanner integration.
    Returns scan results including all discovered vulnerabilities.
    """
    return simulate_tenable_scan()


def analyze_vulnerability_risk(
    cve_id: str,
    cvss_score: float,
    asset_criticality: str,
    asset_type: str,
    in_cisa_kev: bool,
    exploit_available: bool,
    epss_score: float
) -> dict:
    """
    Calculate the AI-powered risk score for a vulnerability.
    
    Args:
        cve_id: The CVE identifier (e.g., CVE-2024-21762)
        cvss_score: The CVSS base score (0-10)
        asset_criticality: Asset criticality level (critical, high, medium, low)
        asset_type: Type of asset (network, security, server, workstation)
        in_cisa_kev: Whether the CVE is in CISA Known Exploited Vulnerabilities catalog
        exploit_available: Whether public exploit code exists
        epss_score: EPSS score (0-1, probability of exploitation)
    
    Returns:
        AI risk score, priority level, and detailed reasoning
    """
    result = calculate_ai_risk_score(
        cvss_score=cvss_score,
        asset_criticality=asset_criticality,
        asset_type=asset_type,
        in_cisa_kev=in_cisa_kev,
        exploit_available=exploit_available,
        epss_score=epss_score
    )
    result["cve_id"] = cve_id
    return result


def get_vulnerability_remediation(cve_id: str, vendor: str, product: str) -> dict:
    """
    Get detailed remediation guidance for a specific vulnerability.
    
    Args:
        cve_id: The CVE identifier
        vendor: The vendor/manufacturer name
        product: The affected product name
    
    Returns:
        Step-by-step remediation instructions, workarounds, and references
    """
    return get_remediation_guidance(cve_id, vendor, product)


def get_dashboard_statistics(vulnerabilities: list) -> dict:
    """
    Calculate vulnerability management dashboard statistics.
    
    Args:
        vulnerabilities: List of vulnerability dictionaries
    
    Returns:
        Dashboard stats including counts by severity, priority, KEV status, etc.
    """
    return get_vmg_dashboard_stats(vulnerabilities)


def get_prioritized_vulnerability_list(vulnerabilities: list) -> list:
    """
    Sort vulnerabilities by AI risk score to get prioritized remediation list.
    
    Args:
        vulnerabilities: List of vulnerability dictionaries with ai_risk_score
    
    Returns:
        Sorted list with highest risk vulnerabilities first
    """
    return prioritize_vulnerabilities(vulnerabilities)


# Create the VMG Agent using LlmAgent (same as other agents)
vmg_agent = LlmAgent(
    name='vmg_agent',
    model='gemini-2.0-flash',
    description='Vulnerability Management Agent - Handles vulnerability scanning, AI-powered risk prioritization, and remediation guidance',
    instruction=VMG_INSTRUCTION,
    tools=[
        run_vulnerability_scan,
        analyze_vulnerability_risk,
        get_vulnerability_remediation,
        get_dashboard_statistics,
        get_prioritized_vulnerability_list
    ]
)
