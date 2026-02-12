"""
VMG Agent - Vulnerability Management Agent
"""
from .agent import vmg_agent
from .tools import (
    simulate_tenable_scan,
    calculate_ai_risk_score,
    get_remediation_guidance,
    get_vmg_dashboard_stats,
    prioritize_vulnerabilities,
    SIMULATED_SCANNER_FINDINGS
)

__all__ = [
    'vmg_agent',
    'simulate_tenable_scan',
    'calculate_ai_risk_score',
    'get_remediation_guidance',
    'get_vmg_dashboard_stats',
    'prioritize_vulnerabilities',
    'SIMULATED_SCANNER_FINDINGS'
]
