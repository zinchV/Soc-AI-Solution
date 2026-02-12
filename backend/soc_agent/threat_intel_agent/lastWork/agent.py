"""Threat Intelligence Agent"""

from google.adk.agents import LlmAgent

# CORRECT import path for YOUR project
from soc_agent.threat_intel_agent.tools import (
    fetch_cisa_kevs_tool,
    check_asset_exposure_tool,
    create_detection_rule_tool,
    find_sigma_rules_tool
)

INSTRUCTION = """You are a Threat Intelligence Analyst.

YOUR JOB:
1. Fetch threat intel from CISA KEV
2. Check if our assets are exposed
3. Find or create detection rules
4. Provide actionable recommendations

Be concise. SOC analysts need clear guidance.
"""

threat_intel_agent = LlmAgent(
    name='threat_intel_agent',
    model='gemini-2.0-flash',
    description='Threat intel to detection rules',
    instruction=INSTRUCTION,
    tools=[
        fetch_cisa_kevs_tool,
        check_asset_exposure_tool,
        create_detection_rule_tool,
        find_sigma_rules_tool
    ]
)
