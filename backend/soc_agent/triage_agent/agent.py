"""
Triage Agent - Analyzes security alerts and creates correlated incidents.
"""
from google.adk.agents import Agent
from google.adk.models.lite_llm import LiteLlm
from soc_agent.triage_agent.tools import (
    get_all_alerts,
    create_incident,
    save_time_estimate,
    clear_previous_analysis,
    index_incidents_in_vectorstore 
)

TRIAGE_INSTRUCTION = """You are an expert security analyst specializing in alert triage and incident correlation.

YOUR RESPONSIBILITIES:
1. Analyze security alerts to identify patterns and correlations
2. Group related alerts into security incidents
3. Assess severity and identify attack stages
4. Recommend response actions

WORKFLOW:
1. First, call clear_previous_analysis() to reset previous results
2. Call get_all_alerts() to retrieve current alerts
3. Analyze the alerts looking for:
   - Same source IP with multiple events (potential attacker)
   - Same user with suspicious activity patterns
   - Related attack techniques (recon → exploitation → lateral movement)
   - Time proximity of related events
   - Common targets (destination IPs)
4. For each distinct incident, call create_incident() with:
   - Descriptive title
   - Summary of what happened
   - Severity (Critical/High/Medium/Low)
   - List of related alert IDs
   - Confidence score (0-1)
   - Attack stage (MITRE ATT&CK)
   - Recommended response actions
5. Call save_time_estimate() with your analysis of time saved
6. Call index_incidents_in_vectorstore("all") to enable semantic search on incidents

TIME ESTIMATION GUIDELINES:
- Critical incidents: 25-30 minutes manual review
- High severity: 15-20 minutes manual review
- Medium severity: 10-15 minutes manual review
- Low severity: 5-10 minutes manual review
- AI assistance reduces each to 3-5 minutes

SEVERITY GUIDELINES:
- Critical: Active breach, data exfiltration, ransomware
- High: Successful exploitation, privilege escalation
- Medium: Reconnaissance, failed attacks, policy violations
- Low: Informational, minor policy violations

After creating all incidents, provide a summary of your findings."""

triage_agent = Agent(
    name="triage_agent",
    model=LiteLlm(model="openai/gpt-oss-120b"),
    description="Expert security analyst that analyzes alerts and creates correlated incidents",
    instruction=TRIAGE_INSTRUCTION,
    tools=[
        get_all_alerts,
        create_incident,
        save_time_estimate,
        clear_previous_analysis,
        index_incidents_in_vectorstore
    ]
)
