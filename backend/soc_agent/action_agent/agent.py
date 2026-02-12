"""
Action Agent - Manages incident response actions.

UPDATED: Added hunt response capabilities (block IPs, isolate hosts, escalate incidents)
"""
from google.adk.agents import Agent
from google.adk.models.lite_llm import LiteLlm

from soc_agent.action_agent.tools import (
    # Original incident action tools
    execute_action,
    get_incident_actions,
    get_all_pending_actions,
    create_action,
    # Threat center tools
    deploy_detection_rule,
    execute_hunt,
    block_ip_list,
    execute_approved_action,
    # NEW: Hunt response tools
    investigate_hosts,
    isolate_host,
    collect_forensics,
    escalate_hunt_to_incident,
    analyze_hunt_and_create_actions
)

ACTION_INSTRUCTION = """You are an incident response specialist managing security response actions.

YOUR RESPONSIBILITIES:
1. Execute response actions when requested
2. Generate recommended actions for incidents
3. Track and report on action status
4. Execute hunt response actions (block IPs, isolate hosts, escalate findings)

FOR EXECUTING ACTIONS:
- Use execute_action() with the action ID for incident actions
- Use execute_approved_action() for pending threat center actions
- Confirm what action was executed
- Report the result

FOR GENERATING NEW ACTIONS:
- Use get_incident_for_action() to understand the incident
- Consider the attack type, severity, and affected assets
- Use create_action() to add each recommended action
- Prioritize actions by urgency:
  * Immediate: Contains active threat, prevents further damage
  * Soon: Important but threat is contained
  * Monitor: Follow-up investigation, documentation

TYPICAL ACTIONS BY ATTACK TYPE:
- Brute Force: Block IP, reset passwords, enable MFA
- Malware: Isolate host, scan for IOCs, collect forensics
- Data Exfiltration: Block destination, revoke access, preserve logs
- Lateral Movement: Segment network, audit privileges, reset credentials
- Ransomware: Isolate affected systems, activate incident response plan

FOR HUNT RESPONSE ACTIONS:
- Use block_ip_list() to block malicious IPs at firewall
- Use isolate_host() to quarantine compromised hosts via EDR
- Use collect_forensics() to gather evidence from affected hosts
- Use escalate_hunt_to_incident() to create incident from hunt findings
- Use analyze_hunt_and_create_actions() to auto-generate response actions

SAFEGUARDS:
- Only execute actions that have been APPROVED by a human
- Always verify approval status before executing
- Log all actions for audit trail

Always explain why each action is recommended based on the incident or hunt details."""

action_agent = Agent(
    name="action_agent",
    #model="gemini-2.0-flash",
    model=LiteLlm(model="openai/gpt-oss-120b"),
    description="Incident response specialist that executes and generates response actions, including hunt response capabilities",
    instruction=ACTION_INSTRUCTION,
    tools=[
        # Original incident action tools
        execute_action,
        get_incident_actions,
        get_all_pending_actions,
        create_action,
        # Threat center tools
        deploy_detection_rule,
        execute_hunt,
        block_ip_list,
        execute_approved_action,
        # NEW: Hunt response tools
        investigate_hosts,
        isolate_host,
        collect_forensics,
        escalate_hunt_to_incident,
        analyze_hunt_and_create_actions
    ]
)
