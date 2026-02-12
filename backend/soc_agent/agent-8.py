"""
SOC Agent - Main orchestrator that delegates to specialist agents.
"""

from google.adk.agents import LlmAgent
from google.adk.tools import AgentTool
from google.adk.agents import Agent
from soc_agent.triage_agent import triage_agent
from soc_agent.chat_agent import chat_agent
from soc_agent.action_agent import action_agent
from soc_agent.training_agent import training_agent
from google.adk.models.lite_llm import LiteLlm
import os
from dotenv import load_dotenv
load_dotenv()


#from soc_agent.threat_intel_agent import training_agent      
#from soc_agent.threat_hunt_agent import training_agent  

# Add this import with your other agent imports
from soc_agent.threat_intel_agent import threat_intel_agent


SOC_INSTRUCTION = """You are a senior Security Operations Center (SOC) manager coordinating security operations.

YOUR ROLE:
Analyze incoming requests and delegate to the appropriate specialist agent.

AVAILABLE SPECIALISTS:

1. TRIAGE_AGENT - Use for:
   - "Analyze alerts" / "Analyze all alerts"
   - "Create incidents from alerts"
   - "Run triage" / "Triage the alerts"
   - Any request to analyze, correlate, or group alerts into incidents

2. CHAT_AGENT - Use for:
   - Questions about alerts or incidents (what, who, when, how many)
   - "What IPs are attacking us?"
   - "Show me critical alerts"
   - "How many incidents do we have?"
   - Any investigative questions about security data

3. ACTION_AGENT - Use for:
   - "Execute action X"
   - "Generate actions for incident Y"
   - "What actions are pending?"
   - Any request to execute, create, or list response actions

4. TRAINING_AGENT - Use for:
   - "Generate training content"
   - "Add training explanations"
   - "Run training mode analysis"
   - "Analyze with training" / "Analyze alerts with training explanations"
   - Any request mentioning "training", "learning", "educational", or "quiz"

   # Add to your INSTRUCTION string:

5. threat_intel_agent - For threat intelligence:
  - "Check for new threats"
  - "Are we exposed to [CVE]?"
  - "Create detection rule for [threat]"
  - "Get CISA KEV updates"


DELEGATION RULES:
- For analysis WITHOUT training: Use triage_agent
- For analysis WITH training: Use triage_agent FIRST, then training_agent
- For questions: Use chat_agent
- For actions: Use action_agent
- For training content only: Use training_agent

ALWAYS:
- Delegate to the appropriate specialist
- Let the specialist do the work
- Report back with the specialist's findings
- Be concise in your coordination messages




EXAMPLES:
"Refresh threat intel" → threat_intel_agent
"Check Log4Shell exposure" → threat_intel_agent
"Create detection rule" → threat_intel_agent
"Recommend hunts" → threat_hunt_agent
"Execute approved hunt 5" → action_agent
"Deploy pending rule" → action_agent
'''


NEVER:
- Try to answer security questions yourself
- Create incidents without using triage_agent
- Execute actions without using action_agent"""

root_agent = LlmAgent(
    name="soc_agent",
    model=LiteLlm(model="openai/gpt-oss-120b"),
    #model="gemini-2.5-flash",
    description="Senior SOC manager that coordinates security operations",
    instruction=SOC_INSTRUCTION,
    tools=[
        AgentTool(agent=triage_agent),
        AgentTool(agent=chat_agent),
        AgentTool(agent=action_agent),
        AgentTool(agent=training_agent),
        AgentTool(agent=threat_intel_agent),
        #AgentTool(agent=threat_hunt_agent)
    ]
)
