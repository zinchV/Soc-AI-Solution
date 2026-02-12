"""
SOC Agent Package - Multi-agent security operations system.

This package provides:
- soc_agent: Main orchestrator agent
- runner: ADK Runner for executing agent interactions
- Sub-agents: triage, chat, action, training
"""


# SSL bypass - MUST be at very top before any other imports
import ssl
import os
import urllib3

# Disable SSL warnings and verification
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
os.environ['CURL_CA_BUNDLE'] = ''
os.environ['REQUESTS_CA_BUNDLE'] = ''
os.environ['SSL_CERT_FILE'] = ''
os.environ['GRPC_SSL_CIPHER_SUITES'] = 'HIGH+ECDSA'

# Monkey-patch SSL context
ssl._create_default_https_context = ssl._create_unverified_context

# Patch httpx to disable SSL verification
import httpx
_original_client = httpx.Client
_original_async_client = httpx.AsyncClient

class PatchedClient(_original_client):
    def __init__(self, *args, **kwargs):
        kwargs['verify'] = False
        super().__init__(*args, **kwargs)

class PatchedAsyncClient(_original_async_client):
    def __init__(self, *args, **kwargs):
        kwargs['verify'] = False
        super().__init__(*args, **kwargs)

httpx.Client = PatchedClient
httpx.AsyncClient = PatchedAsyncClient
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()



from google.adk.agents import Agent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

# Import the main orchestrator
from soc_agent.agent import soc_agent

# Import sub-agents for direct access if needed
from soc_agent.triage_agent import triage_agent
from soc_agent.chat_agent import chat_agent
from soc_agent.action_agent import action_agent
from soc_agent.training_agent import training_agent

# Create session service for conversation memory
session_service = InMemorySessionService()

# Create the runner
runner = Runner(
    agent=soc_agent,
    app_name="soc_ai_tool",
    session_service=session_service
)

# Constants
APP_NAME = "soc_ai_tool"
DEFAULT_USER_ID = "soc_analyst"

async def run_agent(message: str, user_id: str = DEFAULT_USER_ID, session_id: str = None):
    """
    Run the SOC agent with a message.
    
    Args:
        message: The user's message/request
        user_id: User identifier (default: soc_analyst)
        session_id: Session ID for conversation continuity
    
    Returns:
        Dictionary with agent response and metadata
    """
    import uuid
    
    if session_id is None:
        session_id = str(uuid.uuid4())
    
    try:
        # Always create a fresh session
        session = await session_service.create_session(
            app_name=APP_NAME,
            user_id=user_id,
            session_id=session_id
        )
        
        # Run the agent
        response_text = ""
        async for event in runner.run_async(
            user_id=user_id,
            session_id=session_id,
            new_message=types.Content(
                role="user",
                parts=[types.Part(text=message)]
            )
        ):
            if hasattr(event, 'content') and event.content:
                if hasattr(event.content, 'parts'):
                    for part in event.content.parts:
                        if hasattr(part, 'text') and part.text:
                            response_text += part.text
        
        return {
            "success": True,
            "response": response_text,
            "session_id": session_id,
            "user_id": user_id
        }
        
    except Exception as e:
        import traceback
        return {
            "success": False,
            "error": str(e),
            "traceback": traceback.format_exc(),
            "session_id": session_id
        }


__all__ = [
    'soc_agent',
    'runner',
    'session_service',
    'run_agent',
    'triage_agent',
    'chat_agent',
    'action_agent',
    'training_agent',
    'APP_NAME',
    'DEFAULT_USER_ID'
]
