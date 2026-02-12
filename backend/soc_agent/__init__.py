"""
SOC Agent - Multi-agent system for Security Operations Center automation.

This module provides:
- run_agent: Function to run the orchestrator agent
- run_agent_stream: Async generator for streaming responses
- APP_NAME: Application name constant
- Individual agents: triage_agent, action_agent, threat_intel_agent, threat_hunt_agent
"""
import asyncio
from typing import Dict, Any, Optional, AsyncGenerator

from dotenv import load_dotenv
load_dotenv()

from soc_agent.agent import root_agent, soc_agent

# Application constants
APP_NAME = "soc_ai_tool"

# Import individual agents
try:
    from soc_agent.triage_agent import triage_agent
except ImportError:
    triage_agent = None

try:
    from soc_agent.action_agent import action_agent
except ImportError:
    action_agent = None

try:
    from soc_agent.threat_intel_agent import threat_intel_agent
except ImportError:
    threat_intel_agent = None

try:
    from soc_agent.threat_hunt_agent import threat_hunt_agent
except ImportError:
    threat_hunt_agent = None

try:
    from soc_agent.soc_agent import root_agent
except ImportError:
    orchestrator_agent = None


async def run_agent(
    user_message: str = None,
    message: str = None,  # Alias for backward compatibility
    user_id: str = "default_user",
    session_id: str = None,
    agent_type: str = "orchestrator"
) -> Dict[str, Any]:
    """
    Run the SOC AI agent with a user message.
    
    Args:
        user_message: The user's input message
        message: Alias for user_message (backward compatibility)
        user_id: User identifier for session management
        session_id: Optional session ID for conversation continuity
        agent_type: Type of agent to run (orchestrator, triage, action, threat_intel, threat_hunt)
    
    Returns:
        Dictionary with agent response
    """
    # Support both parameter names
    msg = user_message or message
    if not msg:
        return {
            "success": False,
            "error": "No message provided",
            "response": "Please provide a message."
        }
    
    try:
        # Import the runner here to avoid circular imports
        from google.adk.runners import Runner
        from google.adk.sessions import InMemorySessionService
        
        # Select the appropriate agent
        if agent_type == "triage" and triage_agent:
            agent = triage_agent
        elif agent_type == "action" and action_agent:
            agent = action_agent
        elif agent_type == "threat_intel" and threat_intel_agent:
            agent = threat_intel_agent
        elif agent_type == "threat_hunt" and threat_hunt_agent:
            agent = threat_hunt_agent
        elif orchestrator_agent:
            agent = orchestrator_agent
        elif triage_agent:
            # Fallback to triage if orchestrator not available
            agent = triage_agent
        else:
            return {
                "success": False,
                "error": "No agent available",
                "response": "Sorry, no AI agent is currently configured."
            }
        
        # Create session service and runner
        session_service = InMemorySessionService()
        runner = Runner(
            agent=root_agent,
            app_name=APP_NAME,
            session_service=session_service
        )
        
        # Generate session ID if not provided
        if not session_id:
            import uuid
            session_id = str(uuid.uuid4())
        
        # Create or get session
        session = await session_service.create_session(
            app_name=APP_NAME,
            user_id=user_id,
            session_id=session_id
        )
        
        # Run the agent
        from google.genai import types
        content = types.Content(
            role="user",
            parts=[types.Part(text=msg)]
        )
        
        response_text = ""
        async for event in runner.run_async(
            user_id=user_id,
            session_id=session_id,
            new_message=content
        ):
            if hasattr(event, 'content') and event.content:
                for part in event.content.parts:
                    if hasattr(part, 'text') and part.text:
                        response_text += part.text
        
        return {
            "success": True,
            "response": response_text,
            "session_id": session_id,
            "agent_type": agent_type
        }
        
    except Exception as e:
        import traceback
        return {
            "success": False,
            "error": str(e),
            "traceback": traceback.format_exc(),
            "response": f"Sorry, I encountered an error: {str(e)}"
        }


async def run_agent_stream(
    user_message: str = None,
    message: str = None,  # Alias for backward compatibility
    user_id: str = "default_user",
    session_id: str = None,
    agent_type: str = "orchestrator"
) -> AsyncGenerator[str, None]:
    """
    Run the SOC AI agent with streaming response.
    
    Yields:
        String chunks of the agent's response
    """
    # Support both parameter names
    msg = user_message or message
    if not msg:
        yield "Please provide a message."
        return
    
    try:
        from google.adk.runners import Runner
        from google.adk.sessions import InMemorySessionService
        
        # Select the appropriate agent
        if agent_type == "triage" and triage_agent:
            agent = triage_agent
        elif agent_type == "action" and action_agent:
            agent = action_agent
        elif agent_type == "threat_intel" and threat_intel_agent:
            agent = threat_intel_agent
        elif agent_type == "threat_hunt" and threat_hunt_agent:
            agent = threat_hunt_agent
        elif orchestrator_agent:
            agent = orchestrator_agent
        elif triage_agent:
            agent = triage_agent
        else:
            yield "Sorry, no AI agent is currently configured."
            return
        
        # Create session service and runner
        session_service = InMemorySessionService()
        runner = Runner(
            agent=agent,
            app_name=APP_NAME,
            session_service=session_service
        )
        
        # Generate session ID if not provided
        if not session_id:
            import uuid
            session_id = str(uuid.uuid4())
        
        # Create session
        session = await session_service.create_session(
            app_name=APP_NAME,
            user_id=user_id,
            session_id=session_id
        )
        
        # Run the agent with streaming
        from google.genai import types
        content = types.Content(
            role="user",
            parts=[types.Part(text=msg)]
        )
        
        async for event in runner.run_async(
            user_id=user_id,
            session_id=session_id,
            new_message=content
        ):
            if hasattr(event, 'content') and event.content:
                for part in event.content.parts:
                    if hasattr(part, 'text') and part.text:
                        yield part.text
                        
    except Exception as e:
        yield f"Sorry, I encountered an error: {str(e)}"


# Export all public symbols
__all__ = [
    'APP_NAME',
    'run_agent',
    'runner',
    'session_service',
    'run_agent_stream',
    'triage_agent',
    'vmg_agent'
    'action_agent',
    'threat_intel_agent',
    'training_agent'
    'threat_hunt_agent',
    'chat_agent',
    'orchestrator_agent'
]



