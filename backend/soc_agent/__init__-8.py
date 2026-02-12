"""
SOC Agent Module - Entry point for the multi-agent system
SSL bypass for corporate networks included.
"""
import os
import ssl
import warnings

# ============================================
# AGGRESSIVE SSL BYPASS - Must be FIRST
# ============================================

# Disable all SSL warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Set environment variables BEFORE any imports
os.environ['CURL_CA_BUNDLE'] = ''
os.environ['REQUESTS_CA_BUNDLE'] = ''
os.environ['SSL_CERT_FILE'] = ''
os.environ['SSL_CERT_DIR'] = ''
os.environ['PYTHONHTTPSVERIFY'] = '0'
os.environ['GRPC_SSL_CIPHER_SUITES'] = 'HIGH+ECDSA'

# Disable SSL verification globally
ssl._create_default_https_context = ssl._create_unverified_context

# Create unverified context
try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    pass
else:
    ssl._create_default_https_context = _create_unverified_https_context

# Disable urllib3 warnings
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except:
    pass

# ============================================
# PATCH HTTPX BEFORE ANYTHING ELSE
# ============================================
import httpx

# Store originals
_OriginalClient = httpx.Client
_OriginalAsyncClient = httpx.AsyncClient

class PatchedClient(_OriginalClient):
    def __init__(self, *args, **kwargs):
        kwargs['verify'] = False
        kwargs.setdefault('timeout', 60.0)
        super().__init__(*args, **kwargs)

class PatchedAsyncClient(_OriginalAsyncClient):
    def __init__(self, *args, **kwargs):
        kwargs['verify'] = False
        kwargs.setdefault('timeout', 60.0)
        super().__init__(*args, **kwargs)

# Replace globally
httpx.Client = PatchedClient
httpx.AsyncClient = PatchedAsyncClient

# ============================================
# PATCH GOOGLE GENAI SSL
# ============================================
try:
    import google.auth.transport.requests
    original_request = google.auth.transport.requests.Request
    
    class PatchedRequest(original_request):
        def __init__(self, session=None):
            super().__init__(session)
            if self.session:
                self.session.verify = False
    
    google.auth.transport.requests.Request = PatchedRequest
except:
    pass

# ============================================
# NOW IMPORT GOOGLE ADK
# ============================================
from google.adk.sessions import InMemorySessionService
from google.adk.runners import Runner
from google.genai import types

# Import our agent
from soc_agent.agent import root_agent

# ============================================
# SETUP
# ============================================
APP_NAME = "soc_ai_tool"
session_service = InMemorySessionService()

runner = Runner(
    agent=root_agent,
    app_name=APP_NAME,
    session_service=session_service
)

# ============================================
# MAIN RUN FUNCTION
# ============================================
async def run_agent(message: str, user_id: str = "analyst", session_id: str = None):
    """
    Main entry point for running the SOC agent.
    """
    import uuid
    import traceback
    
    if not session_id:
        session_id = str(uuid.uuid4())
    
    try:
        # Create or get session
        session = await session_service.get_session(
            app_name=APP_NAME,
            user_id=user_id,
            session_id=session_id
        )
        
        if not session:
            session = await session_service.create_session(
                app_name=APP_NAME,
                user_id=user_id,
                session_id=session_id
            )
        
        # Create proper Content object for the message
        user_message = types.Content(
            role="user",
            parts=[types.Part(text=message)]
        )
        
        # Run the agent
        response_text = ""
        async for event in runner.run_async(
            user_id=user_id,
            session_id=session_id,
            new_message=user_message  # Pass Content object, not string
        ):
            if hasattr(event, 'content'):
                if event.content and hasattr(event.content, 'parts'):
                    for part in event.content.parts:
                        if hasattr(part, 'text') and part.text:
                            response_text += part.text
            elif hasattr(event, 'text') and event.text:
                response_text += event.text
        
        return {
            "success": True,
            "response": response_text,
            "session_id": session_id
        }
        
    except Exception as e:
        error_trace = traceback.format_exc()
        print(f"Agent error: {e}")
        print(error_trace)
        return {
            "success": False,
            "error": str(e),
            "traceback": error_trace,
            "session_id": session_id
        }
