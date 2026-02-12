"""
API Key Authentication for Ingestion Endpoints
Provides security for webhook endpoints.
"""
import os
import secrets
import hashlib
from datetime import datetime
from typing import Optional, Dict, Any
from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader
from dotenv import load_dotenv

load_dotenv()


# API Key header configuration
API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


# In-memory API key store (in production, use a database)
API_KEYS: Dict[str, Dict[str, Any]] = {}


def init_default_keys():
    """Initialize default API keys from environment"""
    default_key = os.getenv("INGESTION_API_KEY", "")
    
    if not default_key:
        default_key = secrets.token_urlsafe(32)
        print(f"⚠️  No INGESTION_API_KEY set. Generated default key: {default_key}")
        print(f"   Add to .env: INGESTION_API_KEY={default_key}")
    
    key_hash = hashlib.sha256(default_key.encode()).hexdigest()
    API_KEYS[key_hash] = {
        "name": "default",
        "created_at": datetime.utcnow(),
        "permissions": ["ingest", "read"]
    }
    
    return default_key


def generate_api_key(name: str, permissions: list = None) -> str:
    """Generate a new API key."""
    raw_key = secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    
    API_KEYS[key_hash] = {
        "name": name,
        "created_at": datetime.utcnow(),
        "permissions": permissions or ["ingest"]
    }
    
    return raw_key


def validate_api_key(api_key: str, required_permission: str = "ingest") -> Dict[str, Any]:
    """Validate an API key and check permissions."""
    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="API key required. Include X-API-Key header."
        )
    
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    key_data = API_KEYS.get(key_hash)
    
    if not key_data:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    if required_permission not in key_data.get("permissions", []):
        raise HTTPException(
            status_code=403,
            detail=f"Insufficient permissions. Required: {required_permission}"
        )
    
    return key_data


async def require_api_key(
    api_key: str = Security(API_KEY_HEADER)
) -> Dict[str, Any]:
    """FastAPI dependency for requiring API key authentication."""
    return validate_api_key(api_key, "ingest")


async def optional_api_key(
    api_key: Optional[str] = Security(API_KEY_HEADER)
) -> Optional[Dict[str, Any]]:
    """FastAPI dependency for optional API key authentication."""
    if not api_key:
        require_auth = os.getenv("REQUIRE_INGESTION_AUTH", "false").lower() == "true"
        if require_auth:
            raise HTTPException(
                status_code=401,
                detail="API key required. Include X-API-Key header."
            )
        return None
    
    return validate_api_key(api_key, "ingest")


def list_api_keys() -> list:
    """List all API keys (without revealing the actual keys)."""
    return [
        {
            "key_hash": key_hash[:16] + "...",
            "name": data["name"],
            "created_at": data["created_at"].isoformat(),
            "permissions": data["permissions"]
        }
        for key_hash, data in API_KEYS.items()
    ]


# Initialize default keys on module load
DEFAULT_API_KEY = init_default_keys()
