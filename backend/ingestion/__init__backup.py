"""
Ingestion Module
Handles real-time alert ingestion from various SIEM systems.
"""
from ingestion.router import router as ingestion_router
from ingestion.auth import (
    require_api_key,
    optional_api_key,
    generate_api_key,
    list_api_keys,
    DEFAULT_API_KEY
)
from ingestion.normalizer import (
    normalize_alert,
    normalize_alerts,
    get_normalizer,
    NORMALIZERS
)
from ingestion.auto_triage import (
    auto_triage_manager,
    AutoTriageConfig,
    TriggerType
)

__all__ = [
    'ingestion_router',
    'require_api_key',
    'optional_api_key',
    'generate_api_key',
    'list_api_keys',
    'DEFAULT_API_KEY',
    'normalize_alert',
    'normalize_alerts',
    'get_normalizer',
    'NORMALIZERS',
    'auto_triage_manager',
    'AutoTriageConfig',
    'TriggerType'
]
