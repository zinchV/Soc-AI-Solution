"""
Ingestion Module
Handles alert ingestion from multiple SIEM formats with auto-triage.
"""

from .router import ingestion_router
from .auto_triage import auto_triage_manager, AutoTriageManager, TriageMode
from .normalizer import AlertNormalizer

__all__ = [
    "ingestion_router",
    "auto_triage_manager",
    "AutoTriageManager",
    "TriageMode",
    "AlertNormalizer"
]
