"""
SOC AI Tool Database Models
Complete version with Threat Center models
"""
from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean, DateTime, Float, Index, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import os
import pathlib

from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

BASE_DIR = pathlib.Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

# Convert to string and use proper escaping for SQLite
DATABASE_PATH = str(DATA_DIR / "soc_tool.db").replace("\\", "/")
DATABASE_URL = f"sqlite:///{DATABASE_PATH}"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# ========================= CORE SOC MODELS =========================

class Alert(Base):
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    severity = Column(String(20), index=True)
    source_ip = Column(String(45), index=True)
    destination_ip = Column(String(45))
    user = Column(String(100), index=True)
    description = Column(Text)
    event_type = Column(String(50), index=True)
    upload_id = Column(String(36), index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_alerts_severity_timestamp', 'severity', 'timestamp'),
    )


class Incident(Base):
    __tablename__ = "incidents"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(200))
    summary = Column(Text)
    severity = Column(String(20), index=True)
    alert_count = Column(Integer, default=0)
    alert_ids = Column(Text)  # JSON array as string
    status = Column(String(20), default="active", index=True)
    assigned_to = Column(String(100))
    confidence = Column(Float, default=0.0)
    attack_stage = Column(String(50))
    training_explanation = Column(Text, nullable=True)  # JSON string for training mode
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Action(Base):
    __tablename__ = "actions"
    
    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, index=True)
    action_type = Column(String(50))
    title = Column(String(200))
    description = Column(Text)
    urgency = Column(String(20))  # Immediate, Soon, Monitor
    parameters = Column(Text)  # JSON as string
    executed = Column(Boolean, default=False)
    executed_at = Column(DateTime)
    executed_by = Column(String(100))
    result = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)


class ChatMessage(Base):
    __tablename__ = "chat_messages"
    
    id = Column(Integer, primary_key=True, index=True)
    sender = Column(String(20))  # 'user' or 'ai'
    message = Column(Text)
    sources = Column(Text)  # JSON array of alert IDs
    created_at = Column(DateTime, default=datetime.utcnow)


class MetricsHistory(Base):
    __tablename__ = "metrics_history"
    
    id = Column(Integer, primary_key=True, index=True)
    alert_count = Column(Integer, default=0)
    incident_count = Column(Integer, default=0)
    actions_executed = Column(Integer, default=0)
    time_saved_minutes = Column(Float, default=0.0)
    recorded_at = Column(DateTime, default=datetime.utcnow)


class AITimeEstimate(Base):
    __tablename__ = "ai_time_estimates"
    
    id = Column(Integer, primary_key=True, index=True)
    total_alerts = Column(Integer, default=0)
    total_incidents = Column(Integer, default=0)
    manual_review_minutes = Column(Integer, default=0)
    ai_assisted_minutes = Column(Integer, default=0)
    time_saved_minutes = Column(Integer, default=0)
    explanation = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)


# ========================= THREAT INTELLIGENCE MODELS =========================

class ThreatIntel(Base):
    """Threat intelligence from CISA KEV and other sources"""
    __tablename__ = 'threat_intel'
    
    id = Column(Integer, primary_key=True)
    source = Column(String(50))              # 'cisa_kev', 'nvd', etc.
    cve_id = Column(String(20), unique=True, index=True)
    vendor = Column(String(100))
    product = Column(String(100))
    vulnerability_name = Column(String(200))
    description = Column(Text)
    severity = Column(String(20))
    date_added = Column(DateTime)
    due_date = Column(DateTime, nullable=True)
    ransomware_use = Column(Boolean, default=False)
    notes = Column(Text, nullable=True)
    status = Column(String(20), default='new')  # new, reviewed, actioned
    created_at = Column(DateTime, default=datetime.utcnow)


# ========================= DETECTION RULES MODELS =========================

class DetectionRule(Base):
    """Detection rules awaiting approval and deployment to SIEM"""
    __tablename__ = 'detection_rules'
    
    id = Column(Integer, primary_key=True)
    
    # Rule metadata
    title = Column(String(200))
    description = Column(Text)
    severity = Column(String(20))  # critical, high, medium, low
    mitre_techniques = Column(Text)  # JSON: ['T1059', 'T1190']
    
    # Source context
    source_cve = Column(String(50), nullable=True)
    threat_intel_id = Column(Integer, ForeignKey('threat_intel.id'), nullable=True)
    
    # Rule content
    sigma_rule = Column(Text)  # Original Sigma YAML
    kql_query = Column(Text)   # Converted KQL for Sentinel
    siem_platform = Column(String(50), default='sentinel')  # sentinel, elastic, splunk
    
    # APPROVAL WORKFLOW
    status = Column(String(20), default='pending')
    # Status: pending → approved/rejected → deploying → deployed/failed
    approved_by = Column(String(100), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    rejected_reason = Column(Text, nullable=True)
    
    # Deployment tracking
    deployed_at = Column(DateTime, nullable=True)
    sentinel_rule_id = Column(String(100), nullable=True)
    deployment_error = Column(Text, nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# ========================= THREAT HUNTING MODELS =========================

class Hunt(Base):
    """Threat hunt hypothesis - requires human approval to execute"""
    __tablename__ = 'hunts'
    
    id = Column(Integer, primary_key=True)
    title = Column(String(200))
    description = Column(Text)
    hypothesis = Column(Text)  # What we're looking for
    rationale = Column(Text)   # Why this hunt matters
    mitre_technique = Column(String(50))
    hunt_query = Column(Text)  # Query to run
    data_sources = Column(Text)  # JSON: ['windows_logs', 'firewall']
    priority = Column(String(20))
    
    # Trigger context
    threat_intel_id = Column(Integer, ForeignKey('threat_intel.id'), nullable=True)
    related_cve = Column(String(50), nullable=True)
    detection_rule_id = Column(Integer, ForeignKey('detection_rules.id'), nullable=True)
    
    # APPROVAL WORKFLOW
    status = Column(String(20), default='pending')
    # Status: pending → approved/rejected → executing → completed/failed
    approved_by = Column(String(100), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    rejected_reason = Column(Text, nullable=True)
    
    # Execution tracking
    executed_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    results = relationship('HuntResult', back_populates='hunt')


class HuntResult(Base):
    """Results from an executed hunt"""
    __tablename__ = 'hunt_results'
    
    id = Column(Integer, primary_key=True)
    hunt_id = Column(Integer, ForeignKey('hunts.id'))
    
    # Findings
    findings_count = Column(Integer, default=0)
    findings_summary = Column(Text)
    
    # Extracted IOCs (JSON arrays)
    malicious_ips = Column(Text)        # ['1.2.3.4', '5.6.7.8']
    suspicious_domains = Column(Text)
    suspicious_hashes = Column(Text)
    affected_hosts = Column(Text)       # ['server-01', 'ws-042']
    raw_results = Column(Text)          # Full query results
    
    # Escalation
    escalated = Column(Boolean, default=False)
    incident_id = Column(Integer, ForeignKey('incidents.id'), nullable=True)
    
    executed_at = Column(DateTime, default=datetime.utcnow)
    hunt = relationship('Hunt', back_populates='results')


# ========================= PENDING ACTIONS MODEL =========================

class PendingAction(Base):
    """Actions awaiting human approval (block IPs, deploy rules, quarantine, etc.)"""
    __tablename__ = 'pending_actions'
    
    id = Column(Integer, primary_key=True)
    
    # Action details
    action_type = Column(String(50))  # 'deploy_rule', 'block_ips', 'quarantine_host', 'disable_user'
    title = Column(String(200))
    description = Column(Text)
    payload = Column(Text)  # JSON: {ips: [...], rule_id: ..., etc.}
    
    # Source context
    source_type = Column(String(50))  # 'hunt', 'alert', 'incident', 'threat_intel'
    source_id = Column(Integer)
    
    priority = Column(String(20))
    
    # APPROVAL WORKFLOW
    status = Column(String(20), default='pending')
    # Status: pending → approved/rejected → executing → completed/failed
    approved_by = Column(String(100), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    rejected_reason = Column(Text, nullable=True)
    
    # Execution
    executed_at = Column(DateTime, nullable=True)
    execution_result = Column(Text)
    
    created_at = Column(DateTime, default=datetime.utcnow)


# ========================= LEGACY ALIAS (for backward compatibility) =========================

# Alias for code that uses HuntRecommendation
HuntRecommendation = Hunt


# ========================= DATABASE FUNCTIONS =========================

def init_db():
    """Initialize all database tables"""
    Base.metadata.create_all(bind=engine)
    print("✅ Database tables created/verified")


def get_db():
    """Get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Export all models
__all__ = [
    'Base', 'engine', 'SessionLocal', 'init_db', 'get_db',
    'Alert', 'Incident', 'Action', 'ChatMessage', 'MetricsHistory', 'AITimeEstimate',
    'ThreatIntel', 'DetectionRule',
    'Hunt', 'HuntResult', 'HuntRecommendation',
    'PendingAction'
]
