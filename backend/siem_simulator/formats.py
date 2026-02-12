"""
SIEM Format Generators
Generates alerts in various SIEM-specific formats.
"""
import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List
import random


class SIEMFormatGenerator:
    """Base class for SIEM format generators"""
    
    def generate(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError


class SplunkFormatGenerator(SIEMFormatGenerator):
    """Generates alerts in Splunk format"""
    
    def generate(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "result": {
                "_time": alert_data.get("timestamp", datetime.utcnow().isoformat()),
                "_raw": alert_data.get("description", ""),
                "host": alert_data.get("source_ip", "unknown"),
                "source": "siem:splunk",
                "sourcetype": "security_alert",
                "index": "security",
                "_cd": f"{random.randint(1, 100)}:{random.randint(1000, 9999)}",
                "event_id": str(uuid.uuid4()),
                "severity": self._map_severity(alert_data.get("severity", "Medium")),
                "category": alert_data.get("event_type", "unknown"),
                "src_ip": alert_data.get("source_ip", ""),
                "dest_ip": alert_data.get("destination_ip", ""),
                "user": alert_data.get("user", "unknown"),
                "signature": alert_data.get("description", ""),
                "action": "allowed",
                "vendor_product": "Splunk Enterprise Security"
            },
            "sid": f"rt_splunk_{uuid.uuid4().hex[:8]}",
            "search_name": "SOC Alert Detection",
            "app": "SplunkEnterpriseSecuritySuite",
            "owner": "admin",
            "results_link": f"https://splunk.local:8000/app/search/alert?sid={uuid.uuid4().hex}"
        }
    
    def _map_severity(self, severity: str) -> str:
        mapping = {
            "Critical": "critical",
            "High": "high", 
            "Medium": "medium",
            "Low": "low",
            "Informational": "informational"
        }
        return mapping.get(severity, "medium")


class QRadarFormatGenerator(SIEMFormatGenerator):
    """Generates alerts in IBM QRadar format"""
    
    def generate(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "offense_id": random.randint(10000, 99999),
            "offense_type": self._map_offense_type(alert_data.get("event_type", "")),
            "offense_source": alert_data.get("source_ip", "unknown"),
            "description": alert_data.get("description", ""),
            "severity": self._map_severity(alert_data.get("severity", "Medium")),
            "magnitude": self._calculate_magnitude(alert_data.get("severity", "Medium")),
            "credibility": random.randint(7, 10),
            "relevance": random.randint(7, 10),
            "start_time": self._to_epoch(alert_data.get("timestamp")),
            "last_updated_time": self._to_epoch(datetime.utcnow().isoformat()),
            "event_count": random.randint(1, 100),
            "flow_count": random.randint(0, 50),
            "assigned_to": None,
            "status": "OPEN",
            "closing_user": None,
            "closing_reason_id": None,
            "categories": [alert_data.get("event_type", "Unknown")],
            "source_network": "Internal",
            "destination_networks": ["External"],
            "log_sources": [
                {
                    "id": random.randint(100, 999),
                    "name": "Firewall",
                    "type_id": 12,
                    "type_name": "Firewall"
                }
            ],
            "rules": [
                {
                    "id": random.randint(1000, 9999),
                    "name": f"Rule: {alert_data.get('event_type', 'Detection')}"
                }
            ],
            "local_destination_address_ids": [],
            "source_address_ids": [random.randint(1, 1000)],
            "domain_id": 0,
            "security_category_count": 1,
            "device_count": 1,
            "username_count": 1 if alert_data.get("user") else 0,
            "policy_category_count": 0
        }
    
    def _map_severity(self, severity: str) -> int:
        mapping = {"Critical": 10, "High": 8, "Medium": 5, "Low": 3, "Informational": 1}
        return mapping.get(severity, 5)
    
    def _calculate_magnitude(self, severity: str) -> int:
        mapping = {"Critical": 9, "High": 7, "Medium": 5, "Low": 3, "Informational": 1}
        return mapping.get(severity, 5)
    
    def _map_offense_type(self, event_type: str) -> int:
        # QRadar offense type IDs
        mapping = {
            "Authentication": 1,
            "Malware": 2,
            "Reconnaissance": 3,
            "Data Exfiltration": 4,
            "Lateral Movement": 5,
            "Privilege Escalation": 6,
            "C2 Communication": 7,
            "Policy Violation": 8
        }
        return mapping.get(event_type, 0)
    
    def _to_epoch(self, timestamp) -> int:
        if isinstance(timestamp, str):
            try:
                dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                return int(dt.timestamp() * 1000)
            except:
                pass
        return int(datetime.utcnow().timestamp() * 1000)


class ElasticFormatGenerator(SIEMFormatGenerator):
    """Generates alerts in Elastic SIEM (ECS) format"""
    
    def generate(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "@timestamp": alert_data.get("timestamp", datetime.utcnow().isoformat()),
            "ecs": {"version": "8.0.0"},
            "event": {
                "kind": "alert",
                "category": [self._map_category(alert_data.get("event_type", ""))],
                "type": ["indicator"],
                "severity": self._map_severity_num(alert_data.get("severity", "Medium")),
                "risk_score": self._calculate_risk_score(alert_data.get("severity", "Medium")),
                "created": datetime.utcnow().isoformat(),
                "dataset": "security_detection_engine",
                "module": "siem",
                "action": alert_data.get("event_type", "unknown"),
                "outcome": "unknown"
            },
            "host": {
                "ip": [alert_data.get("destination_ip", "")],
                "name": f"host-{random.randint(1, 100)}"
            },
            "source": {
                "ip": alert_data.get("source_ip", ""),
                "port": random.randint(1024, 65535),
                "geo": {
                    "country_name": random.choice(["United States", "Russia", "China", "Unknown"])
                }
            },
            "destination": {
                "ip": alert_data.get("destination_ip", ""),
                "port": random.choice([22, 80, 443, 3389, 445])
            },
            "user": {
                "name": alert_data.get("user", "unknown"),
                "domain": "CORP"
            },
            "rule": {
                "id": str(uuid.uuid4()),
                "name": f"Detection: {alert_data.get('event_type', 'Unknown')}",
                "description": alert_data.get("description", ""),
                "category": alert_data.get("event_type", "unknown"),
                "severity": alert_data.get("severity", "Medium").lower()
            },
            "threat": {
                "framework": "MITRE ATT&CK",
                "tactic": {
                    "name": self._map_mitre_tactic(alert_data.get("event_type", ""))
                }
            },
            "message": alert_data.get("description", ""),
            "tags": ["security", "alert", alert_data.get("event_type", "").lower().replace(" ", "_")]
        }
    
    def _map_category(self, event_type: str) -> str:
        mapping = {
            "Authentication": "authentication",
            "Malware": "malware",
            "Reconnaissance": "network",
            "Data Exfiltration": "network",
            "Lateral Movement": "network",
            "Privilege Escalation": "iam",
            "C2 Communication": "network",
            "Policy Violation": "configuration"
        }
        return mapping.get(event_type, "network")
    
    def _map_severity_num(self, severity: str) -> int:
        mapping = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Informational": 0}
        return mapping.get(severity, 2)
    
    def _calculate_risk_score(self, severity: str) -> float:
        mapping = {"Critical": 95.0, "High": 75.0, "Medium": 50.0, "Low": 25.0, "Informational": 10.0}
        return mapping.get(severity, 50.0)
    
    def _map_mitre_tactic(self, event_type: str) -> str:
        mapping = {
            "Authentication": "Credential Access",
            "Malware": "Execution",
            "Reconnaissance": "Reconnaissance",
            "Data Exfiltration": "Exfiltration",
            "Lateral Movement": "Lateral Movement",
            "Privilege Escalation": "Privilege Escalation",
            "C2 Communication": "Command and Control",
            "Policy Violation": "Defense Evasion"
        }
        return mapping.get(event_type, "Unknown")


class MicrosoftSentinelFormatGenerator(SIEMFormatGenerator):
    """Generates alerts in Microsoft Sentinel format"""
    
    def generate(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": str(uuid.uuid4()),
            "name": f"Alert - {alert_data.get('event_type', 'Unknown')}",
            "type": "Microsoft.SecurityInsights/incidents",
            "properties": {
                "title": alert_data.get("description", "Security Alert")[:100],
                "description": alert_data.get("description", ""),
                "severity": alert_data.get("severity", "Medium"),
                "status": "New",
                "owner": {"assignedTo": None},
                "labels": [
                    {"labelName": alert_data.get("event_type", "unknown")}
                ],
                "firstActivityTimeUtc": alert_data.get("timestamp", datetime.utcnow().isoformat()),
                "lastActivityTimeUtc": datetime.utcnow().isoformat(),
                "createdTimeUtc": datetime.utcnow().isoformat(),
                "incidentNumber": random.randint(10000, 99999),
                "additionalData": {
                    "alertsCount": 1,
                    "bookmarksCount": 0,
                    "commentsCount": 0,
                    "alertProductNames": ["Azure Sentinel"],
                    "tactics": [self._map_tactic(alert_data.get("event_type", ""))]
                },
                "relatedAnalyticRuleIds": [str(uuid.uuid4())],
                "providerName": "Azure Sentinel",
                "providerIncidentId": str(random.randint(100000, 999999)),
                "alerts": [
                    {
                        "alertId": str(uuid.uuid4()),
                        "sourceIp": alert_data.get("source_ip", ""),
                        "destinationIp": alert_data.get("destination_ip", ""),
                        "userName": alert_data.get("user", "unknown"),
                        "severity": alert_data.get("severity", "Medium"),
                        "alertType": alert_data.get("event_type", "Unknown"),
                        "timestamp": alert_data.get("timestamp", datetime.utcnow().isoformat())
                    }
                ]
            }
        }
    
    def _map_tactic(self, event_type: str) -> str:
        mapping = {
            "Authentication": "CredentialAccess",
            "Malware": "Execution",
            "Reconnaissance": "Reconnaissance", 
            "Data Exfiltration": "Exfiltration",
            "Lateral Movement": "LateralMovement",
            "Privilege Escalation": "PrivilegeEscalation",
            "C2 Communication": "CommandAndControl",
            "Policy Violation": "DefenseEvasion"
        }
        return mapping.get(event_type, "Unknown")


class GenericCEFFormatGenerator(SIEMFormatGenerator):
    """Generates alerts in Common Event Format (CEF)"""
    
    def generate(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        severity_num = {"Critical": 10, "High": 8, "Medium": 5, "Low": 3}.get(
            alert_data.get("severity", "Medium"), 5
        )
        
        cef_string = (
            f"CEF:0|SOC_AI_Tool|SecurityMonitor|1.0|"
            f"{alert_data.get('event_type', 'Unknown')}|"
            f"{alert_data.get('description', '')}|{severity_num}|"
            f"src={alert_data.get('source_ip', '')} "
            f"dst={alert_data.get('destination_ip', '')} "
            f"suser={alert_data.get('user', 'unknown')} "
            f"rt={alert_data.get('timestamp', datetime.utcnow().isoformat())}"
        )
        
        return {
            "cef": cef_string,
            "parsed": {
                "cef_version": 0,
                "device_vendor": "SOC_AI_Tool",
                "device_product": "SecurityMonitor",
                "device_version": "1.0",
                "signature_id": alert_data.get("event_type", "Unknown"),
                "name": alert_data.get("description", ""),
                "severity": severity_num,
                "extensions": {
                    "src": alert_data.get("source_ip", ""),
                    "dst": alert_data.get("destination_ip", ""),
                    "suser": alert_data.get("user", "unknown"),
                    "rt": alert_data.get("timestamp", datetime.utcnow().isoformat())
                }
            }
        }


# Factory for getting format generators
FORMAT_GENERATORS = {
    "splunk": SplunkFormatGenerator(),
    "qradar": QRadarFormatGenerator(),
    "elastic": ElasticFormatGenerator(),
    "sentinel": MicrosoftSentinelFormatGenerator(),
    "cef": GenericCEFFormatGenerator()
}


def get_format_generator(siem_type: str) -> SIEMFormatGenerator:
    """Get the appropriate format generator for a SIEM type"""
    return FORMAT_GENERATORS.get(siem_type.lower(), GenericCEFFormatGenerator())
