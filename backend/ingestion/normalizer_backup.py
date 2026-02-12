"""
Alert Normalizer
Converts various SIEM formats to the standard SOC AI Tool format.
"""
from datetime import datetime
from typing import Dict, Any, Optional, List
import json
import re


class AlertNormalizer:
    """Base class for alert normalizers"""
    
    def normalize(self, raw_alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert raw alert to standard format.
        
        Standard format:
        {
            "timestamp": "ISO format datetime",
            "severity": "Critical|High|Medium|Low",
            "source_ip": "IP address",
            "destination_ip": "IP address",
            "user": "username",
            "description": "Alert description",
            "event_type": "Category of event"
        }
        """
        raise NotImplementedError


class GenericNormalizer(AlertNormalizer):
    """Normalizer for generic/standard format alerts"""
    
    def normalize(self, raw_alert: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "timestamp": raw_alert.get("timestamp", datetime.utcnow().isoformat()),
            "severity": self._normalize_severity(raw_alert.get("severity", "Medium")),
            "source_ip": raw_alert.get("source_ip", raw_alert.get("src_ip", "unknown")),
            "destination_ip": raw_alert.get("destination_ip", raw_alert.get("dest_ip", "unknown")),
            "user": raw_alert.get("user", raw_alert.get("username", "unknown")),
            "description": raw_alert.get("description", raw_alert.get("message", "")),
            "event_type": raw_alert.get("event_type", raw_alert.get("category", "Unknown"))
        }
    
    def _normalize_severity(self, severity: Any) -> str:
        """Normalize severity to standard values"""
        if isinstance(severity, int):
            if severity >= 9:
                return "Critical"
            elif severity >= 7:
                return "High"
            elif severity >= 4:
                return "Medium"
            else:
                return "Low"
        
        severity_str = str(severity).lower()
        if severity_str in ["critical", "crit", "emergency", "10", "9"]:
            return "Critical"
        elif severity_str in ["high", "major", "8", "7"]:
            return "High"
        elif severity_str in ["medium", "moderate", "warning", "6", "5", "4"]:
            return "Medium"
        else:
            return "Low"


class SplunkNormalizer(AlertNormalizer):
    """Normalizer for Splunk alert format"""
    
    def normalize(self, raw_alert: Dict[str, Any]) -> Dict[str, Any]:
        # Handle nested result object
        result = raw_alert.get("result", raw_alert)
        
        return {
            "timestamp": result.get("_time", datetime.utcnow().isoformat()),
            "severity": self._normalize_severity(result.get("severity", "medium")),
            "source_ip": result.get("src_ip", result.get("src", "unknown")),
            "destination_ip": result.get("dest_ip", result.get("dest", "unknown")),
            "user": result.get("user", result.get("suser", "unknown")),
            "description": result.get("signature", result.get("_raw", "")),
            "event_type": self._map_category(result.get("category", "Unknown"))
        }
    
    def _normalize_severity(self, severity: str) -> str:
        mapping = {
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "informational": "Low"
        }
        return mapping.get(str(severity).lower(), "Medium")
    
    def _map_category(self, category: str) -> str:
        mapping = {
            "authentication": "Authentication",
            "malware": "Malware",
            "network": "Reconnaissance",
            "access": "Authentication"
        }
        return mapping.get(str(category).lower(), category)


class QRadarNormalizer(AlertNormalizer):
    """Normalizer for IBM QRadar offense format"""
    
    def normalize(self, raw_alert: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "timestamp": self._epoch_to_iso(raw_alert.get("start_time")),
            "severity": self._normalize_severity(raw_alert.get("severity", 5)),
            "source_ip": raw_alert.get("offense_source", "unknown"),
            "destination_ip": self._get_destination(raw_alert),
            "user": self._get_username(raw_alert),
            "description": raw_alert.get("description", ""),
            "event_type": self._map_offense_type(raw_alert.get("offense_type", 0))
        }
    
    def _epoch_to_iso(self, epoch_ms: int) -> str:
        if not epoch_ms:
            return datetime.utcnow().isoformat()
        try:
            return datetime.fromtimestamp(epoch_ms / 1000).isoformat()
        except:
            return datetime.utcnow().isoformat()
    
    def _normalize_severity(self, severity: int) -> str:
        if severity >= 9:
            return "Critical"
        elif severity >= 7:
            return "High"
        elif severity >= 4:
            return "Medium"
        else:
            return "Low"
    
    def _get_destination(self, raw_alert: Dict) -> str:
        networks = raw_alert.get("destination_networks", [])
        return networks[0] if networks else "unknown"
    
    def _get_username(self, raw_alert: Dict) -> str:
        if raw_alert.get("username_count", 0) > 0:
            return "user_detected"
        return "unknown"
    
    def _map_offense_type(self, offense_type: int) -> str:
        mapping = {
            1: "Authentication",
            2: "Malware",
            3: "Reconnaissance",
            4: "Data Exfiltration",
            5: "Lateral Movement",
            6: "Privilege Escalation",
            7: "C2 Communication",
            8: "Policy Violation"
        }
        return mapping.get(offense_type, "Unknown")


class ElasticNormalizer(AlertNormalizer):
    """Normalizer for Elastic SIEM (ECS) format"""
    
    def normalize(self, raw_alert: Dict[str, Any]) -> Dict[str, Any]:
        event = raw_alert.get("event", {})
        source = raw_alert.get("source", {})
        destination = raw_alert.get("destination", {})
        user = raw_alert.get("user", {})
        rule = raw_alert.get("rule", {})
        
        return {
            "timestamp": raw_alert.get("@timestamp", datetime.utcnow().isoformat()),
            "severity": self._normalize_severity(event.get("severity", 2)),
            "source_ip": source.get("ip", "unknown"),
            "destination_ip": destination.get("ip", "unknown"),
            "user": user.get("name", "unknown"),
            "description": rule.get("description", raw_alert.get("message", "")),
            "event_type": self._map_category(event.get("category", ["unknown"])[0] if isinstance(event.get("category"), list) else event.get("category", "unknown"))
        }
    
    def _normalize_severity(self, severity: int) -> str:
        if severity >= 4:
            return "Critical"
        elif severity >= 3:
            return "High"
        elif severity >= 2:
            return "Medium"
        else:
            return "Low"
    
    def _map_category(self, category: str) -> str:
        mapping = {
            "authentication": "Authentication",
            "malware": "Malware",
            "network": "Reconnaissance",
            "iam": "Privilege Escalation",
            "configuration": "Policy Violation"
        }
        return mapping.get(str(category).lower(), category)


class SentinelNormalizer(AlertNormalizer):
    """Normalizer for Microsoft Sentinel format"""
    
    def normalize(self, raw_alert: Dict[str, Any]) -> Dict[str, Any]:
        props = raw_alert.get("properties", raw_alert)
        alerts = props.get("alerts", [{}])
        first_alert = alerts[0] if alerts else {}
        
        return {
            "timestamp": props.get("firstActivityTimeUtc", datetime.utcnow().isoformat()),
            "severity": props.get("severity", "Medium"),
            "source_ip": first_alert.get("sourceIp", "unknown"),
            "destination_ip": first_alert.get("destinationIp", "unknown"),
            "user": first_alert.get("userName", "unknown"),
            "description": props.get("description", props.get("title", "")),
            "event_type": self._map_tactic(props.get("additionalData", {}).get("tactics", ["Unknown"])[0])
        }
    
    def _map_tactic(self, tactic: str) -> str:
        mapping = {
            "CredentialAccess": "Authentication",
            "Execution": "Malware",
            "Reconnaissance": "Reconnaissance",
            "Exfiltration": "Data Exfiltration",
            "LateralMovement": "Lateral Movement",
            "PrivilegeEscalation": "Privilege Escalation",
            "CommandAndControl": "C2 Communication",
            "DefenseEvasion": "Policy Violation"
        }
        return mapping.get(tactic, tactic)


class CEFNormalizer(AlertNormalizer):
    """Normalizer for Common Event Format (CEF)"""
    
    def normalize(self, raw_alert: Dict[str, Any]) -> Dict[str, Any]:
        # Handle both raw CEF string and parsed format
        if "cef" in raw_alert and "parsed" in raw_alert:
            parsed = raw_alert["parsed"]
            ext = parsed.get("extensions", {})
            
            return {
                "timestamp": ext.get("rt", datetime.utcnow().isoformat()),
                "severity": self._normalize_severity(parsed.get("severity", 5)),
                "source_ip": ext.get("src", "unknown"),
                "destination_ip": ext.get("dst", "unknown"),
                "user": ext.get("suser", "unknown"),
                "description": parsed.get("name", ""),
                "event_type": parsed.get("signature_id", "Unknown")
            }
        elif "cef" in raw_alert:
            return self._parse_cef_string(raw_alert["cef"])
        else:
            # Try generic normalization
            return GenericNormalizer().normalize(raw_alert)
    
    def _parse_cef_string(self, cef_string: str) -> Dict[str, Any]:
        """Parse a raw CEF string"""
        # CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extensions
        parts = cef_string.split("|")
        
        if len(parts) < 8:
            return GenericNormalizer().normalize({"description": cef_string})
        
        extensions = self._parse_extensions(parts[7] if len(parts) > 7 else "")
        
        return {
            "timestamp": extensions.get("rt", datetime.utcnow().isoformat()),
            "severity": self._normalize_severity(int(parts[6]) if parts[6].isdigit() else 5),
            "source_ip": extensions.get("src", "unknown"),
            "destination_ip": extensions.get("dst", "unknown"),
            "user": extensions.get("suser", "unknown"),
            "description": parts[5] if len(parts) > 5 else "",
            "event_type": parts[4] if len(parts) > 4 else "Unknown"
        }
    
    def _parse_extensions(self, ext_string: str) -> Dict[str, str]:
        """Parse CEF extension key=value pairs"""
        extensions = {}
        pattern = r'(\w+)=([^\s]+)'
        matches = re.findall(pattern, ext_string)
        for key, value in matches:
            extensions[key] = value
        return extensions
    
    def _normalize_severity(self, severity: int) -> str:
        if severity >= 9:
            return "Critical"
        elif severity >= 7:
            return "High"
        elif severity >= 4:
            return "Medium"
        else:
            return "Low"


# Factory for getting normalizers
NORMALIZERS = {
    "generic": GenericNormalizer(),
    "splunk": SplunkNormalizer(),
    "qradar": QRadarNormalizer(),
    "elastic": ElasticNormalizer(),
    "sentinel": SentinelNormalizer(),
    "cef": CEFNormalizer()
}


def get_normalizer(siem_type: str) -> AlertNormalizer:
    """Get the appropriate normalizer for a SIEM type"""
    return NORMALIZERS.get(siem_type.lower(), GenericNormalizer())


def normalize_alert(raw_alert: Dict[str, Any], siem_type: str = "generic") -> Dict[str, Any]:
    """
    Convenience function to normalize an alert.
    
    Args:
        raw_alert: Raw alert data from SIEM
        siem_type: Type of SIEM (splunk, qradar, elastic, sentinel, cef, generic)
    
    Returns:
        Normalized alert in standard format
    """
    normalizer = get_normalizer(siem_type)
    return normalizer.normalize(raw_alert)


def normalize_alerts(raw_alerts: List[Dict[str, Any]], siem_type: str = "generic") -> List[Dict[str, Any]]:
    """
    Normalize a list of alerts.
    
    Args:
        raw_alerts: List of raw alerts from SIEM
        siem_type: Type of SIEM
    
    Returns:
        List of normalized alerts
    """
    normalizer = get_normalizer(siem_type)
    return [normalizer.normalize(alert) for alert in raw_alerts]
