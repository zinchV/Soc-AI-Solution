"""
Alert Normalizer
Converts alerts from various SIEM formats to a standard format.
"""
from typing import Dict, Any, Optional
from datetime import datetime


class AlertNormalizer:
    """
    Normalizes alerts from different SIEM formats to a standard format.
    
    Standard format:
    {
        "timestamp": "ISO datetime string",
        "severity": "Critical|High|Medium|Low",
        "source_ip": "IP address",
        "destination_ip": "IP address",
        "user": "username",
        "description": "Alert description",
        "event_type": "Event category"
    }
    """
    
    def normalize(self, siem_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize alert data from a specific SIEM format.
        
        Args:
            siem_type: One of 'generic', 'splunk', 'qradar', 'elastic', 'sentinel', 'cef'
            data: Raw alert data from the SIEM
            
        Returns:
            Normalized alert dictionary
        """
        normalizers = {
            "generic": self._normalize_generic,
            "splunk": self._normalize_splunk,
            "qradar": self._normalize_qradar,
            "elastic": self._normalize_elastic,
            "sentinel": self._normalize_sentinel,
            "cef": self._normalize_cef
        }
        
        normalizer_func = normalizers.get(siem_type, self._normalize_generic)
        return normalizer_func(data)
    
    def _normalize_generic(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize generic format (pass-through with defaults)"""
        return {
            "timestamp": data.get("timestamp", datetime.now().isoformat()),
            "severity": self._normalize_severity(data.get("severity", "Medium")),
            "source_ip": data.get("source_ip", ""),
            "destination_ip": data.get("destination_ip", ""),
            "user": data.get("user", "unknown"),
            "description": data.get("description", "No description"),
            "event_type": data.get("event_type", "Unknown")
        }
    
    def _normalize_splunk(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize Splunk Enterprise Security format.
        
        Expected format:
        {
            "result": {
                "_time": "timestamp",
                "severity": "critical|high|medium|low",
                "src_ip": "source IP",
                "dest_ip": "destination IP",
                "user": "username",
                "signature": "alert description",
                "category": "event type"
            },
            "sid": "search ID",
            "search_name": "saved search name"
        }
        """
        result = data.get("result", data)
        
        return {
            "timestamp": result.get("_time", datetime.now().isoformat()),
            "severity": self._normalize_severity(result.get("severity", "medium")),
            "source_ip": result.get("src_ip", result.get("src", "")),
            "destination_ip": result.get("dest_ip", result.get("dest", "")),
            "user": result.get("user", result.get("src_user", "unknown")),
            "description": result.get("signature", result.get("description", data.get("search_name", "Splunk Alert"))),
            "event_type": result.get("category", result.get("type", "Splunk Alert"))
        }
    
    def _normalize_qradar(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize IBM QRadar offense format.
        
        Expected format:
        {
            "offense_id": 12345,
            "offense_source": "source IP",
            "description": "offense description",
            "severity": 1-10,
            "magnitude": 1-10,
            "event_count": number,
            "categories": ["category1", "category2"],
            "start_time": epoch_ms
        }
        """
        # QRadar severity is 1-10, map to Critical/High/Medium/Low
        qradar_severity = data.get("severity", 5)
        if qradar_severity >= 9:
            severity = "Critical"
        elif qradar_severity >= 7:
            severity = "High"
        elif qradar_severity >= 4:
            severity = "Medium"
        else:
            severity = "Low"
        
        # Convert epoch milliseconds to ISO format
        start_time = data.get("start_time")
        if start_time:
            try:
                timestamp = datetime.fromtimestamp(start_time / 1000).isoformat()
            except:
                timestamp = datetime.now().isoformat()
        else:
            timestamp = datetime.now().isoformat()
        
        categories = data.get("categories", [])
        event_type = categories[0] if categories else "QRadar Offense"
        
        return {
            "timestamp": timestamp,
            "severity": severity,
            "source_ip": data.get("offense_source", ""),
            "destination_ip": data.get("local_destination_address_ids", [""])[0] if isinstance(data.get("local_destination_address_ids"), list) else "",
            "user": data.get("username", "unknown"),
            "description": f"[QRadar #{data.get('offense_id', 'N/A')}] {data.get('description', 'No description')}",
            "event_type": event_type
        }
    
    def _normalize_elastic(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize Elastic SIEM (ECS) format.
        
        Expected format:
        {
            "@timestamp": "ISO timestamp",
            "event": {
                "kind": "alert",
                "category": ["authentication"],
                "severity": 1-4
            },
            "source": {"ip": "source IP"},
            "destination": {"ip": "dest IP"},
            "user": {"name": "username"},
            "rule": {
                "name": "rule name",
                "description": "description"
            }
        }
        """
        event = data.get("event", {})
        source = data.get("source", {})
        destination = data.get("destination", {})
        user = data.get("user", {})
        rule = data.get("rule", {})
        
        # Elastic severity is 1-4
        elastic_severity = event.get("severity", 2)
        severity_map = {1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
        severity = severity_map.get(elastic_severity, "Medium")
        
        categories = event.get("category", [])
        event_type = categories[0] if categories else "Elastic Alert"
        
        return {
            "timestamp": data.get("@timestamp", datetime.now().isoformat()),
            "severity": severity,
            "source_ip": source.get("ip", ""),
            "destination_ip": destination.get("ip", ""),
            "user": user.get("name", "unknown"),
            "description": rule.get("description", rule.get("name", "Elastic SIEM Alert")),
            "event_type": event_type.replace("_", " ").title() if isinstance(event_type, str) else "Elastic Alert"
        }
    
    def _normalize_sentinel(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize Microsoft Sentinel incident format.
        
        Expected format:
        {
            "properties": {
                "title": "incident title",
                "description": "description",
                "severity": "High|Medium|Low|Informational",
                "status": "New|Active|Closed",
                "firstActivityTimeUtc": "timestamp",
                "alerts": [
                    {
                        "sourceIp": "IP",
                        "destinationIp": "IP",
                        "userName": "user"
                    }
                ],
                "additionalData": {
                    "tactics": ["tactic1"]
                }
            }
        }
        """
        props = data.get("properties", data)
        alerts = props.get("alerts", [{}])
        first_alert = alerts[0] if alerts else {}
        additional = props.get("additionalData", {})
        
        severity = props.get("severity", "Medium")
        if severity == "Informational":
            severity = "Low"
        
        tactics = additional.get("tactics", [])
        event_type = tactics[0] if tactics else "Sentinel Alert"
        
        return {
            "timestamp": props.get("firstActivityTimeUtc", datetime.now().isoformat()),
            "severity": self._normalize_severity(severity),
            "source_ip": first_alert.get("sourceIp", first_alert.get("source_ip", "")),
            "destination_ip": first_alert.get("destinationIp", first_alert.get("destination_ip", "")),
            "user": first_alert.get("userName", first_alert.get("user", "unknown")),
            "description": f"{props.get('title', 'Sentinel Incident')}: {props.get('description', '')}",
            "event_type": event_type
        }
    
    def _normalize_cef(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize Common Event Format (CEF).
        
        Expected format:
        {
            "cef": "CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extensions",
            "parsed": {
                "device_vendor": "vendor",
                "device_product": "product",
                "signature_id": "sig_id",
                "name": "event name",
                "severity": 1-10,
                "extensions": {
                    "src": "source IP",
                    "dst": "dest IP",
                    "suser": "source user"
                }
            }
        }
        """
        parsed = data.get("parsed", {})
        extensions = parsed.get("extensions", {})
        
        # CEF severity is 0-10
        cef_severity = parsed.get("severity", 5)
        if isinstance(cef_severity, str):
            try:
                cef_severity = int(cef_severity)
            except:
                cef_severity = 5
        
        if cef_severity >= 9:
            severity = "Critical"
        elif cef_severity >= 7:
            severity = "High"
        elif cef_severity >= 4:
            severity = "Medium"
        else:
            severity = "Low"
        
        return {
            "timestamp": extensions.get("rt", extensions.get("deviceReceiptTime", datetime.now().isoformat())),
            "severity": severity,
            "source_ip": extensions.get("src", extensions.get("sourceAddress", "")),
            "destination_ip": extensions.get("dst", extensions.get("destinationAddress", "")),
            "user": extensions.get("suser", extensions.get("sourceUserName", "unknown")),
            "description": f"[{parsed.get('device_vendor', 'Unknown')}/{parsed.get('device_product', 'Unknown')}] {parsed.get('name', 'CEF Event')}",
            "event_type": parsed.get("signature_id", "CEF Event")
        }
    
    def _normalize_severity(self, severity: Any) -> str:
        """Normalize severity to Critical/High/Medium/Low"""
        if severity is None:
            return "Medium"
        
        severity_str = str(severity).lower().strip()
        
        # Map common variations
        severity_map = {
            "critical": "Critical",
            "crit": "Critical",
            "4": "Critical",
            "high": "High",
            "3": "High",
            "medium": "Medium",
            "med": "Medium",
            "2": "Medium",
            "low": "Low",
            "1": "Low",
            "informational": "Low",
            "info": "Low",
            "0": "Low"
        }
        
        return severity_map.get(severity_str, "Medium")
