"""
Attack Scenarios for SIEM Simulator
Defines realistic attack patterns that generate correlated alerts.
"""
import random
from datetime import datetime, timedelta
from typing import List, Dict, Any
import ipaddress


class AttackScenario:
    """Base class for attack scenarios"""
    
    name: str = "Base Scenario"
    description: str = ""
    
    def generate_alerts(self, start_time: datetime = None) -> List[Dict[str, Any]]:
        raise NotImplementedError


class BruteForceScenario(AttackScenario):
    """Simulates brute force SSH/RDP attack followed by successful login"""
    
    name = "Brute Force Attack"
    description = "Multiple failed login attempts followed by successful authentication"
    
    def generate_alerts(self, start_time: datetime = None) -> List[Dict[str, Any]]:
        if not start_time:
            start_time = datetime.utcnow()
        
        attacker_ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
        target_ip = f"10.0.0.{random.randint(1, 100)}"
        target_user = random.choice(["admin", "root", "administrator", "sysadmin"])
        
        alerts = []
        failed_attempts = random.randint(20, 100)
        
        # Failed login attempts
        for i in range(failed_attempts):
            alerts.append({
                "timestamp": (start_time + timedelta(seconds=i * 2)).isoformat(),
                "severity": "Medium" if i < failed_attempts - 10 else "High",
                "source_ip": attacker_ip,
                "destination_ip": target_ip,
                "user": target_user,
                "description": f"Failed SSH login attempt ({i+1}/{failed_attempts}) for user {target_user}",
                "event_type": "Authentication"
            })
        
        # Successful login (breach)
        alerts.append({
            "timestamp": (start_time + timedelta(seconds=failed_attempts * 2 + 5)).isoformat(),
            "severity": "Critical",
            "source_ip": attacker_ip,
            "destination_ip": target_ip,
            "user": target_user,
            "description": f"Successful SSH login after {failed_attempts} failed attempts - possible brute force",
            "event_type": "Authentication"
        })
        
        return alerts


class LateralMovementScenario(AttackScenario):
    """Simulates lateral movement across network after initial compromise"""
    
    name = "Lateral Movement"
    description = "Attacker moving through network after initial access"
    
    def generate_alerts(self, start_time: datetime = None) -> List[Dict[str, Any]]:
        if not start_time:
            start_time = datetime.utcnow()
        
        attacker_ip = f"192.168.1.{random.randint(100, 200)}"
        compromised_user = random.choice(["admin", "svc-backup", "domain_admin"])
        
        targets = [
            ("10.0.0.10", "Domain Controller"),
            ("10.0.0.20", "File Server"),
            ("10.0.0.30", "Database Server"),
            ("10.0.0.40", "Application Server")
        ]
        
        alerts = []
        
        for i, (target_ip, target_name) in enumerate(targets[:random.randint(2, 4)]):
            # SMB connection
            alerts.append({
                "timestamp": (start_time + timedelta(minutes=i * 5)).isoformat(),
                "severity": "High",
                "source_ip": attacker_ip,
                "destination_ip": target_ip,
                "user": compromised_user,
                "description": f"SMB connection from internal host to {target_name} ({target_ip})",
                "event_type": "Lateral Movement"
            })
            
            # Remote execution
            alerts.append({
                "timestamp": (start_time + timedelta(minutes=i * 5 + 1)).isoformat(),
                "severity": "Critical",
                "source_ip": attacker_ip,
                "destination_ip": target_ip,
                "user": compromised_user,
                "description": f"PsExec/WMI remote execution detected on {target_name}",
                "event_type": "Lateral Movement"
            })
        
        return alerts


class RansomwareScenario(AttackScenario):
    """Simulates ransomware attack with encryption and ransom note"""
    
    name = "Ransomware Attack"
    description = "File encryption activity with ransom note creation"
    
    def generate_alerts(self, start_time: datetime = None) -> List[Dict[str, Any]]:
        if not start_time:
            start_time = datetime.utcnow()
        
        affected_host = f"10.0.0.{random.randint(50, 100)}"
        c2_server = random.choice([
            "45.33.32.156", "185.220.101.1", "91.219.29.81"
        ])
        ransomware_name = random.choice(["LockBit", "BlackCat", "REvil", "Conti"])
        
        alerts = [
            {
                "timestamp": start_time.isoformat(),
                "severity": "Critical",
                "source_ip": "unknown",
                "destination_ip": affected_host,
                "user": "SYSTEM",
                "description": f"Ransomware signature detected - {ransomware_name} file encryption activity",
                "event_type": "Malware"
            },
            {
                "timestamp": (start_time + timedelta(seconds=15)).isoformat(),
                "severity": "Critical",
                "source_ip": "unknown",
                "destination_ip": affected_host,
                "user": "SYSTEM",
                "description": "Multiple files renamed with .encrypted extension - mass encryption detected",
                "event_type": "Malware"
            },
            {
                "timestamp": (start_time + timedelta(seconds=30)).isoformat(),
                "severity": "Critical",
                "source_ip": "unknown",
                "destination_ip": affected_host,
                "user": "SYSTEM",
                "description": "Ransom note created - README_DECRYPT.txt",
                "event_type": "Malware"
            },
            {
                "timestamp": (start_time + timedelta(seconds=45)).isoformat(),
                "severity": "Critical",
                "source_ip": affected_host,
                "destination_ip": c2_server,
                "user": "SYSTEM",
                "description": f"Connection attempt to known ransomware C2 server ({c2_server})",
                "event_type": "Malware"
            },
            {
                "timestamp": (start_time + timedelta(minutes=1)).isoformat(),
                "severity": "Critical",
                "source_ip": affected_host,
                "destination_ip": c2_server,
                "user": "SYSTEM",
                "description": "Encryption keys being transmitted to C2 server",
                "event_type": "C2 Communication"
            }
        ]
        
        return alerts


class DataExfiltrationScenario(AttackScenario):
    """Simulates data exfiltration via various methods"""
    
    name = "Data Exfiltration"
    description = "Sensitive data being transferred outside the network"
    
    def generate_alerts(self, start_time: datetime = None) -> List[Dict[str, Any]]:
        if not start_time:
            start_time = datetime.utcnow()
        
        internal_host = f"192.168.1.{random.randint(100, 200)}"
        external_ip = f"{random.randint(100, 200)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        user = random.choice(["jsmith", "analyst1", "contractor_bob", "temp_user"])
        
        alerts = [
            {
                "timestamp": start_time.isoformat(),
                "severity": "Medium",
                "source_ip": internal_host,
                "destination_ip": "dns.company.com",
                "user": user,
                "description": f"Unusual DNS query volume - {random.randint(300, 1000)} queries in 5 minutes",
                "event_type": "DNS Anomaly"
            },
            {
                "timestamp": (start_time + timedelta(minutes=2)).isoformat(),
                "severity": "High",
                "source_ip": internal_host,
                "destination_ip": external_ip,
                "user": user,
                "description": "Connection to known Tor exit node detected",
                "event_type": "C2 Communication"
            },
            {
                "timestamp": (start_time + timedelta(minutes=4)).isoformat(),
                "severity": "Critical",
                "source_ip": internal_host,
                "destination_ip": external_ip,
                "user": user,
                "description": f"Large data transfer ({random.randint(100, 1000)}MB) to external IP",
                "event_type": "Data Exfiltration"
            },
            {
                "timestamp": (start_time + timedelta(minutes=5)).isoformat(),
                "severity": "High",
                "source_ip": internal_host,
                "destination_ip": "cloud-storage.suspicious.com",
                "user": user,
                "description": "Multiple confidential files uploaded to unauthorized cloud storage",
                "event_type": "Data Loss Prevention"
            }
        ]
        
        return alerts


class ReconnaissanceScenario(AttackScenario):
    """Simulates network reconnaissance and scanning"""
    
    name = "Reconnaissance"
    description = "Network scanning and enumeration activity"
    
    def generate_alerts(self, start_time: datetime = None) -> List[Dict[str, Any]]:
        if not start_time:
            start_time = datetime.utcnow()
        
        scanner_ip = f"203.0.113.{random.randint(1, 254)}"
        target_subnet = "10.0.0"
        
        alerts = [
            {
                "timestamp": start_time.isoformat(),
                "severity": "High",
                "source_ip": scanner_ip,
                "destination_ip": f"{target_subnet}.0/24",
                "user": "unknown",
                "description": f"Port scan detected - {random.randint(1000, 5000)} ports scanned in 60 seconds",
                "event_type": "Reconnaissance"
            },
            {
                "timestamp": (start_time + timedelta(minutes=1)).isoformat(),
                "severity": "High",
                "source_ip": scanner_ip,
                "destination_ip": f"{target_subnet}.100",
                "user": "unknown",
                "description": "Vulnerability scan signatures detected - Nmap OS fingerprinting",
                "event_type": "Reconnaissance"
            },
            {
                "timestamp": (start_time + timedelta(minutes=2)).isoformat(),
                "severity": "Medium",
                "source_ip": scanner_ip,
                "destination_ip": f"{target_subnet}.100",
                "user": "unknown",
                "description": "Web application vulnerability scan - SQL injection attempts",
                "event_type": "Web Attack"
            },
            {
                "timestamp": (start_time + timedelta(minutes=3)).isoformat(),
                "severity": "High",
                "source_ip": scanner_ip,
                "destination_ip": f"{target_subnet}.100",
                "user": "unknown",
                "description": "Directory traversal attack attempt on web server",
                "event_type": "Web Attack"
            }
        ]
        
        return alerts


class PrivilegeEscalationScenario(AttackScenario):
    """Simulates privilege escalation attempts"""
    
    name = "Privilege Escalation"
    description = "Attempts to gain elevated privileges"
    
    def generate_alerts(self, start_time: datetime = None) -> List[Dict[str, Any]]:
        if not start_time:
            start_time = datetime.utcnow()
        
        host_ip = f"192.168.1.{random.randint(100, 200)}"
        target_server = f"10.0.0.{random.randint(10, 50)}"
        user = random.choice(["jdoe", "contractor1", "temp_admin"])
        
        alerts = [
            {
                "timestamp": start_time.isoformat(),
                "severity": "High",
                "source_ip": host_ip,
                "destination_ip": target_server,
                "user": user,
                "description": f"Sudo privilege escalation attempt by {user}",
                "event_type": "Privilege Escalation"
            },
            {
                "timestamp": (start_time + timedelta(seconds=30)).isoformat(),
                "severity": "Critical",
                "source_ip": host_ip,
                "destination_ip": target_server,
                "user": user,
                "description": "Successful privilege escalation - user gained root access",
                "event_type": "Privilege Escalation"
            },
            {
                "timestamp": (start_time + timedelta(minutes=1)).isoformat(),
                "severity": "Critical",
                "source_ip": host_ip,
                "destination_ip": target_server,
                "user": "root",
                "description": "Sensitive system files accessed with elevated privileges",
                "event_type": "Privilege Escalation"
            },
            {
                "timestamp": (start_time + timedelta(minutes=2)).isoformat(),
                "severity": "Critical",
                "source_ip": host_ip,
                "destination_ip": target_server,
                "user": "root",
                "description": "New user account created with administrative privileges",
                "event_type": "Persistence"
            }
        ]
        
        return alerts


class InsiderThreatScenario(AttackScenario):
    """Simulates insider threat with policy violations and data access"""
    
    name = "Insider Threat"
    description = "Suspicious employee activity and policy violations"
    
    def generate_alerts(self, start_time: datetime = None) -> List[Dict[str, Any]]:
        if not start_time:
            start_time = datetime.utcnow()
        
        employee_ip = f"192.168.1.{random.randint(50, 100)}"
        employee = random.choice(["jsmith", "bwilliams", "mgarcia"])
        
        alerts = [
            {
                "timestamp": start_time.isoformat(),
                "severity": "Medium",
                "source_ip": employee_ip,
                "destination_ip": "mail.company.com",
                "user": employee,
                "description": f"Email sent with sensitive keywords in subject by {employee}",
                "event_type": "Data Loss Prevention"
            },
            {
                "timestamp": (start_time + timedelta(minutes=5)).isoformat(),
                "severity": "Medium",
                "source_ip": employee_ip,
                "destination_ip": "cloud-storage.com",
                "user": employee,
                "description": "Large file upload to personal cloud storage",
                "event_type": "Data Loss Prevention"
            },
            {
                "timestamp": (start_time + timedelta(minutes=10)).isoformat(),
                "severity": "High",
                "source_ip": employee_ip,
                "destination_ip": "cloud-storage.com",
                "user": employee,
                "description": "Multiple confidential files uploaded to unauthorized location",
                "event_type": "Data Loss Prevention"
            },
            {
                "timestamp": (start_time + timedelta(minutes=15)).isoformat(),
                "severity": "Medium",
                "source_ip": employee_ip,
                "destination_ip": "10.0.0.10",
                "user": employee,
                "description": f"After-hours access to sensitive database by {employee}",
                "event_type": "Policy Violation"
            }
        ]
        
        return alerts


class PhishingScenario(AttackScenario):
    """Simulates phishing attack with credential theft"""
    
    name = "Phishing Attack"
    description = "Phishing email leading to credential compromise"
    
    def generate_alerts(self, start_time: datetime = None) -> List[Dict[str, Any]]:
        if not start_time:
            start_time = datetime.utcnow()
        
        victim_ip = f"192.168.1.{random.randint(100, 200)}"
        victim = random.choice(["asmith", "bjohnson", "cwilliams"])
        phishing_domain = random.choice([
            "login-microsoft365.malicious.com",
            "secure-banking-update.evil.net",
            "sharepoint-document.phish.io"
        ])
        
        alerts = [
            {
                "timestamp": start_time.isoformat(),
                "severity": "Medium",
                "source_ip": "mail-server.company.com",
                "destination_ip": victim_ip,
                "user": victim,
                "description": f"Suspicious email with link to {phishing_domain} delivered",
                "event_type": "Phishing"
            },
            {
                "timestamp": (start_time + timedelta(minutes=5)).isoformat(),
                "severity": "High",
                "source_ip": victim_ip,
                "destination_ip": phishing_domain,
                "user": victim,
                "description": f"User {victim} clicked phishing link - connection to known malicious domain",
                "event_type": "Phishing"
            },
            {
                "timestamp": (start_time + timedelta(minutes=6)).isoformat(),
                "severity": "Critical",
                "source_ip": victim_ip,
                "destination_ip": phishing_domain,
                "user": victim,
                "description": "Credentials submitted to phishing page - potential account compromise",
                "event_type": "Credential Theft"
            },
            {
                "timestamp": (start_time + timedelta(minutes=30)).isoformat(),
                "severity": "Critical",
                "source_ip": "external-vpn.suspicious.net",
                "destination_ip": "10.0.0.100",
                "user": victim,
                "description": f"Login from unusual location using {victim}'s credentials - potential account takeover",
                "event_type": "Authentication"
            }
        ]
        
        return alerts


# Registry of available scenarios
SCENARIOS = {
    "brute_force": BruteForceScenario(),
    "lateral_movement": LateralMovementScenario(),
    "ransomware": RansomwareScenario(),
    "data_exfiltration": DataExfiltrationScenario(),
    "reconnaissance": ReconnaissanceScenario(),
    "privilege_escalation": PrivilegeEscalationScenario(),
    "insider_threat": InsiderThreatScenario(),
    "phishing": PhishingScenario()
}


def get_scenario(name: str) -> AttackScenario:
    """Get a scenario by name"""
    return SCENARIOS.get(name.lower())


def get_random_scenario() -> AttackScenario:
    """Get a random attack scenario"""
    return random.choice(list(SCENARIOS.values()))


def list_scenarios() -> List[Dict[str, str]]:
    """List all available scenarios"""
    return [
        {"name": name, "description": scenario.description}
        for name, scenario in SCENARIOS.items()
    ]
