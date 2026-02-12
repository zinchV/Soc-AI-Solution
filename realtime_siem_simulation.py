"""
Real-Time Multi-SIEM Simulation Script
Simulates alerts from Splunk, QRadar, Sentinel, and Generic sources
pushing to the SOC AI Tool in real-time.

Usage:
    python realtime_siem_simulation.py

This simulates a realistic SOC environment where different SIEM tools
are sending alerts to your centralized SOC AI Tool.
"""

import requests
import time
import random
from datetime import datetime, timedelta
import json

# Configuration
BASE_URL = "http://localhost:8080"
SIMULATION_DURATION_MINUTES = 10  # How long to run
ALERT_INTERVAL_SECONDS = 15       # Time between alerts (15-45 seconds randomly)

# Track simulation stats
stats = {
    "splunk": 0,
    "qradar": 0,
    "sentinel": 0,
    "generic": 0,
    "total": 0,
    "failed": 0
}

# ============================================
# REALISTIC ALERT DATA
# ============================================

USERS = ["jsmith", "admin", "svc_backup", "contractor1", "mwilliams", "analyst1", "dbadmin", "root"]
INTERNAL_IPS = ["192.168.1." + str(i) for i in range(50, 150)]
EXTERNAL_IPS = ["45.33.32.156", "104.131.0.69", "185.220.101.1", "91.121.87.10", "23.129.64.100"]
SERVERS = ["10.0.0." + str(i) for i in range(10, 50)]
DOMAINS = ["evil-domain.ru", "malware-c2.net", "phishing-site.com", "data-exfil.io"]

# Realistic attack scenarios that unfold over time
ATTACK_SCENARIOS = {
    "brute_force": {
        "phases": [
            {"severity": "Low", "desc": "Failed SSH login attempt", "type": "Authentication"},
            {"severity": "Low", "desc": "Failed SSH login attempt", "type": "Authentication"},
            {"severity": "Medium", "desc": "Multiple failed login attempts detected", "type": "Authentication"},
            {"severity": "High", "desc": "Brute force attack in progress", "type": "Authentication"},
            {"severity": "Critical", "desc": "Successful login after brute force", "type": "Authentication"},
        ]
    },
    "ransomware": {
        "phases": [
            {"severity": "Medium", "desc": "Suspicious email attachment opened", "type": "Malware"},
            {"severity": "High", "desc": "Unknown process spawned by Office application", "type": "Malware"},
            {"severity": "Critical", "desc": "File encryption activity detected", "type": "Malware"},
            {"severity": "Critical", "desc": "Ransom note file created", "type": "Malware"},
            {"severity": "Critical", "desc": "C2 communication to known ransomware IP", "type": "Malware"},
        ]
    },
    "data_exfil": {
        "phases": [
            {"severity": "Low", "desc": "Large file access by user", "type": "Data Loss Prevention"},
            {"severity": "Medium", "desc": "Unusual data transfer volume detected", "type": "Data Loss Prevention"},
            {"severity": "High", "desc": "Sensitive data copied to USB device", "type": "Data Loss Prevention"},
            {"severity": "Critical", "desc": "Data exfiltration to external IP detected", "type": "Data Loss Prevention"},
        ]
    },
    "lateral_movement": {
        "phases": [
            {"severity": "Medium", "desc": "Unusual SMB connection between workstations", "type": "Network"},
            {"severity": "High", "desc": "PsExec execution detected", "type": "Network"},
            {"severity": "High", "desc": "Pass-the-hash attack indicators", "type": "Credential Access"},
            {"severity": "Critical", "desc": "Domain admin credentials used from workstation", "type": "Credential Access"},
        ]
    }
}

# Current attack state (simulates ongoing attacks)
active_attacks = {}


# ============================================
# SIEM FORMAT GENERATORS
# ============================================

def generate_splunk_alert(severity: str, source_ip: str, dest_ip: str, user: str, description: str, event_type: str):
    """Generate Splunk Enterprise Security format alert"""
    return {
        "result": {
            "_time": datetime.now().isoformat(),
            "severity": severity.lower(),
            "src_ip": source_ip,
            "dest_ip": dest_ip,
            "user": user,
            "signature": description,
            "category": event_type.lower().replace(" ", "_"),
            "vendor_product": "Splunk ES",
            "rule_name": f"SOC-{random.randint(1000, 9999)}",
            "risk_score": {"Critical": 95, "High": 75, "Medium": 50, "Low": 25}[severity],
            "app": "enterprise_security"
        },
        "sid": f"rt_splunk_{int(time.time())}_{random.randint(1000, 9999)}",
        "search_name": "Real-time Alert Detection",
        "results_link": f"https://splunk.company.com/app/search/{random.randint(10000, 99999)}"
    }


def generate_qradar_offense(severity: str, source_ip: str, dest_ip: str, user: str, description: str, event_type: str):
    """Generate IBM QRadar offense format"""
    severity_map = {"Critical": 10, "High": 8, "Medium": 5, "Low": 3}
    return {
        "offense_id": random.randint(100000, 999999),
        "offense_type": random.randint(1, 10),
        "offense_source": source_ip,
        "local_destination_address_ids": [random.randint(1, 100)],
        "remote_destination_count": 1,
        "destination_networks": ["Internal Network"],
        "source_network": "External" if source_ip in EXTERNAL_IPS else "Internal",
        "description": description,
        "severity": severity_map.get(severity, 5),
        "magnitude": severity_map.get(severity, 5) - 1,
        "credibility": random.randint(7, 10),
        "relevance": random.randint(7, 10),
        "start_time": int(time.time() * 1000),
        "last_updated_time": int(time.time() * 1000),
        "event_count": random.randint(1, 100),
        "flow_count": random.randint(0, 50),
        "status": "OPEN",
        "categories": [event_type],
        "username_count": 1 if user else 0,
        "log_sources": [{"name": "QRadar", "id": random.randint(1, 100)}],
        "rules": [{"name": f"QRadar Rule {random.randint(1, 50)}", "id": random.randint(1, 1000)}]
    }


def generate_sentinel_incident(severity: str, source_ip: str, dest_ip: str, user: str, description: str, event_type: str):
    """Generate Microsoft Sentinel incident format"""
    tactics_map = {
        "Authentication": "CredentialAccess",
        "Malware": "Execution",
        "Data Loss Prevention": "Exfiltration",
        "Network": "LateralMovement",
        "Credential Access": "CredentialAccess",
        "Policy Violation": "InitialAccess"
    }
    return {
        "id": f"/subscriptions/xxx/resourceGroups/soc/providers/Microsoft.SecurityInsights/incidents/{random.randint(10000, 99999)}",
        "name": f"INC-{random.randint(10000, 99999)}",
        "type": "Microsoft.SecurityInsights/incidents",
        "properties": {
            "title": description[:50],
            "description": description,
            "severity": severity,
            "status": "New",
            "classification": None,
            "firstActivityTimeUtc": (datetime.utcnow() - timedelta(minutes=random.randint(1, 5))).isoformat() + "Z",
            "lastActivityTimeUtc": datetime.utcnow().isoformat() + "Z",
            "createdTimeUtc": datetime.utcnow().isoformat() + "Z",
            "incidentNumber": random.randint(1000, 9999),
            "alerts": [
                {
                    "alertDisplayName": description,
                    "severity": severity,
                    "sourceIp": source_ip,
                    "destinationIp": dest_ip,
                    "userName": user,
                    "alertType": event_type
                }
            ],
            "owner": {"assignedTo": None},
            "additionalData": {
                "tactics": [tactics_map.get(event_type, "Unknown")],
                "alertProductNames": ["Azure Sentinel"],
                "alertsCount": 1
            }
        }
    }


def generate_generic_alert(severity: str, source_ip: str, dest_ip: str, user: str, description: str, event_type: str):
    """Generate generic SOC AI Tool format alert"""
    return {
        "timestamp": datetime.now().isoformat(),
        "severity": severity,
        "source_ip": source_ip,
        "destination_ip": dest_ip,
        "user": user,
        "description": description,
        "event_type": event_type
    }


# ============================================
# ALERT SENDING FUNCTIONS
# ============================================

def send_alert(siem_type: str, alert_data: dict):
    """Send alert to the appropriate endpoint"""
    endpoints = {
        "splunk": f"{BASE_URL}/api/v1/ingest/splunk",
        "qradar": f"{BASE_URL}/api/v1/ingest/qradar",
        "sentinel": f"{BASE_URL}/api/v1/ingest/sentinel",
        "generic": f"{BASE_URL}/api/v1/ingest/alert"
    }
    
    try:
        response = requests.post(
            endpoints[siem_type],
            json=alert_data,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        if response.status_code == 200:
            stats[siem_type] += 1
            stats["total"] += 1
            return True
        else:
            stats["failed"] += 1
            print(f"  ❌ Failed: {response.status_code} - {response.text[:100]}")
            return False
            
    except Exception as e:
        stats["failed"] += 1
        print(f"  ❌ Error: {e}")
        return False


def generate_and_send_alert():
    """Generate a random alert and send it via a random SIEM format"""
    
    # Choose SIEM type (weighted - Splunk and Sentinel more common)
    siem_type = random.choices(
        ["splunk", "qradar", "sentinel", "generic"],
        weights=[35, 20, 30, 15]
    )[0]
    
    # Decide if this is part of an ongoing attack or a new random alert
    if random.random() < 0.6 and active_attacks:  # 60% chance to continue an attack
        attack_id = random.choice(list(active_attacks.keys()))
        attack = active_attacks[attack_id]
        
        if attack["phase"] < len(attack["scenario"]["phases"]):
            phase_data = attack["scenario"]["phases"][attack["phase"]]
            severity = phase_data["severity"]
            description = phase_data["desc"]
            event_type = phase_data["type"]
            source_ip = attack["source_ip"]
            dest_ip = attack["dest_ip"]
            user = attack["user"]
            
            attack["phase"] += 1
            
            # Remove completed attacks
            if attack["phase"] >= len(attack["scenario"]["phases"]):
                del active_attacks[attack_id]
        else:
            return generate_random_alert(siem_type)
    else:
        # Start a new attack or generate random alert
        if random.random() < 0.4:  # 40% chance to start a new attack
            scenario_name = random.choice(list(ATTACK_SCENARIOS.keys()))
            attack_id = f"{scenario_name}_{int(time.time())}"
            active_attacks[attack_id] = {
                "scenario": ATTACK_SCENARIOS[scenario_name],
                "phase": 0,
                "source_ip": random.choice(INTERNAL_IPS if random.random() < 0.7 else EXTERNAL_IPS),
                "dest_ip": random.choice(SERVERS),
                "user": random.choice(USERS)
            }
            
            phase_data = ATTACK_SCENARIOS[scenario_name]["phases"][0]
            severity = phase_data["severity"]
            description = phase_data["desc"]
            event_type = phase_data["type"]
            source_ip = active_attacks[attack_id]["source_ip"]
            dest_ip = active_attacks[attack_id]["dest_ip"]
            user = active_attacks[attack_id]["user"]
            
            active_attacks[attack_id]["phase"] = 1
        else:
            return generate_random_alert(siem_type)
    
    # Generate alert in the chosen format
    generators = {
        "splunk": generate_splunk_alert,
        "qradar": generate_qradar_offense,
        "sentinel": generate_sentinel_incident,
        "generic": generate_generic_alert
    }
    
    alert_data = generators[siem_type](severity, source_ip, dest_ip, user, description, event_type)
    
    # Print alert info
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] 📤 {siem_type.upper():8} | {severity:8} | {description[:50]}")
    
    return send_alert(siem_type, alert_data)


def generate_random_alert(siem_type: str):
    """Generate a completely random alert"""
    severities = ["Low", "Medium", "High", "Critical"]
    weights = [30, 40, 20, 10]  # Most alerts are Low/Medium
    
    severity = random.choices(severities, weights=weights)[0]
    source_ip = random.choice(INTERNAL_IPS + EXTERNAL_IPS)
    dest_ip = random.choice(SERVERS)
    user = random.choice(USERS)
    
    descriptions = [
        "Unusual network traffic pattern detected",
        "Failed authentication attempt",
        "Firewall rule violation",
        "Suspicious process execution",
        "Antivirus signature match",
        "IDS alert triggered",
        "Anomalous user behavior detected",
        "Unauthorized access attempt",
        "Policy violation detected",
        "Suspicious DNS query"
    ]
    
    event_types = ["Authentication", "Network", "Malware", "Policy Violation", "Anomaly"]
    
    description = random.choice(descriptions)
    event_type = random.choice(event_types)
    
    generators = {
        "splunk": generate_splunk_alert,
        "qradar": generate_qradar_offense,
        "sentinel": generate_sentinel_incident,
        "generic": generate_generic_alert
    }
    
    alert_data = generators[siem_type](severity, source_ip, dest_ip, user, description, event_type)
    
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] 📤 {siem_type.upper():8} | {severity:8} | {description[:50]}")
    
    return send_alert(siem_type, alert_data)


# ============================================
# MAIN SIMULATION
# ============================================

def print_banner():
    print("\n" + "=" * 70)
    print("🔴 REAL-TIME MULTI-SIEM SIMULATION")
    print("=" * 70)
    print(f"Target:     {BASE_URL}")
    print(f"Duration:   {SIMULATION_DURATION_MINUTES} minutes")
    print(f"Interval:   {ALERT_INTERVAL_SECONDS}-{ALERT_INTERVAL_SECONDS + 30} seconds")
    print(f"SIEM Types: Splunk, QRadar, Sentinel, Generic")
    print("=" * 70)
    print("\nStarting simulation... Press Ctrl+C to stop\n")


def print_stats():
    print("\n" + "=" * 70)
    print("📊 SIMULATION STATISTICS")
    print("=" * 70)
    print(f"  Splunk:   {stats['splunk']:4} alerts")
    print(f"  QRadar:   {stats['qradar']:4} alerts")
    print(f"  Sentinel: {stats['sentinel']:4} alerts")
    print(f"  Generic:  {stats['generic']:4} alerts")
    print(f"  ─────────────────────")
    print(f"  Total:    {stats['total']:4} alerts")
    print(f"  Failed:   {stats['failed']:4} alerts")
    print("=" * 70)


def run_simulation():
    """Run the real-time simulation"""
    print_banner()
    
    start_time = time.time()
    end_time = start_time + (SIMULATION_DURATION_MINUTES * 60)
    
    try:
        while time.time() < end_time:
            generate_and_send_alert()
            
            # Random interval between alerts (15-45 seconds)
            interval = random.uniform(ALERT_INTERVAL_SECONDS, ALERT_INTERVAL_SECONDS + 30)
            
            # Show countdown
            remaining = int(end_time - time.time())
            mins, secs = divmod(remaining, 60)
            print(f"    ⏳ Next alert in {interval:.0f}s | Remaining: {mins}m {secs}s | Active attacks: {len(active_attacks)}")
            
            time.sleep(interval)
            
    except KeyboardInterrupt:
        print("\n\n⚠️  Simulation stopped by user")
    
    print_stats()
    
    print("\n💡 TIP: Now trigger triage to analyze the alerts:")
    print(f"   POST {BASE_URL}/api/v1/ingest/auto-triage/trigger")


if __name__ == "__main__":
    # Check if server is running
    try:
        response = requests.get(f"{BASE_URL}/api/v1/health", timeout=5)
        if response.status_code != 200:
            print("❌ Server is not healthy. Please start the server first.")
            exit(1)
    except:
        print(f"❌ Cannot connect to {BASE_URL}")
        print("   Please start the server: python -m uvicorn main:app --reload --port 8080")
        exit(1)
    
    run_simulation()
