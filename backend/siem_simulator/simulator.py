"""
SIEM Simulator Engine
Generates realistic security alerts in various SIEM formats.
Can run continuously or generate on-demand.
"""
import asyncio
import random
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import httpx
import json

from siem_simulator.scenarios import (
    SCENARIOS, 
    get_scenario, 
    get_random_scenario,
    list_scenarios
)
from siem_simulator.formats import (
    FORMAT_GENERATORS,
    get_format_generator
)


class SIEMSimulator:
    """
    Simulates SIEM alert generation for testing purposes.
    Can output in multiple SIEM formats and run various attack scenarios.
    """
    
    def __init__(self, target_url: str = "http://localhost:8080", api_key: str = None):
        """
        Initialize the simulator.
        
        Args:
            target_url: Base URL of the SOC AI Tool API
            api_key: API key for authentication (if required)
        """
        self.target_url = target_url.rstrip("/")
        self.api_key = api_key
        self.running = False
        self._task = None
    
    def generate_scenario_alerts(
        self, 
        scenario_name: str = None,
        siem_format: str = "generic",
        start_time: datetime = None
    ) -> List[Dict[str, Any]]:
        """
        Generate alerts for a specific attack scenario.
        
        Args:
            scenario_name: Name of scenario (or random if None)
            siem_format: Output format (splunk, qradar, elastic, sentinel, cef, generic)
            start_time: Start time for the alerts
        
        Returns:
            List of alerts in the specified format
        """
        # Get scenario
        if scenario_name:
            scenario = get_scenario(scenario_name)
            if not scenario:
                raise ValueError(f"Unknown scenario: {scenario_name}")
        else:
            scenario = get_random_scenario()
        
        # Generate base alerts
        base_alerts = scenario.generate_alerts(start_time or datetime.utcnow())
        
        # Convert to specified format
        if siem_format.lower() == "generic":
            return base_alerts
        
        format_generator = get_format_generator(siem_format)
        return [format_generator.generate(alert) for alert in base_alerts]
    
    def generate_random_alert(
        self,
        siem_format: str = "generic"
    ) -> Dict[str, Any]:
        """
        Generate a single random alert.
        
        Args:
            siem_format: Output format
        
        Returns:
            Single alert in specified format
        """
        severities = ["Critical", "High", "Medium", "Low"]
        event_types = [
            "Authentication", "Malware", "Reconnaissance", 
            "Data Exfiltration", "Lateral Movement", "Policy Violation",
            "C2 Communication", "Privilege Escalation"
        ]
        
        alert = {
            "timestamp": datetime.utcnow().isoformat(),
            "severity": random.choice(severities),
            "source_ip": f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
            "destination_ip": f"10.0.0.{random.randint(1,254)}",
            "user": random.choice(["admin", "user1", "svc-account", "unknown"]),
            "description": f"Random security event detected - {random.choice(event_types)}",
            "event_type": random.choice(event_types)
        }
        
        if siem_format.lower() == "generic":
            return alert
        
        format_generator = get_format_generator(siem_format)
        return format_generator.generate(alert)
    
    async def send_alert(
        self,
        alert: Dict[str, Any],
        endpoint: str = "/api/v1/ingest/alert",
        siem_format: str = "generic"
    ) -> Dict[str, Any]:
        """
        Send a single alert to the ingestion API.
        
        Args:
            alert: Alert data to send
            endpoint: API endpoint to use
            siem_format: Format identifier for the endpoint
        
        Returns:
            API response
        """
        url = f"{self.target_url}{endpoint}"
        headers = {"Content-Type": "application/json"}
        
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        
        try:
            async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
                response = await client.post(
                    url,
                    json=alert,
                    headers=headers
                )
                return {
                    "success": response.status_code == 200,
                    "status_code": response.status_code,
                    "response": response.json() if response.status_code == 200 else response.text
                }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def send_batch(
        self,
        alerts: List[Dict[str, Any]],
        endpoint: str = "/api/v1/ingest/alerts"
    ) -> Dict[str, Any]:
        """
        Send multiple alerts in a batch.
        
        Args:
            alerts: List of alerts to send
            endpoint: Batch ingestion endpoint
        
        Returns:
            API response
        """
        url = f"{self.target_url}{endpoint}"
        headers = {"Content-Type": "application/json"}
        
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        
        try:
            async with httpx.AsyncClient(verify=False, timeout=60.0) as client:
                response = await client.post(
                    url,
                    json={"alerts": alerts},
                    headers=headers
                )
                return {
                    "success": response.status_code == 200,
                    "status_code": response.status_code,
                    "response": response.json() if response.status_code == 200 else response.text
                }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def run_continuous(
        self,
        interval_seconds: int = 30,
        alerts_per_interval: int = 1,
        siem_format: str = "generic",
        scenario_weights: Dict[str, float] = None
    ):
        """
        Run continuous alert generation.
        
        Args:
            interval_seconds: Time between alert batches
            alerts_per_interval: Number of alerts per interval
            siem_format: Output format for alerts
            scenario_weights: Optional weights for scenario selection
        """
        self.running = True
        print(f"🚀 Starting continuous simulation (interval: {interval_seconds}s, format: {siem_format})")
        
        while self.running:
            try:
                # Decide whether to run a scenario (30%) or random alerts (70%)
                if random.random() < 0.3:
                    # Run a full scenario
                    scenario = get_random_scenario()
                    alerts = self.generate_scenario_alerts(
                        scenario_name=None,
                        siem_format=siem_format
                    )
                    print(f"📋 Running scenario: {scenario.name} ({len(alerts)} alerts)")
                else:
                    # Generate random alerts
                    alerts = [
                        self.generate_random_alert(siem_format)
                        for _ in range(alerts_per_interval)
                    ]
                    print(f"🎲 Generated {len(alerts)} random alerts")
                
                # Send to API
                if len(alerts) == 1:
                    result = await self.send_alert(alerts[0])
                else:
                    result = await self.send_batch(alerts)
                
                if result["success"]:
                    print(f"✅ Sent {len(alerts)} alerts successfully")
                else:
                    print(f"❌ Failed to send alerts: {result.get('error', result.get('response'))}")
                
                # Wait for next interval
                await asyncio.sleep(interval_seconds)
                
            except asyncio.CancelledError:
                print("🛑 Simulation stopped")
                break
            except Exception as e:
                print(f"❌ Error during simulation: {e}")
                await asyncio.sleep(interval_seconds)
        
        self.running = False
    
    def stop(self):
        """Stop continuous simulation"""
        self.running = False
        if self._task:
            self._task.cancel()


# Singleton instance for easy access
simulator = SIEMSimulator()


def generate_demo_data(
    num_scenarios: int = 5,
    siem_format: str = "generic"
) -> List[Dict[str, Any]]:
    """
    Generate demo data with multiple attack scenarios.
    Useful for testing and demonstrations.
    
    Args:
        num_scenarios: Number of scenarios to generate
        siem_format: Output format
    
    Returns:
        List of all generated alerts
    """
    all_alerts = []
    start_time = datetime.utcnow() - timedelta(hours=2)
    
    scenario_names = list(SCENARIOS.keys())
    selected_scenarios = random.sample(
        scenario_names, 
        min(num_scenarios, len(scenario_names))
    )
    
    for i, scenario_name in enumerate(selected_scenarios):
        scenario_start = start_time + timedelta(minutes=i * 20)
        alerts = simulator.generate_scenario_alerts(
            scenario_name=scenario_name,
            siem_format=siem_format,
            start_time=scenario_start
        )
        all_alerts.extend(alerts)
    
    return all_alerts
