"""
Microsoft Sentinel Integration for SOC AI Tool
Enables deploying detection rules to Azure Sentinel via Azure SDK.

This module complements the read-only Sentinel MCP by providing WRITE capabilities.
"""

import os
import uuid
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

# Azure SDK imports
from azure.identity import DefaultAzureCredential, AzureCliCredential
from azure.mgmt.securityinsight import SecurityInsights
from azure.mgmt.securityinsight.models import (
    ScheduledAlertRule,
    AlertRuleKind,
    AttackTactic,
    EventGroupingSettings,
    EventGroupingAggregationKind,
    IncidentConfiguration,
    GroupingConfiguration,
    MatchingMethod,
)
from azure.core.exceptions import HttpResponseError


class SentinelRuleDeployer:
    """
    Deploy detection rules to Microsoft Sentinel.
    
    Usage:
        deployer = SentinelRuleDeployer(
            subscription_id="xxx",
            resource_group="soc-demo-rg",
            workspace_name="soc-demo-workspace"
        )
        result = deployer.deploy_scheduled_rule(
            rule_name="Detect CVE-2025-8110",
            query="SecurityEvent | where ...",
            severity="High"
        )
    """
    
    def __init__(
        self,
        subscription_id: str = None,
        resource_group: str = None,
        workspace_name: str = None,
        tenant_id: str = None
    ):
        """
        Initialize Sentinel deployer.
        
        Args:
            subscription_id: Azure subscription ID
            resource_group: Resource group containing Sentinel workspace
            workspace_name: Log Analytics workspace name
            tenant_id: Azure tenant ID (optional)
        """
        # Load from environment if not provided
        self.subscription_id = subscription_id or os.getenv("AZURE_SUBSCRIPTION_ID")
        self.resource_group = resource_group or os.getenv("AZURE_RESOURCE_GROUP")
        self.workspace_name = workspace_name or os.getenv("AZURE_WORKSPACE_NAME")
        self.tenant_id = tenant_id or os.getenv("AZURE_TENANT_ID")
        
        # Validate required parameters
        if not all([self.subscription_id, self.resource_group, self.workspace_name]):
            raise ValueError(
                "Missing required parameters. Provide subscription_id, resource_group, "
                "and workspace_name either as arguments or environment variables."
            )
        
        # Initialize Azure credential (uses az login or service principal)
        try:
            self.credential = AzureCliCredential()
            # Test the credential
            self.credential.get_token("https://management.azure.com/.default")
        except Exception:
            # Fallback to DefaultAzureCredential
            self.credential = DefaultAzureCredential()
        
        # Initialize Security Insights client
        self.client = SecurityInsights(
            credential=self.credential,
            subscription_id=self.subscription_id
        )
        
        print(f"✅ Sentinel deployer initialized for workspace: {self.workspace_name}")
    
    def deploy_scheduled_rule(
        self,
        rule_name: str,
        display_name: str,
        query: str,
        severity: str = "High",
        description: str = "",
        tactics: list = None,
        techniques: list = None,
        query_frequency: str = "PT5H",  # ISO 8601 duration (5 hours)
        query_period: str = "PT5H",     # ISO 8601 duration
        trigger_operator: str = "GreaterThan",
        trigger_threshold: int = 0,
        suppression_duration: str = "PT1H",
        suppression_enabled: bool = False,
        enabled: bool = True,
        create_incident: bool = True
    ) -> Dict[str, Any]:
        """
        Deploy a scheduled analytics rule to Sentinel.
        
        Args:
            rule_name: Unique identifier for the rule (no spaces)
            display_name: Human-readable rule name
            query: KQL query for the rule
            severity: High, Medium, Low, Informational
            description: Rule description
            tactics: List of MITRE tactics (e.g., ["InitialAccess", "Execution"])
            techniques: List of MITRE techniques (e.g., ["T1190", "T1059"])
            query_frequency: How often to run (ISO 8601)
            query_period: Time window to query (ISO 8601)
            trigger_operator: GreaterThan, LessThan, Equal, NotEqual
            trigger_threshold: Alert threshold
            suppression_duration: Suppress duplicates duration
            suppression_enabled: Enable suppression
            enabled: Enable the rule immediately
            create_incident: Auto-create incidents from alerts
        
        Returns:
            Dict with deployment result
        """
        try:
            # Generate unique rule ID
            rule_id = f"soc-ai-{rule_name.lower().replace(' ', '-').replace('_', '-')[:50]}"
            
            # Map severity string to proper casing
            severity_map = {
                "critical": "High",  # Sentinel doesn't have Critical, use High
                "high": "High",
                "medium": "Medium",
                "low": "Low",
                "informational": "Informational"
            }
            sentinel_severity = severity_map.get(severity.lower(), "High")
            
            # Map tactics to Sentinel enum values
            tactic_map = {
                "initial_access": "InitialAccess",
                "initialaccess": "InitialAccess",
                "execution": "Execution",
                "persistence": "Persistence",
                "privilege_escalation": "PrivilegeEscalation",
                "privilegeescalation": "PrivilegeEscalation",
                "defense_evasion": "DefenseEvasion",
                "defenseevasion": "DefenseEvasion",
                "credential_access": "CredentialAccess",
                "credentialaccess": "CredentialAccess",
                "discovery": "Discovery",
                "lateral_movement": "LateralMovement",
                "lateralmovement": "LateralMovement",
                "collection": "Collection",
                "command_and_control": "CommandAndControl",
                "commandandcontrol": "CommandAndControl",
                "exfiltration": "Exfiltration",
                "impact": "Impact",
            }
            
            sentinel_tactics = []
            if tactics:
                for t in tactics:
                    mapped = tactic_map.get(t.lower().replace(" ", "_").replace("-", "_"))
                    if mapped:
                        sentinel_tactics.append(mapped)
            
            # If no tactics provided, default to InitialAccess
            if not sentinel_tactics:
                sentinel_tactics = ["InitialAccess"]
            
            # Create incident configuration
            incident_config = IncidentConfiguration(
                create_incident=create_incident,
                grouping_configuration=GroupingConfiguration(
                    enabled=True,
                    reopen_closed_incident=False,
                    lookback_duration="PT5H",
                    matching_method=MatchingMethod.ALL_ENTITIES,
                    group_by_entities=[],
                    group_by_alert_details=[],
                    group_by_custom_details=[]
                )
            )
            
            # Create the scheduled alert rule
            rule = ScheduledAlertRule(
                display_name=display_name,
                description=description or f"Auto-generated rule: {display_name}",
                severity=sentinel_severity,
                enabled=enabled,
                query=query,
                query_frequency=query_frequency,
                query_period=query_period,
                trigger_operator=trigger_operator,
                trigger_threshold=trigger_threshold,
                suppression_duration=suppression_duration,
                suppression_enabled=suppression_enabled,
                tactics=sentinel_tactics,
                techniques=techniques or [],
                incident_configuration=incident_config,
                event_grouping_settings=EventGroupingSettings(
                    aggregation_kind=EventGroupingAggregationKind.SINGLE_ALERT
                )
            )
            
            # Deploy the rule
            print(f"🚀 Deploying rule '{display_name}' to Sentinel...")
            
            result = self.client.alert_rules.create_or_update(
                resource_group_name=self.resource_group,
                workspace_name=self.workspace_name,
                rule_id=rule_id,
                alert_rule=rule
            )
            
            print(f"✅ Rule deployed successfully!")
            print(f"   Rule ID: {result.name}")
            print(f"   Display Name: {result.display_name}")
            print(f"   Severity: {result.severity}")
            print(f"   Status: {'Enabled' if result.enabled else 'Disabled'}")
            
            return {
                "success": True,
                "rule_id": result.name,
                "display_name": result.display_name,
                "severity": result.severity,
                "enabled": result.enabled,
                "message": f"Rule '{display_name}' deployed to Sentinel successfully!"
            }
            
        except HttpResponseError as e:
            error_msg = str(e)
            print(f"❌ Deployment failed: {error_msg}")
            
            # Parse common errors
            if "AuthorizationFailed" in error_msg:
                suggestion = "Ensure you have 'Microsoft Sentinel Contributor' role on the workspace."
            elif "ResourceNotFound" in error_msg:
                suggestion = "Check that the workspace exists and you have access."
            elif "InvalidQuery" in error_msg:
                suggestion = "The KQL query has syntax errors. Validate it first."
            else:
                suggestion = "Check Azure portal for more details."
            
            return {
                "success": False,
                "error": error_msg,
                "suggestion": suggestion
            }
        except Exception as e:
            print(f"❌ Unexpected error: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def list_rules(self, limit: int = 20) -> Dict[str, Any]:
        """List existing analytics rules in Sentinel."""
        try:
            rules = self.client.alert_rules.list(
                resource_group_name=self.resource_group,
                workspace_name=self.workspace_name
            )
            
            rule_list = []
            for i, rule in enumerate(rules):
                if i >= limit:
                    break
                rule_list.append({
                    "id": rule.name,
                    "display_name": getattr(rule, 'display_name', 'N/A'),
                    "kind": rule.kind,
                    "severity": getattr(rule, 'severity', 'N/A'),
                    "enabled": getattr(rule, 'enabled', False)
                })
            
            return {
                "success": True,
                "count": len(rule_list),
                "rules": rule_list
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def delete_rule(self, rule_id: str) -> Dict[str, Any]:
        """Delete an analytics rule from Sentinel."""
        try:
            self.client.alert_rules.delete(
                resource_group_name=self.resource_group,
                workspace_name=self.workspace_name,
                rule_id=rule_id
            )
            return {
                "success": True,
                "message": f"Rule '{rule_id}' deleted successfully"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def get_rule(self, rule_id: str) -> Dict[str, Any]:
        """Get details of a specific rule."""
        try:
            rule = self.client.alert_rules.get(
                resource_group_name=self.resource_group,
                workspace_name=self.workspace_name,
                rule_id=rule_id
            )
            return {
                "success": True,
                "rule": {
                    "id": rule.name,
                    "display_name": getattr(rule, 'display_name', 'N/A'),
                    "kind": rule.kind,
                    "severity": getattr(rule, 'severity', 'N/A'),
                    "enabled": getattr(rule, 'enabled', False),
                    "query": getattr(rule, 'query', 'N/A'),
                    "description": getattr(rule, 'description', 'N/A')
                }
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }


# Convenience function for quick deployment
def deploy_rule_to_sentinel(
    kql_query: str,
    rule_name: str,
    description: str = "",
    severity: str = "High",
    cve_id: str = None
) -> Dict[str, Any]:
    """
    Quick function to deploy a rule to Sentinel.
    
    Uses environment variables for Azure configuration.
    """
    try:
        deployer = SentinelRuleDeployer()
        
        display_name = rule_name
        if cve_id:
            display_name = f"[SOC-AI] {cve_id} - {rule_name[:50]}"
        
        return deployer.deploy_scheduled_rule(
            rule_name=rule_name.replace(" ", "-").lower()[:50],
            display_name=display_name,
            query=kql_query,
            severity=severity,
            description=description,
            tactics=["InitialAccess"],
            techniques=["T1190"] if cve_id else []
        )
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


# Test function
if __name__ == "__main__":
    # Test the deployer
    print("Testing Sentinel Integration...")
    
    try:
        deployer = SentinelRuleDeployer()
        
        # List existing rules
        print("\n📋 Listing existing rules...")
        rules = deployer.list_rules(limit=5)
        print(f"Found {rules.get('count', 0)} rules")
        
        # Test deploy a simple rule
        print("\n🚀 Testing rule deployment...")
        test_query = """
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4625
| summarize FailedLogins = count() by TargetAccount, IpAddress
| where FailedLogins > 5
"""
        
        result = deployer.deploy_scheduled_rule(
            rule_name="soc-ai-test-rule",
            display_name="[SOC-AI] Test Rule - Failed Logins",
            query=test_query,
            severity="Medium",
            description="Test rule from SOC AI Tool - detects multiple failed logins",
            enabled=False  # Don't enable for testing
        )
        
        print(f"\nResult: {result}")
        
    except Exception as e:
        print(f"Error: {e}")
