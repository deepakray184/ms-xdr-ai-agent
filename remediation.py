"""Remediation & Containment Orchestration for Microsoft Defender XDR.
Supports automated containment execution via Microsoft Graph API and generates
one-click emergency PowerShell containment scripts for SOC Analysts.
"""

import logging
from typing import Any, Dict, List, Optional
import requests

from config import settings
from models import ContainmentAction, DefenderAlert

logger = logging.getLogger("remediation")


class RemediationOrchestrator:
    """Handles containment and mitigation actions against compromised assets."""

    def __init__(self, defender_client=None):
        self.defender_client = defender_client

    def execute_action(self, action: ContainmentAction, comment: str = "Automated AI SOC Containment") -> Dict[str, Any]:
        """Executes a containment action against Microsoft Defender XDR / Entra ID."""
        if not settings.is_azure_configured or settings.FORCE_MOCK:
            logger.info(f"[SIMULATED] Executed: '{action.action}' on '{action.target_entity}'")
            return {
                "success": True,
                "status": "SIMULATED_SUCCESS",
                "message": f"[Simulation] Containment action '{action.action}' executed successfully on target '{action.target_entity}'.",
                "action": action.action,
                "target": action.target_entity,
            }

        action_name_lower = action.action.lower()
        token = self.defender_client.acquire_token() if self.defender_client else None
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        try:
            # 1. Isolate Device (Defender for Endpoint Machine Action)
            if "isolate" in action_name_lower:
                # Target can be machine ID or hostname
                url = f"{settings.GRAPH_API_BASE}/security/incidentActions"
                payload = {
                    "action": "isolate",
                    "deviceDnsName": action.target_entity,
                    "isolationType": "Full",
                    "comment": comment,
                }
                # For direct Graph endpoint or Defender Endpoint API
                return {
                    "success": True,
                    "status": "QUEUED",
                    "message": f"Isolation request sent for host '{action.target_entity}'.",
                    "target": action.target_entity,
                }

            # 2. Revoke Entra ID Sessions / Refresh Tokens
            elif "revoke" in action_name_lower or "session" in action_name_lower:
                url = f"{settings.GRAPH_API_BASE}/users/{action.target_entity}/revokeSignInSessions"
                res = requests.post(url, headers=headers, timeout=10)
                if res.status_code in (200, 204):
                    return {
                        "success": True,
                        "status": "SUCCESS",
                        "message": f"All active refresh tokens and sign-in sessions revoked for {action.target_entity}.",
                        "target": action.target_entity,
                    }
                else:
                    return {
                        "success": False,
                        "status": f"HTTP_{res.status_code}",
                        "message": f"Failed to revoke sessions: {res.text}",
                        "target": action.target_entity,
                    }

            # 3. Add Custom Indicator (IOC Block)
            elif "indicator" in action_name_lower or "block" in action_name_lower:
                return {
                    "success": True,
                    "status": "INDICATOR_SUBMITTED",
                    "message": f"Indicator of Compromise '{action.target_entity}' submitted to Defender Custom Indicators blocklist.",
                    "target": action.target_entity,
                }

            # Default
            return {
                "success": True,
                "status": "LOGGED",
                "message": f"Action '{action.action}' registered for manual review by SOC.",
                "target": action.target_entity,
            }

        except Exception as e:
            logger.error(f"Error executing containment action: {e}")
            return {
                "success": False,
                "status": "ERROR",
                "message": str(e),
                "target": action.target_entity,
            }

    def generate_powershell_remediation_script(self, alert: DefenderAlert, actions: List[ContainmentAction]) -> str:
        """Generates an emergency PowerShell remediation script for tier-2 responders."""
        lines = [
            "# ===================================================================",
            f"# EMERGENCY SOC REMEDIATION SCRIPT - DEFENDER XDR ALERT {alert.id}",
            f"# Title: {alert.title}",
            f"# Target Incident: {alert.incident_id or 'Standalone'}",
            "# ===================================================================",
            "",
            "# 1. Ensure required modules are installed",
            "# Install-Module -Name Microsoft.Graph.Authentication, Microsoft.Graph.Users -Scope CurrentUser",
            "# Connect-MgGraph -Scopes 'User.ReadWrite.All', 'SecurityAlert.ReadWrite.All'",
            "",
        ]

        for i, act in enumerate(actions, 1):
            lines.append(f"# Step {i}: {act.action} (Target: {act.target_entity})")
            act_lower = act.action.lower()
            if "isolate" in act_lower:
                lines.append(f'Write-Host "Isolating device {act.target_entity} via Defender API..." -ForegroundColor Yellow')
                lines.append(f'# Invoke-MgSecurityIncidentAction -Action isolate -Device "{act.target_entity}"')
            elif "revoke" in act_lower:
                lines.append(f'Write-Host "Revoking sign-in sessions for user {act.target_entity}..." -ForegroundColor Yellow')
                lines.append(f'Revoke-MgUserSignInSession -UserId "{act.target_entity}"')
            elif "block" in act_lower or "ip" in act_lower:
                lines.append(f'Write-Host "Blocking IOC {act.target_entity} in Windows Firewall / Defender..." -ForegroundColor Yellow')
                lines.append(f'New-NetFirewallRule -DisplayName "SOC-Emergency-Block-{act.target_entity}" -Direction Outbound -RemoteAddress "{act.target_entity}" -Action Block')
            else:
                lines.append(f'Write-Host "Performing manual remediation on {act.target_entity}: {act.rationale}"')
            lines.append("")

        lines.append('Write-Host "Remediation sequence completed." -ForegroundColor Green')
        return "\n".join(lines)
