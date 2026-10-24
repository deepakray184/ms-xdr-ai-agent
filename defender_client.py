"""Microsoft Defender XDR API Client.
Connects to Microsoft Graph Security API v1.0 (/security/alerts_v2 and /security/incidents)
using Microsoft Entra ID (MSAL) OAuth2 client credentials.
"""

import logging
from typing import Any, Dict, List, Optional
import requests
import msal

from config import settings
from models import (
    AlertEntity,
    AlertSeverity,
    AlertStatus,
    DefenderAlert,
    EntityType,
    MitreTechnique,
)
from mock_data import MOCK_DEFENDER_ALERTS

logger = logging.getLogger("defender_client")


class DefenderXDRClient:
    """Client for querying and managing Microsoft Defender XDR alerts and incidents."""

    def __init__(self):
        self._app: Optional[msal.ConfidentialClientApplication] = None
        self._token: Optional[Dict[str, Any]] = None

    def _get_msal_app(self) -> Optional[msal.ConfidentialClientApplication]:
        if not settings.is_azure_configured:
            return None
        if self._app is None:
            authority = f"https://login.microsoftonline.com/{settings.AZURE_TENANT_ID}"
            self._app = msal.ConfidentialClientApplication(
                client_id=settings.AZURE_CLIENT_ID,
                client_credential=settings.AZURE_CLIENT_SECRET,
                authority=authority,
            )
        return self._app

    def acquire_token(self) -> Optional[str]:
        """Acquires OAuth2 Bearer token from Entra ID for Microsoft Graph API."""
        if not settings.is_azure_configured or settings.FORCE_MOCK:
            return None

        app = self._get_msal_app()
        if not app:
            return None

        scopes = [settings.GRAPH_SCOPE]
        result = app.acquire_token_silent(scopes, account=None)
        if not result:
            result = app.acquire_token_for_client(scopes=scopes)

        if "access_token" in result:
            self._token = result
            return result["access_token"]
        else:
            err_msg = result.get("error_description", result.get("error", "Unknown MSAL error"))
            logger.error(f"Failed to acquire token from Entra ID: {err_msg}")
            raise ConnectionError(f"Entra ID Authentication Failed: {err_msg}")

    def test_connection(self) -> Dict[str, Any]:
        """Validates connectivity to Entra ID and Defender XDR Graph Security API."""
        if settings.FORCE_MOCK:
            return {
                "connected": True,
                "mode": "MOCK",
                "message": "Running in Simulation / Mock Mode (FORCE_MOCK is enabled).",
                "tenant_id": "Simulated-Tenant",
                "alerts_accessible": True,
            }

        if not settings.is_azure_configured:
            return {
                "connected": False,
                "mode": "MOCK_FALLBACK",
                "message": "Azure credentials not configured in .env. Falling back to realistic simulation mode.",
                "missing": [
                    k for k in ["AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"]
                    if not getattr(settings, k) or getattr(settings, k).startswith("your-")
                ],
                "alerts_accessible": True,
            }

        try:
            token = self.acquire_token()
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }
            # Test query: Get single alert to verify SecurityAlert.Read.All permission
            url = f"{settings.GRAPH_API_BASE}/security/alerts_v2?$top=1"
            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json()
                count = len(data.get("value", []))
                return {
                    "connected": True,
                    "mode": "LIVE",
                    "message": f"Successfully connected to Microsoft Defender XDR. Tenant verified.",
                    "tenant_id": settings.AZURE_TENANT_ID,
                    "client_id": settings.AZURE_CLIENT_ID,
                    "sample_records_found": count,
                    "status_code": 200,
                }
            elif response.status_code == 403:
                return {
                    "connected": False,
                    "mode": "ERROR",
                    "message": "Connected to Entra ID, but lacks permission for Defender XDR. Ensure 'SecurityAlert.Read.All' or 'SecurityIncident.Read.All' application permission is granted and admin-consented in Azure Portal.",
                    "status_code": 403,
                    "details": response.text,
                }
            else:
                return {
                    "connected": False,
                    "mode": "ERROR",
                    "message": f"Graph API responded with HTTP {response.status_code}: {response.text}",
                    "status_code": response.status_code,
                }
        except Exception as e:
            return {
                "connected": False,
                "mode": "ERROR",
                "message": f"Connection error: {str(e)}",
            }

    def get_alerts(
        self,
        top: int = 20,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[DefenderAlert]:
        """Fetches alerts from Defender XDR (or mock data if not configured)."""
        if not settings.is_azure_configured or settings.FORCE_MOCK:
            alerts = [self.parse_alert_payload(raw) for raw in MOCK_DEFENDER_ALERTS]
            if severity:
                alerts = [a for a in alerts if a.severity.value.lower() == severity.lower()]
            if status:
                alerts = [a for a in alerts if a.status.value.lower() == status.lower()]
            return alerts[:top]

        token = self.acquire_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        query_params = [f"$top={top}"]
        filters = []
        if severity:
            filters.append(f"severity eq '{severity.lower()}'")
        if status:
            filters.append(f"status eq '{status}'")
        if filters:
            query_params.append(f"$filter={' and '.join(filters)}")
        query_params.append("$orderby=createdDateTime desc")

        url = f"{settings.GRAPH_API_BASE}/security/alerts_v2?{'&'.join(query_params)}"
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()

        raw_alerts = response.json().get("value", [])
        return [self.parse_alert_payload(raw) for raw in raw_alerts]

    def get_alert_by_id(self, alert_id: str) -> Optional[DefenderAlert]:
        """Fetches a single Defender XDR alert by ID."""
        if not settings.is_azure_configured or settings.FORCE_MOCK:
            for raw in MOCK_DEFENDER_ALERTS:
                if raw.get("id") == alert_id or raw.get("providerAlertId") == alert_id:
                    return self.parse_alert_payload(raw)
            return None

        token = self.acquire_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        url = f"{settings.GRAPH_API_BASE}/security/alerts_v2/{alert_id}"
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return self.parse_alert_payload(response.json())

    def update_alert_status(self, alert_id: str, status: str, comment: Optional[str] = None) -> bool:
        """Updates alert status in Microsoft Defender XDR."""
        if not settings.is_azure_configured or settings.FORCE_MOCK:
            logger.info(f"[MOCK] Updated alert {alert_id} status to {status} with comment: {comment}")
            return True

        token = self.acquire_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        url = f"{settings.GRAPH_API_BASE}/security/alerts_v2/{alert_id}"
        payload = {"status": status}
        if comment:
            payload["comments"] = [{"comment": comment}]

        response = requests.patch(url, json=payload, headers=headers, timeout=15)
        return response.status_code in (200, 204)

    def parse_alert_payload(self, raw: Dict[str, Any]) -> DefenderAlert:
        """Parses Microsoft Graph /security/alerts_v2 JSON schema into DefenderAlert model."""
        evidence_list = raw.get("evidence", [])
        entities: List[AlertEntity] = []

        # Parse Evidence & Entities
        for ev in evidence_list:
            odata_type = ev.get("@odata.type", "")

            # Device
            if "deviceEvidence" in odata_type:
                device_name = ev.get("deviceDnsName") or ev.get("mdeDeviceId") or "Unknown-Device"
                entities.append(AlertEntity(
                    entity_type=EntityType.DEVICE,
                    identifier=device_name,
                    details={
                        "osPlatform": ev.get("osPlatform"),
                        "riskScore": ev.get("riskScore"),
                        "healthStatus": ev.get("healthStatus"),
                        "ipInterfaces": ev.get("ipInterfaces", []),
                        "loggedOnUsers": ev.get("loggedOnUsers", [])
                    }
                ))

            # User
            elif "userEvidence" in odata_type:
                user_acct = ev.get("userAccount", {})
                upn = user_acct.get("userPrincipalName") or user_acct.get("accountName") or "Unknown-User"
                entities.append(AlertEntity(
                    entity_type=EntityType.USER,
                    identifier=upn,
                    details={
                        "domain": user_acct.get("domainName"),
                        "userSid": user_acct.get("userSid"),
                        "roles": ev.get("roles", [])
                    }
                ))

            # Process
            elif "processEvidence" in odata_type:
                cmd = ev.get("processCommandLine") or "Unknown-Process"
                img = ev.get("imageFile", {}).get("fileName") or "process"
                entities.append(AlertEntity(
                    entity_type=EntityType.PROCESS,
                    identifier=f"{img} (PID: {ev.get('processId')})",
                    details={
                        "commandLine": cmd,
                        "parentCommandLine": ev.get("parentProcessCommandLine"),
                        "processId": ev.get("processId"),
                        "parentProcessId": ev.get("parentProcessId"),
                        "sha256": ev.get("imageFile", {}).get("sha256")
                    }
                ))

            # File
            elif "fileEvidence" in odata_type:
                fname = ev.get("fileName") or ev.get("filePath") or "Unknown-File"
                entities.append(AlertEntity(
                    entity_type=EntityType.FILE,
                    identifier=fname,
                    details={
                        "filePath": ev.get("filePath"),
                        "sha256": ev.get("sha256") or ev.get("fileDetails", {}).get("sha256"),
                        "roles": ev.get("roles", [])
                    }
                ))

            # IP
            elif "ipEvidence" in odata_type:
                ip = ev.get("ipAddress") or "Unknown-IP"
                entities.append(AlertEntity(
                    entity_type=EntityType.IP,
                    identifier=ip,
                    details={
                        "countryCode": ev.get("countryCode"),
                        "url": ev.get("url")
                    }
                ))

            # Mailbox
            elif "mailboxEvidence" in odata_type:
                primary = ev.get("primaryAddress") or "Unknown-Mailbox"
                entities.append(AlertEntity(
                    entity_type=EntityType.MAILBOX,
                    identifier=primary,
                    details={
                        "forwardingAddress": ev.get("forwardingAddress"),
                    }
                ))

        # Parse MITRE Techniques
        mitre_list: List[MitreTechnique] = []
        for tech in raw.get("mitreTechniques", []):
            if isinstance(tech, str):
                mitre_list.append(MitreTechnique(
                    technique_id=tech,
                    name=self._get_mitre_technique_name(tech),
                    tactic=self._get_mitre_tactic(tech)
                ))
            elif isinstance(tech, dict):
                mitre_list.append(MitreTechnique(
                    technique_id=tech.get("id", "Unknown"),
                    name=tech.get("name", "Unknown"),
                    tactic=tech.get("tactic", "Unknown")
                ))

        # Severity mapping
        sev_str = raw.get("severity", "low").lower()
        severity = AlertSeverity(sev_str) if sev_str in AlertSeverity._value2member_map_ else AlertSeverity.UNKNOWN

        # Status mapping
        st_str = raw.get("status", "new")
        status = AlertStatus(st_str) if st_str in AlertStatus._value2member_map_ else AlertStatus.UNKNOWN

        return DefenderAlert(
            id=raw.get("id", ""),
            title=raw.get("title", "Untitled Alert"),
            description=raw.get("description", ""),
            severity=severity,
            status=status,
            category=raw.get("category", "General"),
            created_date_time=raw.get("createdDateTime"),
            last_update_date_time=raw.get("lastUpdateDateTime"),
            incident_id=raw.get("incidentId"),
            service_source=raw.get("serviceSource", "microsoftDefenderForEndpoint"),
            detection_source=raw.get("detectionSource"),
            provider_alert_id=raw.get("providerAlertId"),
            recommended_actions=raw.get("recommendedActions"),
            mitre_techniques=mitre_list,
            entities=entities,
            raw_evidence=evidence_list,
            raw_payload=raw,
        )

    def _get_mitre_technique_name(self, tech_id: str) -> str:
        lookup = {
            "T1003.001": "OS Credential Dumping: LSASS Memory",
            "T1059.001": "PowerShell Execution",
            "T1078.002": "Valid Accounts: Domain Accounts",
            "T1078.004": "Valid Accounts: Cloud Accounts",
            "T1204.002": "User Execution: Malicious File",
            "T1071.001": "Web Protocols (C2)",
            "T1114.003": "Email Forwarding Rule",
            "T1021.002": "SMB/Windows Admin Shares",
            "T1569.002": "Service Execution",
            "T1486": "Data Encrypted for Impact (Ransomware)",
        }
        return lookup.get(tech_id, f"Technique {tech_id}")

    def _get_mitre_tactic(self, tech_id: str) -> str:
        lookup = {
            "T1003.001": "Credential Access",
            "T1059.001": "Execution",
            "T1078.002": "Defense Evasion / Initial Access",
            "T1078.004": "Initial Access",
            "T1204.002": "Execution",
            "T1071.001": "Command and Control",
            "T1114.003": "Collection / Exfiltration",
            "T1021.002": "Lateral Movement",
            "T1569.002": "Execution",
            "T1486": "Impact",
        }
        return lookup.get(tech_id, "Tactic")
