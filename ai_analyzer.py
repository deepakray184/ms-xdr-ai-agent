"""AI SOC Analyst Engine for Microsoft Defender XDR Alerts.
Supports Google Gemini, OpenAI, Azure OpenAI, and an Expert SOC Heuristic Engine.
"""

import base64
import json
import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from config import settings
from models import (
    AIAnalysisReport,
    AlertEntity,
    AlertSeverity,
    ContainmentAction,
    DefenderAlert,
    EntityType,
    KqlHuntingQuery,
    MitreTechnique,
    TriageVerdict,
)

logger = logging.getLogger("ai_analyzer")

SYSTEM_PROMPT = """You are a Principal Security Operations Center (SOC) Analyst and Threat Intelligence specialist analyzing an alert from Microsoft Defender XDR.

Your job is to thoroughly analyze the alert, evidence, entities (devices, users, processes, files, network IPs, mailboxes), and MITRE ATT&CK techniques.

Provide your investigation in structured JSON format with EXACTLY the following keys:
{
  "verdict": "True Positive (Malicious)" | "False Positive (Benign/Authorized)" | "Suspicious (Needs Further Investigation)" | "Benign Positive (Expected Security Test/Admin Tool)",
  "confidence_score": 0-100 (integer),
  "severity_assessment": "informational" | "low" | "medium" | "high",
  "executive_summary": "Concise non-technical risk summary for C-level & SOC managers (2-3 sentences)",
  "technical_narrative": "Detailed technical attack story: parent/child processes, command-line arguments (decode base64 if found), persistence, C2, and attacker intent",
  "attack_vector": "Identified initial access or execution vector",
  "blast_radius_assessment": "Assessment of potential lateral movement, domain impact, and compromised identities",
  "false_positive_indicators": ["List of checks or conditions that would indicate this is benign"],
  "containment_actions": [
    {
      "action": "Specific containment step (e.g. Isolate Device, Disable User, Revoke Refresh Tokens, Block Indicator)",
      "target_entity": "Target hostname, UPN, IP, or hash",
      "priority": "Immediate" | "High" | "Medium" | "Low",
      "rationale": "Why this action is necessary",
      "automated_capability": true
    }
  ],
  "hunting_queries": [
    {
      "title": "Title of KQL query",
      "description": "What this query investigates in Defender Advanced Hunting",
      "table": "DeviceProcessEvents | DeviceNetworkEvents | DeviceFileEvents | SigninLogs",
      "query": "Valid executable Kusto Query Language (KQL) query"
    }
  ],
  "next_steps_for_analyst": [
    "Step 1...",
    "Step 2..."
  ]
}

Return ONLY valid JSON. Do not include markdown code block quotes around the JSON if possible, or use standard ```json.
"""


class AISOCAnalyzer:
    """SOC Analyst Agent for automated Defender XDR alert triaging and investigation."""

    def __init__(self):
        self.provider = settings.LLM_PROVIDER
        self._gemini_client = None
        self._openai_client = None
        self._anthropic_client = None

    def analyze_alert(self, alert: DefenderAlert) -> AIAnalysisReport:
        """Analyzes a Defender XDR alert using LLM or Expert Heuristic engine."""
        # 1. Google Gemini
        if self.provider == "gemini" and settings.GEMINI_API_KEY and not settings.GEMINI_API_KEY.startswith("your-"):
            try:
                return self._analyze_with_gemini(alert)
            except Exception as e:
                logger.warning(f"Gemini analysis failed ({e}), falling back to Expert Heuristic Analyst.")

        # 2. Anthropic Claude
        elif self.provider in ("claude", "anthropic") and settings.ANTHROPIC_API_KEY and not settings.ANTHROPIC_API_KEY.startswith("your-"):
            try:
                return self._analyze_with_anthropic(alert)
            except Exception as e:
                logger.warning(f"Claude analysis failed ({e}), falling back to Expert Heuristic Analyst.")

        # 3. OpenAI, ChatGPT, Azure OpenAI & Microsoft Copilot API
        elif self.provider in ("openai", "chatgpt", "azure_openai", "copilot", "ms_copilot") and (settings.OPENAI_API_KEY or settings.AZURE_OPENAI_API_KEY):
            try:
                return self._analyze_with_openai(alert)
            except Exception as e:
                logger.warning(f"OpenAI/Copilot analysis failed ({e}), falling back to Expert Heuristic Analyst.")

        # 4. Ollama / Local Models
        elif self.provider in ("ollama", "local", "custom"):
            try:
                return self._analyze_with_ollama(alert)
            except Exception as e:
                logger.warning(f"Ollama/Local analysis failed ({e}), falling back to Expert Heuristic Analyst.")

        # 5. Fallback: Expert SOC Heuristic Engine (deterministic, offline-ready, deep inspection)
        return self._analyze_with_expert_heuristics(alert)

    def _build_alert_context(self, alert: DefenderAlert) -> str:
        """Builds structured alert summary for LLM prompt."""
        entities_summary = []
        for ent in alert.entities:
            entities_summary.append(f"- [{ent.entity_type.value.upper()}] {ent.identifier} | Details: {json.dumps(ent.details)}")

        mitre_summary = [f"{m.technique_id} ({m.name}) - Tactic: {m.tactic}" for m in alert.mitre_techniques]

        context = f"""
ALERT TO ANALYZE:
================
Alert ID: {alert.id}
Provider Alert ID: {alert.provider_alert_id}
Incident ID: {alert.incident_id}
Title: {alert.title}
Severity: {alert.severity.value}
Category: {alert.category}
Service Source: {alert.service_source}
Detection Source: {alert.detection_source}
Created: {alert.created_date_time}
Description: {alert.description}
Recommended Actions from Defender: {alert.recommended_actions}

MITRE ATT&CK Techniques:
{chr(10).join(mitre_summary) if mitre_summary else 'None identified'}

Impacted Entities & Evidence ({len(alert.entities)} detected):
{chr(10).join(entities_summary) if entities_summary else 'No entities extracted'}

Raw Evidence Snippets:
{json.dumps(alert.raw_evidence, indent=2)}
"""
        return context

    def _analyze_with_gemini(self, alert: DefenderAlert) -> AIAnalysisReport:
        """Invokes Google Gemini model."""
        from google import genai
        from google.genai import types

        if self._gemini_client is None:
            self._gemini_client = genai.Client(api_key=settings.GEMINI_API_KEY)

        prompt = self._build_alert_context(alert)

        response = self._gemini_client.models.generate_content(
            model=settings.GEMINI_MODEL,
            contents=[SYSTEM_PROMPT, prompt],
            config=types.GenerateContentConfig(
                temperature=0.2,
                response_mime_type="application/json"
            )
        )

        content = response.text or "{}"
        return self._parse_llm_json_response(content, alert, model_name=f"Gemini ({settings.GEMINI_MODEL})")

    def _analyze_with_openai(self, alert: DefenderAlert) -> AIAnalysisReport:
        """Invokes OpenAI or Azure OpenAI model."""
        from openai import OpenAI, AzureOpenAI

        if settings.LLM_PROVIDER in ("azure_openai", "copilot", "ms_copilot"):
            client = AzureOpenAI(
                api_key=settings.AZURE_OPENAI_API_KEY,
                api_version=settings.AZURE_OPENAI_API_VERSION,
                azure_endpoint=settings.AZURE_OPENAI_ENDPOINT,
            )
            model_name = settings.AZURE_OPENAI_DEPLOYMENT
            brand = "Azure OpenAI / Copilot"
        else:
            client = OpenAI(
                api_key=settings.OPENAI_API_KEY,
                base_url=settings.OPENAI_BASE_URL,
            )
            model_name = settings.OPENAI_MODEL
            brand = "OpenAI / ChatGPT"

        prompt = self._build_alert_context(alert)
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]

        response = client.chat.completions.create(
            model=model_name,
            messages=messages,
            temperature=0.2,
            response_format={"type": "json_object"}
        )

        content = response.choices[0].message.content or "{}"
        return self._parse_llm_json_response(content, alert, model_name=f"{brand} ({model_name})")

    def _analyze_with_anthropic(self, alert: DefenderAlert) -> AIAnalysisReport:
        """Invokes Anthropic Claude model."""
        import anthropic

        if self._anthropic_client is None:
            self._anthropic_client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)

        prompt = self._build_alert_context(alert)
        system_instruction = SYSTEM_PROMPT + "\nRemember: Output ONLY valid JSON."

        response = self._anthropic_client.messages.create(
            model=settings.ANTHROPIC_MODEL,
            max_tokens=4096,
            temperature=0.2,
            system=system_instruction,
            messages=[{"role": "user", "content": prompt}],
        )

        content = response.content[0].text or "{}"
        return self._parse_llm_json_response(content, alert, model_name=f"Claude ({settings.ANTHROPIC_MODEL})")

    def _analyze_with_ollama(self, alert: DefenderAlert) -> AIAnalysisReport:
        """Invokes local Ollama / OpenAI-compatible endpoint."""
        from openai import OpenAI

        client = OpenAI(
            base_url=settings.OLLAMA_BASE_URL,
            api_key="ollama",
        )
        prompt = self._build_alert_context(alert)
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]
        response = client.chat.completions.create(
            model=settings.OLLAMA_MODEL,
            messages=messages,
            temperature=0.2,
            response_format={"type": "json_object"}
        )
        content = response.choices[0].message.content or "{}"
        return self._parse_llm_json_response(content, alert, model_name=f"Ollama ({settings.OLLAMA_MODEL})")

    def _parse_llm_json_response(self, content: str, alert: DefenderAlert, model_name: str) -> AIAnalysisReport:
        """Parses and sanitizes LLM JSON output into AIAnalysisReport."""
        # Clean json backticks if present
        cleaned = re.sub(r"^```json\s*", "", content.strip(), flags=re.MULTILINE)
        cleaned = re.sub(r"```$", "", cleaned.strip(), flags=re.MULTILINE)

        data = json.loads(cleaned)

        # Map verdict
        raw_verdict = data.get("verdict", "Suspicious (Needs Further Investigation)")
        verdict = TriageVerdict.SUSPICIOUS
        for v in TriageVerdict:
            if v.value.lower().split()[0] in raw_verdict.lower():
                verdict = v
                break

        # Map severity
        sev_str = data.get("severity_assessment", alert.severity.value).lower()
        severity = AlertSeverity(sev_str) if sev_str in AlertSeverity._value2member_map_ else alert.severity

        # Containment actions
        containment_actions = []
        for c in data.get("containment_actions", []):
            containment_actions.append(ContainmentAction(
                action=c.get("action", "Investigate Target"),
                target_entity=c.get("target_entity", "Unknown Entity"),
                priority=c.get("priority", "High"),
                rationale=c.get("rationale", ""),
                automated_capability=c.get("automated_capability", True)
            ))

        # KQL Hunting Queries
        hunting_queries = []
        for q in data.get("hunting_queries", []):
            hunting_queries.append(KqlHuntingQuery(
                title=q.get("title", "Hunting Query"),
                description=q.get("description", ""),
                table=q.get("table", "DeviceProcessEvents"),
                query=q.get("query", "// Query not provided")
            ))

        return AIAnalysisReport(
            alert_id=alert.id,
            alert_title=alert.title,
            verdict=verdict,
            confidence_score=int(data.get("confidence_score", 85)),
            severity_assessment=severity,
            executive_summary=data.get("executive_summary", "Executive summary not provided."),
            technical_narrative=data.get("technical_narrative", alert.description or ""),
            attack_vector=data.get("attack_vector", alert.category or "Unknown"),
            mitre_attack_chain=alert.mitre_techniques,
            impacted_entities=alert.entities,
            blast_radius_assessment=data.get("blast_radius_assessment", "Potential exposure across correlated devices and accounts."),
            false_positive_indicators=data.get("false_positive_indicators", []),
            containment_actions=containment_actions,
            hunting_queries=hunting_queries,
            next_steps_for_analyst=data.get("next_steps_for_analyst", []),
            model_used=model_name,
        )

    def _analyze_with_expert_heuristics(self, alert: DefenderAlert) -> AIAnalysisReport:
        """Deterministic Expert SOC Rule-based Analyst Engine.
        Analyzes command-lines, decodes Base64, inspects process ancestry and entities.
        """
        title_lower = alert.title.lower()
        desc_lower = (alert.description or "").lower()

        # Extract entities
        devices = [e for e in alert.entities if e.entity_type == EntityType.DEVICE]
        users = [e for e in alert.entities if e.entity_type == EntityType.USER]
        processes = [e for e in alert.entities if e.entity_type == EntityType.PROCESS]
        files = [e for e in alert.entities if e.entity_type == EntityType.FILE]
        ips = [e for e in alert.entities if e.entity_type == EntityType.IP]
        mailboxes = [e for e in alert.entities if e.entity_type == EntityType.MAILBOX]

        primary_device = devices[0].identifier if devices else "Unknown-Host"
        primary_user = users[0].identifier if users else "Unknown-User"

        # Check for encoded commands in process arguments
        decoded_command_notes = []
        for p in processes:
            cmd = p.details.get("commandLine", "")
            match = re.search(r"-[eE](?:nc|ncodedcommand)?\s+([A-Za-z0-9+/=]{20,})", cmd)
            if match:
                try:
                    raw_b64 = match.group(1)
                    decoded_bytes = base64.b64decode(raw_b64)
                    if len(decoded_bytes) % 2 != 0:
                        decoded_bytes = decoded_bytes[:-1]
                    try:
                        decoded_str = decoded_bytes.decode("utf-16le").replace("\x00", "")
                    except UnicodeDecodeError:
                        decoded_str = decoded_bytes.decode("utf-8", errors="replace").replace("\x00", "")
                    decoded_command_notes.append(f"Decoded Base64 Command: `{decoded_str}`")
                except Exception:
                    pass

        containment_actions = []
        hunting_queries = []
        fp_indicators = []
        next_steps = []

        # Scenario 1: Credential Theft / LSASS
        if "lsass" in title_lower or "credential" in title_lower or any("t1003" in m.technique_id.lower() for m in alert.mitre_techniques):
            verdict = TriageVerdict.TRUE_POSITIVE
            confidence = 96
            severity = AlertSeverity.HIGH
            attack_vector = "Credential Access via LSASS Memory Injection / Mimikatz / ProcDump"
            exec_summary = (
                f"CRITICAL: Active credential dumping detected on host {primary_device} targeting LSASS memory. "
                f"User credentials for {primary_user} may have been compromised. Immediate device isolation and password resets required."
            )
            tech_narrative = (
                f"An unauthorized process was detected reading the memory space of Local Security Authority Subsystem Service (lsass.exe). "
                f"Commands observed: {'; '.join([p.details.get('commandLine', '') for p in processes if p.details.get('commandLine')])}. "
                + (" ".join(decoded_command_notes) if decoded_command_notes else "")
                + " This allows unprivileged or privileged attackers to extract plaintext credentials, NTLM hashes, and Kerberos tickets."
            )
            blast_radius = f"High. Compromised service/admin account '{primary_user}' and any machines sharing local admin credentials with {primary_device}."

            containment_actions.append(ContainmentAction(
                action="Isolate Device via Defender for Endpoint",
                target_entity=primary_device,
                priority="Immediate",
                rationale="Halt active credential harvesting and block lateral movement across the network.",
                automated_capability=True
            ))
            containment_actions.append(ContainmentAction(
                action="Force Password Reset & Revoke Entra ID Refresh Tokens",
                target_entity=primary_user,
                priority="Immediate",
                rationale="Invalidate compromised Kerberos tickets and session tokens.",
                automated_capability=True
            ))
            for f in files:
                containment_actions.append(ContainmentAction(
                    action="Submit File Indicator of Compromise (IOC) Block",
                    target_entity=f.details.get("sha256") or f.identifier,
                    priority="High",
                    rationale=f"Block malicious binary '{f.identifier}' tenant-wide in Defender for Endpoint.",
                    automated_capability=True
                ))

            hunting_queries.append(KqlHuntingQuery(
                title="Detect Lateral Movement via Pass-The-Hash or WMI",
                description="Searches for remote authentication attempts originating from this host in the last 24 hours.",
                table="DeviceLogonEvents",
                query=(
                    f"DeviceLogonEvents\n"
                    f"| where Timestamp >= ago(24h)\n"
                    f"| where DeviceName =~ '{primary_device}' or RemoteDeviceName =~ '{primary_device}'\n"
                    f"| where LogonType in (3, 10) // Network or RemoteInteractive\n"
                    f"| project Timestamp, DeviceName, RemoteDeviceName, AccountName, LogonType, FailureReason"
                )
            ))
            hunting_queries.append(KqlHuntingQuery(
                title="Detect Additional Suspicious Access to LSASS",
                description="Checks for any other processes attempting Read/Open access to lsass.exe memory.",
                table="DeviceEvents",
                query=(
                    f"DeviceEvents\n"
                    f"| where Timestamp >= ago(24h)\n"
                    f"| where ActionType == 'OpenProcessApiCall'\n"
                    f"| where FileName =~ 'lsass.exe'\n"
                    f"| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine"
                )
            ))
            fp_indicators = [
                "Legitimate backup software agents (e.g., Veeam, Commvault, Symantec) running authorized volume snapshot routines.",
                "Authorized security diagnostic tools used by Sysadmins during pre-notified maintenance."
            ]
            next_steps = [
                f"Verify if {primary_device} is a Domain Controller or Tier-0 asset.",
                "Review Kerberos ticket requests (Event ID 4768/4769) in Active Directory logs.",
                "Collect live memory dump / automated triage package from Defender for Endpoint portal."
            ]

        # Scenario 2: Malicious Macro / Office Dropper / C2 Beaconing
        elif "macro" in title_lower or "word" in desc_lower or "beacon" in title_lower or "encoded" in title_lower:
            verdict = TriageVerdict.TRUE_POSITIVE
            confidence = 94
            severity = AlertSeverity.HIGH
            attack_vector = "Phishing Delivery & Malicious Office Macro Execution (Initial Access / Execution)"
            exec_summary = (
                f"HIGH SEVERITY: Phishing document executed on {primary_device} under user {primary_user}. "
                f"Microsoft Word spawned an obfuscated PowerShell process that attempted outbound C2 connection."
            )
            tech_narrative = (
                f"Office application spawned an obfuscated shell process. "
                + (" ".join(decoded_command_notes) if decoded_command_notes else "Obfuscated command-line detected.")
                + f" Network outbound connection attempted to untrusted C2 infrastructure."
            )
            blast_radius = f"Workstation {primary_device} compromised. Threat actor likely has user-level interactive shell and download capability."

            containment_actions.append(ContainmentAction(
                action="Isolate Workstation from Corporate LAN",
                target_entity=primary_device,
                priority="Immediate",
                rationale="Prevent remote C2 control and staging of secondary payloads or ransomware.",
                automated_capability=True
            ))
            for ip in ips:
                containment_actions.append(ContainmentAction(
                    action="Add IP to Defender Blocked Indicators",
                    target_entity=ip.identifier,
                    priority="High",
                    rationale=f"Block C2 command & control server ({ip.identifier}) on all enterprise endpoints.",
                    automated_capability=True
                ))

            hunting_queries.append(KqlHuntingQuery(
                title="Identify Other Users Who Received the Phishing Document",
                description="Searches Defender for Office 365 EmailEvents for attachments matching the payload name or sender.",
                table="EmailAttachmentInfo",
                query=(
                    f"EmailAttachmentInfo\n"
                    f"| where Timestamp >= ago(7d)\n"
                    f"| where FileName endswith '.docm' or FileName endswith '.xlsm'\n"
                    f"| join kind=inner EmailEvents on NetworkMessageId\n"
                    f"| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, FileName, SHA256"
                )
            ))
            hunting_queries.append(KqlHuntingQuery(
                title="Search C2 Network Connections Across All Corporate Devices",
                description="Identifies if any other workstation made network requests to the attacker IP.",
                table="DeviceNetworkEvents",
                query=(
                    f"DeviceNetworkEvents\n"
                    f"| where Timestamp >= ago(7d)\n"
                    + (f"| where RemoteIP == '{ips[0].identifier}'\n" if ips else "| where RemotePort in (80, 443, 8080, 8443)\n")
                    + f"| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemoteUrl"
                )
            ))
            fp_indicators = [
                "Authorized macro written by internal finance/accounting department (check digital signature of document).",
                "Internal red team or phishing simulation (e.g. KnowBe4, Attack Simulation Training)."
            ]
            next_steps = [
                "Purge malicious email from all Office 365 inboxes via Threat Explorer.",
                "Extract dropped payload from C:\\Users\\... for sandboxing in Defender portal.",
                "Interview user to verify email origin and any suspicious caller/Teams chat."
            ]

        # Scenario 3: Cloud Impossible Travel / BEC Forwarding
        elif "travel" in title_lower or "cloud" in title_lower or "forwarding" in title_lower or mailboxes:
            verdict = TriageVerdict.SUSPICIOUS
            confidence = 88
            severity = AlertSeverity.MEDIUM
            attack_vector = "Credential Compromise / Session Token Theft / Business Email Compromise (BEC)"
            exec_summary = (
                f"SUSPICIOUS: Atypical geographical travel detected for {primary_user}, accompanied by mailbox forwarding creation. "
                f"Potential Business Email Compromise (BEC) in progress."
            )
            tech_narrative = (
                f"User account {primary_user} authenticated from distant locations within an impossible timeframe. "
                f"Immediately following sign-in, an email forwarding rule was configured pointing outside the organization. "
                f"This pattern is classic attacker activity to exfiltrate financial data or invoice communications silently."
            )
            blast_radius = f"Cloud identity '{primary_user}' and all connected Microsoft 365 data (Exchange, OneDrive, SharePoint, Teams)."

            containment_actions.append(ContainmentAction(
                action="Revoke Entra ID User Sessions & Reset Password",
                target_entity=primary_user,
                priority="Immediate",
                rationale="Kick out the attacker and terminate stolen session tokens.",
                automated_capability=True
            ))
            containment_actions.append(ContainmentAction(
                action="Delete Malicious Inbox Forwarding Rule",
                target_entity=primary_user,
                priority="High",
                rationale="Stop ongoing exfiltration of sensitive organizational emails.",
                automated_capability=True
            ))

            hunting_queries.append(KqlHuntingQuery(
                title="Audit Atypical Sign-ins and Conditional Access Failures",
                description="Checks all Entra ID sign-in logs for this user across countries and user-agent strings.",
                table="SigninLogs",
                query=(
                    f"SigninLogs\n"
                    f"| where CreatedDateTime >= ago(3d)\n"
                    f"| where UserPrincipalName =~ '{primary_user}'\n"
                    f"| project CreatedDateTime, IPAddress, Location, AppDisplayName, Status, ConditionalAccessStatus"
                )
            ))
            hunting_queries.append(KqlHuntingQuery(
                title="Detect All Exchange Inbox Rule Modifications",
                description="Audits all inbox rules created across the tenant in the last 48 hours.",
                table="CloudAppEvents",
                query=(
                    f"CloudAppEvents\n"
                    f"| where Timestamp >= ago(48h)\n"
                    f"| where ActionType in ('New-InboxRule', 'Set-InboxRule')\n"
                    f"| project Timestamp, AccountDisplayName, IPAddress, RawEventData"
                )
            ))
            fp_indicators = [
                "User connecting through an enterprise VPN with exit nodes in different countries.",
                "Legitimate user-created forwarding rule to personal email (still violates corporate security policy, but not malicious)."
            ]
            next_steps = [
                f"Contact {primary_user} via out-of-band channel (phone/SMS) to verify their physical location.",
                "Check Sent Items folder for wire transfer or invoice modification emails sent by threat actor.",
                "Enable Number Matching MFA and Conditional Access strict location policies."
            ]

        # Scenario 4: Admin Tool / PsExec / False Positive candidate
        elif "psexec" in title_lower or "admin" in desc_lower or "lateralmovement" in alert.category.lower():
            verdict = TriageVerdict.SUSPICIOUS
            confidence = 80
            severity = AlertSeverity.LOW
            attack_vector = "Administrative Remote Execution / Potential Dual-Use Tooling"
            exec_summary = (
                f"LOW/SUSPICIOUS: PsExec or remote service execution observed on {primary_device} by user {primary_user}. "
                f"May be authorized IT operations or unapproved administrative lateral tool."
            )
            tech_narrative = (
                f"PSEXESVC service binary was initiated remotely on {primary_device}. While PsExec is a dual-use tool commonly "
                f"leveraged by IT administrators, attackers frequently utilize it for lateral movement after obtaining admin credentials."
            )
            blast_radius = f"Limited to {primary_device} unless associated with unauthorized credential usage."

            containment_actions.append(ContainmentAction(
                action="Verify IT Change Request Ticket",
                target_entity=primary_user,
                priority="Medium",
                rationale="Confirm if user was scheduled to perform maintenance on this host during this time window.",
                automated_capability=False
            ))

            hunting_queries.append(KqlHuntingQuery(
                title="Identify Originating Source Machine for PsExec Connection",
                description="Locates the machine from which the PsExec service was triggered.",
                table="DeviceNetworkEvents",
                query=(
                    f"DeviceNetworkEvents\n"
                    f"| where Timestamp >= ago(4h)\n"
                    f"| where DeviceName =~ '{primary_device}'\n"
                    f"| where RemotePort in (445, 139) // SMB\n"
                    f"| project Timestamp, InitiatingProcessFileName, LocalIP, RemoteIP, RemoteDeviceName"
                )
            ))
            fp_indicators = [
                "Authorized IT Administrator listed in ServiceNow Change Request window.",
                "Approved systems management script pushing emergency patch or software update."
            ]
            next_steps = [
                f"Cross-reference timestamp with change management system (ServiceNow/Jira).",
                f"Verify if {primary_user} normally conducts remote administrative tasks on this server."
            ]

        # Scenario 5: Microsoft Sentinel - Cloud Resource Compromise / Key Vault / Cryptomining
        elif "sentinel" in (alert.service_source or "").lower() or "sentinel" in title_lower or "keyvault" in title_lower or "cryptominer" in title_lower or "miner" in title_lower:
            verdict = TriageVerdict.TRUE_POSITIVE
            confidence = 95
            severity = AlertSeverity.HIGH
            attack_vector = "Cloud Identity Abuse & Secret Exfiltration leading to Resource Hijacking (Cryptomining)"
            cloud_res = [e.identifier for e in alert.entities if e.entity_type == EntityType.CLOUD_RESOURCE]
            cloud_res_str = ", ".join(cloud_res) if cloud_res else "Cloud Resources"

            exec_summary = (
                f"HIGH SEVERITY (Microsoft Sentinel): Compromised identity '{primary_user}' performed mass secret retrieval from Key Vault "
                f"and launched unauthorized compute resources ({cloud_res_str}). Immediate credential revocation and cloud asset teardown required."
            )
            tech_narrative = (
                f"Microsoft Sentinel analytic rule detected anomalous API operations initiated by {primary_user} from untrusted IP "
                f"{ips[0].identifier if ips else 'external IP'}. Telemetry indicates rapid Key Vault secret extraction followed by "
                f"ARM template deployment of high-cost compute infrastructure. This pattern matches financial resource hijacking / illicit cryptocurrency mining."
            )
            blast_radius = f"Cloud Tenant & Azure Subscription. Secrets stored in Key Vault may be compromised, risking databases, APIs, and cloud infrastructure."

            containment_actions.append(ContainmentAction(
                action="Rotate Service Principal Secret & Revoke Tokens",
                target_entity=primary_user,
                priority="Immediate",
                rationale="Halt ongoing unauthorized API calls and prevent further infrastructure provisioning.",
                automated_capability=True
            ))
            for cr in cloud_res:
                if "miner" in cr.lower() or "vm" in cr.lower():
                    containment_actions.append(ContainmentAction(
                        action="Deallocate & Terminate Rogue Azure VM",
                        target_entity=cr,
                        priority="Immediate",
                        rationale="Stop unauthorized compute resource consumption and potential internal cloud reconnaissance.",
                        automated_capability=True
                    ))
                elif "vault" in cr.lower() or "kv" in cr.lower():
                    containment_actions.append(ContainmentAction(
                        action="Restrict Key Vault Firewall to Private Endpoints",
                        target_entity=cr,
                        priority="High",
                        rationale="Prevent external internet access to sensitive encryption keys and secrets.",
                        automated_capability=True
                    ))

            hunting_queries.append(KqlHuntingQuery(
                title="Sentinel Hunting: Audit Key Vault Secret Access Operations",
                description="Queries AzureDiagnostics to identify all secrets accessed by the actor IP or identity.",
                table="AzureDiagnostics",
                query=(
                    f"AzureDiagnostics\n"
                    f"| where TimeGenerated >= ago(24h)\n"
                    f"| where ResourceProvider == 'MICROSOFT.KEYVAULT'\n"
                    f"| where OperationName in ('SecretGet', 'SecretList', 'KeyGet')\n"
                    f"| project TimeGenerated, Resource, OperationName, CallerIPAddress, identity_claim_upn_s"
                )
            ))
            hunting_queries.append(KqlHuntingQuery(
                title="Sentinel Hunting: Audit Rogue Azure VM & ARM Deployments",
                description="Queries AzureActivity for all virtual machine and resource group deployments in the last 48h.",
                table="AzureActivity",
                query=(
                    f"AzureActivity\n"
                    f"| where TimeGenerated >= ago(48h)\n"
                    f"| where OperationNameValue has 'Microsoft.Compute/virtualMachines/write'\n"
                    f"| where ActivityStatusValue == 'Success'\n"
                    f"| project TimeGenerated, Caller, CallerIpAddress, ResourceGroup, Resource, ActivitySubstatusValue"
                )
            ))
            hunting_queries.append(KqlHuntingQuery(
                title="Sentinel Hunting: High-Risk Service Principal Sign-ins",
                description="Audits AADServicePrincipalSignInLogs for sign-ins from unexpected external IP addresses.",
                table="AADServicePrincipalSignInLogs",
                query=(
                    f"AADServicePrincipalSignInLogs\n"
                    f"| where TimeGenerated >= ago(7d)\n"
                    + (f"| where ServicePrincipalName has '{primary_user.split('@')[0]}'\n" if primary_user != "Unknown-User" else "")
                    + f"| project TimeGenerated, ServicePrincipalName, IPAddress, Location, ResourceDisplayName"
                )
            ))
            fp_indicators = [
                "Authorized Terraform/Bicep CI/CD deployment pipeline running in a cloud-hosted runner.",
                "Approved emergency capacity expansion approved in ServiceNow change request."
            ]
            next_steps = [
                "Audit all 48 secrets accessed from the Key Vault and initiate emergency rotation.",
                "Review Azure Cost Management budget alerts for unexpected cost spikes.",
                "Enable Sentinel Behavioral Analytics and UEBA on all service principal identities."
            ]

        # Generic / Unknown Alert Fallback
        else:
            verdict = TriageVerdict.SUSPICIOUS
            confidence = 75
            severity = alert.severity
            attack_vector = f"Defender Detection: {alert.category}"
            exec_summary = (
                f"Investigation of '{alert.title}' on {primary_device}. Severity: {alert.severity.value}. "
                f"Requires analyst verification of correlated entity activities."
            )
            tech_narrative = (
                f"Defender XDR triggered an alert with detection source '{alert.detection_source}'. "
                f"Description: {alert.description}. Entities involved: {', '.join([e.identifier for e in alert.entities])}."
            )
            blast_radius = f"Potential impact on device {primary_device} and user {primary_user}."
            containment_actions.append(ContainmentAction(
                action="Review Endpoint Telemetry",
                target_entity=primary_device,
                priority="Medium",
                rationale="Establish full timeline before containment.",
                automated_capability=False
            ))
            hunting_queries.append(KqlHuntingQuery(
                title="General Process Telemetry on Impacted Device",
                description="List all processes executed around the alert timestamp.",
                table="DeviceProcessEvents",
                query=(
                    f"DeviceProcessEvents\n"
                    f"| where Timestamp >= ago(2h)\n"
                    f"| where DeviceName =~ '{primary_device}'\n"
                    f"| project Timestamp, FileName, ProcessCommandLine, AccountName, InitiatingProcessFileName"
                )
            ))
            fp_indicators = ["Standard corporate software update or security scan."]
            next_steps = ["Inspect device timeline in Defender for Endpoint portal."]

        return AIAnalysisReport(
            alert_id=alert.id,
            alert_title=alert.title,
            verdict=verdict,
            confidence_score=confidence,
            severity_assessment=severity,
            executive_summary=exec_summary,
            technical_narrative=tech_narrative,
            attack_vector=attack_vector,
            mitre_attack_chain=alert.mitre_techniques,
            impacted_entities=alert.entities,
            blast_radius_assessment=blast_radius,
            false_positive_indicators=fp_indicators,
            containment_actions=containment_actions,
            hunting_queries=hunting_queries,
            next_steps_for_analyst=next_steps,
            model_used="Expert SOC Heuristic Engine (Offline / Deterministic)",
        )
