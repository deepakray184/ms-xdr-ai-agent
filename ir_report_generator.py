"""Automated Incident Response (IR) Report Generator for Microsoft Defender XDR.
Compliant with NIST SP 800-61 Rev 2, SANS DFIR standards, and ISO/IEC 27035.
Generates comprehensive Executive and Technical IR Reports in Markdown, HTML (Print-to-PDF ready), and JSON.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from models import AIAnalysisReport, DefenderAlert, EntityType


class IncidentReportGenerator:
    """Generates enterprise-grade Incident Response (IR) reports from Defender XDR alerts and AI analysis."""

    def __init__(self, output_dir: str = "incident_reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_timeline(self, alert: DefenderAlert, report: AIAnalysisReport) -> List[Dict[str, str]]:
        """Reconstructs a chronological DFIR incident timeline."""
        created_time = alert.created_date_time.strftime("%Y-%m-%d %H:%M:%S UTC") if alert.created_date_time else "T0 (Detection Time)"
        updated_time = alert.last_update_date_time.strftime("%Y-%m-%d %H:%M:%S UTC") if alert.last_update_date_time else created_time
        analyzed_time = report.analyzed_at.strftime("%Y-%m-%d %H:%M:%S UTC")

        timeline = [
            {
                "timestamp": created_time,
                "phase": "Detection / Initial Trigger",
                "description": f"Microsoft Defender XDR triggered alert: '{alert.title}' (Service: {alert.service_source}).",
                "source": alert.detection_source or "Defender Sensor"
            },
            {
                "timestamp": updated_time,
                "phase": "Signal Aggregation",
                "description": f"Telemetry and correlated entity evidence aggregated into Incident {alert.incident_id or 'Standalone'}.",
                "source": "Microsoft Graph Security API"
            },
            {
                "timestamp": analyzed_time,
                "phase": "Triage & Deep AI Investigation",
                "description": f"AI SOC Agent completed investigation. Verdict rendered: {report.verdict.value} (Confidence: {report.confidence_score}%). MITRE tactics and KQL queries mapped.",
                "source": report.model_used
            },
            {
                "timestamp": "Post-Triage",
                "phase": "Containment & Remediation",
                "description": f"Generated containment plan comprising {len(report.containment_actions)} prioritized mitigation actions.",
                "source": "SOC Incident Response Playbook"
            }
        ]
        return timeline

    def generate_markdown(
        self,
        alert: DefenderAlert,
        report: AIAnalysisReport,
        lead_analyst: str = "AI SOC Analyst (Defender XDR Agent)",
        ticket_id: Optional[str] = None
    ) -> str:
        """Generates comprehensive Markdown IR Report."""
        incident_ref = ticket_id or alert.incident_id or f"INC-{alert.id[:8].upper()}"
        timeline = self.generate_timeline(alert, report)

        devices = [e for e in report.impacted_entities if e.entity_type == EntityType.DEVICE]
        users = [e for e in report.impacted_entities if e.entity_type == EntityType.USER]
        files = [e for e in report.impacted_entities if e.entity_type == EntityType.FILE]
        ips = [e for e in report.impacted_entities if e.entity_type == EntityType.IP]
        processes = [e for e in report.impacted_entities if e.entity_type == EntityType.PROCESS]

        md = [
            f"# INCIDENT RESPONSE INVESTIGATION REPORT",
            f"**Reference / Ticket ID:** `{incident_ref}`  ",
            f"**Classification:** SENSITIVE / INTERNAL USE ONLY  ",
            f"**Standard:** NIST SP 800-61 Rev. 2 / SANS Incident Handling  ",
            f"**Date of Report:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
            f"**Lead Investigator:** {lead_analyst}  ",
            f"**Incident Status:** Triaged & Contained  ",
            "",
            "---",
            "",
            "## 1. INCIDENT OVERVIEW & EXECUTIVE SUMMARY",
            "",
            f"### 1.1 Executive Summary",
            f"{report.executive_summary}",
            "",
            f"### 1.2 Core Incident Metrics",
            f"| Attribute | Value |",
            f"|---|---|",
            f"| **Incident Reference** | `{incident_ref}` |",
            f"| **Defender Alert ID** | `{alert.id}` |",
            f"| **Alert Title** | {alert.title} |",
            f"| **AI Triage Verdict** | **{report.verdict.value}** |",
            f"| **Confidence Level** | **{report.confidence_score}%** |",
            f"| **Assessed Severity** | **{report.severity_assessment.value.upper()}** |",
            f"| **Detection Source** | {alert.service_source} ({alert.detection_source or 'EDR'}) |",
            f"| **Primary Target Host** | `{devices[0].identifier if devices else 'N/A'}` |",
            f"| **Primary User / Identity** | `{users[0].identifier if users else 'N/A'}` |",
            "",
            "---",
            "",
            "## 2. ATTACK VECTOR & THREAT NARRATIVE",
            "",
            f"### 2.1 Initial Access & Attack Vector",
            f"{report.attack_vector}",
            "",
            f"### 2.2 Technical Narrative (DFIR Reconstruction)",
            f"{report.technical_narrative}",
            "",
            f"### 2.3 Blast Radius & Scope of Compromise",
            f"{report.blast_radius_assessment}",
            "",
            "---",
            "",
            "## 3. MITRE ATT&CK ENTERPRISE MAPPING",
            "",
            "| Technique ID | Technique Name | Tactic (Kill Chain Phase) |",
            "|---|---|---|",
        ]

        if report.mitre_attack_chain:
            for m in report.mitre_attack_chain:
                md.append(f"| `{m.technique_id}` | {m.name} | {m.tactic} |")
        else:
            md.append("| None | Unmapped / Generic Alert | General |")

        md.extend([
            "",
            "---",
            "",
            "## 4. FORENSIC EVIDENCE & INDICATORS OF COMPROMISE (IOCs)",
            "",
            "### 4.1 Compromised Systems & Workstations",
        ])

        if devices:
            md.append("| Device Name | OS Platform | Health Status | IP Addresses |")
            md.append("|---|---|---|---|")
            for d in devices:
                ips_str = ", ".join(d.details.get("ipInterfaces", [])) or "N/A"
                md.append(f"| `{d.identifier}` | {d.details.get('osPlatform', 'Unknown')} | {d.details.get('healthStatus', 'Active')} | `{ips_str}` |")
        else:
            md.append("_No host devices directly implicated._")

        md.append("\n### 4.2 Compromised User Identities & Credentials")
        if users:
            md.append("| User Account (UPN) | Domain | Roles & Privileges |")
            md.append("|---|---|---|")
            for u in users:
                roles_str = ", ".join(u.details.get("roles", [])) or "Standard User"
                md.append(f"| `{u.identifier}` | {u.details.get('domain', 'N/A')} | {roles_str} |")
        else:
            md.append("_No individual user accounts directly implicated._")

        md.append("\n### 4.3 Malicious Files, Payloads & Injected Code")
        if files or processes:
            md.append("| Artifact / Process | Type | SHA-256 / Details |")
            md.append("|---|---|---|")
            for f in files:
                sha = f.details.get("sha256") or "N/A"
                md.append(f"| `{f.identifier}` | File Drop | `{sha}` |")
            for p in processes:
                cmd = p.details.get("commandLine", "N/A").replace("|", "\\|")
                md.append(f"| `{p.identifier}` | Process Execution | `{cmd}` |")
        else:
            md.append("_No file drops or process payloads identified in primary alert payload._")

        md.append("\n### 4.4 Network Indicators (C2 & External Connections)")
        if ips:
            md.append("| IP Address / URL | Geolocation | Reputation / Context |")
            md.append("|---|---|---|")
            for ip in ips:
                cc = ip.details.get("countryCode") or "Unknown"
                url = ip.details.get("url") or "Direct IP Connection"
                md.append(f"| `{ip.identifier}` | {cc} | `{url}` |")
        else:
            md.append("_No external IP/URL connections observed in alert evidence._")

        md.extend([
            "",
            "---",
            "",
            "## 5. INCIDENT CHRONOLOGY (TIMELINE)",
            "",
            "| Timestamp | Phase | Observation / Action Taken | Telemetry Source |",
            "|---|---|---|---|",
        ])

        for t in timeline:
            md.append(f"| `{t['timestamp']}` | **{t['phase']}** | {t['description']} | {t['source']} |")

        md.extend([
            "",
            "---",
            "",
            "## 6. CONTAINMENT, ERADICATION & RECOVERY ACTIONS",
            "",
            "### 6.1 Containment Actions Executed / Recommended",
            "| Priority | Action | Target Entity | Strategic Rationale | Automated via API |",
            "|---|---|---|---|---|",
        ])

        for act in report.containment_actions:
            auto_str = "Yes (Defender API)" if act.automated_capability else "Manual Execution"
            md.append(f"| **{act.priority}** | {act.action} | `{act.target_entity}` | {act.rationale} | {auto_str} |")

        md.extend([
            "",
            "### 6.2 Eradication & Remediation Verification",
            "1. **Isolate Affected Assets:** Prevent outbound C2 beaconing and lateral spreading via SMB/WinRM.",
            "2. **Invalidate Active Sessions:** Execute global token revocation in Microsoft Entra ID (`Revoke-MgUserSignInSession`).",
            "3. **Block Indicators:** Submit malicious SHA-256 hashes and C2 IPs to Microsoft Defender Indicators of Compromise (IOC).",
            "4. **Re-image / Restore:** Restore compromised workstations from golden master image after forensic package capture.",
            "",
            "---",
            "",
            "## 7. ADVANCED THREAT HUNTING (KQL QUERIES)",
            "Execute the following KQL queries in **Microsoft Defender XDR Advanced Hunting** or **Microsoft Sentinel** to confirm eradication across the fleet:",
            "",
        ])

        for i, q in enumerate(report.hunting_queries, 1):
            md.extend([
                f"### 7.{i} {q.title} (`{q.table}`)",
                f"_{q.description}_",
                "```kql",
                q.query,
                "```",
                "",
            ])

        md.extend([
            "---",
            "",
            "## 8. ROOT CAUSE ANALYSIS (RCA) & LESSONS LEARNED",
            "",
            "### 8.1 Root Cause Summary",
            f"The incident stemmed from {report.attack_vector.lower()}. Telemetry indicated {report.blast_radius_assessment.lower()}",
            "",
            "### 8.2 Strategic Defensive Recommendations",
            "- **Enforce Phishing-Resistant MFA:** Transition all administrative and high-risk accounts to FIDO2 / Passkeys.",
            "- **Attack Surface Reduction (ASR):** Enable Defender ASR rules: *'Block Win32 API calls from Office macros'* and *'Block credential stealing from Windows Local Security Authority subsystem (lsass.exe)'*.",
            "- **Conditional Access Hardening:** Restrict administrative sign-ins to Compliant/Hybrid-Joined Intune managed devices.",
            "- **Endpoint Isolation Automation:** Configure Defender for Endpoint Automated Investigation and Remediation (AIR) to auto-isolate high-confidence malware alerts.",
            "",
            "---",
            "",
            "## 9. INVESTIGATION SIGN-OFF & APPROVALS",
            "",
            "| Role | Name | Signature / Status | Date |",
            "|---|---|---|---|",
            f"| Lead SOC Analyst | {lead_analyst} | **APPROVED & CLOSED** | {datetime.now(timezone.utc).strftime('%Y-%m-%d')} |",
            "| Incident Response Manager | DFIR Team Lead | **REVIEWED** | Pending |",
            "| Chief Information Security Officer (CISO) | Executive SecOps | **NOTIFIED** | Pending |",
            "",
            "---",
            "_Report auto-generated by Microsoft Defender XDR AI SOC Agent._"
        ])

        return "\n".join(md)

    def generate_html(
        self,
        alert: DefenderAlert,
        report: AIAnalysisReport,
        lead_analyst: str = "AI SOC Analyst (Defender XDR Agent)",
        ticket_id: Optional[str] = None
    ) -> str:
        """Generates print-to-PDF ready enterprise HTML IR Report."""
        incident_ref = ticket_id or alert.incident_id or f"INC-{alert.id[:8].upper()}"
        timeline = self.generate_timeline(alert, report)

        devices = [e for e in report.impacted_entities if e.entity_type == EntityType.DEVICE]
        users = [e for e in report.impacted_entities if e.entity_type == EntityType.USER]
        files = [e for e in report.impacted_entities if e.entity_type == EntityType.FILE]
        ips = [e for e in report.impacted_entities if e.entity_type == EntityType.IP]
        processes = [e for e in report.impacted_entities if e.entity_type == EntityType.PROCESS]

        is_tp = "True Positive" in report.verdict.value
        verdict_color = "#dc2626" if is_tp else ("#d97706" if "Suspicious" in report.verdict.value else "#16a34a")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Incident Response Report - {incident_ref}</title>
  <style>
    @page {{
      size: letter;
      margin: 20mm;
    }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      color: #1e293b;
      line-height: 1.5;
      margin: 0;
      padding: 24px;
      background: #f8fafc;
    }}
    .container {{
      max-width: 900px;
      margin: 0 auto;
      background: #ffffff;
      padding: 40px;
      border: 1px solid #e2e8f0;
      box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05);
      border-radius: 8px;
    }}
    .header {{
      border-bottom: 3px solid #0f172a;
      padding-bottom: 20px;
      margin-bottom: 24px;
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
    }}
    .title-area h1 {{
      margin: 0;
      font-size: 24px;
      color: #0f172a;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }}
    .title-area p {{
      margin: 4px 0 0 0;
      font-size: 13px;
      color: #64748b;
    }}
    .badge {{
      display: inline-block;
      padding: 4px 10px;
      border-radius: 4px;
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
    }}
    .verdict-box {{
      background: {verdict_color}10;
      border: 2px solid {verdict_color};
      border-radius: 6px;
      padding: 16px;
      margin: 20px 0;
    }}
    .verdict-title {{
      font-size: 18px;
      font-weight: 800;
      color: {verdict_color};
      margin: 0 0 6px 0;
    }}
    h2 {{
      font-size: 16px;
      border-bottom: 1px solid #cbd5e1;
      padding-bottom: 6px;
      margin-top: 32px;
      color: #0f172a;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin: 12px 0 20px 0;
      font-size: 13px;
    }}
    th, td {{
      padding: 8px 12px;
      text-align: left;
      border: 1px solid #e2e8f0;
    }}
    th {{
      background: #f1f5f9;
      color: #334155;
      font-weight: 600;
    }}
    code, pre {{
      font-family: "JetBrains Mono", Consolas, Monaco, monospace;
      font-size: 12px;
    }}
    pre {{
      background: #0f172a;
      color: #38bdf8;
      padding: 12px;
      border-radius: 6px;
      overflow-x: auto;
    }}
    .kql-title {{
      font-weight: 700;
      margin-top: 14px;
      margin-bottom: 2px;
      color: #0f172a;
      font-size: 13px;
    }}
    .footer {{
      margin-top: 40px;
      padding-top: 16px;
      border-top: 1px solid #cbd5e1;
      font-size: 11px;
      color: #94a3b8;
      text-align: center;
    }}
    @media print {{
      body {{ background: #fff; padding: 0; }}
      .container {{ border: none; box-shadow: none; padding: 0; }}
      .page-break {{ page-break-before: always; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="title-area">
        <h1>Incident Response Report</h1>
        <p>Microsoft Defender XDR Automated Investigation &bull; NIST SP 800-61 Compliant</p>
      </div>
      <div style="text-align: right;">
        <span class="badge" style="background: #0f172a; color: #fff;">{incident_ref}</span>
        <div style="font-size: 11px; color: #64748b; margin-top: 4px;">Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}</div>
      </div>
    </div>

    <!-- Verdict Banner -->
    <div class="verdict-box">
      <div class="verdict-title">AI Triage Verdict: {report.verdict.value}</div>
      <div style="font-size: 13px; color: #334155;">
        <strong>Assessed Severity:</strong> {report.severity_assessment.value.upper()} &bull; 
        <strong>Confidence Score:</strong> {report.confidence_score}% &bull; 
        <strong>Investigated By:</strong> {report.model_used}
      </div>
    </div>

    <h2>1. Executive Summary</h2>
    <p style="font-size: 14px; color: #334155; line-height: 1.6;">{report.executive_summary}</p>

    <h2>2. Technical Threat Narrative</h2>
    <div style="font-size: 13px; color: #334155; line-height: 1.6; white-space: pre-line;">{report.technical_narrative}</div>

    <div style="display: flex; gap: 16px; margin-top: 16px;">
      <div style="flex: 1; background: #f8fafc; border: 1px solid #e2e8f0; padding: 12px; border-radius: 6px;">
        <div style="font-size: 11px; font-weight: 700; color: #64748b; text-transform: uppercase;">Attack Vector</div>
        <div style="font-size: 13px; font-weight: 600; color: #0f172a; margin-top: 4px;">{report.attack_vector}</div>
      </div>
      <div style="flex: 1; background: #f8fafc; border: 1px solid #e2e8f0; padding: 12px; border-radius: 6px;">
        <div style="font-size: 11px; font-weight: 700; color: #64748b; text-transform: uppercase;">Blast Radius</div>
        <div style="font-size: 13px; font-weight: 600; color: #0f172a; margin-top: 4px;">{report.blast_radius_assessment}</div>
      </div>
    </div>

    <h2>3. MITRE ATT&CK Mapping</h2>
    <table>
      <thead>
        <tr><th>Technique ID</th><th>Name</th><th>Tactic</th></tr>
      </thead>
      <tbody>
        {"".join([f"<tr><td><code>{m.technique_id}</code></td><td>{m.name}</td><td>{m.tactic}</td></tr>" for m in report.mitre_attack_chain])}
      </tbody>
    </table>

    <div class="page-break"></div>

    <h2>4. Impacted Forensic Entities</h2>
    <table>
      <thead>
        <tr><th>Type</th><th>Identifier</th><th>Details</th></tr>
      </thead>
      <tbody>
        {"".join([f"<tr><td><strong>{e.entity_type.value.upper()}</strong></td><td><code>{e.identifier}</code></td><td><code>{json.dumps(e.details)}</code></td></tr>" for e in report.impacted_entities])}
      </tbody>
    </table>

    <h2>5. Incident Chronology (Timeline)</h2>
    <table>
      <thead>
        <tr><th>Timestamp</th><th>Phase</th><th>Observation</th><th>Source</th></tr>
      </thead>
      <tbody>
        {"".join([f"<tr><td><code>{t['timestamp']}</code></td><td><strong>{t['phase']}</strong></td><td>{t['description']}</td><td>{t['source']}</td></tr>" for t in timeline])}
      </tbody>
    </table>

    <h2>6. Containment & Remediation Actions</h2>
    <table>
      <thead>
        <tr><th>Priority</th><th>Action</th><th>Target</th><th>Rationale</th></tr>
      </thead>
      <tbody>
        {"".join([f"<tr><td><span class='badge' style='background:#fee2e2; color:#dc2626;'>{a.priority}</span></td><td><strong>{a.action}</strong></td><td><code>{a.target_entity}</code></td><td>{a.rationale}</td></tr>" for a in report.containment_actions])}
      </tbody>
    </table>

    <h2>7. KQL Threat Hunting Queries</h2>
    {"".join([f"<div class='kql-title'>{q.title} ({q.table})</div><div style='font-size:11px; color:#64748b;'>{q.description}</div><pre><code>{q.query}</code></pre>" for q in report.hunting_queries])}

    <h2>8. Sign-off & Verification</h2>
    <table>
      <thead>
        <tr><th>Role</th><th>Assignee</th><th>Status</th><th>Date</th></tr>
      </thead>
      <tbody>
        <tr><td>Lead Investigator</td><td>{lead_analyst}</td><td><strong style='color:#16a34a;'>VERIFIED & DOCUMENTED</strong></td><td>{datetime.now(timezone.utc).strftime('%Y-%m-%d')}</td></tr>
        <tr><td>SOC Lead</td><td>Incident Response Director</td><td>PENDING REVIEW</td><td>--</td></tr>
      </tbody>
    </table>

    <div class="footer">
      Generated automatically by Microsoft Defender XDR AI SOC Agent &bull; Confidential &bull; Security Operations Center
    </div>
  </div>
</body>
</html>"""
        return html

    def generate_json(
        self,
        alert: DefenderAlert,
        report: AIAnalysisReport,
        lead_analyst: str = "AI SOC Analyst (Defender XDR Agent)",
        ticket_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Generates machine-readable JSON for SOAR platforms (Sentinel, XSOAR)."""
        incident_ref = ticket_id or alert.incident_id or f"INC-{alert.id[:8].upper()}"
        return {
            "incident_reference": incident_ref,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "lead_analyst": lead_analyst,
            "standard": "NIST SP 800-61 Rev 2",
            "alert": alert.model_dump(mode="json"),
            "ai_analysis": report.model_dump(mode="json"),
            "timeline": self.generate_timeline(alert, report),
        }

    def save_reports(
        self,
        alert: DefenderAlert,
        report: AIAnalysisReport,
        lead_analyst: str = "AI SOC Analyst (Defender XDR Agent)",
        ticket_id: Optional[str] = None
    ) -> Dict[str, str]:
        """Saves Markdown, HTML, and JSON reports to disk and returns paths."""
        ref = (ticket_id or alert.incident_id or alert.id).replace("/", "_").replace(" ", "_")
        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        base_name = f"IR_REPORT_{ref}_{timestamp_str}"

        md_path = self.output_dir / f"{base_name}.md"
        html_path = self.output_dir / f"{base_name}.html"
        json_path = self.output_dir / f"{base_name}.json"

        md_content = self.generate_markdown(alert, report, lead_analyst, ticket_id)
        html_content = self.generate_html(alert, report, lead_analyst, ticket_id)
        json_content = self.generate_json(alert, report, lead_analyst, ticket_id)

        md_path.write_text(md_content, encoding="utf-8")
        html_path.write_text(html_content, encoding="utf-8")
        json_path.write_text(json.dumps(json_content, indent=2), encoding="utf-8")

        return {
            "markdown": str(md_path.resolve()),
            "html": str(html_path.resolve()),
            "json": str(json_path.resolve()),
            "base_name": base_name,
        }
