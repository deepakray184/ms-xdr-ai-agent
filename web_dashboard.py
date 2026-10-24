"""FastAPI Web Dashboard for Microsoft Defender XDR AI SOC Analyst.
Provides REST APIs and an interactive dark-themed SOC operations interface.
"""

import logging
from typing import Optional, Dict, Any
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from config import settings
from defender_client import DefenderXDRClient
from ai_analyzer import AISOCAnalyzer
from remediation import RemediationOrchestrator
from ir_report_generator import IncidentReportGenerator
from models import ContainmentAction

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("web_dashboard")

app = FastAPI(
    title="Microsoft Defender XDR AI SOC Agent",
    description="Automated Alert Triaging, MITRE Mapping & KQL Threat Hunting for Microsoft Defender XDR",
    version="1.0.0",
)

templates = Jinja2Templates(directory="templates")
defender_client = DefenderXDRClient()
ai_analyzer = AISOCAnalyzer()
remediation_orchestrator = RemediationOrchestrator(defender_client)
report_generator = IncidentReportGenerator()


class AzureTestRequest(BaseModel):
    tenant_id: str
    client_id: str
    client_secret: str


class ContainmentExecuteRequest(BaseModel):
    action: str
    target_entity: str
    priority: str = "High"
    rationale: str = ""


@app.get("/", response_class=HTMLResponse)
async def get_dashboard(request: Request):
    """Renders the main SOC dashboard."""
    conn_status = defender_client.test_connection()
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "conn_status": conn_status,
            "llm_provider": settings.LLM_PROVIDER,
            "llm_configured": settings.is_llm_configured,
        },
    )


@app.get("/api/status")
async def get_status():
    """Returns connectivity and diagnostic status."""
    conn = defender_client.test_connection()
    return {
        "azure_connectivity": conn,
        "llm_provider": settings.LLM_PROVIDER,
        "llm_configured": settings.is_llm_configured,
        "gemini_model": settings.GEMINI_MODEL,
        "openai_model": settings.OPENAI_MODEL,
        "force_mock": settings.FORCE_MOCK,
    }


@app.get("/api/alerts")
async def list_alerts(top: int = 20, severity: Optional[str] = None):
    """Fetches Defender XDR alerts."""
    try:
        alerts = defender_client.get_alerts(top=top, severity=severity)
        return [alert.model_dump() for alert in alerts]
    except Exception as e:
        logger.error(f"Error fetching alerts: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/alerts/{alert_id}")
async def get_alert(alert_id: str):
    """Fetches details of a specific alert."""
    alert = defender_client.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert.model_dump()


@app.post("/api/alerts/{alert_id}/analyze")
async def analyze_alert(alert_id: str):
    """Runs the AI SOC Analyst on an alert."""
    alert = defender_client.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    try:
        report = ai_analyzer.analyze_alert(alert)
        return report.model_dump()
    except Exception as e:
        logger.error(f"Error analyzing alert {alert_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/containment/execute")
async def execute_containment(req: ContainmentExecuteRequest):
    """Executes a containment action."""
    action = ContainmentAction(
        action=req.action,
        target_entity=req.target_entity,
        priority=req.priority,
        rationale=req.rationale,
    )
    result = remediation_orchestrator.execute_action(action)
    return result


@app.post("/api/settings/test-azure")
async def test_azure_credentials(req: AzureTestRequest):
    """Dynamically tests user-provided Azure Entra ID credentials."""
    import msal
    import requests

    authority = f"https://login.microsoftonline.com/{req.tenant_id.strip()}"
    app = msal.ConfidentialClientApplication(
        client_id=req.client_id.strip(),
        client_credential=req.client_secret.strip(),
        authority=authority,
    )
    scopes = ["https://graph.microsoft.com/.default"]
    result = app.acquire_token_for_client(scopes=scopes)

    if "access_token" in result:
        token = result["access_token"]
        # Verify Defender API access
        headers = {"Authorization": f"Bearer {token}"}
        url = "https://graph.microsoft.com/v1.0/security/alerts_v2?$top=1"
        res = requests.get(url, headers=headers, timeout=10)
        if res.status_code == 200:
            return {
                "success": True,
                "message": "Authentication successful! SecurityAlert.Read.All permission verified.",
                "status_code": 200,
            }
        elif res.status_code == 403:
            return {
                "success": False,
                "message": "Token acquired, but lack 'SecurityAlert.Read.All' permission in Azure Portal. Grant application permission and Admin Consent.",
                "status_code": 403,
            }
        else:
            return {
                "success": False,
                "message": f"Graph API returned HTTP {res.status_code}: {res.text}",
                "status_code": res.status_code,
            }
    else:
        return {
            "success": False,
            "message": result.get("error_description", result.get("error", "Failed to authenticate")),
        }


@app.get("/api/alerts/{alert_id}/report.md", response_class=PlainTextResponse)
async def export_markdown_report(alert_id: str):
    """Generates a downloadable SOC incident report in Markdown."""
    alert = defender_client.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    report = ai_analyzer.analyze_alert(alert)

    md = [
        f"# SOC Incident Investigation Report - Alert {alert.id}",
        f"**Generated:** {report.analyzed_at.strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
        f"**Investigated By:** {report.model_used}  ",
        "",
        "## 1. Executive Summary",
        f"- **Verdict:** {report.verdict.value}",
        f"- **Confidence:** {report.confidence_score}%",
        f"- **Assessed Severity:** {report.severity_assessment.value.upper()}",
        f"- **Summary:** {report.executive_summary}",
        "",
        "## 2. Technical Narrative & Attack Story",
        f"{report.technical_narrative}",
        "",
        "## 3. Threat Classification & MITRE ATT&CK",
        f"- **Attack Vector:** {report.attack_vector}",
        f"- **Blast Radius:** {report.blast_radius_assessment}",
        "",
        "| Technique ID | Technique Name | Tactic |",
        "|---|---|---|",
    ]

    for m in report.mitre_attack_chain:
        md.append(f"| {m.technique_id} | {m.name} | {m.tactic} |")

    md.extend([
        "",
        "## 4. Impacted Entities",
        "| Type | Identifier | Details |",
        "|---|---|---|",
    ])

    for e in report.impacted_entities:
        md.append(f"| {e.entity_type.value} | {e.identifier} | `{e.details}` |")

    md.extend([
        "",
        "## 5. Containment & Remediation Actions",
    ])

    for i, a in enumerate(report.containment_actions, 1):
        md.append(f"{i}. **[{a.priority}] {a.action}** on `{a.target_entity}`: {a.rationale}")

    md.extend([
        "",
        "## 6. Defender Advanced Hunting Queries (KQL)",
    ])

    for q in report.hunting_queries:
        md.append(f"### {q.title} ({q.table})")
        md.append(f"_{q.description}_")
        md.append("```kql")
        md.append(q.query)
        md.append("```")
        md.append("")

    md.extend([
        "## 7. Next Steps for SOC Responders",
    ])
    for s in report.next_steps_for_analyst:
        md.append(f"- {s}")

    return "\n".join(md)


@app.get("/api/alerts/{alert_id}/ir-report/html", response_class=HTMLResponse)
async def get_incident_response_html_report(alert_id: str, ticket_id: Optional[str] = None):
    """Generates and serves a styled, print-to-PDF NIST SP 800-61 Incident Response report."""
    alert = defender_client.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    report = ai_analyzer.analyze_alert(alert)
    html_content = report_generator.generate_html(alert, report, ticket_id=ticket_id)
    return HTMLResponse(content=html_content)


@app.get("/api/alerts/{alert_id}/ir-report/markdown", response_class=PlainTextResponse)
async def get_incident_response_markdown_report(alert_id: str, ticket_id: Optional[str] = None):
    """Generates NIST SP 800-61 Incident Response report in Markdown."""
    alert = defender_client.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    report = ai_analyzer.analyze_alert(alert)
    md_content = report_generator.generate_markdown(alert, report, ticket_id=ticket_id)
    return PlainTextResponse(
        content=md_content,
        headers={"Content-Disposition": f"attachment; filename=IR_REPORT_{alert_id}.md"}
    )


@app.get("/api/alerts/{alert_id}/ir-report/json")
async def get_incident_response_json_report(alert_id: str, ticket_id: Optional[str] = None):
    """Generates machine-readable DFIR incident response report in JSON."""
    alert = defender_client.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    report = ai_analyzer.analyze_alert(alert)
    return report_generator.generate_json(alert, report, ticket_id=ticket_id)


@app.post("/api/alerts/{alert_id}/ir-report/generate")
async def save_incident_response_report(alert_id: str, ticket_id: Optional[str] = None):
    """Generates and saves Markdown, HTML, and JSON reports to disk in incident_reports/."""
    alert = defender_client.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    report = ai_analyzer.analyze_alert(alert)
    files = report_generator.save_reports(alert, report, ticket_id=ticket_id)
    return {
        "success": True,
        "message": "Incident Response Report generated and saved to disk.",
        "files": files,
        "base_name": files["base_name"],
    }

