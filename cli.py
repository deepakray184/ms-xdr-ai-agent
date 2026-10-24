"""Interactive Command-Line Interface (CLI) for Microsoft Defender XDR AI SOC Agent.
Provides formatted terminal analysis, connectivity diagnostics, and threat hunting workflows.
"""

import argparse
import sys
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax
from rich.markdown import Markdown

from config import settings
from defender_client import DefenderXDRClient
from ai_analyzer import AISOCAnalyzer
from remediation import RemediationOrchestrator
from ir_report_generator import IncidentReportGenerator

console = Console()


def display_banner():
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║       MICROSOFT DEFENDER XDR - AI SOC ANALYST AGENT           ║
    ║   Automated Alert Triaging, MITRE Mapping & Threat Hunting    ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    console.print(f"[bold cyan]{banner}[/bold cyan]")


def cmd_test_connection():
    """Diagnoses connectivity to Microsoft Entra ID and Defender XDR Graph API."""
    console.print("\n[bold yellow]🔍 Diagnosing Microsoft Defender XDR Connectivity...[/bold yellow]\n")
    client = DefenderXDRClient()
    result = client.test_connection()

    table = Table(title="Connection Status Diagnostic", border_style="cyan")
    table.add_column("Property", style="bold white", width=25)
    table.add_column("Status / Value", style="green")

    mode = result.get("mode")
    table.add_row("Execution Mode", f"[bold yellow]{mode}[/bold yellow]")
    table.add_row("Entra ID Connected", "[bold green]YES[/bold green]" if result.get("connected") else "[bold red]NO[/bold red]")
    table.add_row("Details", result.get("message", ""))

    if "tenant_id" in result:
        table.add_row("Tenant ID", str(result.get("tenant_id")))
    if "client_id" in result:
        table.add_row("Client ID", str(result.get("client_id")))

    # LLM Status
    table.add_row("AI Engine Provider", f"[cyan]{settings.LLM_PROVIDER.upper()}[/cyan]")
    table.add_row("LLM Key Configured", "[bold green]YES[/bold green]" if settings.is_llm_configured else "[yellow]No (Using Expert Heuristic Engine)[/yellow]")
    if settings.LLM_PROVIDER == "gemini":
        table.add_row("Model Name", settings.GEMINI_MODEL)
    elif settings.LLM_PROVIDER in ("openai", "chatgpt"):
        table.add_row("Model Name", settings.OPENAI_MODEL)
    elif settings.LLM_PROVIDER in ("claude", "anthropic"):
        table.add_row("Model Name", settings.ANTHROPIC_MODEL)
    elif settings.LLM_PROVIDER in ("azure_openai", "copilot", "ms_copilot"):
        table.add_row("Deployment", settings.AZURE_OPENAI_DEPLOYMENT)
    elif settings.LLM_PROVIDER in ("ollama", "local", "custom"):
        table.add_row("Model Name", settings.OLLAMA_MODEL)

    console.print(table)

    if not result.get("connected") and mode != "MOCK":
        console.print("\n[yellow]💡 Note:[/yellow] To enable Live Defender XDR API mode, update [bold].env[/bold] with:")
        console.print("  AZURE_TENANT_ID=<your-tenant-id>")
        console.print("  AZURE_CLIENT_ID=<your-client-id>")
        console.print("  AZURE_CLIENT_SECRET=<your-client-secret>")
        console.print("  Required API Permissions in Azure Portal: [bold]SecurityAlert.Read.All[/bold], [bold]SecurityIncident.Read.All[/bold]")
        console.print("\n[green]Simulation / Mock mode is active and fully functional for demonstrations.[/green]\n")


def cmd_list_alerts(top=10, severity=None):
    """Lists Defender XDR alerts."""
    client = DefenderXDRClient()
    console.print(f"\n[bold]Fetching Defender XDR Alerts (Limit: {top}, Severity: {severity or 'All'})...[/bold]")
    alerts = client.get_alerts(top=top, severity=severity)

    if not alerts:
        console.print("[yellow]No alerts found.[/yellow]")
        return

    table = Table(title=f"Defender XDR & Sentinel Alerts ({len(alerts)} found)", border_style="blue")
    table.add_column("Alert ID", style="cyan", width=20)
    table.add_column("Severity", width=10)
    table.add_column("Source", width=14)
    table.add_column("Title", style="bold white", width=34)
    table.add_column("Category", width=14)
    table.add_column("Entities", style="magenta", width=24)
    table.add_column("Status", width=10)

    for a in alerts:
        # Severity color
        sev_color = {
            "high": "bold red",
            "medium": "bold yellow",
            "low": "blue",
            "informational": "dim",
        }.get(a.severity.value.lower(), "white")

        sev_badge = f"[{sev_color}]{a.severity.value.upper()}[/{sev_color}]"

        source_disp = (
            "[bold magenta]Sentinel[/bold magenta]"
            if "sentinel" in (a.service_source or "").lower()
            else "[cyan]Defender[/cyan]"
        )

        # Summarize primary entities
        entity_strs = [e.identifier.split(".")[0] for e in a.entities[:2]]
        entities_disp = ", ".join(entity_strs) if entity_strs else "None"

        table.add_row(
            a.id,
            sev_badge,
            source_disp,
            a.title,
            a.category,
            entities_disp,
            a.status.value,
        )

    console.print(table)
    console.print(f"\n[dim]To analyze an alert in depth, run: [bold cyan]python cli.py analyze <alert_id>[/bold cyan][/dim]\n")


def cmd_analyze_alert(alert_id: str):
    """Runs the AI SOC Analyst on a specific alert."""
    client = DefenderXDRClient()
    alert = client.get_alert_by_id(alert_id)
    if not alert:
        console.print(f"[bold red]Error: Alert with ID '{alert_id}' not found.[/bold red]")
        console.print("Run [bold cyan]python cli.py list[/bold cyan] to see available alert IDs.")
        return

    console.print(f"\n[bold yellow]🤖 Running AI SOC Analyst Investigation on Alert: [cyan]{alert.id}[/cyan]...[/bold yellow]")
    with console.status("[bold green]Analyzing threat telemetry, decoding commands, correlating MITRE techniques...[/bold green]"):
        analyzer = AISOCAnalyzer()
        report = analyzer.analyze_alert(alert)

    # 1. Verdict & Confidence Banner
    verdict_color = "red" if "True Positive" in report.verdict.value else ("yellow" if "Suspicious" in report.verdict.value else "green")
    console.print("\n")
    console.print(Panel(
        f"[bold {verdict_color}]VERDICT: {report.verdict.value}[/bold {verdict_color}]\n"
        f"[bold]Confidence Score:[/bold] {report.confidence_score}%\n"
        f"[bold]Assessed Severity:[/bold] [{verdict_color}]{report.severity_assessment.value.upper()}[/{verdict_color}]\n"
        f"[bold]Analysis Model:[/bold] {report.model_used}",
        title="AI SOC TRIAGE VERDICT",
        border_style=verdict_color,
    ))

    # 2. Executive Summary
    console.print(Panel(
        report.executive_summary,
        title="Executive Summary (CISO / SOC Management)",
        border_style="cyan"
    ))

    # 3. Technical Narrative
    console.print(Panel(
        report.technical_narrative,
        title="Technical Threat Narrative & Attack Story",
        border_style="magenta"
    ))

    # 4. MITRE ATT&CK & Blast Radius
    if report.mitre_attack_chain:
        mitre_table = Table(title="MITRE ATT&CK Mapping", border_style="yellow")
        mitre_table.add_column("Technique ID", style="bold yellow")
        mitre_table.add_column("Name", style="white")
        mitre_table.add_column("Tactic", style="cyan")
        for m in report.mitre_attack_chain:
            mitre_table.add_row(m.technique_id, m.name, m.tactic)
        console.print(mitre_table)

    console.print(Panel(
        f"[bold]Attack Vector:[/bold] {report.attack_vector}\n"
        f"[bold]Blast Radius Assessment:[/bold] {report.blast_radius_assessment}",
        title="Impact & Blast Radius",
        border_style="blue"
    ))

    # 5. Containment Actions
    if report.containment_actions:
        action_table = Table(title="Recommended Containment & Mitigation Actions", border_style="red")
        action_table.add_column("Priority", style="bold red", width=12)
        action_table.add_column("Action", style="bold white", width=35)
        action_table.add_column("Target Entity", style="cyan", width=25)
        action_table.add_column("Rationale", style="dim", width=40)
        for act in report.containment_actions:
            action_table.add_row(act.priority, act.action, act.target_entity, act.rationale)
        console.print(action_table)

    # 6. Advanced Hunting KQL Queries
    if report.hunting_queries:
        console.print("\n[bold cyan]🔎 Generated KQL Threat Hunting Queries for Defender / Sentinel:[/bold cyan]\n")
        for i, q in enumerate(report.hunting_queries, 1):
            console.print(f"[bold yellow]#{i}. {q.title}[/bold yellow] ({q.table})")
            console.print(f"[dim]{q.description}[/dim]")
            syntax = Syntax(q.query, "kql", theme="monokai", line_numbers=True)
            console.print(syntax)
            console.print()

    # 7. Next Steps for Analyst
    if report.next_steps_for_analyst:
        console.print("[bold green]📋 Next Recommended Steps for Tier-1/Tier-2 Analyst:[/bold green]")
        for step in report.next_steps_for_analyst:
            console.print(f"  • {step}")
        console.print()


def cmd_generate_report(alert_id: str, ticket_id: str = None, lead_analyst: str = "AI SOC Analyst"):
    """Generates an official NIST SP 800-61 Incident Response Report."""
    client = DefenderXDRClient()
    alert = client.get_alert_by_id(alert_id)
    if not alert:
        console.print(f"[bold red]Error: Alert with ID '{alert_id}' not found.[/bold red]")
        return

    console.print(f"\n[bold yellow]📝 Generating NIST SP 800-61 Incident Response Report for: [cyan]{alert.id}[/cyan]...[/bold yellow]")
    with console.status("[bold green]Reconstructing incident timeline, formatting forensics & generating reports...[/bold green]"):
        analyzer = AISOCAnalyzer()
        report = analyzer.analyze_alert(alert)
        generator = IncidentReportGenerator()
        files = generator.save_reports(alert, report, lead_analyst=lead_analyst, ticket_id=ticket_id)

    console.print(Panel(
        f"[bold green]Incident Response Report successfully compiled and saved![/bold green]\n\n"
        f"📄 [bold]Markdown Report:[/bold] [cyan]{files['markdown']}[/cyan]\n"
        f"🌐 [bold]Print-Ready HTML (PDF):[/bold] [cyan]{files['html']}[/cyan]\n"
        f"💾 [bold]SOAR / SIEM JSON:[/bold] [cyan]{files['json']}[/cyan]\n\n"
        f"[dim]Tip: You can open the HTML file in any browser and choose 'Print -> Save as PDF' to produce an executive PDF document.[/dim]",
        title="INCIDENT RESPONSE REPORT GENERATED",
        border_style="green"
    ))


def interactive_menu():
    """Runs interactive menu loop."""
    display_banner()
    while True:
        console.print("\n[bold cyan]Available Actions:[/bold cyan]")
        console.print("  [bold]1[/bold]. Test Entra ID & Defender XDR Connectivity")
        console.print("  [bold]2[/bold]. List Recent Defender XDR Alerts")
        console.print("  [bold]3[/bold]. Analyze Alert by ID with AI SOC Agent")
        console.print("  [bold]4[/bold]. Generate Emergency Remediation PowerShell Script")
        console.print("  [bold]5[/bold]. Generate Full Incident Response (IR) Report (NIST SP 800-61)")
        console.print("  [bold]6[/bold]. Start Web Dashboard (FastAPI / Browser UI)")
        console.print("  [bold]q[/bold]. Quit\n")

        choice = input("Enter choice (1-6, q): ").strip()
        if choice == "1":
            cmd_test_connection()
        elif choice == "2":
            cmd_list_alerts()
        elif choice == "3":
            alert_id = input("Enter Alert ID (e.g. da-9821-lsass-dump): ").strip()
            if alert_id:
                cmd_analyze_alert(alert_id)
        elif choice == "4":
            alert_id = input("Enter Alert ID for Remediation Script: ").strip()
            client = DefenderXDRClient()
            alert = client.get_alert_by_id(alert_id)
            if alert:
                analyzer = AISOCAnalyzer()
                report = analyzer.analyze_alert(alert)
                orch = RemediationOrchestrator(client)
                script = orch.generate_powershell_remediation_script(alert, report.containment_actions)
                console.print("\n[bold yellow]Generated Emergency Remediation Script:[/bold yellow]\n")
                syntax = Syntax(script, "powershell", theme="monokai", line_numbers=True)
                console.print(syntax)
            else:
                console.print(f"[red]Alert ID '{alert_id}' not found.[/red]")
        elif choice == "5":
            alert_id = input("Enter Alert ID for Incident Report: ").strip()
            if alert_id:
                ticket_id = input("Enter Ticket / Incident ID (optional, e.g. INC-9941): ").strip() or None
                lead = input("Enter Lead Analyst Name (optional): ").strip() or "AI SOC Analyst"
                cmd_generate_report(alert_id, ticket_id=ticket_id, lead_analyst=lead)
        elif choice == "6":
            console.print("[green]Launching Web Dashboard at http://localhost:8000 ...[/green]")
            import uvicorn
            uvicorn.run("web_dashboard:app", host=settings.HOST, port=settings.PORT, reload=False)
        elif choice.lower() in ("q", "quit", "exit"):
            console.print("[cyan]Exiting AI SOC Analyst. Goodbye![/cyan]")
            break
        else:
            console.print("[red]Invalid selection. Please choose 1-6 or q.[/red]")


def main():
    parser = argparse.ArgumentParser(description="Microsoft Defender XDR AI SOC Analyst Agent")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # test
    subparsers.add_parser("test", help="Test connectivity to Entra ID and Defender XDR")

    # list
    list_parser = subparsers.add_parser("list", help="List recent Defender XDR alerts")
    list_parser.add_argument("--top", type=int, default=10, help="Number of alerts to fetch (default: 10)")
    list_parser.add_argument("--severity", type=str, choices=["high", "medium", "low", "informational"], help="Filter by severity")

    # analyze
    analyze_parser = subparsers.add_parser("analyze", help="Analyze a Defender XDR alert with AI")
    analyze_parser.add_argument("alert_id", type=str, help="Alert ID to analyze")

    # report
    report_parser = subparsers.add_parser("report", help="Generate full NIST SP 800-61 Incident Response report")
    report_parser.add_argument("alert_id", type=str, help="Alert ID to generate report for")
    report_parser.add_argument("--ticket", type=str, default=None, help="Optional Ticket/Incident ID reference")
    report_parser.add_argument("--lead", type=str, default="AI SOC Analyst", help="Lead investigator name")

    # web
    subparsers.add_parser("web", help="Launch the Web SOC Dashboard")

    # parse
    args = parser.parse_args()

    if args.command == "test":
        cmd_test_connection()
    elif args.command == "list":
        cmd_list_alerts(top=args.top, severity=args.severity)
    elif args.command == "analyze":
        cmd_analyze_alert(args.alert_id)
    elif args.command == "report":
        cmd_generate_report(args.alert_id, ticket_id=args.ticket, lead_analyst=args.lead)
    elif args.command == "web":
        import uvicorn
        console.print(f"[bold green]Starting Defender XDR SOC Web Dashboard on http://{settings.HOST}:{settings.PORT} ...[/bold green]")
        uvicorn.run("web_dashboard:app", host=settings.HOST, port=settings.PORT, reload=False)
    else:
        # Default to interactive menu
        interactive_menu()


if __name__ == "__main__":
    main()
