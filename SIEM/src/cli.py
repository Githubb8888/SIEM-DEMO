#!/usr/bin/env python3
"""Command-line interface for Fintech Mini-SIEM & SOAR Web Console."""

import argparse
import os
import sys
import json
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import print as rprint
from rich.prompt import Confirm

from src.models import NormalizedEvent, Alert, Incident, PlaybookAction, EntityProfile
from src.collector import LogCollector, parse_jsonl_file, batch_ingest, generate_sample_traffic, follow_file
from src.enrichment import load_threat_intel, enrich_event
from src.storage import init_db, get_db_path, store_event, get_alerts, get_incidents, get_blocked_ips, get_frozen_accounts, get_audit_log, update_entity_risk
from src.engine import DetectionEngine, get_engine
import src.soar as soar

console = Console()
collector = LogCollector()


def cmd_init(args):
    """Initialize the SIEM database."""
    db_path = get_db_path()
    init_db(db_path)
    console.print(f"[green]Database initialized at:[/green] {db_path}")
    return 0


def cmd_ingest(args):
    """Ingest log files into the SIEM."""
    filepath = args.file

    if not os.path.exists(filepath):
        console.print(f"[red]Error: File not found: {filepath}[/red]")
        return 1

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Parsing logs...", total=None)
        events = parse_jsonl_file(filepath, args.log_type)

    progress.update(task, completed=True, description="[green]Enriching events...")

    # Load threat intel and enrich events
    try:
        ioc_data = load_threat_intel()
        enriched_events = [enrich_event(e, ioc_data) for e in events]
    except Exception as e:
        console.print(f"[yellow]Warning: Could not enrich events: {e}[/yellow]")
        enriched_events = events

    # Store events
    progress.update(task, description="[cyan]Storing events...")
    stored_count = 0

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        console=console
    ) as progress2:
        task = progress2.add_task("[cyan]Storing...", total=len(enriched_events))
        for event in enriched_events:
            try:
                store_event(event)
                stored_count += 1
            except Exception as e:
                console.print(f"[yellow]Warning: Could not store event: {e}[/yellow]")
            progress2.update(task, advance=1)

    console.print(f"\n[green]Ingested {stored_count} events[/green]")

    # Generate alerts from processed events
    engine = get_engine()
    alert_count = 0
    for event in enriched_events[:10]:  # Process first 10 for demo
        alerts = engine.process_event(event)
        alert_count += len(alerts)

    console.print(f"[cyan]Generated {alert_count} alerts from processed events[/cyan]")

    return 0


def cmd_alerts(args):
    """Show active alerts."""
    alerts = get_alerts(severities=args.severity, statuses=args.status)

    if not alerts:
        console.print("[yellow]No alerts found[/yellow]")
        return 0

    table = Table(title="Security Alerts")
    table.add_column("ID", style="dim", width=8)
    table.add_column("MITRE ID", width=10)
    table.add_column("Severity", width=10)
    table.add_column("Risk", width=6, justify="right")
    table.add_column("Status", width=12)
    table.add_column("Source IP", width=15)
    table.add_column("User", width=15)
    table.add_column("Title", min_width=30)

    for alert in sorted(alerts, key=lambda a: a.risk_score, reverse=True):
        severity_color = {
            "CRITICAL": "red",
            "HIGH": "yellow",
            "MEDIUM": "cyan",
            "LOW": "dim"
        }.get(alert.severity, "white")

        status_color = {
            "NEW": "blue",
            "INVESTIGATING": "yellow",
            "RESOLVED": "green",
            "FALSE_POSITIVE": "dim"
        }.get(alert.status, "white")

        table.add_row(
            alert.id[:8],
            alert.mitre_id,
            f"[{severity_color}]{alert.severity}[/{severity_color}]",
            str(alert.risk_score),
            f"[{status_color}]{alert.status}[/{status_color}]",
            alert.source_ip,
            alert.user_id or "-",
            alert.title
        )

    console.print(table)
    return 0


def cmd_incidents(args):
    """Show security incidents."""
    incidents = get_incidents()

    if not incidents:
        console.print("[yellow]No incidents found[/yellow]")
        return 0

    table = Table(title="Security Incidents")
    table.add_column("ID", style="dim", width=8)
    table.add_column("Severity", width=10)
    table.add_column("Alerts", width=6)
    table.add_column("Created", min_width=20)
    table.add_column("Resolved", min_width=15)

    for incident in incidents:
        severity_color = {
            "CRITICAL": "red",
            "HIGH": "yellow",
            "MEDIUM": "cyan",
            "LOW": "dim"
        }.get(incident.severity, "white")

        resolved = "No" if incident.resolved_at is None else "Yes"

        table.add_row(
            incident.id[:8],
            f"[{severity_color}]{incident.severity}[/{severity_color}]",
            str(len(incident.alerts)),
            incident.created_at.strftime("%Y-%m-%d %H:%M") if incident.created_at else "-",
            resolved
        )

    console.print(table)
    return 0


def cmd_respond(args):
    """Execute a SOAR response action."""
    action_type = args.action
    target = args.target
    reason = args.reason or f"Manual action: {action_type} for {target}"

    result = soar.execute_playbook(
        action_type=action_type,
        target=target,
        reason=reason,
        performed_by=args.analyst or "manual"
    )

    if result.get('success'):
        console.print(f"[green]Action executed successfully[/green]")
        console.print(f"  Action: {result['action_type']}")
        console.print(f"  Target: {result['target']}")
        console.print(f"  ID: {result['id']}")
    else:
        console.print(f"[red]Action failed: {result.get('error', 'Unknown error')}[/red]")

    return 0


def cmd_simulate(args):
    """Run attack simulation scenarios."""
    console.print("\n[bold]Available Simulation Scenarios:[/bold]")
    console.print("  1. brute-force    - Simulate brute-force login attacks")
    console.print("  2. password-spray - Simulate password spraying attacks")
    console.print("  3. impossible-trav - Simulate impossible travel")
    console.print("  4. api-scan       - Simulate API endpoint enumeration")
    console.print("  5. sql-injection  - Simulate SQL injection probes")
    console.print("  6. fraud          - Simulate high-value transfer fraud")
    console.print()

    scenario = input("Select scenario (or 'all' for full demo): ").strip().lower()

    if scenario == 'all':
        console.print("\n[bold green]Running full demonstration...[/bold green]")
        generate_sample_traffic(count=200, output_path="sample_logs/demo_stream.jsonl")
        ingest_result = cmd_ingest(type('Args', (), {'file': 'sample_logs/demo_stream.jsonl', 'log_type': None})())
        console.print(f"\n[green]Simulation complete[/green]")
    else:
        # Map scenario names to functions
        scenarios = {
            '1': 'brute-force',
            '2': 'password-spray',
            '3': 'impossible-trav',
            '4': 'api-scan',
            '5': 'sql-injection',
            '6': 'fraud',
            'brute-force': 'brute-force',
            'password-spray': 'password-spray',
            'impossible-trav': 'impossible-trav',
            'api-scan': 'api-scan',
            'sql-injection': 'sql-injection',
            'fraud': 'fraud'
        }
        if scenario in scenarios:
            console.print(f"\n[yellow]Simulating {scenarios[scenario]}...[/yellow]")
            # Generate traffic for specific scenario
            # This would generate targeted attack traffic
            console.print("[dim]Scenario implementation pending[/dim]")
        else:
            console.print("[red]Invalid scenario[/red]")
            return 1

    return 0


def cmd_export(args):
    """Export incident reports."""
    incidents = get_incidents()

    if not incidents:
        console.print("[yellow]No incidents to export[/yellow]")
        return 0

    incident = incidents[0]  # Export first incident
    alerts = [a for a in get_alerts() if a.id in incident.alerts]

    output_path = args.output or "incidents"

    if args.format == 'json':
        filepath = f"{output_path}.json"
        from src.reporter import export_incident_json
        export_incident_json(incident, alerts, filepath)
    elif args.format == 'csv':
        filepath = f"{output_path}.csv"
        from src.reporter import export_incident_csv
        export_incident_csv(incidents, filepath)
    elif args.format == 'markdown':
        filepath = f"{output_path}.md"
        from src.reporter import export_incident_markdown
        export_incident_markdown(incident, alerts, filepath)
    else:
        console.print(f"[red]Unknown format: {args.format}[/red]")
        return 1

    console.print(f"[green]Exported to {filepath}[/green]")
    return 0


def cmd_serve(args):
    """Start the web dashboard server."""
    port = args.port or 8080

    console.print(f"\n[bold blue]═══════════════════════════════════════════════════════════════[/bold blue]")
    console.print("[bold blue]              FINTECH MINI-SIEM WEB DASHBOARD                      [/bold blue]")
    console.print("[bold blue]═══════════════════════════════════════════════════════════════[/bold blue]")
    console.print(f"\n[green]Starting web server at http://127.0.0.1:{port}[/green]")
    console.print("[yellow]Press Ctrl+C to stop the server[/yellow]\n")

    try:
        import uvicorn
        from src.web_server import app

        uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
    except ImportError:
        console.print("[red]uvicorn not installed. Install with: pip install uvicorn[/red]")
        return 1
    except KeyboardInterrupt:
        console.print("\n[yellow]Server stopped[/yellow]")
        return 0


def cmd_status(args):
    """Show SIEM status summary."""
    alerts = get_alerts()
    incidents = get_incidents()
    blocked = get_blocked_ips()
    frozen = get_frozen_accounts()

    table = Table(title="SIEM Status")
    table.add_column("Metric", width=25)
    table.add_column("Value", width=15)

    table.add_row("Total Alerts", str(len(alerts)))
    table.add_row("Critical Alerts", str(len([a for a in alerts if a.severity == "CRITICAL"])))
    table.add_row("Open Incidents", str(len([i for i in incidents if i.resolved_at is None])))
    table.add_row("Blocked IPs", str(len(blocked)))
    table.add_row("Frozen Accounts", str(len(frozen)))
    table.add_row("DB Path", get_db_path())

    console.print(table)
    return 0


def main():
    """Main entry point for CLI."""
    parser = argparse.ArgumentParser(
        prog='fintech-mini-siem',
        description='Fintech Mini-SIEM & SOAR Web Console CLI'
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # init command
    init_parser = subparsers.add_parser('init', help='Initialize the SIEM database')
    init_parser.set_defaults(func=cmd_init)

    # ingest command
    ingest_parser = subparsers.add_parser('ingest', help='Ingest log files')
    ingest_parser.add_argument('file', help='Path to log file (JSONL format)')
    ingest_parser.add_argument('--log-type', choices=['auth_service', 'api_gateway', 'payment_engine'],
                                help='Override log type auto-detection')
    ingest_parser.add_argument('--follow', action='store_true', help='Follow file for live updates')
    ingest_parser.set_defaults(func=cmd_ingest)

    # alerts command
    alerts_parser = subparsers.add_parser('alerts', help='Show active alerts')
    alerts_parser.add_argument('--severity', choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                                help='Filter by severity')
    alerts_parser.add_argument('--status', choices=['NEW', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'],
                                help='Filter by status')
    alerts_parser.set_defaults(func=cmd_alerts)

    # incidents command
    incidents_parser = subparsers.add_parser('incidents', help='Show security incidents')
    incidents_parser.set_defaults(func=cmd_incidents)

    # respond command
    respond_parser = subparsers.add_parser('respond', help='Execute SOAR response')
    respond_parser.add_argument('action', choices=['block_ip', 'freeze_account', 'revoke_sessions'],
                               help='Action to execute')
    respond_parser.add_argument('target', help='Target IP or user ID')
    respond_parser.add_argument('--reason', '-r', help='Reason for action')
    respond_parser.add_argument('--analyst', '-a', help='Analyst name')
    respond_parser.set_defaults(func=cmd_respond)

    # simulate command
    simulate_parser = subparsers.add_parser('simulate', help='Run attack scenarios')
    simulate_parser.set_defaults(func=cmd_simulate)

    # export command
    export_parser = subparsers.add_parser('export', help='Export incident reports')
    export_parser.add_argument('--format', '-f', choices=['json', 'csv', 'markdown'],
                              default='json', help='Export format')
    export_parser.add_argument('--output', '-o', help='Output file path')
    export_parser.set_defaults(func=cmd_export)

    # serve command
    serve_parser = subparsers.add_parser('serve', help='Start web dashboard')
    serve_parser.add_argument('--port', '-p', type=int, default=8080, help='Port number')
    serve_parser.set_defaults(func=cmd_serve)

    # status command
    status_parser = subparsers.add_parser('status', help='Show SIEM status')
    status_parser.set_defaults(func=cmd_status)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())