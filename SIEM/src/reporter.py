"""Rich terminal report generation for SIEM events, alerts, and incidents."""

from datetime import datetime
from typing import Optional, List
import json
import csv
import io

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.tree import Tree
from rich import print as rprint

from src.models import Alert, Incident, NormalizedEvent


console = Console()


def generate_alert_table(alerts: List[Alert]) -> Table:
    """Generate a Rich table for alerts.

    Args:
        alerts: List of Alert objects to display

    Returns:
        Rich Table object
    """
    table = Table(title="Security Alerts", show_header=True, header_style="bold cyan")

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
            alert.title[:30] + "..." if len(alert.title) > 30 else alert.title
        )

    return table


def generate_incident_table(incidents: List[Incident]) -> Table:
    """Generate a Rich table for incidents.

    Args:
        incidents: List of Incident objects to display

    Returns:
        Rich Table object
    """
    table = Table(title="Security Incidents", show_header=True, header_style="bold red")

    table.add_column("ID", style="dim", width=8)
    table.add_column("Severity", width=10)
    table.add_column("Alerts", width=6)
    table.add_column("Created", min_width=20)
    table.add_column("Resolved", min_width=15)
    table.add_column("Title", min_width=30)

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
            resolved,
            incident.title[:30] + "..." if len(incident.title) > 30 else incident.title
        )

    return table


def generate_kpi_panel(alerts: List[Alert], incidents: List[Incident],
                       blocked_ips: List[dict], frozen_accounts: List[dict]) -> Panel:
    """Generate a KPI summary panel.

    Args:
        alerts: List of alerts
        incidents: List of incidents
        blocked_ips: List of blocked IPs
        frozen_accounts: List of frozen accounts

    Returns:
        Rich Panel object
    """
    critical_alerts = len([a for a in alerts if a.severity == "CRITICAL"])
    high_alerts = len([a for a in alerts if a.severity == "HIGH"])

    critical_incidents = len([i for i in incidents if i.severity == "CRITICAL"])
    active_incidents = len([i for i in incidents if i.resolved_at is None])

    content = f"""
[bold]KPIs[/bold]
┌─────────────────────────────────────┐
│  Critical Alerts: [red]{critical_alerts}[/red]    │
│  High Alerts:     [yellow]{high_alerts}[/yellow]      │
│  Critical Incidents: [red]{critical_incidents}[/red]  │
│  Active Incidents: [cyan]{active_incidents}[/cyan]       │
│  Blocked IPs:     [green]{len(blocked_ips)}[/green]       │
│  Frozen Accounts: [magenta]{len(frozen_accounts)}[/magenta]     │
└─────────────────────────────────────┘
"""
    return Panel(content, title="SIEM Dashboard", border_style="bold blue")


def generate_mitre_breakdown(alerts: List[Alert]) -> Table:
    """Generate a table showing MITRE ATT&CK technique breakdown.

    Args:
        alerts: List of alerts

    Returns:
        Rich Table object
    """
    technique_counts = {}
    for alert in alerts:
        mitre_id = alert.mitre_id
        technique_counts[mitre_id] = technique_counts.get(mitre_id, 0) + 1

    table = Table(title="MITRE ATT&CK Technique Frequency", show_header=True)
    table.add_column("Technique ID", width=15)
    table.add_column("Count", width=8)
    table.add_column("Severity", width=10)

    rule_severity = {}
    for alert in alerts:
        if alert.mitre_id not in rule_severity:
            # Map technique IDs to readable names
            pass

    for mitre_id, count in sorted(technique_counts.items(), key=lambda x: x[1], reverse=True):
        table.add_row(mitre_id, str(count), "-")

    return table


def generate_incident_report(incident: Incident, alerts: List[Alert]) -> dict:
    """Generate a detailed incident report as dictionary.

    Args:
        incident: Incident object
        alerts: List of related alerts

    Returns:
        Dictionary with incident report details
    """
    timeline_events = []
    for step in incident.timeline:
        timeline_events.append({
            "event": step.get("event", ""),
            "timestamp": step.get("time", ""),
            "description": step.get("description", "")
        })

    return {
        "incident_id": incident.id,
        "title": incident.title,
        "severity": incident.severity,
        "created_at": incident.created_at.isoformat() if incident.created_at else None,
        "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
        "alerts": incident.alerts,
        "timeline": timeline_events,
        "summary": incident.summary
    }


def export_incident_json(incident: Incident, alerts: List[Alert], filepath: str) -> None:
    """Export incident report as JSON file.

    Args:
        incident: Incident object
        alerts: List of related alerts
        filepath: Path to save the JSON file
    """
    report = generate_incident_report(incident, alerts)

    with open(filepath, 'w') as f:
        json.dump(report, f, indent=2, default=str)


def export_incident_csv(incidents: List[Incident], filepath: str) -> None:
    """Export incidents as CSV file.

    Args:
        incidents: List of Incident objects
        filepath: Path to save the CSV file
    """
    with open(filepath, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['ID', 'Title', 'Severity', 'Created', 'Resolved', 'Alert Count', 'Summary'])

        for incident in incidents:
            writer.writerow([
                incident.id,
                incident.title,
                incident.severity,
                incident.created_at.isoformat() if incident.created_at else "",
                incident.resolved_at.isoformat() if incident.resolved_at else "",
                len(incident.alerts),
                incident.summary
            ])


def export_incident_markdown(incident: Incident, alerts: List[Alert], filepath: str) -> None:
    """Export incident report as Markdown file.

    Args:
        incident: Incident object
        alerts: List of related alerts
        filepath: Path to save the Markdown file
    """
    lines = [
        f"# Incident Report: {incident.title}",
        "",
        f"**ID:** {incident.id}",
        f"**Severity:** {incident.severity}",
        f"**Created:** {incident.created_at}",
        f"**Resolved:** {incident.resolved_at or 'Not Resolved'}",
        f"**Alerts:** {len(incident.alerts)}",
        "",
        "## Summary",
        "",
        incident.summary,
        "",
        "## Timeline",
        "",
    ]

    for step in incident.timeline:
        lines.append(f"- [{step.get('time', 'N/A')}] {step.get('event', '')}: {step.get('description', '')}")

    lines.extend([
        "",
        "## Related Alerts",
        "",
    ])

    for alert in alerts:
        lines.append(f"- **{alert.mitre_id}** ({alert.severity}): {alert.title}")

    with open(filepath, 'w') as f:
        f.write('\n'.join(lines))


def render_dashboard(alerts: List[Alert], incidents: List[Incident],
                     blocked_ips: List[dict], frozen_accounts: List[dict],
                     total_events: int, risk_score_avg: float) -> None:
    """Render the full SIEM dashboard to terminal.

    Args:
        alerts: List of alerts
        incidents: List of incidents
        blocked_ips: List of blocked IPs
        frozen_accounts: List of frozen accounts
        total_events: Total number of events processed
        risk_score_avg: Average risk score
    """
    # Clear screen
    console.clear()

    # Title
    console.print("\n[bold blue]═══════════════════════════════════════════════════════════════[/bold blue]")
    console.print("[bold blue]              FINTECH MINI-SIEM & SOAR CONSOLE                 [/bold blue]")
    console.print("[bold blue]═══════════════════════════════════════════════════════════════[/bold blue]\n")

    # KPI Panel
    kpi = generate_kpi_panel(alerts, incidents, blocked_ips, frozen_accounts)
    console.print(kpi)
    console.print()

    # Alerts by Severity
    severity_counts = {
        "CRITICAL": len([a for a in alerts if a.severity == "CRITICAL"]),
        "HIGH": len([a for a in alerts if a.severity == "HIGH"]),
        "MEDIUM": len([a for a in alerts if a.severity == "MEDIUM"]),
        "LOW": len([a for a in alerts if a.severity == "LOW"])
    }

    severity_table = Table(title="Alerts by Severity")
    severity_table.add_column("Severity", width=10)
    severity_table.add_column("Count", width=8, justify="right")

    colors = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "cyan", "LOW": "dim"}
    for sev, count in severity_counts.items():
        severity_table.add_row(f"[{colors[sev]}]{sev}[/{colors[sev]}]", str(count))

    console.print(severity_table)
    console.print()

    # MITRE Breakdown if there are alerts
    if alerts:
        mitre_table = generate_mitre_breakdown(alerts)
        console.print(mitre_table)
        console.print()

    # Status summary
    status_counts = {
        "NEW": len([a for a in alerts if a.status == "NEW"]),
        "INVESTIGATING": len([a for a in alerts if a.status == "INVESTIGATING"]),
        "RESOLVED": len([a for a in alerts if a.status == "RESOLVED"]),
        "FALSE_POSITIVE": len([a for a in alerts if a.status == "FALSE_POSITIVE"])
    }

    status_table = Table(title="Alert Status")
    status_table.add_column("Status", width=15)
    status_table.add_column("Count", width=8, justify="right")

    for status, count in status_counts.items():
        status_table.add_row(status, str(count))

    console.print(status_table)
    console.print()

    # Recent Incidents
    if incidents:
        console.print("[bold]Recent Incidents (Unresolved)[/bold]")
        for incident in sorted(incidents, key=lambda i: i.created_at, reverse=True)[:5]:
            if incident.resolved_at is None:
                console.print(f"  • [{incident.severity}] {incident.title} ({incident.id[:8]})")
    else:
        console.print("[dim]No active incidents[/dim]")

    console.print()
    console.print("[dim]Press Ctrl+C to exit web server mode[/dim]")