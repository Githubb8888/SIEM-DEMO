"""Tests for the SIEM reporter module."""

import pytest
from datetime import datetime
from io import StringIO

from src.models import Alert, Incident
from src.reporter import (
    generate_alert_table,
    generate_incident_table,
    generate_incident_report,
    export_incident_markdown
)


class TestAlertTable:
    """Tests for alert table generation."""

    def test_alert_table_with_alerts(self):
        """Verify alert table is generated correctly."""
        alerts = [
            Alert(
                id='alert-1',
                event_id='event-1',
                mitre_id='T1110.001',
                severity='CRITICAL',
                risk_score=95,
                title='Brute Force Attack',
                description='Test',
                timestamp=datetime.now(),
                source_ip='1.2.3.4',
                user_id='user1',
                status='NEW',
                correlated=False
            ),
            Alert(
                id='alert-2',
                event_id='event-2',
                mitre_id='T1078',
                severity='HIGH',
                risk_score=85,
                title='Impossible Travel',
                description='Test',
                timestamp=datetime.now(),
                source_ip='5.6.7.8',
                user_id='user2',
                status='INVESTIGATING',
                correlated=False
            )
        ]

        table = generate_alert_table(alerts)
        assert table is not None
        rows = list(table.rows)
        assert len(rows) == 2

    def test_alert_table_empty(self):
        """Verify empty alert list returns empty table."""
        table = generate_alert_table([])
        assert table is not None


class TestIncidentTable:
    """Tests for incident table generation."""

    def test_incident_table_with_incidents(self):
        """Verify incident table is generated correctly."""
        incidents = [
            Incident(
                id='inc-1',
                title='Account Compromise',
                severity='CRITICAL',
                created_at=datetime.now(),
                resolved_at=None,
                alerts=['alert-1', 'alert-2'],
                timeline=[],
                summary='Test incident'
            )
        ]

        table = generate_incident_table(incidents)
        assert table is not None


class TestIncidentReport:
    """Tests for incident report generation."""

    def test_generate_incident_report(self):
        """Verify incident report is generated correctly."""
        incident = Incident(
            id='inc-1',
            title='Test Incident',
            severity='HIGH',
            created_at=datetime.now(),
            resolved_at=None,
            alerts=['alert-1'],
            timeline=[
                {'event': 'login', 'time': '2024-01-15T10:00:00Z', 'description': 'Initial access'},
                {'event': 'alert', 'time': '2024-01-15T10:05:00Z', 'description': 'Alert triggered'}
            ],
            summary='Test summary'
        )

        alerts = [
            Alert(
                id='alert-1',
                event_id='event-1',
                mitre_id='T1110.001',
                severity='HIGH',
                risk_score=75,
                title='Brute Force',
                description='Test',
                timestamp=datetime.now(),
                source_ip='1.2.3.4',
                user_id='user1',
                status='NEW',
                correlated=False
            )
        ]

        report = generate_incident_report(incident, alerts)

        assert report['incident_id'] == 'inc-1'
        assert report['title'] == 'Test Incident'
        assert len(report['timeline']) == 2


class TestMarkdownExport:
    """Tests for Markdown export."""

    def test_export_incident_markdown(self, tmp_path):
        """Verify Markdown export works."""
        incident = Incident(
            id='inc-1',
            title='Test Incident',
            severity='HIGH',
            created_at=datetime.now(),
            resolved_at=None,
            alerts=['alert-1'],
            timeline=[],
            summary='Test summary for export'
        )

        alerts = []
        filepath = tmp_path / "test_report.md"

        export_incident_markdown(incident, alerts, str(filepath))

        assert filepath.exists()
        content = filepath.read_text()
        assert "Test Incident" in content
        assert "Test summary for export" in content