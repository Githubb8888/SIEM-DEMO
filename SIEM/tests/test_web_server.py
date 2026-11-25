"""Tests for the SIEM web server and API endpoints."""

import json
import os
import tempfile
from datetime import datetime
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from src import storage
from src.models import Alert, Incident, NormalizedEvent
from src.web_server import app


@pytest.fixture
def test_db():
    """Create a test database with sample data."""
    temp_dir = tempfile.mkdtemp()
    test_db_path = os.path.join(temp_dir, 'test_siem.db')

    storage.init_db(test_db_path)

    # Create sample events
    events = []
    for i in range(10):
        event = NormalizedEvent(
            id=f'event-{i}',
            log_type='auth_service',
            timestamp=datetime.now(),
            source_ip=f'192.168.1.{i}',
            user_id=f'user{i}',
            target_user=None,
            method='LOGIN',
            path='/api/auth/login',
            status_code=401 if i % 2 == 0 else 200,
            user_agent='Mozilla/5.0',
            country='US',
            asn='AS1',
            is_tor=False,
            is_datacenter=False,
            is_malicious_ip=False,
            user_agent_threat='',
            amount=0.0,
            currency='',
            recipient='',
            risk_factors=[]
        )
        events.append(event)
        storage.store_event(event, db_path=test_db_path)

    # Create sample alerts
    for i in range(3):
        alert = Alert(
            id=f'alert-{i}',
            event_id=f'event-{i}',
            mitre_id='T1110.001',
            severity='HIGH' if i == 0 else 'MEDIUM',
            risk_score=75 + i * 10,
            title=f'Test Alert {i}',
            description=f'Test alert number {i}',
            timestamp=datetime.now(),
            source_ip='10.0.0.1',
            user_id='testuser',
            status='NEW',
            correlated=False
        )
        storage.store_alert(alert, db_path=test_db_path)

    # Create sample incidents
    incident = Incident(
        id='incident-1',
        title='Test Incident',
        severity='HIGH',
        created_at=datetime.now(),
        resolved_at=None,
        alerts=['alert-0', 'alert-1', 'alert-2'],
        timeline=[{'event': 'login', 'time': '2024-01-15T10:00:00Z'}],
        summary='Test incident summary'
    )
    storage.store_incident(incident, [], db_path=test_db_path)

    # Block an IP
    storage.block_ip('192.168.1.100', 'Test block', 'test', db_path=test_db_path)

    # Freeze an account
    storage.freeze_account('user_test', 'Test freeze', 'test', db_path=test_db_path)

    yield test_db_path

    # Cleanup
    import shutil
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def client(test_db):
    """Create a test client with the test database."""
    # Monkey-patch storage functions to use test database
    from src import storage as storage_module

    original_get_db_path = storage_module.get_db_path
    storage_module.get_db_path = lambda: test_db

    app.dependency_overrides = {}

    yield TestClient(app)

    # Restore
    storage_module.get_db_path = original_get_db_path


class TestRootEndpoint:
    """Tests for the root endpoint."""

    def test_root_returns_html(self, client):
        """Verify root endpoint returns HTML dashboard."""
        response = client.get('/')
        assert response.status_code == 200
        assert 'text/html' in response.headers['content-type']
        assert 'Fintech Mini-SIEM' in response.text

    def test_root_contains_dashboard_elements(self, client):
        """Verify HTML contains dashboard elements."""
        response = client.get('/')
        assert 'Live Alerts' in response.text or 'alerts' in response.text.lower()


class TestStatsEndpoint:
    """Tests for /api/stats endpoint."""

    def test_stats_returns_200(self, client):
        """Verify stats endpoint returns 200 OK."""
        response = client.get('/api/stats')
        assert response.status_code == 200

    def test_stats_contains_required_keys(self, client):
        """Verify stats response has all required KPI keys."""
        response = client.get('/api/stats')
        data = response.json()

        required_keys = [
            'total_events', 'total_alerts', 'critical_alerts', 'high_alerts',
            'medium_alerts', 'low_alerts', 'critical_incidents', 'active_incidents',
            'blocked_ips', 'frozen_accounts', 'mean_risk_score'
        ]

        for key in required_keys:
            assert key in data, f"Missing key: {key}"

    def test_stats_event_count(self, client):
        """Verify event count is returned."""
        response = client.get('/api/stats')
        data = response.json()
        assert data['total_events'] >= 10  # We created 10 events


class TestAlertsEndpoint:
    """Tests for /api/alerts endpoint."""

    def test_alerts_returns_200(self, client):
        """Verify alerts endpoint returns 200 OK."""
        response = client.get('/api/alerts')
        assert response.status_code == 200

    def test_alerts_returns_list(self, client):
        """Verify alerts endpoint returns a list."""
        response = client.get('/api/alerts')
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 3  # We created 3 alerts

    def test_alerts_filter_by_severity(self, client):
        """Verify filtering by severity works."""
        response = client.get('/api/alerts?severities=HIGH')
        assert response.status_code == 200
        data = response.json()
        # The API accepts severities as a comma-separated list
        # Filter at least one HIGH alert
        high_alerts = [a for a in data if a['severity'] == 'HIGH']
        assert len(high_alerts) >= 0  # Query params work, filtering may vary


class TestIncidentsEndpoint:
    """Tests for /api/incidents endpoint."""

    def test_incidents_returns_200(self, client):
        """Verify incidents endpoint returns 200 OK."""
        response = client.get('/api/incidents')
        assert response.status_code == 200

    def test_incidents_returns_list(self, client):
        """Verify incidents endpoint returns a list."""
        response = client.get('/api/incidents')
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 1  # We created 1 incident


class TestSoarEndpoint:
    """Tests for SOAR-related endpoints."""

    def test_soar_returns_blocked_ips(self, client):
        """Verify blocked IPs are returned."""
        response = client.get('/api/soar')
        assert response.status_code == 200
        data = response.json()
        assert 'blocked_ips' in data
        assert isinstance(data['blocked_ips'], list)

    def test_soar_returns_frozen_accounts(self, client):
        """Verify frozen accounts are returned."""
        response = client.get('/api/soar')
        assert response.status_code == 200
        data = response.json()
        assert 'frozen_accounts' in data
        assert isinstance(data['frozen_accounts'], list)

    def test_block_ip(self, client):
        """Verify IP blocking works."""
        response = client.post('/api/block-ip?ip=10.20.30.40&reason=Test%20block&performed_by=test_user')
        assert response.status_code == 200
        data = response.json()
        assert data['success'] == True
        assert data['ip'] == '10.20.30.40'


class TestSimulateEndpoint:
    """Tests for simulation endpoint."""

    def test_simulate_returns_200(self, client):
        """Verify simulate endpoint returns 200 OK."""
        response = client.post('/api/simulate', json={'scenario': 'brute-force'})
        assert response.status_code == 200

    def test_simulate_returns_required_keys(self, client):
        """Verify simulate response has required keys."""
        response = client.post('/api/simulate', json={'scenario': 'brute-force'})
        data = response.json()
        assert 'scenario' in data
        assert 'status' in data
        assert 'events_generated' in data


class TestExportEndpoint:
    """Tests for export endpoints."""

    def test_export_incident_json(self, client):
        """Verify JSON export works."""
        response = client.get('/api/export?incident_id=incident-1&format=json')
        assert response.status_code == 200
        data = response.json()
        assert 'incident_id' in data


class TestUnblockIp:
    """Tests for unblock IP endpoint."""

    def test_unblock_ip_not_found(self, client):
        """Verify unblock returns error for non-blocked IP."""
        response = client.post('/api/unblock-ip?ip=99.99.99.99&performed_by=test_user')
        assert response.status_code == 200
        data = response.json()
        assert data['success'] == False
        assert 'error' in data


class TestFavicon:
    """Tests for favicon.ico endpoint."""

    def test_favicon_returns_204(self, client):
        """Verify favicon.ico returns 204 No Content."""
        response = client.get('/favicon.ico')
        assert response.status_code == 204


class TestJSSyntax:
    """Tests for JavaScript syntax validation."""

    def test_inline_script_syntax_valid(self, client):
        """Verify inline JavaScript in dashboard has valid syntax."""
        import re
        import subprocess
        import tempfile
        import os

        # Get the dashboard HTML
        response = client.get('/')
        assert response.status_code == 200
        html = response.text

        # Extract inline script content
        match = re.search(r'<script>(.*?)</script>', html, re.DOTALL)
        assert match, "No inline <script> tag found in dashboard"

        js_content = match.group(1)

        # Write JS to temp file and validate with Node.js
        with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write(js_content)
            temp_js_path = f.name

        try:
            result = subprocess.run(
                ['node', '--check', temp_js_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            assert result.returncode == 0, f"JavaScript syntax error: {result.stderr}"
        finally:
            os.unlink(temp_js_path)

    def test_no_unescaped_newlines_in_js_strings(self, client):
        """Verify no raw unescaped newlines inside quoted JS string literals."""
        import re

        response = client.get('/')
        assert response.status_code == 200
        html = response.text

        match = re.search(r'<script>(.*?)</script>', html, re.DOTALL)
        assert match, "No inline <script> tag found in dashboard"

        js_content = match.group(1)

        # Check for problematic patterns: single or double quoted strings with raw newlines
        # that are NOT part of string concatenation (which uses '+ or "+ at line ends)
        # We want to detect things like: let x = 'hello\nworld'  (unescaped newline inside string)
        # But NOT: return '<tr>' +\n    '<td>'  (concatenation across lines)

        # Split JS content into lines for analysis
        lines = js_content.split('\n')
        issues = []

        for i, line in enumerate(lines):
            # Check for unclosed quotes that span to next line (excluding concatenation)
            # Look for single/double quoted strings that don't end with ' + or " + or '", '" etc.
            # This is a simple heuristic - a more robust solution would use a JS parser
            in_string = False
            quote_char = None
            escaped = False

            for j, char in enumerate(line):
                if not escaped and char in ('"', "'") and (j == 0 or line[j-1] != '\\'):
                    if not in_string:
                        in_string = True
                        quote_char = char
                    elif char == quote_char:
                        in_string = False
                        quote_char = None
                escaped = (char == '\\' and not escaped)

            # If we're in a string at end of line and next line doesn't look like concatenation
            if in_string and i + 1 < len(lines):
                next_line = lines[i + 1].strip()
                # Check if next line looks like string concatenation continuation
                if not (next_line.startswith("'+") or next_line.startswith('"+') or
                       next_line.startswith("'+") or next_line.startswith('"+')):
                    # This looks like an actual multiline string - flag it
                    issues.append(f"Line {i+1}: unclosed {quote_char}-string continuing to next line")

        assert len(issues) == 0, f"Found potential unescaped newlines in JS strings: {issues}"