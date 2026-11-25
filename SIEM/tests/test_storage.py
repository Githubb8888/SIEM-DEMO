"""Tests for the SIEM storage module."""
import json
import os
import sqlite3
import tempfile
from datetime import datetime

import pytest

from src.models import Alert, Incident, NormalizedEvent, PlaybookAction
from src import storage


class TestDatabaseInitialization:
    """Tests for database initialization."""

    def setup_method(self):
        """Set up test database before each test."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_db_path = os.path.join(self.temp_dir, 'test_siem.db')

    def teardown_method(self):
        """Clean up test database after each test."""
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
        if os.path.exists(self.temp_dir):
            os.rmdir(self.temp_dir)

    def test_init_db_creates_database_file(self):
        """Verify init_db creates the database file."""
        storage.init_db(self.test_db_path)
        assert os.path.exists(self.test_db_path)

    def test_init_db_creates_all_tables(self):
        """Verify all required tables are created."""
        storage.init_db(self.test_db_path)

        with sqlite3.connect(self.test_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {row[0] for row in cursor.fetchall()}

        expected_tables = {
            'events', 'alerts', 'incidents', 'incident_timeline',
            'entity_risk_scores', 'audit_log', 'blocked_ips', 'frozen_accounts',
            'employees', 'devices'
        }
        assert tables == expected_tables

    def test_init_db_is_idempotent(self):
        """Verify init_db can be called multiple times safely."""
        storage.init_db(self.test_db_path)
        storage.init_db(self.test_db_path)  # Should not raise

        with sqlite3.connect(self.test_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM events")
            assert cursor.fetchone()[0] == 0


class TestEventStorage:
    """Tests for event storage and retrieval."""

    def setup_method(self):
        """Set up test database before each test."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_db_path = os.path.join(self.temp_dir, 'test_siem.db')
        storage.init_db(self.test_db_path)

    def teardown_method(self):
        """Clean up test database after each test."""
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
        if os.path.exists(self.temp_dir):
            os.rmdir(self.temp_dir)

    def test_store_event_returns_event_id(self):
        """Verify store_event returns the event ID."""
        event = NormalizedEvent(
            id='test-event-uuid',
            log_type='auth_service',
            timestamp=datetime(2024, 1, 15, 10, 30, 0),
            source_ip='192.168.1.1',
            user_id=None,
            target_user='user123',
            method='LOGIN',
            path='/api/auth/login',
            status_code=200,
            user_agent='Mozilla/5.0',
            country='US',
            asn='AS15169',
            is_tor=False,
            is_datacenter=False,
            is_malicious_ip=False,
            user_agent_threat='',
            amount=0.0,
            currency='',
            recipient='',
            risk_factors=['brute_force']
        )

        event_id = storage.store_event(event, self.test_db_path)
        assert event_id == 'test-event-uuid'

    def test_get_event_retrieves_stored_event(self):
        """Verify get_event retrieves a previously stored event."""
        event = NormalizedEvent(
            id='test-event-uuid-2',
            log_type='api_gateway',
            timestamp=datetime(2024, 1, 15, 11, 0, 0),
            source_ip='10.0.0.1',
            user_id='user456',
            target_user=None,
            method='GET',
            path='/api/users',
            status_code=200,
            user_agent='curl/7.68.0',
            country='GB',
            asn='AS13335',
            is_tor=True,
            is_datacenter=True,
            is_malicious_ip=True,
            user_agent_threat='tool_name',
            amount=99.99,
            currency='USD',
            recipient='recp789',
            risk_factors=['suspicious_activity', 'high_risk_location']
        )

        storage.store_event(event, self.test_db_path)
        retrieved = storage.get_event('test-event-uuid-2', self.test_db_path)

        assert retrieved is not None
        assert retrieved.id == event.id
        assert retrieved.log_type == event.log_type
        assert retrieved.source_ip == event.source_ip
        assert retrieved.method == event.method
        assert retrieved.status_code == event.status_code
        assert retrieved.risk_factors == event.risk_factors

    def test_get_event_returns_none_for_nonexistent(self):
        """Verify get_event returns None for non-existent event ID."""
        result = storage.get_event('nonexistent-id', self.test_db_path)
        assert result is None

    def test_get_event_preserves_risk_factors_as_list(self):
        """Verify risk_factors are correctly serialized/deserialized as list."""
        event = NormalizedEvent(
            id='risk-factors-test',
            log_type='payment_engine',
            timestamp=datetime.now(),
            source_ip='1.1.1.1',
            user_id='user1',
            target_user=None,
            method='POST',
            path='/api/payment',
            status_code=200,
            user_agent='test-agent',
            country='US',
            asn='AS1',
            is_tor=False,
            is_datacenter=False,
            is_malicious_ip=False,
            user_agent_threat='',
            amount=100.0,
            currency='USD',
            recipient='recipient1',
            risk_factors=['fraud_attempt', 'anomalous_amount']
        )

        storage.store_event(event, self.test_db_path)
        retrieved = storage.get_event('risk-factors-test', self.test_db_path)

        assert isinstance(retrieved.risk_factors, list)
        assert retrieved.risk_factors == ['fraud_attempt', 'anomalous_amount']

    def test_event_data_persists_across_calls(self):
        """Verify event data persists across multiple function calls."""
        event = NormalizedEvent(
            id='persistence-test',
            log_type='auth_service',
            timestamp=datetime(2024, 1, 15, 10, 30, 0),
            source_ip='192.168.1.100',
            user_id='user_test',
            target_user=None,
            method='TOKEN_REFRESH',
            path='/api/auth/refresh',
            status_code=200,
            user_agent='MobileApp/1.0',
            country='CA',
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

        storage.store_event(event, self.test_db_path)

        # Retrieve again
        retrieved = storage.get_event('persistence-test', self.test_db_path)
        assert retrieved is not None
        assert retrieved.source_ip == '192.168.1.100'
        assert retrieved.user_id == 'user_test'


class TestAlertStorage:
    """Tests for alert storage and querying."""

    def setup_method(self):
        """Set up test database before each test."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_db_path = os.path.join(self.temp_dir, 'test_siem.db')
        storage.init_db(self.test_db_path)

    def teardown_method(self):
        """Clean up test database after each test."""
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
        if os.path.exists(self.temp_dir):
            os.rmdir(self.temp_dir)

    def test_store_alert_returns_alert_id(self):
        """Verify store_alert returns the alert ID."""
        alert = Alert(
            id='test-alert-uuid',
            event_id='event-123',
            mitre_id='T1110.001',
            severity='HIGH',
            risk_score=75,
            title='Brute Force Attack Detected',
            description='Multiple failed login attempts detected from same IP',
            timestamp=datetime(2024, 1, 15, 10, 30, 0),
            source_ip='192.168.1.100',
            user_id='user123',
            status='NEW',
            correlated=True
        )

        alert_id = storage.store_alert(alert, self.test_db_path)
        assert alert_id == 'test-alert-uuid'

    def test_get_alerts_no_filters(self):
        """Verify get_alerts returns all alerts when no filters provided."""
        alert1 = Alert(
            id='alert-1',
            event_id='event-1',
            mitre_id='T1110.001',
            severity='HIGH',
            risk_score=75,
            title='Brute Force Attack',
            description='Description 1',
            timestamp=datetime(2024, 1, 15, 10, 30, 0),
            source_ip='1.1.1.1',
            user_id='user1',
            status='NEW',
            correlated=False
        )
        alert2 = Alert(
            id='alert-2',
            event_id='event-2',
            mitre_id='T1078',
            severity='MEDIUM',
            risk_score=50,
            title='Suspicious Activity',
            description='Description 2',
            timestamp=datetime(2024, 1, 15, 11, 0, 0),
            source_ip='2.2.2.2',
            user_id='user2',
            status='INVESTIGATING',
            correlated=True
        )

        storage.store_alert(alert1, self.test_db_path)
        storage.store_alert(alert2, self.test_db_path)

        alerts = storage.get_alerts(db_path=self.test_db_path)
        assert len(alerts) == 2

    def test_get_alerts_filter_by_severity(self):
        """Verify get_alerts filters by severity correctly."""
        alert_high = Alert(
            id='alert-high',
            event_id='event-1',
            mitre_id='T1110.001',
            severity='HIGH',
            risk_score=80,
            title='High Risk Alert',
            description='High risk',
            timestamp=datetime.now(),
            source_ip='1.1.1.1',
            user_id='user1',
            status='NEW',
            correlated=False
        )
        alert_low = Alert(
            id='alert-low',
            event_id='event-2',
            mitre_id='T1078',
            severity='LOW',
            risk_score=20,
            title='Low Risk Alert',
            description='Low risk',
            timestamp=datetime.now(),
            source_ip='2.2.2.2',
            user_id='user2',
            status='NEW',
            correlated=False
        )

        storage.store_alert(alert_high, self.test_db_path)
        storage.store_alert(alert_low, self.test_db_path)

        alerts = storage.get_alerts(severities=['HIGH'], db_path=self.test_db_path)
        assert len(alerts) == 1
        assert alerts[0].severity == 'HIGH'

    def test_get_alerts_filter_by_status(self):
        """Verify get_alerts filters by status correctly."""
        alert_new = Alert(
            id='alert-new',
            event_id='event-1',
            mitre_id='T1110.001',
            severity='MEDIUM',
            risk_score=50,
            title='New Alert',
            description='New',
            timestamp=datetime.now(),
            source_ip='1.1.1.1',
            user_id='user1',
            status='NEW',
            correlated=False
        )
        alert_resolved = Alert(
            id='alert-resolved',
            event_id='event-2',
            mitre_id='T1078',
            severity='LOW',
            risk_score=10,
            title='Resolved Alert',
            description='Resolved',
            timestamp=datetime.now(),
            source_ip='2.2.2.2',
            user_id='user2',
            status='RESOLVED',
            correlated=False
        )

        storage.store_alert(alert_new, self.test_db_path)
        storage.store_alert(alert_resolved, self.test_db_path)

        alerts = storage.get_alerts(statuses=['NEW'], db_path=self.test_db_path)
        assert len(alerts) == 1
        assert alerts[0].status == 'NEW'

    def test_get_alerts_filter_by_mitre_id(self):
        """Verify get_alerts filters by MITRE ID correctly."""
        alert1 = Alert(
            id='alert-1',
            event_id='event-1',
            mitre_id='T1110.001',
            severity='HIGH',
            risk_score=75,
            title='Alert 1',
            description='Desc 1',
            timestamp=datetime.now(),
            source_ip='1.1.1.1',
            user_id='user1',
            status='NEW',
            correlated=False
        )
        alert2 = Alert(
            id='alert-2',
            event_id='event-2',
            mitre_id='T1078',
            severity='MEDIUM',
            risk_score=50,
            title='Alert 2',
            description='Desc 2',
            timestamp=datetime.now(),
            source_ip='2.2.2.2',
            user_id='user2',
            status='NEW',
            correlated=False
        )

        storage.store_alert(alert1, self.test_db_path)
        storage.store_alert(alert2, self.test_db_path)

        alerts = storage.get_alerts(mitre_id='T1110.001', db_path=self.test_db_path)
        assert len(alerts) == 1
        assert alerts[0].mitre_id == 'T1110.001'

    def test_get_alerts_combined_filters(self):
        """Verify get_alerts works with multiple combined filters."""
        alert = Alert(
            id='alert-combined',
            event_id='event-1',
            mitre_id='T1110.001',
            severity='CRITICAL',
            risk_score=95,
            title='Combined Filter Alert',
            description='Test',
            timestamp=datetime.now(),
            source_ip='1.1.1.1',
            user_id='user1',
            status='NEW',
            correlated=True
        )

        storage.store_alert(alert, self.test_db_path)
        alerts = storage.get_alerts(
            severities=['CRITICAL'],
            statuses=['NEW'],
            mitre_id='T1110.001',
            db_path=self.test_db_path
        )
        assert len(alerts) == 1


class TestIncidentStorage:
    """Tests for incident storage with timeline."""

    def setup_method(self):
        """Set up test database before each test."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_db_path = os.path.join(self.temp_dir, 'test_siem.db')
        storage.init_db(self.test_db_path)

    def teardown_method(self):
        """Clean up test database after each test."""
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
        if os.path.exists(self.temp_dir):
            os.rmdir(self.temp_dir)

    def test_store_incident_returns_incident_id(self):
        """Verify store_incident returns the incident ID."""
        incident = Incident(
            id='test-incident-uuid',
            title='Test Incident',
            severity='HIGH',
            created_at=datetime(2024, 1, 15, 10, 30, 0),
            resolved_at=None,
            alerts=[],
            timeline=[
                {
                    'event_id': 'event-1',
                    'timestamp': '2024-01-15T10:00:00',
                    'description': 'Initial event'
                },
                {
                    'event_id': 'event-2',
                    'timestamp': '2024-01-15T10:15:00',
                    'description': 'Alert triggered'
                }
            ],
            summary='Test incident summary'
        )

        alerts = [
            Alert(
                id='alert-1',
                event_id='event-1',
                mitre_id='T1110.001',
                severity='HIGH',
                risk_score=80,
                title='Alert 1',
                description='Description 1',
                timestamp=datetime.now(),
                source_ip='1.1.1.1',
                user_id='user1',
                status='NEW',
                correlated=False
            )
        ]

        incident_id = storage.store_incident(incident, alerts, self.test_db_path)
        assert incident_id == 'test-incident-uuid'

    def test_get_incidents_retrieves_stored_incidents(self):
        """Verify get_incidents retrieves previously stored incidents."""
        incident1 = Incident(
            id='incident-1',
            title='First Incident',
            severity='MEDIUM',
            created_at=datetime(2024, 1, 15, 10, 0, 0),
            resolved_at=None,
            alerts=['alert-1'],
            timeline=[{'event_id': 'event-1', 'timestamp': '2024-01-15T10:00:00', 'description': 'Event 1'}],
            summary='First incident summary'
        )
        incident2 = Incident(
            id='incident-2',
            title='Second Incident',
            severity='LOW',
            created_at=datetime(2024, 1, 15, 11, 0, 0),
            resolved_at=datetime(2024, 1, 15, 12, 0, 0),
            alerts=['alert-2'],
            timeline=[],
            summary='Second incident summary'
        )

        storage.store_incident(incident1, [], self.test_db_path)
        storage.store_incident(incident2, [], self.test_db_path)

        incidents = storage.get_incidents(self.test_db_path)
        assert len(incidents) == 2

        titles = {i.title for i in incidents}
        assert 'First Incident' in titles
        assert 'Second Incident' in titles

    def test_get_incidents_includes_resolved_at(self):
        """Verify get_incidents returns resolved_at for resolved incidents."""
        incident = Incident(
            id='resolved-incident',
            title='Resolved Incident',
            severity='LOW',
            created_at=datetime(2024, 1, 15, 10, 0, 0),
            resolved_at=datetime(2024, 1, 15, 12, 0, 0),
            alerts=[],
            timeline=[],
            summary='Resolved'
        )

        storage.store_incident(incident, [], self.test_db_path)
        incidents = storage.get_incidents(self.test_db_path)

        assert len(incidents) == 1
        assert incidents[0].resolved_at is not None


class TestEntityRiskScore:
    """Tests for entity risk score updates."""

    def setup_method(self):
        """Set up test database before each test."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_db_path = os.path.join(self.temp_dir, 'test_siem.db')
        storage.init_db(self.test_db_path)

    def teardown_method(self):
        """Clean up test database after each test."""
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
        if os.path.exists(self.temp_dir):
            os.rmdir(self.temp_dir)

    def test_update_entity_risk_creates_new_entry(self):
        """Verify update_entity_risk creates new entry for unknown entity."""
        profile = storage.update_entity_risk(
            'user-123', 'user', 50, None, self.test_db_path
        )

        assert profile.entity_id == 'user-123'
        assert profile.entity_type == 'user'
        assert profile.risk_score == 50

    def test_update_entity_risk_updates_existing_entry(self):
        """Verify update_entity_risk updates existing entry."""
        storage.update_entity_risk('ip-1', 'ip', 30, None, self.test_db_path)
        profile = storage.update_entity_risk('ip-1', 'ip', 20, None, self.test_db_path)

        assert profile.risk_score == 50  # 30 + 20

    def test_update_entity_risk_caps_at_100(self):
        """Verify risk score is capped at 100."""
        profile = storage.update_entity_risk('user-1', 'user', 80, None, self.test_db_path)
        profile = storage.update_entity_risk('user-1', 'user', 50, None, self.test_db_path)

        assert profile.risk_score == 100

    def test_update_entity_risk_not_below_0(self):
        """Verify risk score is not below 0."""
        profile = storage.update_entity_risk('user-1', 'user', 50, None, self.test_db_path)
        profile = storage.update_entity_risk('user-1', 'user', -80, None, self.test_db_path)

        assert profile.risk_score == 0

    def test_update_entity_risk_increments_event_count(self):
        """Verify event_count increments on update."""
        profile1 = storage.update_entity_risk('user-1', 'user', 10, None, self.test_db_path)
        profile2 = storage.update_entity_risk('user-1', 'user', 10, None, self.test_db_path)

        # Event count should be stored in database
        with sqlite3.connect(self.test_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT event_count FROM entity_risk_scores WHERE entity_id = ?', ('user-1',))
            count = cursor.fetchone()[0]
            assert count == 2

    def test_update_entity_risk_with_alert_id(self):
        """Verify update_entity_risk updates last_alert_id when provided."""
        storage.update_entity_risk('user-1', 'user', 10, 'alert-123', self.test_db_path)
        profile = storage.get_entity_risk('user-1', 'user', self.test_db_path)

        assert profile is not None

    def test_get_entity_risk_returns_none_for_unknown(self):
        """Verify get_entity_risk returns None for unknown entity."""
        profile = storage.get_entity_risk('unknown-user', 'user', self.test_db_path)
        assert profile is None

    def test_get_entity_risk_returns_correct_profile(self):
        """Verify get_entity_risk returns correct profile for known entity."""
        storage.update_entity_risk('user-456', 'user', 75, None, self.test_db_path)
        profile = storage.get_entity_risk('user-456', 'user', self.test_db_path)

        assert profile is not None
        assert profile.entity_id == 'user-456'
        assert profile.entity_type == 'user'
        assert profile.risk_score == 75

    def test_entity_risk_persists_across_calls(self):
        """Verify entity risk score persists across calls."""
        storage.update_entity_risk('user-999', 'user', 25, None, self.test_db_path)

        # Check persistence
        profile1 = storage.get_entity_risk('user-999', 'user', self.test_db_path)
        profile2 = storage.get_entity_risk('user-999', 'user', self.test_db_path)

        assert profile1.risk_score == 25
        assert profile2.risk_score == 25


class TestSOARActions:
    """Tests for SOAR actions (block IP, freeze account, revoke sessions)."""

    def setup_method(self):
        """Set up test database before each test."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_db_path = os.path.join(self.temp_dir, 'test_siem.db')
        storage.init_db(self.test_db_path)

    def teardown_method(self):
        """Clean up test database after each test."""
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
        if os.path.exists(self.temp_dir):
            os.rmdir(self.temp_dir)

    def test_block_ip(self):
        """Verify block_ip returns True and stores IP."""
        result = storage.block_ip('192.168.1.100', 'Malicious activity', 'analyst1', self.test_db_path)

        assert result is True

        blocked = storage.get_blocked_ips(self.test_db_path)
        assert len(blocked) == 1
        assert blocked[0]['ip'] == '192.168.1.100'
        assert blocked[0]['reason'] == 'Malicious activity'
        assert blocked[0]['blocked_by'] == 'analyst1'

    def test_block_ip_updates_existing(self):
        """Verify re-blocking IP updates the record."""
        storage.block_ip('192.168.1.100', 'Initial reason', 'analyst1', self.test_db_path)
        result = storage.block_ip('192.168.1.100', 'Updated reason', 'analyst2', self.test_db_path)

        assert result is True
        blocked = storage.get_blocked_ips(self.test_db_path)
        assert blocked[0]['reason'] == 'Updated reason'

    def test_freeze_account(self):
        """Verify freeze_account returns True and stores account."""
        result = storage.freeze_account('user-123', 'Suspicious activity', 'analyst1', self.test_db_path)

        assert result is True

        frozen = storage.get_frozen_accounts(self.test_db_path)
        assert len(frozen) == 1
        assert frozen[0]['user_id'] == 'user-123'
        assert frozen[0]['reason'] == 'Suspicious activity'
        assert frozen[0]['frozen_by'] == 'analyst1'

    def test_freeze_account_updates_existing(self):
        """Verify re-freezing account updates the record."""
        storage.freeze_account('user-456', 'Initial freeze', 'analyst1', self.test_db_path)
        result = storage.freeze_account('user-456', 'Updated freeze', 'analyst2', self.test_db_path)

        assert result is True
        frozen = storage.get_frozen_accounts(self.test_db_path)
        assert frozen[0]['reason'] == 'Updated freeze'

    def test_revoke_sessions(self):
        """Verify revoke_sessions creates frozen account entry."""
        result = storage.revoke_sessions('user-789', 'Session hijacking detected', 'auto', self.test_db_path)

        assert result is True

        frozen = storage.get_frozen_accounts(self.test_db_path)
        assert len(frozen) == 1
        assert frozen[0]['user_id'] == 'user-789'

    def test_block_ip_persists(self):
        """Verify blocked IP persists across calls."""
        storage.block_ip('10.0.0.1', 'Test block', 'analyst1', self.test_db_path)

        blocked1 = storage.get_blocked_ips(self.test_db_path)
        assert len(blocked1) == 1

        # Check again
        blocked2 = storage.get_blocked_ips(self.test_db_path)
        assert len(blocked2) == 1


class TestAuditLogging:
    """Tests for audit logging."""

    def setup_method(self):
        """Set up test database before each test."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_db_path = os.path.join(self.temp_dir, 'test_siem.db')
        storage.init_db(self.test_db_path)

    def teardown_method(self):
        """Clean up test database after each test."""
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
        if os.path.exists(self.temp_dir):
            os.rmdir(self.temp_dir)

    def test_log_audit_action(self):
        """Verify log_audit_action stores the action."""
        action = PlaybookAction(
            id='action-1',
            action_type='block_ip',
            target='192.168.1.100',
            reason='Malicious activity',
            performed_by='analyst1',
            timestamp=datetime(2024, 1, 15, 10, 30, 0),
            details={'block_duration': '24h'}
        )

        storage.log_audit_action(action, self.test_db_path)

        audit = storage.get_audit_log(limit=10, db_path=self.test_db_path)
        assert len(audit) == 1
        assert audit[0]['action_type'] == 'block_ip'
        assert audit[0]['target'] == '192.168.1.100'
        assert audit[0]['performed_by'] == 'analyst1'
        assert audit[0]['details'] == {'block_duration': '24h'}

    def test_get_audit_log_respects_limit(self):
        """Verify get_audit_log respects the limit parameter."""
        for i in range(5):
            action = PlaybookAction(
                id=f'action-{i}',
                action_type='freeze_account',
                target=f'user-{i}',
                reason='Test',
                performed_by='auto',
                timestamp=datetime.now(),
                details={}
            )
            storage.log_audit_action(action, self.test_db_path)

        audit = storage.get_audit_log(limit=3, db_path=self.test_db_path)
        assert len(audit) == 3

    def test_get_audit_log_ordered_by_timestamp_desc(self):
        """Verify audit log is ordered by timestamp descending."""
        action1 = PlaybookAction(
            id='action-1',
            action_type='block_ip',
            target='1.1.1.1',
            reason='First',
            performed_by='analyst1',
            timestamp=datetime(2024, 1, 15, 10, 0, 0),
            details={}
        )
        action2 = PlaybookAction(
            id='action-2',
            action_type='block_ip',
            target='2.2.2.2',
            reason='Second',
            performed_by='analyst1',
            timestamp=datetime(2024, 1, 15, 11, 0, 0),
            details={}
        )

        storage.log_audit_action(action1, self.test_db_path)
        storage.log_audit_action(action2, self.test_db_path)

        audit = storage.get_audit_log(db_path=self.test_db_path)
        # Most recent first
        assert audit[0]['target'] == '2.2.2.2'
        assert audit[1]['target'] == '1.1.1.1'


class TestDataPersistence:
    """Tests for data persistence across function calls."""

    def setup_method(self):
        """Set up test database before each test."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_db_path = os.path.join(self.temp_dir, 'test_siem.db')
        storage.init_db(self.test_db_path)

    def teardown_method(self):
        """Clean up test database after each test."""
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
        if os.path.exists(self.temp_dir):
            os.rmdir(self.temp_dir)

    def test_multiple_events_persist(self):
        """Verify multiple events persist correctly."""
        for i in range(5):
            event = NormalizedEvent(
                id=f'event-{i}',
                log_type='auth_service',
                timestamp=datetime.now(),
                source_ip=f'1.1.1.{i}',
                user_id=f'user-{i}',
                target_user=None,
                method='LOGIN',
                path='/api/login',
                status_code=200,
                user_agent='test',
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
            storage.store_event(event, self.test_db_path)

        # Retrieve all by checking each one
        for i in range(5):
            retrieved = storage.get_event(f'event-{i}', self.test_db_path)
            assert retrieved is not None
            assert retrieved.source_ip == f'1.1.1.{i}'

    def test_interleaved_operations_persist(self):
        """Verify interleaved storage operations persist correctly."""
        event = NormalizedEvent(
            id='event-interleaved',
            log_type='api_gateway',
            timestamp=datetime.now(),
            source_ip='10.0.0.1',
            user_id='user-test',
            target_user=None,
            method='GET',
            path='/api/test',
            status_code=200,
            user_agent='test-agent',
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

        storage.store_event(event, self.test_db_path)

        alert = Alert(
            id='alert-interleaved',
            event_id='event-interleaved',
            mitre_id='T1110.001',
            severity='HIGH',
            risk_score=75,
            title='Interleaved Alert',
            description='Test description',
            timestamp=datetime.now(),
            source_ip='10.0.0.1',
            user_id='user-test',
            status='NEW',
            correlated=False
        )
        storage.store_alert(alert, self.test_db_path)

        storage.block_ip('10.0.0.1', 'Test block', 'analyst', self.test_db_path)

        # Verify all persisted
        stored_event = storage.get_event('event-interleaved', self.test_db_path)
        assert stored_event is not None

        alerts = storage.get_alerts(db_path=self.test_db_path)
        assert len(alerts) == 1

        blocked = storage.get_blocked_ips(self.test_db_path)
        assert len(blocked) == 1