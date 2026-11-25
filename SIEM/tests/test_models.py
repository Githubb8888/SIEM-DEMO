"""Tests for the SIEM models module."""
import pytest
from datetime import datetime
from dataclasses import fields, is_dataclass
import json

from src.models import NormalizedEvent, Alert, Incident, PlaybookAction, EntityProfile


class TestNormalizedEvent:
    """Tests for NormalizedEvent dataclass."""

    def test_is_dataclass(self):
        """Verify NormalizedEvent is a dataclass."""
        assert is_dataclass(NormalizedEvent)

    def test_has_all_required_fields(self):
        """Verify NormalizedEvent has all required fields."""
        field_names = {f.name for f in fields(NormalizedEvent)}
        expected_fields = {
            'id', 'log_type', 'timestamp', 'source_ip', 'user_id',
            'target_user', 'method', 'path', 'status_code', 'user_agent',
            'country', 'asn', 'is_tor', 'is_datacenter', 'is_malicious_ip',
            'user_agent_threat', 'amount', 'currency', 'recipient', 'risk_factors'
        }
        assert field_names == expected_fields

    def test_can_instantiate_with_required_fields(self):
        """Test instantiation with required fields."""
        event = NormalizedEvent(
            id='test-uuid-123',
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
            risk_factors=[]
        )
        assert event.id == 'test-uuid-123'
        assert event.log_type == 'auth_service'
        assert event.source_ip == '192.168.1.1'
        assert event.status_code == 200
        assert event.risk_factors == []

    def test_field_types(self):
        """Verify field types are correct."""
        event = NormalizedEvent(
            id='test-uuid',
            log_type='api_gateway',
            timestamp=datetime.now(),
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
            risk_factors=['brute_force', 'tor_ip']
        )

        assert isinstance(event.id, str)
        assert isinstance(event.log_type, str)
        assert isinstance(event.timestamp, datetime)
        assert isinstance(event.source_ip, str)
        assert isinstance(event.user_id, (str, type(None)))
        assert isinstance(event.target_user, (str, type(None)))
        assert isinstance(event.method, str)
        assert isinstance(event.path, str)
        assert isinstance(event.status_code, int)
        assert isinstance(event.user_agent, str)
        assert isinstance(event.country, str)
        assert isinstance(event.asn, str)
        assert isinstance(event.is_tor, bool)
        assert isinstance(event.is_datacenter, bool)
        assert isinstance(event.is_malicious_ip, bool)
        assert isinstance(event.user_agent_threat, str)
        assert isinstance(event.amount, float)
        assert isinstance(event.currency, str)
        assert isinstance(event.recipient, str)
        assert isinstance(event.risk_factors, list)

    def test_log_type_values(self):
        """Test valid log_type values."""
        valid_types = ['auth_service', 'api_gateway', 'payment_engine']
        for log_type in valid_types:
            event = NormalizedEvent(
                id='test-uuid',
                log_type=log_type,
                timestamp=datetime.now(),
                source_ip='1.1.1.1',
                user_id=None,
                target_user=None,
                method='GET',
                path='/test',
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
            assert event.log_type == log_type

    def test_payment_fields_optional(self):
        """Test that payment-specific fields can be empty/default."""
        event = NormalizedEvent(
            id='test-uuid',
            log_type='api_gateway',
            timestamp=datetime.now(),
            source_ip='1.1.1.1',
            user_id='user1',
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
        assert event.amount == 0.0
        assert event.currency == ''
        assert event.recipient == ''


class TestAlert:
    """Tests for Alert dataclass."""

    def test_is_dataclass(self):
        """Verify Alert is a dataclass."""
        assert is_dataclass(Alert)

    def test_has_all_required_fields(self):
        """Verify Alert has all required fields."""
        field_names = {f.name for f in fields(Alert)}
        expected_fields = {
            'id', 'event_id', 'mitre_id', 'severity', 'risk_score',
            'title', 'description', 'timestamp', 'source_ip', 'user_id',
            'status', 'correlated'
        }
        assert field_names == expected_fields

    def test_can_instantiate(self):
        """Test Alert instantiation."""
        alert = Alert(
            id='alert-uuid-123',
            event_id='event-uuid-456',
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
        assert alert.id == 'alert-uuid-123'
        assert alert.event_id == 'event-uuid-456'
        assert alert.mitre_id == 'T1110.001'
        assert alert.severity == 'HIGH'
        assert alert.risk_score == 75
        assert alert.status == 'NEW'
        assert alert.correlated is True

    def test_severity_values(self):
        """Test valid severity values."""
        valid_severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        for severity in valid_severities:
            alert = Alert(
                id='alert-uuid',
                event_id='event-uuid',
                mitre_id='T1110.001',
                severity=severity,
                risk_score=50,
                title='Test Alert',
                description='Test Description',
                timestamp=datetime.now(),
                source_ip='1.1.1.1',
                user_id='user1',
                status='NEW',
                correlated=False
            )
            assert alert.severity == severity

    def test_status_values(self):
        """Test valid status values."""
        valid_statuses = ['NEW', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE']
        for status in valid_statuses:
            alert = Alert(
                id='alert-uuid',
                event_id='event-uuid',
                mitre_id='T1110.001',
                severity='MEDIUM',
                risk_score=50,
                title='Test Alert',
                description='Test',
                timestamp=datetime.now(),
                source_ip='1.1.1.1',
                user_id='user1',
                status=status,
                correlated=False
            )
            assert alert.status == status

    def test_risk_score_range(self):
        """Test risk_score is in valid range 0-100."""
        # Note: validation would be done at application level
        alert = Alert(
            id='alert-uuid',
            event_id='event-uuid',
            mitre_id='T1110.001',
            severity='MEDIUM',
            risk_score=0,
            title='Test',
            description='Test',
            timestamp=datetime.now(),
            source_ip='1.1.1.1',
            user_id='user1',
            status='NEW',
            correlated=False
        )
        assert alert.risk_score == 0

        alert2 = Alert(
            id='alert-uuid',
            event_id='event-uuid',
            mitre_id='T1110.001',
            severity='CRITICAL',
            risk_score=100,
            title='Test',
            description='Test',
            timestamp=datetime.now(),
            source_ip='1.1.1.1',
            user_id='user1',
            status='NEW',
            correlated=False
        )
        assert alert2.risk_score == 100


class TestIncident:
    """Tests for Incident dataclass."""

    def test_is_dataclass(self):
        """Verify Incident is a dataclass."""
        assert is_dataclass(Incident)

    def test_has_all_required_fields(self):
        """Verify Incident has all required fields."""
        field_names = {f.name for f in fields(Incident)}
        expected_fields = {
            'id', 'title', 'severity', 'created_at', 'resolved_at',
            'alerts', 'timeline', 'summary'
        }
        assert field_names == expected_fields

    def test_can_instantiate(self):
        """Test Incident instantiation."""
        incident = Incident(
            id='incident-uuid-123',
            title='Credential Compromise Incident',
            severity='HIGH',
            created_at=datetime(2024, 1, 15, 10, 30, 0),
            resolved_at=None,
            alerts=['alert-1', 'alert-2'],
            timeline=[
                {'event': 'login_attempt', 'time': '2024-01-15T10:00:00Z'},
                {'event': 'alert_triggered', 'time': '2024-01-15T10:30:00Z'}
            ],
            summary='User account was compromised through credential stuffing attack'
        )
        assert incident.id == 'incident-uuid-123'
        assert incident.title == 'Credential Compromise Incident'
        assert incident.severity == 'HIGH'
        assert incident.resolved_at is None
        assert len(incident.alerts) == 2
        assert len(incident.timeline) == 2

    def test_resolved_at_optional(self):
        """Test that resolved_at can be None or set."""
        incident1 = Incident(
            id='incident-uuid-1',
            title='Open Incident',
            severity='MEDIUM',
            created_at=datetime.now(),
            resolved_at=None,
            alerts=[],
            timeline=[],
            summary='Not resolved yet'
        )
        assert incident1.resolved_at is None

        incident2 = Incident(
            id='incident-uuid-2',
            title='Resolved Incident',
            severity='LOW',
            created_at=datetime(2024, 1, 15),
            resolved_at=datetime(2024, 1, 16),
            alerts=[],
            timeline=[],
            summary='Resolved'
        )
        assert incident2.resolved_at is not None


class TestPlaybookAction:
    """Tests for PlaybookAction dataclass."""

    def test_is_dataclass(self):
        """Verify PlaybookAction is a dataclass."""
        assert is_dataclass(PlaybookAction)

    def test_has_all_required_fields(self):
        """Verify PlaybookAction has all required fields."""
        field_names = {f.name for f in fields(PlaybookAction)}
        expected_fields = {
            'id', 'action_type', 'target', 'reason', 'performed_by',
            'timestamp', 'details'
        }
        assert field_names == expected_fields

    def test_can_instantiate(self):
        """Test PlaybookAction instantiation."""
        action = PlaybookAction(
            id='action-uuid-123',
            action_type='block_ip',
            target='192.168.1.100',
            reason='Malicious activity detected',
            performed_by='auto',
            timestamp=datetime(2024, 1, 15, 10, 30, 0),
            details={'block_duration': '24h', 'rule_id': 'rule-1'}
        )
        assert action.id == 'action-uuid-123'
        assert action.action_type == 'block_ip'
        assert action.target == '192.168.1.100'
        assert action.performed_by == 'auto'
        assert isinstance(action.details, dict)

    def test_action_type_values(self):
        """Test valid action_type values."""
        valid_types = ['block_ip', 'freeze_account', 'revoke_sessions']
        for action_type in valid_types:
            action = PlaybookAction(
                id='action-uuid',
                action_type=action_type,
                target='target-1',
                reason='Test reason',
                performed_by='analyst1',
                timestamp=datetime.now(),
                details={}
            )
            assert action.action_type == action_type


class TestEntityProfile:
    """Tests for EntityProfile dataclass."""

    def test_is_dataclass(self):
        """Verify EntityProfile is a dataclass."""
        assert is_dataclass(EntityProfile)

    def test_has_all_required_fields(self):
        """Verify EntityProfile has all required fields."""
        field_names = {f.name for f in fields(EntityProfile)}
        expected_fields = {
            'entity_id', 'entity_type', 'risk_score', 'last_updated',
            'risk_factors', 'associated_events'
        }
        assert field_names == expected_fields

    def test_can_instantiate_user_entity(self):
        """Test EntityProfile instantiation for user."""
        profile = EntityProfile(
            entity_id='user-123',
            entity_type='user',
            risk_score=45,
            last_updated=datetime(2024, 1, 15, 10, 30, 0),
            risk_factors=['suspicious_login', 'unusual_location'],
            associated_events=15
        )
        assert profile.entity_id == 'user-123'
        assert profile.entity_type == 'user'
        assert profile.risk_score == 45
        assert len(profile.risk_factors) == 2
        assert profile.associated_events == 15

    def test_can_instantiate_ip_entity(self):
        """Test EntityProfile instantiation for IP."""
        profile = EntityProfile(
            entity_id='192.168.1.100',
            entity_type='ip',
            risk_score=85,
            last_updated=datetime.now(),
            risk_factors=['tor_exit', 'malicious_activity'],
            associated_events=100
        )
        assert profile.entity_id == '192.168.1.100'
        assert profile.entity_type == 'ip'
        assert profile.risk_score == 85

    def test_entity_type_values(self):
        """Test valid entity_type values."""
        valid_types = ['user', 'ip']
        for entity_type in valid_types:
            profile = EntityProfile(
                entity_id=f'{entity_type}-id',
                entity_type=entity_type,
                risk_score=50,
                last_updated=datetime.now(),
                risk_factors=[],
                associated_events=0
            )
            assert profile.entity_type == entity_type

    def test_risk_score_range(self):
        """Test risk_score is in valid range 0-100."""
        profile = EntityProfile(
            entity_id='user-1',
            entity_type='user',
            risk_score=0,
            last_updated=datetime.now(),
            risk_factors=[],
            associated_events=0
        )
        assert profile.risk_score == 0

        profile2 = EntityProfile(
            entity_id='user-2',
            entity_type='user',
            risk_score=100,
            last_updated=datetime.now(),
            risk_factors=[],
            associated_events=0
        )
        assert profile2.risk_score == 100


class TestSerialization:
    """Tests for serialization capabilities."""

    def test_normalized_event_to_dict(self):
        """Test NormalizedEvent can be converted to dict."""
        event = NormalizedEvent(
            id='test-uuid',
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
            risk_factors=[]
        )
        event_dict = {f.name: getattr(event, f.name) for f in fields(event)}
        assert event_dict['id'] == 'test-uuid'
        assert event_dict['log_type'] == 'auth_service'
        assert event_dict['source_ip'] == '192.168.1.1'

    def test_alert_to_dict(self):
        """Test Alert can be converted to dict."""
        alert = Alert(
            id='alert-uuid',
            event_id='event-uuid',
            mitre_id='T1110.001',
            severity='HIGH',
            risk_score=75,
            title='Test Alert',
            description='Test Description',
            timestamp=datetime(2024, 1, 15),
            source_ip='1.1.1.1',
            user_id='user1',
            status='NEW',
            correlated=True
        )
        alert_dict = {f.name: getattr(alert, f.name) for f in fields(alert)}
        assert alert_dict['id'] == 'alert-uuid'
        assert alert_dict['severity'] == 'HIGH'

    def test_incident_to_dict(self):
        """Test Incident can be converted to dict."""
        incident = Incident(
            id='incident-uuid',
            title='Test Incident',
            severity='MEDIUM',
            created_at=datetime(2024, 1, 15),
            resolved_at=datetime(2024, 1, 16),
            alerts=['alert-1'],
            timeline=[{'event': 'test'}],
            summary='Test summary'
        )
        incident_dict = {f.name: getattr(incident, f.name) for f in fields(incident)}
        assert incident_dict['id'] == 'incident-uuid'
        assert incident_dict['summary'] == 'Test summary'

    def test_playbook_action_to_dict(self):
        """Test PlaybookAction can be converted to dict."""
        action = PlaybookAction(
            id='action-uuid',
            action_type='block_ip',
            target='192.168.1.1',
            reason='Test reason',
            performed_by='auto',
            timestamp=datetime(2024, 1, 15),
            details={'key': 'value'}
        )
        action_dict = {f.name: getattr(action, f.name) for f in fields(action)}
        assert action_dict['id'] == 'action-uuid'
        assert action_dict['details'] == {'key': 'value'}

    def test_entity_profile_to_dict(self):
        """Test EntityProfile can be converted to dict."""
        profile = EntityProfile(
            entity_id='user-1',
            entity_type='user',
            risk_score=50,
            last_updated=datetime(2024, 1, 15),
            risk_factors=['factor1'],
            associated_events=5
        )
        profile_dict = {f.name: getattr(profile, f.name) for f in fields(profile)}
        assert profile_dict['entity_id'] == 'user-1'
        assert profile_dict['risk_score'] == 50