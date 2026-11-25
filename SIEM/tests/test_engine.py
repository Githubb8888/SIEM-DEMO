"""Tests for the SIEM detection engine module."""

import json
import os
import shutil
import tempfile
from datetime import datetime, timedelta
import pytest

from src.models import Alert, Incident, NormalizedEvent
from src import storage
from src.engine import DetectionEngine


class TestDetectionEngineInitialization:
    """Tests for DetectionEngine initialization."""

    def setup_method(self):
        """Set up test environment before each test."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_db_path = os.path.join(self.temp_dir, 'test_siem.db')
        self.test_rules_path = os.path.join(self.temp_dir, 'detection_rules.json')

        # Copy rules to temp location
        with open(os.path.join(os.path.dirname(__file__), '..', 'rules', 'detection_rules.json'), 'r') as f:
            rules = f.read()
        with open(self.test_rules_path, 'w') as f:
            f.write(rules)

        storage.init_db(self.test_db_path)

    def teardown_method(self):
        """Clean up test environment after each test."""
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
        if os.path.exists(self.test_rules_path):
            os.remove(self.test_rules_path)
        if os.path.exists(self.temp_dir):
            os.rmdir(self.temp_dir)

    def test_engine_loads_rules(self):
        """Verify DetectionEngine loads rules from configuration file."""
        engine = DetectionEngine(rules_path=self.test_rules_path, db_path=self.test_db_path)

        assert len(engine.rules) == 6
        assert 'T1110.001' in engine.rules
        assert 'T1110.003' in engine.rules
        assert 'T1078' in engine.rules
        assert 'T1595.003' in engine.rules
        assert 'T1190' in engine.rules
        assert 'T1078-T1657' in engine.rules

    def test_engine_stores_config_values(self):
        """Verify DetectionEngine stores configuration values."""
        engine = DetectionEngine(rules_path=self.test_rules_path, db_path=self.test_db_path)

        assert engine.default_cooldown_seconds == 300
        assert engine.risk_score_cap == 100
        assert engine.risk_score_decay.get('enabled') is True


class TestBruteForceRule:
    """Tests for evaluate_brute_force_rule function."""

    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_db_path = os.path.join(self.temp_dir, 'test_siem.db')
        self.test_rules_path = os.path.join(self.temp_dir, 'detection_rules.json')

        with open(os.path.join(os.path.dirname(__file__), '..', 'rules', 'detection_rules.json'), 'r') as f:
            rules = f.read()
        with open(self.test_rules_path, 'w') as f:
            f.write(rules)

        storage.init_db(self.test_db_path)
        self.engine = DetectionEngine(rules_path=self.test_rules_path, db_path=self.test_db_path)

    def teardown_method(self):
        """Clean up test environment."""
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
        if os.path.exists(self.test_rules_path):
            os.remove(self.test_rules_path)
        if os.path.exists(self.temp_dir):
            os.rmdir(self.temp_dir)

    def test_no_alerts_with_empty_events(self):
        """Verify no alerts generated with empty event list."""
        rule = self.engine.rules['T1110.001']
        alerts = self.engine.evaluate_brute_force_rule([], rule)
        assert len(alerts) == 0

    def test_detects_brute_force_attack(self):
        """Verify brute-force attack is detected."""
        base_time = datetime(2024, 1, 15, 10, 0, 0)
        events = []

        # Create 6 failed login events from same IP for same user
        for i in range(6):
            event = NormalizedEvent(
                id=f'failed-login-{i}',
                log_type='auth_service',
                timestamp=base_time + timedelta(seconds=i * 5),
                source_ip='192.168.1.100',
                user_id='user123',
                target_user=None,
                method='LOGIN',
                path='/api/auth/login',
                status_code=401,
                user_agent='curl/7.68.0',
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

        rule = self.engine.rules['T1110.001']
        alerts = self.engine.evaluate_brute_force_rule(events, rule)

        assert len(alerts) == 1
        assert alerts[0].mitre_id == 'T1110.001'
        assert alerts[0].severity == 'HIGH'
        assert alerts[0].source_ip == '192.168.1.100'
        assert alerts[0].user_id == 'user123'

    def test_no_alert_with_insufficient_attempts(self):
        """Verify no alert with fewer than threshold attempts."""
        base_time = datetime(2024, 1, 15, 10, 0, 0)
        events = []

        # Create only 3 failed login events (threshold is 5)
        for i in range(3):
            event = NormalizedEvent(
                id=f'failed-login-{i}',
                log_type='auth_service',
                timestamp=base_time + timedelta(seconds=i * 10),
                source_ip='192.168.1.100',
                user_id='user123',
                target_user=None,
                method='LOGIN',
                path='/api/auth/login',
                status_code=401,
                user_agent='curl/7.68.0',
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

        rule = self.engine.rules['T1110.001']
        alerts = self.engine.evaluate_brute_force_rule(events, rule)

        assert len(alerts) == 0

    def test_no_alert_with_different_users(self):
        """Verify no alert when events are from different users."""
        base_time = datetime(2024, 1, 15, 10, 0, 0)
        events = []

        # Create 6 failed logins but from different users
        for i in range(6):
            event = NormalizedEvent(
                id=f'failed-login-{i}',
                log_type='auth_service',
                timestamp=base_time + timedelta(seconds=i * 5),
                source_ip='192.168.1.100',
                user_id=f'user{i}',  # Different user each time
                target_user=None,
                method='LOGIN',
                path='/api/auth/login',
                status_code=401,
                user_agent='curl/7.68.0',
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

        rule = self.engine.rules['T1110.001']
        alerts = self.engine.evaluate_brute_force_rule(events, rule)

        assert len(alerts) == 0


class TestPasswordSprayRule:
    """Tests for evaluate_password_spray_rule function."""

    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_db_path = os.path.join(self.temp_dir, 'test_siem.db')
        self.test_rules_path = os.path.join(self.temp_dir, 'detection_rules.json')

        with open(os.path.join(os.path.dirname(__file__), '..', 'rules', 'detection_rules.json'), 'r') as f:
            rules = f.read()
        with open(self.test_rules_path, 'w') as f:
            f.write(rules)

        storage.init_db(self.test_db_path)
        self.engine = DetectionEngine(rules_path=self.test_rules_path, db_path=self.test_db_path)

    def teardown_method(self):
        """Clean up test environment."""
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
        if os.path.exists(self.test_rules_path):
            os.remove(self.test_rules_path)
        if os.path.exists(self.temp_dir):
            os.rmdir(self.temp_dir)

    def test_detects_password_spraying(self):
        """Verify password spraying is detected."""
        base_time = datetime(2024, 1, 15, 10, 0, 0)
        events = []

        # Create 6 failed logins from same IP across 4+ users
        for i in range(6):
            event = NormalizedEvent(
                id=f'failed-spray-{i}',
                log_type='auth_service',
                timestamp=base_time + timedelta(seconds=i * 30),
                source_ip='10.0.0.50',
                user_id=f'user{i % 5}',  # Users: user0, user1, user2, user3, user4, user0
                target_user=None,
                method='LOGIN',
                path='/api/auth/login',
                status_code=401,
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

        rule = self.engine.rules['T1110.003']
        alerts = self.engine.evaluate_password_spray_rule(events, rule)

        assert len(alerts) == 1
        assert alerts[0].mitre_id == 'T1110.003'
        assert alerts[0].severity == 'HIGH'


class TestImpossibleTravelRule:
    """Tests for evaluate_impossible_travel_rule function."""

    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_db_path = os.path.join(self.temp_dir, 'test_siem.db')
        self.test_rules_path = os.path.join(self.temp_dir, 'detection_rules.json')

        with open(os.path.join(os.path.dirname(__file__), '..', 'rules', 'detection_rules.json'), 'r') as f:
            rules = f.read()
        with open(self.test_rules_path, 'w') as f:
            f.write(rules)

        storage.init_db(self.test_db_path)
        self.engine = DetectionEngine(rules_path=self.test_rules_path, db_path=self.test_db_path)

    def teardown_method(self):
        """Clean up test environment."""
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
        if os.path.exists(self.test_rules_path):
            os.remove(self.test_rules_path)
        if os.path.exists(self.temp_dir):
            os.rmdir(self.temp_dir)

    def test_detects_impossible_travel(self):
        """Verify impossible travel is detected."""
        base_time = datetime(2024, 1, 15, 10, 0, 0)
        events = []

        # Create two successful logins from different countries for same user
        event1 = NormalizedEvent(
            id='login-us',
            log_type='auth_service',
            timestamp=base_time,
            source_ip='1.1.1.1',
            user_id='traveler123',
            target_user=None,
            method='LOGIN',
            path='/api/auth/login',
            status_code=200,
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

        event2 = NormalizedEvent(
            id='login-cn',
            log_type='auth_service',
            timestamp=base_time + timedelta(minutes=30),
            source_ip='2.2.2.2',
            user_id='traveler123',
            target_user=None,
            method='LOGIN',
            path='/api/auth/login',
            status_code=200,
            user_agent='Mozilla/5.0',
            country='CN',
            asn='AS2',
            is_tor=False,
            is_datacenter=False,
            is_malicious_ip=False,
            user_agent_threat='',
            amount=0.0,
            currency='',
            recipient='',
            risk_factors=[]
        )

        events = [event1, event2]

        rule = self.engine.rules['T1078']
        alerts = self.engine.evaluate_impossible_travel_rule(events, rule)

        assert len(alerts) == 1
        assert alerts[0].mitre_id == 'T1078'
        assert alerts[0].severity == 'CRITICAL'
        assert alerts[0].user_id == 'traveler123'


class TestEndpointEnumerationRule:
    """Tests for evaluate_endpoint_enumeration_rule function."""

    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_db_path = os.path.join(self.temp_dir, 'test_siem.db')
        self.test_rules_path = os.path.join(self.temp_dir, 'detection_rules.json')

        with open(os.path.join(os.path.dirname(__file__), '..', 'rules', 'detection_rules.json'), 'r') as f:
            rules = f.read()
        with open(self.test_rules_path, 'w') as f:
            f.write(rules)

        storage.init_db(self.test_db_path)
        self.engine = DetectionEngine(rules_path=self.test_rules_path, db_path=self.test_db_path)

    def teardown_method(self):
        """Clean up test environment."""
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
        if os.path.exists(self.test_rules_path):
            os.remove(self.test_rules_path)
        if os.path.exists(self.temp_dir):
            os.rmdir(self.temp_dir)

    def test_detects_endpoint_enumeration(self):
        """Verify endpoint enumeration is detected."""
        base_time = datetime(2024, 1, 15, 10, 0, 0)
        events = []

        # Create 15 HTTP 404 errors from same IP
        for i in range(15):
            event = NormalizedEvent(
                id=f'enum-{i}',
                log_type='api_gateway',
                timestamp=base_time + timedelta(seconds=i * 3),
                source_ip='172.16.0.100',
                user_id=None,
                target_user=None,
                method='GET',
                path=f'/api/admin/secret{i}',
                status_code=404,
                user_agent='python-requests/2.28.0',
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

        rule = self.engine.rules['T1595.003']
        alerts = self.engine.evaluate_endpoint_enumeration_rule(events, rule)

        assert len(alerts) == 1
        assert alerts[0].mitre_id == 'T1595.003'
        assert alerts[0].severity == 'MEDIUM'


class TestInjectionProbeRule:
    """Tests for evaluate_injection_probe_rule function."""

    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_db_path = os.path.join(self.temp_dir, 'test_siem.db')
        self.test_rules_path = os.path.join(self.temp_dir, 'detection_rules.json')

        with open(os.path.join(os.path.dirname(__file__), '..', 'rules', 'detection_rules.json'), 'r') as f:
            rules = f.read()
        with open(self.test_rules_path, 'w') as f:
            f.write(rules)

        storage.init_db(self.test_db_path)
        self.engine = DetectionEngine(rules_path=self.test_rules_path, db_path=self.test_db_path)

    def teardown_method(self):
        """Clean up test environment."""
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
        if os.path.exists(self.test_rules_path):
            os.remove(self.test_rules_path)
        if os.path.exists(self.temp_dir):
            os.rmdir(self.temp_dir)

    def test_detects_sqli_probe(self):
        """Verify SQL injection probe is detected."""
        base_time = datetime(2024, 1, 15, 10, 0, 0)
        events = []

        event = NormalizedEvent(
            id='sqli-attempt',
            log_type='api_gateway',
            timestamp=base_time,
            source_ip='203.0.113.50',
            user_id=None,
            target_user=None,
            method='GET',
            path='/api/users?filter=name=SELECT.*FROM users--',
            status_code=403,
            user_agent='sqlmap/1.5',
            country='US',
            asn='AS1',
            is_tor=False,
            is_datacenter=True,
            is_malicious_ip=True,
            user_agent_threat='sqlmap',
            amount=0.0,
            currency='',
            recipient='',
            risk_factors=['sqli_attempt']
        )
        events.append(event)

        rule = self.engine.rules['T1190']
        alerts = self.engine.evaluate_injection_probe_rule(events, rule)

        assert len(alerts) == 1
        assert alerts[0].mitre_id == 'T1190'
        assert alerts[0].severity == 'HIGH'

    def test_detects_path_traversal_probe(self):
        """Verify path traversal probe is detected."""
        base_time = datetime(2024, 1, 15, 10, 0, 0)
        events = []

        event = NormalizedEvent(
            id='traversal-attempt',
            log_type='api_gateway',
            timestamp=base_time,
            source_ip='198.51.100.25',
            user_id=None,
            target_user=None,
            method='GET',
            path='/api/files/../../../etc/passwd',
            status_code=403,
            user_agent='curl/7.68.0',
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

        rule = self.engine.rules['T1190']
        alerts = self.engine.evaluate_injection_probe_rule(events, rule)

        assert len(alerts) == 1
        assert alerts[0].mitre_id == 'T1190'


class TestAccountTakeoverRule:
    """Tests for evaluate_account_takeover_rule function."""

    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_db_path = os.path.join(self.temp_dir, 'test_siem.db')
        self.test_rules_path = os.path.join(self.temp_dir, 'detection_rules.json')

        with open(os.path.join(os.path.dirname(__file__), '..', 'rules', 'detection_rules.json'), 'r') as f:
            rules = f.read()
        with open(self.test_rules_path, 'w') as f:
            f.write(rules)

        storage.init_db(self.test_db_path)
        self.engine = DetectionEngine(rules_path=self.test_rules_path, db_path=self.test_db_path)

    def teardown_method(self):
        """Clean up test environment."""
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
        if os.path.exists(self.test_rules_path):
            os.remove(self.test_rules_path)
        if os.path.exists(self.temp_dir):
            os.rmdir(self.temp_dir)

    def test_detects_account_takeover(self):
        """Verify account takeover is detected when correlating events."""
        base_time = datetime(2024, 1, 15, 10, 0, 0)
        events = []

        # Brute force login attempt
        login = NormalizedEvent(
            id='login-attempt',
            log_type='auth_service',
            timestamp=base_time,
            source_ip='10.0.0.50',
            user_id='victim123',
            target_user=None,
            method='LOGIN',
            path='/api/auth/login',
            status_code=401,
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

        # High value transfer after apparent compromise
        transfer = NormalizedEvent(
            id='transfer-out',
            log_type='payment_engine',
            timestamp=base_time + timedelta(minutes=5),
            source_ip='10.0.0.50',
            user_id='victim123',
            target_user=None,
            method='POST',
            path='/api/payment/transfer',
            status_code=200,
            user_agent='curl/7.68.0',
            country='US',
            asn='AS1',
            is_tor=False,
            is_datacenter=False,
            is_malicious_ip=False,
            user_agent_threat='',
            amount=5000.00,  # High value
            currency='USD',
            recipient='attacker-acc',
            risk_factors=[]
        )

        events = [login, transfer]

        rule = self.engine.rules['T1078-T1657']
        alerts = self.engine.evaluate_account_takeover_rule(events, rule)

        assert len(alerts) == 1
        assert alerts[0].mitre_id == 'T1078-T1657'
        assert alerts[0].severity == 'CRITICAL'
        assert alerts[0].correlated is True


class TestCorrelationEngine:
    """Tests for correlate_incidents and build_attack_timeline functions."""

    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_db_path = os.path.join(self.temp_dir, 'test_siem.db')
        self.test_rules_path = os.path.join(self.temp_dir, 'detection_rules.json')

        with open(os.path.join(os.path.dirname(__file__), '..', 'rules', 'detection_rules.json'), 'r') as f:
            rules = f.read()
        with open(self.test_rules_path, 'w') as f:
            f.write(rules)

        storage.init_db(self.test_db_path)
        self.engine = DetectionEngine(rules_path=self.test_rules_path, db_path=self.test_db_path)

    def teardown_method(self):
        """Clean up test environment."""
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
        if os.path.exists(self.test_rules_path):
            os.remove(self.test_rules_path)
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_correlate_incidents_empty_alerts(self):
        """Verify no incidents with empty alerts."""
        incidents = self.engine.correlate_incidents([])
        assert len(incidents) == 0

    def test_build_attack_timeline_empty_alerts(self):
        """Verify empty timeline with no alerts."""
        timeline = self.engine.build_attack_timeline([])
        assert timeline == []

    def test_build_attack_timeline_returns_steps(self):
        """Verify timeline returns correct steps from alerts."""
        base_time = datetime(2024, 1, 15, 10, 0, 0)
        alerts = [
            Alert(
                id='alert-1',
                event_id='event-1',
                mitre_id='T1110.001',
                severity='HIGH',
                risk_score=75,
                title='Brute Force Detected',
                description='Test',
                timestamp=base_time,
                source_ip='1.1.1.1',
                user_id='user1',
                status='NEW',
                correlated=False
            ),
            Alert(
                id='alert-2',
                event_id='event-2',
                mitre_id='T1078',
                severity='CRITICAL',
                risk_score=95,
                title='Impossible Travel',
                description='Test',
                timestamp=base_time + timedelta(minutes=10),
                source_ip='1.1.1.1',
                user_id='user1',
                status='NEW',
                correlated=False
            )
        ]

        timeline = self.engine.build_attack_timeline(alerts)

        assert len(timeline) == 2
        assert timeline[0]['event_id'] == 'alert-1'
        assert timeline[1]['event_id'] == 'alert-2'


class TestRiskScoring:
    """Tests for risk scoring functions."""

    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_db_path = os.path.join(self.temp_dir, 'test_siem.db')
        self.test_rules_path = os.path.join(self.temp_dir, 'detection_rules.json')

        with open(os.path.join(os.path.dirname(__file__), '..', 'rules', 'detection_rules.json'), 'r') as f:
            rules = f.read()
        with open(self.test_rules_path, 'w') as f:
            f.write(rules)

        storage.init_db(self.test_db_path)
        self.engine = DetectionEngine(rules_path=self.test_rules_path, db_path=self.test_db_path)

    def teardown_method(self):
        """Clean up test environment."""
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
        if os.path.exists(self.test_rules_path):
            os.remove(self.test_rules_path)
        if os.path.exists(self.temp_dir):
            os.rmdir(self.temp_dir)

    def test_calculate_risk_score_caps_at_100(self):
        """Verify risk score is capped at 100."""
        event = NormalizedEvent(
            id='test-event',
            log_type='auth_service',
            timestamp=datetime.now(),
            source_ip='1.1.1.1',
            user_id='user1',
            target_user=None,
            method='LOGIN',
            path='/api/login',
            status_code=401,
            user_agent='malicious',
            country='US',
            asn='AS1',
            is_tor=True,
            is_datacenter=True,
            is_malicious_ip=True,
            user_agent_threat='tool',
            amount=0.0,
            currency='',
            recipient='',
            risk_factors=['attack']
        )

        alert = Alert(
            id='alert-1',
            event_id='event-1',
            mitre_id='T1110.001',
            severity='HIGH',
            risk_score=90,
            title='Test',
            description='Test',
            timestamp=datetime.now(),
            source_ip='1.1.1.1',
            user_id='user1',
            status='NEW',
            correlated=False
        )

        score = self.engine.calculate_risk_score(event, alert)
        assert score == 100  # Capped at 100

    def test_calculate_risk_score_not_below_0(self):
        """Verify risk score is not below 0."""
        event = NormalizedEvent(
            id='test-event',
            log_type='auth_service',
            timestamp=datetime.now(),
            source_ip='1.1.1.1',
            user_id='user1',
            target_user=None,
            method='LOGIN',
            path='/api/login',
            status_code=200,
            user_agent='normal',
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

        alert = Alert(
            id='alert-1',
            event_id='event-1',
            mitre_id='T1110.001',
            severity='LOW',
            risk_score=0,
            title='Test',
            description='Test',
            timestamp=datetime.now(),
            source_ip='1.1.1.1',
            user_id='user1',
            status='NEW',
            correlated=False
        )

        # Simulate negative delta somehow
        score = self.engine.calculate_risk_score(event, alert)
        assert score >= 0

    def test_update_entity_risk_limits_score(self):
        """Verify entity risk score is limited to 0-100 range."""
        # Test upper cap
        score = self.engine.update_entity_risk('test-user', 'user', 150)
        assert score == 100

        # Reset with new db
        temp_dir2 = tempfile.mkdtemp()
        test_db_path2 = os.path.join(temp_dir2, 'test.db')
        storage.init_db(test_db_path2)
        engine2 = DetectionEngine(db_path=test_db_path2)

        # Test lower bound
        score = engine2.update_entity_risk('test-user2', 'user', -100)
        assert score == 0

        os.remove(test_db_path2)
        os.rmdir(temp_dir2)


class TestAlertDeduplication:
    """Tests for is_duplicate_alert function."""

    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_db_path = os.path.join(self.temp_dir, 'test_siem.db')
        self.test_rules_path = os.path.join(self.temp_dir, 'detection_rules.json')

        with open(os.path.join(os.path.dirname(__file__), '..', 'rules', 'detection_rules.json'), 'r') as f:
            rules = f.read()
        with open(self.test_rules_path, 'w') as f:
            f.write(rules)

        storage.init_db(self.test_db_path)
        self.engine = DetectionEngine(rules_path=self.test_rules_path, db_path=self.test_db_path)

    def teardown_method(self):
        """Clean up test environment."""
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
        if os.path.exists(self.test_rules_path):
            os.remove(self.test_rules_path)
        if os.path.exists(self.temp_dir):
            os.rmdir(self.temp_dir)

    def test_first_alert_not_duplicate(self):
        """Verify first alert is not marked as duplicate."""
        alert = Alert(
            id='new-alert',
            event_id='event-1',
            mitre_id='T1110.001',
            severity='HIGH',
            risk_score=75,
            title='Test Alert',
            description='Test',
            timestamp=datetime.now(),
            source_ip='1.1.1.1',
            user_id='user1',
            status='NEW',
            correlated=False
        )

        is_dup = self.engine.is_duplicate_alert(alert)
        assert is_dup is False

    def test_duplicate_alert_after_cooldown(self):
        """Verify alert is marked as duplicate during cooldown."""
        alert = Alert(
            id='duplicate-alert',
            event_id='event-2',
            mitre_id='T1110.001',
            severity='HIGH',
            risk_score=75,
            title='Test Alert',
            description='Test',
            timestamp=datetime.now(),
            source_ip='1.1.1.1',
            user_id='user1',
            status='NEW',
            correlated=False
        )

        # Record the alert timestamp with a recent time (within cooldown window)
        # Use current time minus 1 second to ensure it's within 300 second cooldown
        recent_time = datetime.now() - timedelta(seconds=1)
        self.engine._alert_timestamps['T1110.001:1.1.1.1:user1'] = recent_time
        self.engine._processed_alerts.add('T1110.001:1.1.1.1:user1')

        # Now check if duplicate - should be in cooldown
        is_dup = self.engine.is_duplicate_alert(alert)
        assert is_dup is True


class TestProcessEvent:
    """Tests for process_event function."""

    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_db_path = os.path.join(self.temp_dir, 'test_siem.db')
        self.test_rules_path = os.path.join(self.temp_dir, 'detection_rules.json')

        with open(os.path.join(os.path.dirname(__file__), '..', 'rules', 'detection_rules.json'), 'r') as f:
            rules = f.read()
        with open(self.test_rules_path, 'w') as f:
            f.write(rules)

        storage.init_db(self.test_db_path)
        # Use direct DetectionEngine instance, not singleton
        self.engine = DetectionEngine(rules_path=self.test_rules_path, db_path=self.test_db_path)

    def teardown_method(self):
        """Clean up test environment."""
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
        if os.path.exists(self.test_rules_path):
            os.remove(self.test_rules_path)
        if os.path.exists(self.temp_dir):
            os.rmdir(self.temp_dir)

    def test_process_event_returns_alerts(self):
        """Verify process_event returns alerts when threshold met."""
        # Create a brute force scenario - 6 failed logins from same IP/user
        base_time = datetime.now()
        events = []

        for i in range(6):
            event = NormalizedEvent(
                id=f'brute-{i}',
                log_type='auth_service',
                timestamp=base_time + timedelta(seconds=i * 5),
                source_ip='192.168.1.100',
                user_id='attacker',
                target_user=None,
                method='LOGIN',
                path='/api/auth/login',
                status_code=401,
                user_agent='curl/7.68.0',
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

        # Process events one by one
        all_alerts = []
        for event in events:
            alerts = self.engine.process_event(event)
            all_alerts.extend(alerts)

        assert len(all_alerts) >= 1

    def test_get_alerts_filters_by_severity(self):
        """Verify get_alerts filters by severity correctly."""
        # Process events that generate brute force
        base_time = datetime.now()
        event = NormalizedEvent(
            id='filter-test',
            log_type='auth_service',
            timestamp=base_time,
            source_ip='1.1.1.1',
            user_id='user1',
            target_user=None,
            method='LOGIN',
            path='/api/auth/login',
            status_code=401,
            user_agent='curl/7.68.0',
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

        # Process multiple failed attempts to trigger brute force
        for i in range(6):
            event.timestamp = base_time + timedelta(seconds=i * 5)
            alerts = self.engine.process_event(event)

        high_alerts = self.engine.get_alerts(severities=['HIGH'])
        assert len(high_alerts) >= 1

    def test_get_incidents_returns_empty_when_none(self):
        """Verify get_incidents returns empty list when no incidents."""
        incidents = self.engine.get_incidents()
        assert incidents == []


class TestProcessEventsBatch:
    """Tests for process_events_batch function."""

    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_db_path = os.path.join(self.temp_dir, 'test_siem.db')
        self.test_rules_path = os.path.join(self.temp_dir, 'detection_rules.json')

        with open(os.path.join(os.path.dirname(__file__), '..', 'rules', 'detection_rules.json'), 'r') as f:
            rules = f.read()
        with open(self.test_rules_path, 'w') as f:
            f.write(rules)

        storage.init_db(self.test_db_path)
        self.engine = DetectionEngine(rules_path=self.test_rules_path, db_path=self.test_db_path)

    def teardown_method(self):
        """Clean up test environment."""
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
        if os.path.exists(self.test_rules_path):
            os.remove(self.test_rules_path)
        if os.path.exists(self.temp_dir):
            os.rmdir(self.temp_dir)

    def test_process_events_batch_empty_list(self):
        """Verify batch processing empty list returns empty alerts."""
        alerts = self.engine.process_events_batch([])
        assert alerts == []

    def test_process_events_batch_returns_all_alerts(self):
        """Verify batch processing returns all generated alerts."""
        base_time = datetime.now()
        events = []

        # Create events that trigger brute force
        for i in range(6):
            event = NormalizedEvent(
                id=f'batch-{i}',
                log_type='auth_service',
                timestamp=base_time + timedelta(seconds=i * 3),
                source_ip='10.0.0.1',
                user_id='user1',
                target_user=None,
                method='LOGIN',
                path='/api/auth/login',
                status_code=401,
                user_agent='curl/7.68.0',
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

        alerts = self.engine.process_events_batch(events)

        assert len(alerts) >= 1
        assert all(a.severity in ['HIGH', 'MEDIUM', 'CRITICAL'] for a in alerts)


class TestEngineEdgeCases:
    """Tests for edge cases in the detection engine."""

    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_db_path = os.path.join(self.temp_dir, 'test_siem.db')
        self.test_rules_path = os.path.join(self.temp_dir, 'detection_rules.json')

        with open(os.path.join(os.path.dirname(__file__), '..', 'rules', 'detection_rules.json'), 'r') as f:
            rules = f.read()
        with open(self.test_rules_path, 'w') as f:
            f.write(rules)

        storage.init_db(self.test_db_path)
        self.engine = DetectionEngine(rules_path=self.test_rules_path, db_path=self.test_db_path)

    def teardown_method(self):
        """Clean up test environment."""
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
        if os.path.exists(self.test_rules_path):
            os.remove(self.test_rules_path)
        if os.path.exists(self.temp_dir):
            os.rmdir(self.temp_dir)

    def test_rules_handles_none_user_id(self):
        """Verify rules handle None user_id gracefully."""
        events = [
            NormalizedEvent(
                id=f'test-{i}',
                log_type='auth_service',
                timestamp=datetime.now() + timedelta(seconds=i * 5),
                source_ip='1.1.1.1',
                user_id=None,  # None user_id
                target_user=None,
                method='LOGIN',
                path='/api/auth/login',
                status_code=401,
                user_agent='curl/7.68.0',
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
            for i in range(6)
        ]

        rule = self.engine.rules['T1110.001']
        alerts = self.engine.evaluate_brute_force_rule(events, rule)

        # Should not crash, may or may not generate alerts
        assert isinstance(alerts, list)

    def test_rules_handles_unknown_log_type(self):
        """Verify rules handle unknown log types gracefully."""
        event = NormalizedEvent(
            id='unknown-type',
            log_type='unknown_service',  # Unknown log type
            timestamp=datetime.now(),
            source_ip='1.1.1.1',
            user_id='user1',
            target_user=None,
            method='GET',
            path='/api/test',
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

        # Should not crash
        alerts = self.engine.process_event(event)
        assert isinstance(alerts, list)