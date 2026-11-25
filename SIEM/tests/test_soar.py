"""Tests for the SOAR (Security Orchestration, Automation, Response) module."""
import os
import sqlite3
import tempfile
from datetime import datetime

import pytest

from src.models import Alert
from src import storage
from src.soar import (
    execute_playbook,
    block_ip,
    freeze_account,
    revoke_sessions,
    unblock_ip,
    unfreeze_account,
    get_blocked_ips,
    get_frozen_accounts,
    get_audit_log,
    run_auto_response,
    PLAYBOOKS
)


class TestPlaybookDefinitions:
    """Tests for playbook definitions."""

    def test_playbooks_contains_block_ip(self):
        """Verify block_ip playbook is defined."""
        assert 'block_ip' in PLAYBOOKS
        assert PLAYBOOKS['block_ip']['name'] == 'Block IP Address'

    def test_playbooks_contains_freeze_account(self):
        """Verify freeze_account playbook is defined."""
        assert 'freeze_account' in PLAYBOOKS
        assert PLAYBOOKS['freeze_account']['name'] == 'Freeze User Account'

    def test_playbooks_contains_revoke_sessions(self):
        """Verify revoke_sessions playbook is defined."""
        assert 'revoke_sessions' in PLAYBOOKS
        assert PLAYBOOKS['revoke_sessions']['name'] == 'Revoke User Sessions'


class TestBlockIp:
    """Tests for block_ip functionality."""

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

    def test_block_ip_returns_true(self):
        """Verify block_ip returns True on success."""
        result = block_ip('192.168.1.100', 'Malicious activity detected', 'analyst1',
                          self.test_db_path)
        assert result is True

    def test_block_ip_stores_in_blocked_ips_table(self):
        """Verify block_ip stores the IP in the database."""
        block_ip('10.0.0.50', 'Brute force attack', 'analyst2', self.test_db_path)

        blocked = get_blocked_ips(self.test_db_path)
        assert len(blocked) == 1
        assert blocked[0]['ip'] == '10.0.0.50'
        assert blocked[0]['reason'] == 'Brute force attack'
        assert blocked[0]['blocked_by'] == 'analyst2'

    def test_block_ip_logs_to_audit(self):
        """Verify block_ip creates an audit log entry."""
        block_ip('172.16.0.1', 'Test block', 'analyst1', self.test_db_path)

        audit = get_audit_log(limit=10, db_path=self.test_db_path)
        assert len(audit) == 1
        assert audit[0]['action_type'] == 'block_ip'
        assert audit[0]['target'] == '172.16.0.1'
        assert audit[0]['performed_by'] == 'analyst1'

    def test_block_ip_with_auto_performed_by(self):
        """Verify block_ip works with 'auto' as performed_by."""
        result = block_ip('192.168.1.200', 'Auto-blocked', 'auto', self.test_db_path)
        assert result is True

        audit = get_audit_log(db_path=self.test_db_path)
        assert audit[0]['performed_by'] == 'auto'

    def test_block_ip_updates_existing(self):
        """Verify re-blocking an IP updates the record."""
        block_ip('192.168.1.100', 'Initial reason', 'analyst1', self.test_db_path)
        block_ip('192.168.1.100', 'Updated reason', 'analyst2', self.test_db_path)

        blocked = get_blocked_ips(self.test_db_path)
        assert len(blocked) == 1
        assert blocked[0]['reason'] == 'Updated reason'

    def test_block_ip_requires_ip(self):
        """Verify block_ip raises error without IP."""
        with pytest.raises(ValueError):
            block_ip('', 'Test', 'analyst1', self.test_db_path)


class TestFreezeAccount:
    """Tests for freeze_account functionality."""

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

    def test_freeze_account_returns_true(self):
        """Verify freeze_account returns True on success."""
        result = freeze_account('user-123', 'Suspicious activity', 'analyst1',
                                self.test_db_path)
        assert result is True

    def test_freeze_account_stores_in_frozen_accounts_table(self):
        """Verify freeze_account stores the account in the database."""
        freeze_account('user-456', 'Password compromise suspected', 'analyst2',
                       self.test_db_path)

        frozen = get_frozen_accounts(self.test_db_path)
        assert len(frozen) == 1
        assert frozen[0]['user_id'] == 'user-456'
        assert frozen[0]['reason'] == 'Password compromise suspected'
        assert frozen[0]['frozen_by'] == 'analyst2'

    def test_freeze_account_logs_to_audit(self):
        """Verify freeze_account creates an audit log entry."""
        freeze_account('user-789', 'Account takeover attempt', 'analyst1',
                       self.test_db_path)

        audit = get_audit_log(limit=10, db_path=self.test_db_path)
        assert len(audit) == 1
        assert audit[0]['action_type'] == 'freeze_account'
        assert audit[0]['target'] == 'user-789'
        assert audit[0]['performed_by'] == 'analyst1'

    def test_freeze_account_with_auto_performed_by(self):
        """Verify freeze_account works with 'auto' as performed_by."""
        result = freeze_account('user-999', 'Auto-frozen', 'auto', self.test_db_path)
        assert result is True

        audit = get_audit_log(db_path=self.test_db_path)
        assert audit[0]['performed_by'] == 'auto'

    def test_freeze_account_updates_existing(self):
        """Verify re-freezing an account updates the record."""
        freeze_account('user-123', 'Initial freeze', 'analyst1', self.test_db_path)
        freeze_account('user-123', 'Updated freeze', 'analyst2', self.test_db_path)

        frozen = get_frozen_accounts(self.test_db_path)
        assert len(frozen) == 1
        assert frozen[0]['reason'] == 'Updated freeze'

    def test_freeze_account_requires_user_id(self):
        """Verify freeze_account raises error without user_id."""
        with pytest.raises(ValueError):
            freeze_account('', 'Test', 'analyst1', self.test_db_path)


class TestRevokeSessions:
    """Tests for revoke_sessions functionality."""

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

    def test_revoke_sessions_returns_true(self):
        """Verify revoke_sessions returns True on success."""
        result = revoke_sessions('user-123', 'Session hijacking detected', 'analyst1',
                                 self.test_db_path)
        assert result is True

    def test_revoke_sessions_creates_frozen_account_entry(self):
        """Verify revoke_sessions creates a frozen account entry."""
        revoke_sessions('user-456', 'Suspicious login pattern', 'analyst2',
                        self.test_db_path)

        frozen = get_frozen_accounts(self.test_db_path)
        assert len(frozen) == 1
        assert frozen[0]['user_id'] == 'user-456'

    def test_revoke_sessions_logs_to_audit(self):
        """Verify revoke_sessions creates an audit log entry."""
        revoke_sessions('user-789', 'Token theft suspected', 'analyst1',
                        self.test_db_path)

        audit = get_audit_log(limit=10, db_path=self.test_db_path)
        assert len(audit) == 1
        assert audit[0]['action_type'] == 'revoke_sessions'
        assert audit[0]['target'] == 'user-789'
        assert audit[0]['performed_by'] == 'analyst1'

    def test_revoke_sessions_with_auto_performed_by(self):
        """Verify revoke_sessions works with 'auto' as performed_by."""
        result = revoke_sessions('user-999', 'Auto-revoked sessions', 'auto',
                                 self.test_db_path)
        assert result is True

        audit = get_audit_log(db_path=self.test_db_path)
        assert audit[0]['performed_by'] == 'auto'

    def test_revoke_sessions_requires_user_id(self):
        """Verify revoke_sessions raises error without user_id."""
        with pytest.raises(ValueError):
            revoke_sessions('', 'Test', 'analyst1', self.test_db_path)


class TestUnblockIpAndUnfreezeAccount:
    """Tests for unblock_ip and unfreeze_account functions."""

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

    def test_unblock_ip_returns_true_when_ip_exists(self):
        """Verify unblock_ip returns True when IP was blocked."""
        # First block the IP
        storage.block_ip('192.168.1.100', 'Test block', 'analyst1', self.test_db_path)

        # Now unblock it
        result = unblock_ip('192.168.1.100', 'analyst2', self.test_db_path)
        assert result is True

    def test_unblock_ip_removes_from_blocked_ips(self):
        """Verify unblock_ip removes IP from blocked_ips table."""
        # First block the IP
        storage.block_ip('10.0.0.50', 'Test block', 'analyst1', self.test_db_path)
        assert len(get_blocked_ips(self.test_db_path)) == 1

        # Unblock and verify
        unblock_ip('10.0.0.50', 'analyst2', self.test_db_path)
        assert len(get_blocked_ips(self.test_db_path)) == 0

    def test_unblock_ip_logs_to_audit(self):
        """Verify unblock_ip creates an audit log entry."""
        storage.block_ip('172.16.0.1', 'Test block', 'analyst1', self.test_db_path)
        unblock_ip('172.16.0.1', 'analyst2', self.test_db_path)

        audit = get_audit_log(db_path=self.test_db_path)
        assert any(entry['action_type'] == 'unblock_ip' for entry in audit)

    def test_unblock_ip_returns_false_for_nonexistent_ip(self):
        """Verify unblock_ip returns False if IP was not blocked."""
        result = unblock_ip('192.168.1.200', 'analyst1', self.test_db_path)
        assert result is False

    def test_unblock_ip_requires_ip(self):
        """Verify unblock_ip raises error without IP."""
        with pytest.raises(ValueError):
            unblock_ip('', 'analyst1', self.test_db_path)

    def test_unfreeze_account_returns_true_when_frozen(self):
        """Verify unfreeze_account returns True when account was frozen."""
        # First freeze the account
        storage.freeze_account('user-123', 'Suspicious activity', 'analyst1',
                               self.test_db_path)

        # Now unfreeze it
        result = unfreeze_account('user-123', 'analyst2', self.test_db_path)
        assert result is True

    def test_unfreeze_account_clears_frozen_state(self):
        """Verify unfreeze_account clears the resolved_at timestamp to indicate unfrozen."""
        # First freeze the account
        storage.freeze_account('user-456', 'Suspicious activity', 'analyst1',
                               self.test_db_path)

        # Verify account is still in frozen list
        frozen = get_frozen_accounts(self.test_db_path)
        assert len(frozen) == 1
        assert frozen[0]['resolved_at'] is None

        # Unfreeze and verify resolved_at is set
        unfreeze_account('user-456', 'analyst2', self.test_db_path)

        frozen = get_frozen_accounts(self.test_db_path)
        # Account should still exist but with resolved_at set
        assert len(frozen) == 1
        assert frozen[0]['resolved_at'] is not None

    def test_unfreeze_account_logs_to_audit(self):
        """Verify unfreeze_account creates an audit log entry."""
        storage.freeze_account('user-789', 'Suspicious activity', 'analyst1',
                               self.test_db_path)
        unfreeze_account('user-789', 'analyst2', self.test_db_path)

        audit = get_audit_log(db_path=self.test_db_path)
        assert any(entry['action_type'] == 'unfreeze_account' for entry in audit)

    def test_unfreeze_account_returns_false_for_nonexistent_account(self):
        """Verify unfreeze_account returns False if account was not frozen."""
        result = unfreeze_account('user-999', 'analyst1', self.test_db_path)
        assert result is False

    def test_unfreeze_account_requires_user_id(self):
        """Verify unfreeze_account raises error without user_id."""
        with pytest.raises(ValueError):
            unfreeze_account('', 'analyst1', self.test_db_path)


class TestAuditLogging:
    """Tests for audit logging functionality."""

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

    def test_block_ip_creates_audit_entry(self):
        """Verify block_ip creates a proper audit log entry."""
        block_ip('192.168.1.100', 'Malicious IP', 'analyst1', self.test_db_path)

        audit = get_audit_log(db_path=self.test_db_path)
        assert len(audit) == 1
        assert audit[0]['action_type'] == 'block_ip'
        assert audit[0]['target'] == '192.168.1.100'
        assert audit[0]['reason'] == 'Malicious IP'
        assert audit[0]['performed_by'] == 'analyst1'
        assert 'timestamp' in audit[0]

    def test_freeze_account_creates_audit_entry(self):
        """Verify freeze_account creates a proper audit log entry."""
        freeze_account('user-123', 'Compromised account', 'analyst1', self.test_db_path)

        audit = get_audit_log(db_path=self.test_db_path)
        assert len(audit) == 1
        assert audit[0]['action_type'] == 'freeze_account'
        assert audit[0]['target'] == 'user-123'
        assert audit[0]['reason'] == 'Compromised account'
        assert audit[0]['performed_by'] == 'analyst1'

    def test_revoke_sessions_creates_audit_entry(self):
        """Verify revoke_sessions creates a proper audit log entry."""
        revoke_sessions('user-456', 'Session hijacking', 'analyst1', self.test_db_path)

        audit = get_audit_log(db_path=self.test_db_path)
        assert len(audit) == 1
        assert audit[0]['action_type'] == 'revoke_sessions'
        assert audit[0]['target'] == 'user-456'
        assert audit[0]['reason'] == 'Session hijacking'
        assert audit[0]['performed_by'] == 'analyst1'

    def test_audit_log_stores_details(self):
        """Verify audit log entries include details field."""
        block_ip('10.0.0.1', 'Test block', 'analyst1', self.test_db_path)

        audit = get_audit_log(db_path=self.test_db_path)
        assert 'details' in audit[0]
        assert isinstance(audit[0]['details'], dict)

    def test_audit_log_ordered_by_timestamp_desc(self):
        """Verify audit log returns entries ordered by timestamp descending."""
        block_ip('1.1.1.1', 'First block', 'analyst1', self.test_db_path)
        block_ip('2.2.2.2', 'Second block', 'analyst1', self.test_db_path)
        block_ip('3.3.3.3', 'Third block', 'analyst1', self.test_db_path)

        audit = get_audit_log(limit=10, db_path=self.test_db_path)
        assert len(audit) == 3
        # Most recent first
        assert audit[0]['target'] == '3.3.3.3'
        assert audit[1]['target'] == '2.2.2.2'
        assert audit[2]['target'] == '1.1.1.1'


class TestExecutePlaybook:
    """Tests for execute_playbook function."""

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

    def test_execute_playbook_block_ip(self):
        """Verify execute_playbook executes block_ip correctly."""
        result = execute_playbook('block_ip', '192.168.1.100', 'Test block',
                                  'analyst1', None, self.test_db_path)

        assert result['success'] is True
        assert result['action_type'] == 'block_ip'
        assert result['target'] == '192.168.1.100'

    def test_execute_playbook_freeze_account(self):
        """Verify execute_playbook executes freeze_account correctly."""
        result = execute_playbook('freeze_account', 'user-123', 'Test freeze',
                                  'analyst1', None, self.test_db_path)

        assert result['success'] is True
        assert result['action_type'] == 'freeze_account'
        assert result['target'] == 'user-123'

    def test_execute_playbook_revoke_sessions(self):
        """Verify execute_playbook executes revoke_sessions correctly."""
        result = execute_playbook('revoke_sessions', 'user-456', 'Test revoke',
                                  'analyst1', None, self.test_db_path)

        assert result['success'] is True
        assert result['action_type'] == 'revoke_sessions'
        assert result['target'] == 'user-456'

    def test_execute_playbook_invalid_action(self):
        """Verify execute_playbook raises error for invalid action type."""
        with pytest.raises(ValueError):
            execute_playbook('invalid_action', 'target', 'Test', 'analyst1',
                             None, self.test_db_path)

    def test_execute_playbook_empty_performed_by(self):
        """Verify execute_playbook raises error for empty performed_by."""
        with pytest.raises(ValueError):
            execute_playbook('block_ip', '192.168.1.100', 'Test', '',
                             None, self.test_db_path)

    def test_execute_playbook_logs_audit(self):
        """Verify execute_playbook logs to audit."""
        execute_playbook('block_ip', '10.0.0.1', 'Test block',
                         'analyst1', None, self.test_db_path)

        audit = get_audit_log(db_path=self.test_db_path)
        assert len(audit) == 1


class TestAutoResponse:
    """Tests for run_auto_response function."""

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

    def test_medium_alert_requires_manual_review(self):
        """Verify MEDIUM alerts do not auto-respond."""
        alert = Alert(
            id='alert-1',
            event_id='event-1',
            mitre_id='T1110.001',
            severity='MEDIUM',
            risk_score=50,
            title='Medium severity alert',
            description='Test description',
            timestamp=datetime.now(),
            source_ip='192.168.1.100',
            user_id='user-123',
            status='NEW',
            correlated=False
        )

        result = run_auto_response(alert, auto_respond=True)
        assert result is None

    def test_low_alert_requires_manual_review(self):
        """Verify LOW alerts do not auto-respond."""
        alert = Alert(
            id='alert-2',
            event_id='event-2',
            mitre_id='T1078',
            severity='LOW',
            risk_score=20,
            title='Low severity alert',
            description='Test description',
            timestamp=datetime.now(),
            source_ip='10.0.0.1',
            user_id='user-456',
            status='NEW',
            correlated=False
        )

        result = run_auto_response(alert, auto_respond=True)
        assert result is None

    def test_critical_alert_auto_blocks_malicious_ip(self):
        """Verify CRITICAL alerts auto-block malicious IPs."""
        alert = Alert(
            id='alert-3',
            event_id='event-3',
            mitre_id='T1110.001',
            severity='CRITICAL',
            risk_score=95,
            title='Critical: Brute force attack',
            description='Test description',
            timestamp=datetime.now(),
            source_ip='10.20.30.40',
            user_id='',
            status='NEW',
            correlated=False
        )

        result = run_auto_response(alert, auto_respond=True, db_path=self.test_db_path)
        assert result is not None
        assert result.action_type in ['block_ip', 'freeze_account', 'revoke_sessions']

        # Verify IP was blocked
        blocked = get_blocked_ips(self.test_db_path)
        assert any(b['ip'] == '10.20.30.40' for b in blocked)

    def test_critical_alert_auto_freezes_user(self):
        """Verify CRITICAL alerts auto-freeze compromised users."""
        alert = Alert(
            id='alert-4',
            event_id='event-4',
            mitre_id='T1078',
            severity='CRITICAL',
            risk_score=90,
            title='Critical: Impossible travel detected',
            description='Test description',
            timestamp=datetime.now(),
            source_ip='50.60.70.80',
            user_id='compromised-user',
            status='NEW',
            correlated=False
        )

        result = run_auto_response(alert, auto_respond=True, db_path=self.test_db_path)
        assert result is not None

        # Verify user was frozen
        frozen = get_frozen_accounts(self.test_db_path)
        assert any(f['user_id'] == 'compromised-user' for f in frozen)

    def test_auto_response_respects_auto_respond_false(self):
        """Verify auto-response does not execute when auto_respond=False."""
        alert = Alert(
            id='alert-5',
            event_id='event-5',
            mitre_id='T1110.001',
            severity='CRITICAL',
            risk_score=95,
            title='Critical alert',
            description='Test description',
            timestamp=datetime.now(),
            source_ip='1.2.3.4',
            user_id='user-xyz',
            status='NEW',
            correlated=False
        )

        result = run_auto_response(alert, auto_respond=False, db_path=self.test_db_path)
        assert result is None

        # Verify no actions were taken
        assert len(get_blocked_ips(self.test_db_path)) == 0
        assert len(get_frozen_accounts(self.test_db_path)) == 0

    def test_auto_response_uses_auto_performed_by(self):
        """Verify auto-response uses 'auto' as performed_by."""
        alert = Alert(
            id='alert-6',
            event_id='event-6',
            mitre_id='T1110.001',
            severity='CRITICAL',
            risk_score=95,
            title='Critical alert',
            description='Test description',
            timestamp=datetime.now(),
            source_ip='1.2.3.5',
            user_id='',
            status='NEW',
            correlated=False
        )

        run_auto_response(alert, auto_respond=True, db_path=self.test_db_path)

        audit = get_audit_log(db_path=self.test_db_path)
        auto_actions = [a for a in audit if a['performed_by'] == 'auto']
        assert len(auto_actions) > 0

    def test_auto_response_includes_alert_details(self):
        """Verify auto-response result includes alert details."""
        alert = Alert(
            id='alert-7',
            event_id='event-7',
            mitre_id='T1110.001',
            severity='CRITICAL',
            risk_score=95,
            title='Critical alert with suspicious IP',
            description='Test description',
            timestamp=datetime.now(),
            source_ip='2.3.4.5',
            user_id='user-abc',
            status='NEW',
            correlated=False
        )

        result = run_auto_response(alert, auto_respond=True, db_path=self.test_db_path)
        assert result is not None
        assert result.details['alert_id'] == alert.id
        assert result.details['alert_severity'] == 'CRITICAL'


class TestReversibleActions:
    """Tests for reversible SOAR actions."""

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

    def test_block_unblock_cycle(self):
        """Verify block/unblock cycle works correctly."""
        # Block IP
        block_ip('192.168.1.100', 'Initial block', 'analyst1', self.test_db_path)
        assert len(get_blocked_ips(self.test_db_path)) == 1

        # Unblock IP
        unblock_ip('192.168.1.100', 'analyst2', self.test_db_path)
        assert len(get_blocked_ips(self.test_db_path)) == 0

    def test_freeze_unfreeze_cycle(self):
        """Verify freeze/unfreeze cycle works correctly."""
        # Freeze account
        freeze_account('user-123', 'Initial freeze', 'analyst1', self.test_db_path)

        # Unfreeze account
        unfreeze_account('user-123', 'analyst2', self.test_db_path)

        # Verify audit logs exist for both actions
        audit = get_audit_log(db_path=self.test_db_path)
        action_types = [a['action_type'] for a in audit]
        assert 'freeze_account' in action_types
        assert 'unfreeze_account' in action_types

    def test_multiple_reversible_operations(self):
        """Verify multiple reversible operations work correctly."""
        # Block multiple IPs
        block_ip('1.1.1.1', 'Block 1', 'analyst1', self.test_db_path)
        block_ip('2.2.2.2', 'Block 2', 'analyst1', self.test_db_path)
        assert len(get_blocked_ips(self.test_db_path)) == 2

        # Unblock one
        unblock_ip('1.1.1.1', 'analyst2', self.test_db_path)
        assert len(get_blocked_ips(self.test_db_path)) == 1

        # Block another
        block_ip('3.3.3.3', 'Block 3', 'analyst1', self.test_db_path)
        assert len(get_blocked_ips(self.test_db_path)) == 2