"""SOAR (Security Orchestration, Automation, Response) engine for automated playbooks."""

import sqlite3
import uuid
from datetime import datetime
from typing import Optional

from src.models import Alert, PlaybookAction
from src import storage


# Playbook definitions
PLAYBOOKS = {
    'block_ip': {
        'name': 'Block IP Address',
        'description': 'Add IP to blocked_ips table',
        'parameters': ['target', 'reason', 'performed_by']
    },
    'freeze_account': {
        'name': 'Freeze User Account',
        'description': 'Mark user account as FROZEN',
        'parameters': ['target', 'reason', 'performed_by']
    },
    'revoke_sessions': {
        'name': 'Revoke User Sessions',
        'description': 'Log session revocation',
        'parameters': ['target', 'reason', 'performed_by']
    }
}


def _generate_id() -> str:
    """Generate a unique identifier."""
    return str(uuid.uuid4())


def _log_audit_action(action_type: str, target: str, reason: str,
                      performed_by: str, details: dict = None,
                      db_path: str = None) -> None:
    """Log an action to the audit log table."""
    if db_path is None:
        db_path = storage.get_db_path()

    action = PlaybookAction(
        id=_generate_id(),
        action_type=action_type,
        target=target,
        reason=reason,
        performed_by=performed_by,
        timestamp=datetime.now(),
        details=details or {}
    )

    storage.log_audit_action(action, db_path)


def execute_playbook(action_type: str, target: str, reason: str,
                     performed_by: str, details: dict = None,
                     db_path: str = None) -> dict:
    """Execute a SOAR playbook action.

    Args:
        action_type: Type of action (block_ip, freeze_account, revoke_sessions)
        target: Target entity (IP address or user ID)
        reason: Reason for the action
        performed_by: Who performed the action ('auto' or analyst name)
        details: Optional additional details
        db_path: Path to SQLite database

    Returns:
        Dictionary with execution result containing:
            - id: Unique action ID
            - action_type: Type of action executed
            - target: Target entity
            - success: Whether action succeeded
            - timestamp: When action was executed
    """
    if db_path is None:
        db_path = storage.get_db_path()

    # Validate performed_by - support both 'auto' and 'analyst_name' formats
    if not performed_by:
        raise ValueError("performed_by is required")

    # Validate action_type first
    if action_type not in PLAYBOOKS:
        raise ValueError(f"Unknown action type: {action_type}")

    # Execute the appropriate action
    success = False
    if action_type == 'block_ip':
        success = storage.block_ip(target, reason, performed_by, db_path)
    elif action_type == 'freeze_account':
        success = storage.freeze_account(target, reason, performed_by, db_path)
    elif action_type == 'revoke_sessions':
        success = storage.revoke_sessions(target, reason, performed_by, db_path)

    # Log to audit
    _log_audit_action(action_type, target, reason, performed_by, details, db_path)

    return {
        'id': _generate_id(),
        'action_type': action_type,
        'target': target,
        'success': success,
        'timestamp': datetime.now().isoformat()
    }


def block_ip(ip: str, reason: str, performed_by: str,
             db_path: str = None) -> bool:
    """Block an IP address.

    Args:
        ip: IP address to block
        reason: Reason for blocking
        performed_by: Who performed the action ('auto' or analyst name)
        db_path: Path to SQLite database

    Returns:
        True if successful, False otherwise
    """
    if db_path is None:
        db_path = storage.get_db_path()

    if not ip:
        raise ValueError("IP address is required")

    result = storage.block_ip(ip, reason, performed_by, db_path)

    # Log the action
    _log_audit_action('block_ip', ip, reason, performed_by, {'reason': reason}, db_path)

    return result


def freeze_account(user_id: str, reason: str, performed_by: str,
                   db_path: str = None) -> bool:
    """Freeze a user account.

    Args:
        user_id: User ID to freeze
        reason: Reason for freezing
        performed_by: Who performed the action ('auto' or analyst name)
        db_path: Path to SQLite database

    Returns:
        True if successful, False otherwise
    """
    if db_path is None:
        db_path = storage.get_db_path()

    if not user_id:
        raise ValueError("User ID is required")

    result = storage.freeze_account(user_id, reason, performed_by, db_path)

    # Log the action
    _log_audit_action('freeze_account', user_id, reason, performed_by, {'reason': reason}, db_path)

    return result


def revoke_sessions(user_id: str, reason: str, performed_by: str,
                    db_path: str = None) -> bool:
    """Log session revocation for a user.

    Args:
        user_id: User ID whose sessions are being revoked
        reason: Reason for session revocation
        performed_by: Who performed the action ('auto' or analyst name)
        db_path: Path to SQLite database

    Returns:
        True if successful, False otherwise
    """
    if db_path is None:
        db_path = storage.get_db_path()

    if not user_id:
        raise ValueError("User ID is required")

    result = storage.revoke_sessions(user_id, reason, performed_by, db_path)

    # Log the action
    _log_audit_action('revoke_sessions', user_id, reason, performed_by, {'reason': reason}, db_path)

    return result


def unblock_ip(ip: str, performed_by: str, db_path: str = None) -> bool:
    """Unblock an IP address.

    Removes the IP from the blocked_ips table.

    Args:
        ip: IP address to unblock
        performed_by: Who performed the action
        db_path: Path to SQLite database

    Returns:
        True if successful, False otherwise
    """
    if db_path is None:
        db_path = storage.get_db_path()

    if not ip:
        raise ValueError("IP address is required")

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM blocked_ips WHERE ip = ?', (ip,))
        conn.commit()
        success = cursor.rowcount > 0

    # Log the action
    _log_audit_action('unblock_ip', ip, 'Unblocked via SOAR playbook', performed_by,
                      {'ip': ip}, db_path)

    return success


def unfreeze_account(user_id: str, performed_by: str, db_path: str = None) -> bool:
    """Unfreeze a user account.

    Clears the resolved_at timestamp to indicate the account is no longer frozen.

    Args:
        user_id: User ID to unfreeze
        performed_by: Who performed the action
        db_path: Path to SQLite database

    Returns:
        True if successful, False otherwise
    """
    if db_path is None:
        db_path = storage.get_db_path()

    if not user_id:
        raise ValueError("User ID is required")

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        # Clear the resolved_at timestamp to mark account as unfrozen
        cursor.execute('UPDATE frozen_accounts SET resolved_at = ? WHERE user_id = ?',
                      (datetime.now().isoformat(), user_id))
        conn.commit()
        success = cursor.rowcount > 0

    # Log the action
    _log_audit_action('unfreeze_account', user_id, 'Account unfrozen via SOAR playbook',
                      performed_by, {'user_id': user_id}, db_path)

    return success


def get_blocked_ips(db_path: str = None) -> list[dict]:
    """Get all blocked IPs.

    Args:
        db_path: Path to SQLite database

    Returns:
        List of dictionaries containing blocked IP information
    """
    return storage.get_blocked_ips(db_path)


def get_frozen_accounts(db_path: str = None) -> list[dict]:
    """Get all frozen accounts.

    Args:
        db_path: Path to SQLite database

    Returns:
        List of dictionaries containing frozen account information
    """
    return storage.get_frozen_accounts(db_path)


def get_audit_log(limit: int = 100, db_path: str = None) -> list[dict]:
    """Get audit log entries.

    Args:
        limit: Maximum number of entries to return
        db_path: Path to SQLite database

    Returns:
        List of dictionaries containing audit log entries
    """
    return storage.get_audit_log(limit=limit, db_path=db_path)


def run_auto_response(alert: Alert, auto_respond: bool = False,
                      db_path: str = None) -> Optional[PlaybookAction]:
    """Run auto-response based on alert severity and content.

    Auto-response policies:
    - CRITICAL alerts with malicious IPs: auto-block IP
    - CRITICAL alerts with compromised users: auto-freeze account
    - MEDIUM alerts: require manual review (no auto-response)

    Args:
        alert: The Alert object to respond to
        auto_respond: If True, execute auto-response; if False, just analyze
        db_path: Path to SQLite database

    Returns:
        PlaybookAction if auto-response was executed, None otherwise
    """
    if db_path is None:
        db_path = storage.get_db_path()

    if alert.severity != 'CRITICAL':
        # MEDIUM and LOW alerts require manual review
        return None

    if not auto_respond:
        return None

    action_taken = None
    performed_by = 'auto'

    # Check if there's a malicious IP in the alert
    if alert.source_ip:
        # Check if IP is already blocked
        blocked = get_blocked_ips(db_path)
        ip_already_blocked = any(b['ip'] == alert.source_ip for b in blocked)

        if not ip_already_blocked:
            block_ip(alert.source_ip, f"Auto-blocked due to critical alert: {alert.title}",
                     performed_by, db_path)
            action_taken = 'block_ip'

    # Check if there's a compromised user
    if alert.user_id:
        # Freeze the user account
        freeze_account(alert.user_id, f"Auto-frozen due to critical alert: {alert.title}",
                       performed_by, db_path)
        action_taken = 'freeze_account'

    if action_taken:
        action = PlaybookAction(
            id=_generate_id(),
            action_type=action_taken,
            target=alert.source_ip or alert.user_id or '',
            reason=f"Auto-response: {alert.title}",
            performed_by=performed_by,
            timestamp=datetime.now(),
            details={'alert_id': alert.id, 'alert_severity': alert.severity}
        )
        return action

    return None