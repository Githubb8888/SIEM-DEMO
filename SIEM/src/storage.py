"""SQLite persistence layer for the Fintech Mini-SIEM."""

import json
import os
import random
import re
import sqlite3
from datetime import datetime
from typing import Optional

from src.models import Alert, Device, Employee, EntityProfile, Incident, NormalizedEvent, PlaybookAction


def get_db_path() -> str:
    """Return path to SQLite database file."""
    return os.path.join(os.path.dirname(__file__), '..', 'data', 'siem.db')


def init_db(db_path: str = None) -> None:
    """Initialize database and create all tables."""
    if db_path is None:
        db_path = get_db_path()

    # Ensure directory exists
    os.makedirs(os.path.dirname(db_path), exist_ok=True)

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()

        # Create events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                log_type TEXT,
                timestamp TEXT,
                source_ip TEXT,
                user_id TEXT,
                target_user TEXT,
                method TEXT,
                path TEXT,
                status_code INTEGER,
                user_agent TEXT,
                country TEXT,
                asn TEXT,
                is_tor BOOLEAN,
                is_datacenter BOOLEAN,
                is_malicious_ip BOOLEAN,
                user_agent_threat TEXT,
                amount REAL,
                currency TEXT,
                recipient TEXT,
                risk_factors TEXT
            )
        ''')

        # Create alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                event_id TEXT,
                mitre_id TEXT,
                severity TEXT,
                risk_score INTEGER,
                title TEXT,
                description TEXT,
                timestamp TEXT,
                source_ip TEXT,
                user_id TEXT,
                status TEXT,
                correlated BOOLEAN,
                FOREIGN KEY (event_id) REFERENCES events(id)
            )
        ''')

        # Create incidents table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                title TEXT,
                severity TEXT,
                created_at TEXT,
                resolved_at TEXT,
                summary TEXT,
                alert_count INTEGER
            )
        ''')

        # Create incident_timeline table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS incident_timeline (
                incident_id TEXT,
                step_number INTEGER,
                event_id TEXT,
                timestamp TEXT,
                description TEXT,
                FOREIGN KEY (incident_id) REFERENCES incidents(id),
                FOREIGN KEY (event_id) REFERENCES events(id)
            )
        ''')

        # Create entity_risk_scores table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS entity_risk_scores (
                entity_id TEXT PRIMARY KEY,
                entity_type TEXT,
                risk_score INTEGER,
                last_updated TEXT,
                last_alert_id TEXT,
                event_count INTEGER
            )
        ''')

        # Create audit_log table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                action_type TEXT,
                target TEXT,
                reason TEXT,
                performed_by TEXT,
                timestamp TEXT,
                details TEXT
            )
        ''')

        # Create blocked_ips table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip TEXT PRIMARY KEY,
                reason TEXT,
                blocked_at TEXT,
                blocked_by TEXT,
                expires_at TEXT
            )
        ''')

        # Create frozen_accounts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS frozen_accounts (
                user_id TEXT PRIMARY KEY,
                reason TEXT,
                frozen_at TEXT,
                frozen_by TEXT,
                expires_at TEXT,
                resolved_at TEXT
            )
        ''')

        # Create employees table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS employees (
                employee_id TEXT PRIMARY KEY,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL,
                department TEXT NOT NULL,
                role TEXT NOT NULL,
                employment_type TEXT NOT NULL,
                work_mode TEXT NOT NULL,
                city TEXT NOT NULL,
                country TEXT NOT NULL,
                training_completed BOOLEAN NOT NULL,
                risk_score INTEGER NOT NULL,
                status TEXT NOT NULL
            )
        ''')

        # Create devices table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                device_id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                employee_id TEXT NOT NULL,
                employee_name TEXT NOT NULL,
                device_type TEXT NOT NULL,
                os_name TEXT NOT NULL,
                employment_type TEXT NOT NULL,
                work_mode TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                city TEXT NOT NULL,
                country TEXT NOT NULL,
                lat REAL NOT NULL,
                lon REAL NOT NULL,
                compliance_status TEXT NOT NULL,
                edr_status TEXT NOT NULL,
                isolated BOOLEAN NOT NULL DEFAULT 0,
                FOREIGN KEY (employee_id) REFERENCES employees(employee_id)
            )
        ''')

        conn.commit()


# =============================================================================
# Event Storage (existing)
# =============================================================================

def store_event(event: NormalizedEvent, db_path: str = None) -> str:
    """Store event, return event ID."""
    if db_path is None:
        db_path = get_db_path()

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO events (
                id, log_type, timestamp, source_ip, user_id, target_user,
                method, path, status_code, user_agent, country, asn,
                is_tor, is_datacenter, is_malicious_ip, user_agent_threat,
                amount, currency, recipient, risk_factors
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            event.id,
            event.log_type,
            event.timestamp.isoformat(),
            event.source_ip,
            event.user_id,
            event.target_user,
            event.method,
            event.path,
            event.status_code,
            event.user_agent,
            event.country,
            event.asn,
            event.is_tor,
            event.is_datacenter,
            event.is_malicious_ip,
            event.user_agent_threat,
            event.amount,
            event.currency,
            event.recipient,
            json.dumps(event.risk_factors) if event.risk_factors else None
        ))

        conn.commit()

    return event.id


def get_event(event_id: str, db_path: str = None) -> Optional[NormalizedEvent]:
    """Retrieve event by ID."""
    if db_path is None:
        db_path = get_db_path()

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM events WHERE id = ?', (event_id,))
        row = cursor.fetchone()

        if row is None:
            return None

        risk_factors = json.loads(row['risk_factors']) if row['risk_factors'] else []

        return NormalizedEvent(
            id=row['id'],
            log_type=row['log_type'],
            timestamp=datetime.fromisoformat(row['timestamp']),
            source_ip=row['source_ip'],
            user_id=row['user_id'],
            target_user=row['target_user'],
            method=row['method'],
            path=row['path'],
            status_code=row['status_code'],
            user_agent=row['user_agent'],
            country=row['country'],
            asn=row['asn'],
            is_tor=bool(row['is_tor']),
            is_datacenter=bool(row['is_datacenter']),
            is_malicious_ip=bool(row['is_malicious_ip']),
            user_agent_threat=row['user_agent_threat'],
            amount=row['amount'],
            currency=row['currency'],
            recipient=row['recipient'],
            risk_factors=risk_factors
        )


def get_event_count(db_path: str = None) -> int:
    """Return total count of stored events.

    Args:
        db_path: Path to SQLite database

    Returns:
        Total number of events in the database
    """
    if db_path is None:
        db_path = get_db_path()

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM events')
        return cursor.fetchone()[0]


# =============================================================================
# Alert Storage (existing)
# =============================================================================

def store_alert(alert: Alert, db_path: str = None) -> str:
    """Store alert, return alert ID."""
    if db_path is None:
        db_path = get_db_path()

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO alerts (
                id, event_id, mitre_id, severity, risk_score, title,
                description, timestamp, source_ip, user_id, status, correlated
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            alert.id,
            alert.event_id,
            alert.mitre_id,
            alert.severity,
            alert.risk_score,
            alert.title,
            alert.description,
            alert.timestamp.isoformat(),
            alert.source_ip,
            alert.user_id,
            alert.status,
            alert.correlated
        ))

        conn.commit()

    return alert.id


def get_alerts(severities: list[str] = None, statuses: list[str] = None,
               mitre_id: str = None, db_path: str = None) -> list[Alert]:
    """Query alerts with filters."""
    if db_path is None:
        db_path = get_db_path()

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = 'SELECT * FROM alerts WHERE 1=1'
        params = []

        if severities:
            placeholders = ','.join(['?' for _ in severities])
            query += f' AND severity IN ({placeholders})'
            params.extend(severities)

        if statuses:
            placeholders = ','.join(['?' for _ in statuses])
            query += f' AND status IN ({placeholders})'
            params.extend(statuses)

        if mitre_id:
            query += ' AND mitre_id = ?'
            params.append(mitre_id)

        cursor.execute(query, params)
        rows = cursor.fetchall()

        alerts = []
        for row in rows:
            alert = Alert(
                id=row['id'],
                event_id=row['event_id'],
                mitre_id=row['mitre_id'],
                severity=row['severity'],
                risk_score=row['risk_score'],
                title=row['title'],
                description=row['description'],
                timestamp=datetime.fromisoformat(row['timestamp']),
                source_ip=row['source_ip'],
                user_id=row['user_id'],
                status=row['status'],
                correlated=bool(row['correlated'])
            )
            alerts.append(alert)

    return alerts


def update_alert_status(alert_id: str, status: str, db_path: str = None) -> bool:
    """Update alert status."""
    if db_path is None:
        db_path = get_db_path()

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute('UPDATE alerts SET status = ? WHERE id = ?', (status, alert_id))
        conn.commit()
        return cursor.rowcount > 0


# =============================================================================
# Incident Storage (existing)
# =============================================================================

def store_incident(incident: Incident, alerts: list[Alert], db_path: str = None) -> str:
    """Store incident with timeline."""
    if db_path is None:
        db_path = get_db_path()

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()

        # Store the incident
        cursor.execute('''
            INSERT INTO incidents (
                id, title, severity, created_at, resolved_at, summary, alert_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            incident.id,
            incident.title,
            incident.severity,
            incident.created_at.isoformat(),
            incident.resolved_at.isoformat() if incident.resolved_at else None,
            incident.summary,
            len(incident.alerts)
        ))

        # Store timeline entries
        for i, step in enumerate(incident.timeline):
            cursor.execute('''
                INSERT INTO incident_timeline (
                    incident_id, step_number, event_id, timestamp, description
                ) VALUES (?, ?, ?, ?, ?)
            ''', (
                incident.id,
                i,
                step.get('event_id', ''),
                step.get('timestamp', ''),
                step.get('description', '')
            ))

        conn.commit()

    return incident.id


def get_incidents(db_path: str = None) -> list[Incident]:
    """Get all incidents."""
    if db_path is None:
        db_path = get_db_path()

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM incidents')
        rows = cursor.fetchall()

        incidents = []
        for row in rows:
            resolved_at = None
            if row['resolved_at']:
                resolved_at = datetime.fromisoformat(row['resolved_at'])

            incident = Incident(
                id=row['id'],
                title=row['title'],
                severity=row['severity'],
                created_at=datetime.fromisoformat(row['created_at']),
                resolved_at=resolved_at,
                alerts=[],
                timeline=[],
                summary=row['summary']
            )

            # Get timeline entries
            cursor.execute(
                'SELECT event_id, timestamp, description FROM incident_timeline WHERE incident_id = ?',
                (row['id'],)
            )
            timeline_rows = cursor.fetchall()
            incident.timeline = [
                {
                    'event_id': t_row['event_id'],
                    'timestamp': t_row['timestamp'],
                    'description': t_row['description']
                }
                for t_row in timeline_rows
            ]

            # Get alert IDs from alerts table
            cursor.execute(
                'SELECT id FROM alerts WHERE id IN (SELECT event_id FROM incident_timeline WHERE incident_id = ?)',
                (row['id'],)
            )
            alert_rows = cursor.fetchall()
            incident.alerts = [a_row['id'] for a_row in alert_rows]

            incidents.append(incident)

    return incidents


# =============================================================================
# Entity Risk Score (existing)
# =============================================================================

def update_entity_risk(entity_id: str, entity_type: str, delta: int,
                      alert_id: str = None, db_path: str = None) -> EntityProfile:
    """Update risk score."""
    if db_path is None:
        db_path = get_db_path()

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()

        # Check if entity exists
        cursor.execute('SELECT * FROM entity_risk_scores WHERE entity_id = ?', (entity_id,))
        row = cursor.fetchone()

        if row:
            new_score = min(100, max(0, row[2] + delta))
            cursor.execute('''
                UPDATE entity_risk_scores
                SET risk_score = ?, last_updated = ?, event_count = event_count + 1
                WHERE entity_id = ?
            ''', (new_score, datetime.now().isoformat(), entity_id))

            if alert_id:
                cursor.execute('''
                    UPDATE entity_risk_scores
                    SET last_alert_id = ?
                    WHERE entity_id = ?
                ''', (alert_id, entity_id))
        else:
            new_score = min(100, max(0, delta))
            cursor.execute('''
                INSERT INTO entity_risk_scores (
                    entity_id, entity_type, risk_score, last_updated, last_alert_id, event_count
                ) VALUES (?, ?, ?, ?, ?, 1)
            ''', (entity_id, entity_type, new_score, datetime.now().isoformat(), alert_id))

        conn.commit()

        # Return updated profile
        cursor.execute('SELECT * FROM entity_risk_scores WHERE entity_id = ?', (entity_id,))
        row = cursor.fetchone()

    return EntityProfile(
        entity_id=row[0],
        entity_type=row[1],
        risk_score=row[2],
        last_updated=datetime.fromisoformat(row[3])
    )


def get_entity_risk(entity_id: str, entity_type: str, db_path: str = None) -> Optional[EntityProfile]:
    """Get entity risk profile."""
    if db_path is None:
        db_path = get_db_path()

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM entity_risk_scores WHERE entity_id = ? AND entity_type = ?',
                      (entity_id, entity_type))
        row = cursor.fetchone()

        if row is None:
            return None

        return EntityProfile(
            entity_id=row['entity_id'],
            entity_type=row['entity_type'],
            risk_score=row['risk_score'],
            last_updated=datetime.fromisoformat(row['last_updated'])
        )


# =============================================================================
# SOAR Actions (existing)
# =============================================================================

def block_ip(ip: str, reason: str, performed_by: str, db_path: str = None) -> bool:
    """Block an IP."""
    if db_path is None:
        db_path = get_db_path()

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()

        try:
            cursor.execute('''
                INSERT INTO blocked_ips (ip, reason, blocked_at, blocked_by)
                VALUES (?, ?, ?, ?)
            ''', (ip, reason, datetime.now().isoformat(), performed_by))

            conn.commit()
            return True
        except sqlite3.IntegrityError:
            # IP already blocked, update instead
            cursor.execute('''
                UPDATE blocked_ips
                SET reason = ?, blocked_at = ?, blocked_by = ?
                WHERE ip = ?
            ''', (reason, datetime.now().isoformat(), performed_by, ip))
            conn.commit()
            return True


def freeze_account(user_id: str, reason: str, performed_by: str, db_path: str = None) -> bool:
    """Freeze a user account."""
    if db_path is None:
        db_path = get_db_path()

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()

        try:
            cursor.execute('''
                INSERT INTO frozen_accounts (user_id, reason, frozen_at, frozen_by)
                VALUES (?, ?, ?, ?)
            ''', (user_id, reason, datetime.now().isoformat(), performed_by))

            conn.commit()
            return True
        except sqlite3.IntegrityError:
            # Account already frozen, update instead
            cursor.execute('''
                UPDATE frozen_accounts
                SET reason = ?, frozen_at = ?, frozen_by = ?
                WHERE user_id = ?
            ''', (reason, datetime.now().isoformat(), performed_by, user_id))
            conn.commit()
            return True


def revoke_sessions(user_id: str, reason: str, performed_by: str, db_path: str = None) -> bool:
    """Log session revocation."""
    if db_path is None:
        db_path = get_db_path()

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()

        # Check if account is frozen, if not, freeze it
        cursor.execute('SELECT user_id FROM frozen_accounts WHERE user_id = ?', (user_id,))
        if cursor.fetchone() is None:
            cursor.execute('''
                INSERT INTO frozen_accounts (user_id, reason, frozen_at, frozen_by)
                VALUES (?, ?, ?, ?)
            ''', (user_id, reason, datetime.now().isoformat(), performed_by))

        conn.commit()
        return True


def log_audit_action(action: PlaybookAction, db_path: str = None) -> None:
    """Log SOAR action."""
    if db_path is None:
        db_path = get_db_path()

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO audit_log (
                id, action_type, target, reason, performed_by, timestamp, details
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            action.id,
            action.action_type,
            action.target,
            action.reason,
            action.performed_by,
            action.timestamp.isoformat(),
            json.dumps(action.details) if action.details else None
        ))

        conn.commit()


def get_blocked_ips(db_path: str = None) -> list[dict]:
    """Get all blocked IPs."""
    if db_path is None:
        db_path = get_db_path()

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM blocked_ips')
        rows = cursor.fetchall()

        blocked_ips = []
        for row in rows:
            blocked_ips.append({
                'ip': row['ip'],
                'reason': row['reason'],
                'blocked_at': row['blocked_at'],
                'blocked_by': row['blocked_by'],
                'expires_at': row['expires_at']
            })

    return blocked_ips


def get_frozen_accounts(db_path: str = None) -> list[dict]:
    """Get all frozen accounts."""
    if db_path is None:
        db_path = get_db_path()

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM frozen_accounts')
        rows = cursor.fetchall()

        frozen_accounts = []
        for row in rows:
            frozen_accounts.append({
                'user_id': row['user_id'],
                'reason': row['reason'],
                'frozen_at': row['frozen_at'],
                'frozen_by': row['frozen_by'],
                'expires_at': row['expires_at'],
                'resolved_at': row['resolved_at']
            })

    return frozen_accounts


def unblock_ip(ip: str, performed_by: str, db_path: str = None) -> bool:
    """Unblock an IP address."""
    if db_path is None:
        db_path = get_db_path()

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()

        cursor.execute('DELETE FROM blocked_ips WHERE ip = ?', (ip,))
        conn.commit()
        deleted = cursor.rowcount > 0

    if deleted:
        # Log the action
        action = PlaybookAction(
            id=str(uuid.uuid4()),
            action_type='unblock_ip',
            target=ip,
            reason='Unblocked via SOAR playbook',
            performed_by=performed_by,
            timestamp=datetime.now(),
            details={'ip': ip}
        )
        log_audit_action(action, db_path)

    return deleted


def unfreeze_account(user_id: str, performed_by: str, db_path: str = None) -> bool:
    """Unfreeze a user account."""
    if db_path is None:
        db_path = get_db_path()

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()

        # Update the resolved_at timestamp to mark account as unfrozen
        cursor.execute('''
            UPDATE frozen_accounts
            SET resolved_at = ?
            WHERE user_id = ?
        ''', (datetime.now().isoformat(), user_id))
        conn.commit()
        unfrozen = cursor.rowcount > 0

    if unfrozen:
        # Log the action
        action = PlaybookAction(
            id=str(uuid.uuid4()),
            action_type='unfreeze_account',
            target=user_id,
            reason='Account unfrozen via SOAR playbook',
            performed_by=performed_by,
            timestamp=datetime.now(),
            details={'user_id': user_id}
        )
        log_audit_action(action, db_path)

    return unfrozen


def get_audit_log(limit: int = 100, db_path: str = None) -> list[dict]:
    """Get audit log entries."""
    if db_path is None:
        db_path = get_db_path()

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('''
            SELECT * FROM audit_log
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (limit,))
        rows = cursor.fetchall()

        audit_entries = []
        for row in rows:
            details = json.loads(row['details']) if row['details'] else {}
            audit_entries.append({
                'id': row['id'],
                'action_type': row['action_type'],
                'target': row['target'],
                'reason': row['reason'],
                'performed_by': row['performed_by'],
                'timestamp': row['timestamp'],
                'details': details
            })

    return audit_entries


# =============================================================================
# Employee & Device CRUD Operations (NEW)
# =============================================================================

def store_employee(employee: Employee, db_path: str = None) -> str:
    """Store employee, return employee ID."""
    if db_path is None:
        db_path = get_db_path()

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO employees (
                employee_id, full_name, email, department, role,
                employment_type, work_mode, city, country,
                training_completed, risk_score, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            employee.employee_id,
            employee.full_name,
            employee.email,
            employee.department,
            employee.role,
            employee.employment_type,
            employee.work_mode,
            employee.city,
            employee.country,
            employee.training_completed,
            employee.risk_score,
            employee.status
        ))

        conn.commit()

    return employee.employee_id


def get_employees(db_path: str = None) -> list[Employee]:
    """Get all employees."""
    if db_path is None:
        db_path = get_db_path()

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM employees ORDER BY full_name')
        rows = cursor.fetchall()

        employees = []
        for row in rows:
            employees.append(Employee(
                employee_id=row['employee_id'],
                full_name=row['full_name'],
                email=row['email'],
                department=row['department'],
                role=row['role'],
                employment_type=row['employment_type'],
                work_mode=row['work_mode'],
                city=row['city'],
                country=row['country'],
                training_completed=bool(row['training_completed']),
                risk_score=row['risk_score'],
                status=row['status']
            ))

    return employees


def get_employee(employee_id: str, db_path: str = None) -> Optional[Employee]:
    """Get employee by ID."""
    if db_path is None:
        db_path = get_db_path()

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM employees WHERE employee_id = ?', (employee_id,))
        row = cursor.fetchone()

        if row is None:
            return None

        return Employee(
            employee_id=row['employee_id'],
            full_name=row['full_name'],
            email=row['email'],
            department=row['department'],
            role=row['role'],
            employment_type=row['employment_type'],
            work_mode=row['work_mode'],
            city=row['city'],
            country=row['country'],
            training_completed=bool(row['training_completed']),
            risk_score=row['risk_score'],
            status=row['status']
        )


def store_device(device: Device, db_path: str = None) -> str:
    """Store device, return device ID."""
    if db_path is None:
        db_path = get_db_path()

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO devices (
                device_id, hostname, employee_id, employee_name,
                device_type, os_name, employment_type, work_mode,
                ip_address, city, country, lat, lon,
                compliance_status, edr_status, isolated
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            device.device_id,
            device.hostname,
            device.employee_id,
            device.employee_name,
            device.device_type,
            device.os_name,
            device.employment_type,
            device.work_mode,
            device.ip_address,
            device.city,
            device.country,
            device.lat,
            device.lon,
            device.compliance_status,
            device.edr_status,
            device.isolated
        ))

        conn.commit()

    return device.device_id


def get_devices(db_path: str = None) -> list[Device]:
    """Get all devices with employee join."""
    if db_path is None:
        db_path = get_db_path()

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('''
            SELECT d.*, e.full_name as employee_full_name, e.email as employee_email,
                   e.department as employee_department, e.role as employee_role,
                   e.employment_type as employee_employment_type, e.work_mode as employee_work_mode,
                   e.city as employee_city, e.country as employee_country,
                   e.training_completed as employee_training_completed,
                   e.risk_score as employee_risk_score, e.status as employee_status
            FROM devices d
            LEFT JOIN employees e ON d.employee_id = e.employee_id
            ORDER BY d.hostname
        ''')
        rows = cursor.fetchall()

        devices = []
        for row in rows:
            devices.append(Device(
                device_id=row['device_id'],
                hostname=row['hostname'],
                employee_id=row['employee_id'],
                employee_name=row['employee_name'],
                device_type=row['device_type'],
                os_name=row['os_name'],
                employment_type=row['employment_type'],
                work_mode=row['work_mode'],
                ip_address=row['ip_address'],
                city=row['city'],
                country=row['country'],
                lat=row['lat'],
                lon=row['lon'],
                compliance_status=row['compliance_status'],
                edr_status=row['edr_status'],
                isolated=bool(row['isolated'])
            ))

    return devices


def get_device(device_id: str, db_path: str = None) -> Optional[Device]:
    """Get device by ID with employee join."""
    if db_path is None:
        db_path = get_db_path()

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('''
            SELECT d.*, e.full_name as employee_full_name
            FROM devices d
            LEFT JOIN employees e ON d.employee_id = e.employee_id
            WHERE d.device_id = ?
        ''', (device_id,))
        row = cursor.fetchone()

        if row is None:
            return None

        return Device(
            device_id=row['device_id'],
            hostname=row['hostname'],
            employee_id=row['employee_id'],
            employee_name=row['employee_name'],
            device_type=row['device_type'],
            os_name=row['os_name'],
            employment_type=row['employment_type'],
            work_mode=row['work_mode'],
            ip_address=row['ip_address'],
            city=row['city'],
            country=row['country'],
            lat=row['lat'],
            lon=row['lon'],
            compliance_status=row['compliance_status'],
            edr_status=row['edr_status'],
            isolated=bool(row['isolated'])
        )


def update_device_isolation(device_id: str, isolated: bool, performed_by: str, reason: str, db_path: str = None) -> bool:
    """Update device isolation status and log to audit."""
    if db_path is None:
        db_path = get_db_path()

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()

        # Update isolation status
        cursor.execute('''
            UPDATE devices
            SET isolated = ?
            WHERE device_id = ?
        ''', (1 if isolated else 0, device_id))

        if cursor.rowcount == 0:
            return False

        # Log to audit
        action_id = f"iso-{device_id}-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
        cursor.execute('''
            INSERT INTO audit_log (id, action_type, target, reason, performed_by, timestamp, details)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            action_id,
            'isolate_device' if isolated else 'unisolate_device',
            device_id,
            reason,
            performed_by,
            datetime.now().isoformat(),
            json.dumps({'isolated': isolated})
        ))

        conn.commit()

    return True


def isolate_device(device_id: str, reason: str, performed_by: str, db_path: str = None) -> bool:
    """Isolate a device."""
    return update_device_isolation(device_id, True, performed_by, reason, db_path)


def unisolate_device(device_id: str, performed_by: str, db_path: str = None) -> bool:
    """Unisolate a device."""
    return update_device_isolation(device_id, False, performed_by, 'Device unisolated by operator', db_path)


def get_fleet_posture(db_path: str = None) -> dict:
    """Get comprehensive fleet posture data."""
    if db_path is None:
        db_path = get_db_path()

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Compliance breakdown
        cursor.execute('''
            SELECT compliance_status, COUNT(*) as count
            FROM devices
            GROUP BY compliance_status
        ''')
        compliance_rows = cursor.fetchall()

        compliance_counts = {'Compliant': 0, 'Exceptions': 0, 'Non-Compliant': 0}
        for row in compliance_rows:
            if row['compliance_status'] in compliance_counts:
                compliance_counts[row['compliance_status']] = row['count']

        total_devices = sum(compliance_counts.values())
        compliance_percentages = {}
        if total_devices > 0:
            for status, count in compliance_counts.items():
                compliance_percentages[status] = round((count / total_devices) * 100, 1)

        compliance_breakdown = {
            'Compliant': compliance_counts['Compliant'],
            'Exceptions': compliance_counts['Exceptions'],
            'Non-Compliant': compliance_counts['Non-Compliant'],
            'percentages': compliance_percentages
        }

        # Fleet KPIs
        cursor.execute('''
            SELECT
                employment_type,
                work_mode,
                COUNT(*) as count
            FROM employees
            WHERE status = 'ACTIVE'
            GROUP BY employment_type, work_mode
        ''')
        kpi_rows = cursor.fetchall()

        fleet_kpis = {
            'employee_office': 0,
            'contingent_office': 0,
            'employee_remote': 0,
            'contingent_remote': 0,
            'total_devices': 0,
            'training_completion_pct': 0
        }

        for row in kpi_rows:
            emp_type = row['employment_type']
            work_mode = row['work_mode']
            count = row['count']

            if emp_type == 'Employee' and work_mode == 'Office':
                fleet_kpis['employee_office'] = count
            elif emp_type == 'Contingent' and work_mode == 'Office':
                fleet_kpis['contingent_office'] = count
            elif emp_type == 'Employee' and work_mode == 'Remote':
                fleet_kpis['employee_remote'] = count
            elif emp_type == 'Contingent' and work_mode == 'Remote':
                fleet_kpis['contingent_remote'] = count

        # Total devices
        cursor.execute('SELECT COUNT(*) FROM devices')
        fleet_kpis['total_devices'] = cursor.fetchone()[0]

        # Training completion percentage
        cursor.execute('''
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN training_completed = 1 THEN 1 ELSE 0 END) as completed
            FROM employees
            WHERE status = 'ACTIVE'
        ''')
        training_row = cursor.fetchone()
        if training_row['total'] > 0:
            fleet_kpis['training_completion_pct'] = round((training_row['completed'] / training_row['total']) * 100, 1)

        # Geo nodes - aggregate devices by city/country with coordinates
        cursor.execute('''
            SELECT
                city,
                country,
                lat,
                lon,
                COUNT(*) as device_count,
                SUM(CASE WHEN compliance_status = 'Non-Compliant' THEN 1 ELSE 0 END) as non_compliant_count
            FROM devices
            GROUP BY city, country, lat, lon
        ''')
        geo_rows = cursor.fetchall()

        geo_nodes = []
        for row in geo_rows:
            geo_nodes.append({
                'city': row['city'],
                'country': row['country'],
                'lat': row['lat'],
                'lon': row['lon'],
                'device_count': row['device_count'],
                'non_compliant_count': row['non_compliant_count'] or 0
            })

        # Devices with employee join
        devices = get_devices(db_path)
        device_list = []
        for d in devices:
            device_list.append({
                'device_id': d.device_id,
                'hostname': d.hostname,
                'employee_id': d.employee_id,
                'employee_name': d.employee_name,
                'device_type': d.device_type,
                'os_name': d.os_name,
                'employment_type': d.employment_type,
                'work_mode': d.work_mode,
                'ip_address': d.ip_address,
                'city': d.city,
                'country': d.country,
                'lat': d.lat,
                'lon': d.lon,
                'compliance_status': d.compliance_status,
                'edr_status': d.edr_status,
                'isolated': d.isolated
            })

    return {
        'compliance_breakdown': compliance_breakdown,
        'fleet_kpis': fleet_kpis,
        'geo_nodes': geo_nodes,
        'devices': device_list
    }


# =============================================================================
# SPL-Style Search Engine (NEW)
# =============================================================================

def search_events(
    q: str = None,
    source_type: str = None,
    status: str = None,
    user: str = None,
    src_ip: str = None,
    hostname: str = None,
    severity: str = None,
    mitre_id: str = None,
    time_range: str = None,
    limit: int = 200,
    db_path: str = None
) -> dict:
    """Execute SPL-style search across events, alerts, and incidents tables.

    Supports:
    - Field filters: source_type, status, user, src_ip, hostname, severity, mitre_id
    - SPL pipes: | stats count by <field1>,<field2> and | where count > <N>
    - Time range filtering

    Args:
        q: Free text query (searches across multiple fields)
        source_type: Filter by log_type (auth|api|payment)
        status: Filter by status (failed|success)
        user: Filter by user_id
        src_ip: Filter by source_ip
        hostname: Filter by device hostname
        severity: Filter by alert severity (HIGH|CRITICAL)
        mitre_id: Filter by MITRE ATT&CK ID (e.g., T1078)
        time_range: Time range (e.g., '1h', '24h', '7d')
        limit: Maximum results to return
        db_path: Path to SQLite database

    Returns:
        Dict with total_matched, events, statistics, stat_columns
    """
    if db_path is None:
        db_path = get_db_path()

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Parse SPL pipes from query
        stats_fields = None
        where_clause = None

        if q and '|' in q:
            parts = q.split('|')
            q = parts[0].strip()
            for part in parts[1:]:
                part = part.strip()
                if part.startswith('stats'):
                    # Parse: stats count by field1,field2
                    match = re.search(r'stats\s+count\s+by\s+(.+)', part, re.IGNORECASE)
                    if match:
                        stats_fields = [f.strip() for f in match.group(1).split(',')]
                elif part.startswith('where'):
                    # Parse: where count > N
                    where_clause = part[5:].strip()  # Remove 'where '

        # Build base query for events
        # We'll search across events, alerts, and incidents
        base_query = '''
            SELECT
                e.id as event_id,
                e.log_type as source_type,
                e.timestamp,
                e.source_ip as src_ip,
                e.user_id,
                e.method,
                e.path,
                e.status_code,
                e.user_agent,
                e.country,
                e.asn,
                e.is_tor,
                e.is_datacenter,
                e.is_malicious_ip,
                e.amount,
                e.currency,
                e.recipient,
                e.risk_factors,
                a.id as alert_id,
                a.mitre_id,
                a.severity,
                a.risk_score,
                a.title as alert_title,
                a.description as alert_description,
                a.status as alert_status,
                a.correlated,
                d.hostname,
                d.compliance_status,
                d.edr_status,
                d.isolated
            FROM events e
            LEFT JOIN alerts a ON e.id = a.event_id
            LEFT JOIN devices d ON e.user_id = d.employee_id
            WHERE 1=1
        '''

        params = []

        # Apply field filters
        if source_type:
            base_query += ' AND e.log_type = ?'
            params.append(source_type)

        if status:
            if status.lower() == 'failed':
                base_query += ' AND e.status_code >= 400'
            elif status.lower() == 'success':
                base_query += ' AND e.status_code < 400'

        if user:
            base_query += ' AND e.user_id = ?'
            params.append(user)

        if src_ip:
            base_query += ' AND e.source_ip = ?'
            params.append(src_ip)

        if hostname:
            base_query += ' AND d.hostname = ?'
            params.append(hostname)

        if severity:
            base_query += ' AND a.severity = ?'
            params.append(severity)

        if mitre_id:
            base_query += ' AND a.mitre_id = ?'
            params.append(mitre_id)

        # Time range filter
        if time_range:
            time_seconds = _parse_time_range(time_range)
            if time_seconds:
                base_query += " AND datetime(e.timestamp) >= datetime('now', ?)"
                params.append(f'-{time_seconds} seconds')

        # Free text search across multiple fields
        if q and q.strip():
            search_term = f'%{q.strip()}%'
            base_query += ''' AND (
                e.source_ip LIKE ? OR
                e.user_id LIKE ? OR
                e.method LIKE ? OR
                e.path LIKE ? OR
                e.user_agent LIKE ? OR
                e.country LIKE ? OR
                a.mitre_id LIKE ? OR
                a.title LIKE ? OR
                a.description LIKE ? OR
                d.hostname LIKE ?
            )'''
            params.extend([search_term] * 10)

        # Order by timestamp descending
        base_query += ' ORDER BY e.timestamp DESC'

        # Execute query to get total count
        count_query = f'SELECT COUNT(*) FROM ({base_query})'
        cursor.execute(count_query, params)
        total_matched = cursor.fetchone()[0]

        # Apply limit
        base_query += ' LIMIT ?'
        params.append(limit)

        # Execute main query
        cursor.execute(base_query, params)
        rows = cursor.fetchall()

        # Build events list
        events = []
        for row in rows:
            event = {
                'event_id': row['event_id'],
                'source_type': row['source_type'],
                'timestamp': row['timestamp'],
                'src_ip': row['src_ip'],
                'user_id': row['user_id'],
                'method': row['method'],
                'path': row['path'],
                'status_code': row['status_code'],
                'user_agent': row['user_agent'],
                'country': row['country'],
                'asn': row['asn'],
                'is_tor': bool(row['is_tor']),
                'is_datacenter': bool(row['is_datacenter']),
                'is_malicious_ip': bool(row['is_malicious_ip']),
                'amount': row['amount'],
                'currency': row['currency'],
                'recipient': row['recipient'],
                'risk_factors': json.loads(row['risk_factors']) if row['risk_factors'] else [],
                'alert_id': row['alert_id'],
                'mitre_id': row['mitre_id'],
                'severity': row['severity'],
                'risk_score': row['risk_score'],
                'alert_title': row['alert_title'],
                'alert_description': row['alert_description'],
                'alert_status': row['alert_status'],
                'correlated': bool(row['correlated']) if row['correlated'] is not None else False,
                'hostname': row['hostname'],
                'compliance_status': row['compliance_status'],
                'edr_status': row['edr_status'],
                'isolated': bool(row['isolated']) if row['isolated'] is not None else False,
            }
            events.append(event)

        # Compute statistics if stats pipe is used
        statistics = []
        stat_columns = []

        if stats_fields:
            # Build aggregation query
            stats_select = ', '.join(stats_fields)
            stats_query = f'''
                SELECT {stats_select}, COUNT(*) as count
                FROM (
                    SELECT
                        e.log_type as source_type,
                        e.source_ip as src_ip,
                        e.user_id,
                        e.method,
                        e.path,
                        e.status_code,
                        e.country,
                        a.mitre_id,
                        a.severity,
                        a.status as alert_status,
                        d.hostname,
                        d.compliance_status,
                        d.edr_status
                    FROM events e
                    LEFT JOIN alerts a ON e.id = a.event_id
                    LEFT JOIN devices d ON e.user_id = d.employee_id
                    WHERE 1=1
            '''
            stats_params = []

            # Apply same filters
            if source_type:
                stats_query += ' AND e.log_type = ?'
                stats_params.append(source_type)
            if status:
                if status.lower() == 'failed':
                    stats_query += ' AND e.status_code >= 400'
                elif status.lower() == 'success':
                    stats_query += ' AND e.status_code < 400'
            if user:
                stats_query += ' AND e.user_id = ?'
                stats_params.append(user)
            if src_ip:
                stats_query += ' AND e.source_ip = ?'
                stats_params.append(src_ip)
            if hostname:
                stats_query += ' AND d.hostname = ?'
                stats_params.append(hostname)
            if severity:
                stats_query += ' AND a.severity = ?'
                stats_params.append(severity)
            if mitre_id:
                stats_query += ' AND a.mitre_id = ?'
                stats_params.append(mitre_id)
            if time_range:
                time_seconds = _parse_time_range(time_range)
                if time_seconds:
                    stats_query += " AND datetime(e.timestamp) >= datetime('now', ?)"
                    stats_params.append(f'-{time_seconds} seconds')
            if q and q.strip():
                search_term = f'%{q.strip()}%'
                stats_query += ''' AND (
                    e.source_ip LIKE ? OR e.user_id LIKE ? OR e.method LIKE ? OR
                    e.path LIKE ? OR e.user_agent LIKE ? OR e.country LIKE ? OR
                    a.mitre_id LIKE ? OR a.title LIKE ? OR a.description LIKE ? OR
                    d.hostname LIKE ?
                )'''
                stats_params.extend([search_term] * 10)

            stats_query += f' GROUP BY {stats_select} ORDER BY count DESC'

            # Apply where clause if present
            if where_clause:
                # Simple where clause parsing for "count > N"
                match = re.search(r'count\s*>\s*(\d+)', where_clause, re.IGNORECASE)
                if match:
                    threshold = int(match.group(1))
                    stats_query = f'SELECT * FROM ({stats_query}) WHERE count > {threshold}'

            cursor.execute(stats_query, stats_params)
            stats_rows = cursor.fetchall()

            stat_columns = stats_fields + ['count']
            for s_row in stats_rows:
                stat_dict = {}
                for col in stat_columns:
                    stat_dict[col] = s_row[col] if col in s_row.keys() else s_row[col.lower()] if col.lower() in s_row.keys() else None
                statistics.append(stat_dict)

        return {
            'total_matched': total_matched,
            'events': events,
            'statistics': statistics,
            'stat_columns': stat_columns
        }


def _parse_time_range(time_range: str) -> Optional[int]:
    """Parse time range string to seconds.
    Supports: 1m, 1h, 1d, 7d, 30d, etc.
    """
    if not time_range:
        return None

    time_range = time_range.strip().lower()
    match = re.match(r'^(\d+)([mhd])$', time_range)
    if not match:
        return None

    value = int(match.group(1))
    unit = match.group(2)

    if unit == 'm':
        return value * 60
    elif unit == 'h':
        return value * 3600
    elif unit == 'd':
        return value * 86400

    return None


# =============================================================================
# Seeding Function (NEW)
# =============================================================================

def seed_realistic_environment(db_path: str = None, reset: bool = False) -> tuple[int, int]:
    """Seed the database with realistic employee and device data.

    Creates:
    - 75 employees with diverse international names
    - 110 devices with realistic hostnames
    - 75% training completion rate
    - Compliance ratios: 58% Compliant, 24% Exceptions, 18% Non-Compliant
    - Distribution across Employee Office, Contingent Office, Employee Remote, Contingent Remote

    Args:
        db_path: Path to SQLite database
        reset: If True, clear existing data before seeding

    Returns:
        Tuple of (employee_count, device_count)
    """
    if db_path is None:
        db_path = get_db_path()

    if reset:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM devices')
            cursor.execute('DELETE FROM employees')
            conn.commit()

    # Check if already seeded
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM employees')
        if cursor.fetchone()[0] > 0:
            cursor.execute('SELECT COUNT(*) FROM devices')
            device_count = cursor.fetchone()[0]
            return (75, device_count)

    # Diverse international employee names
    employee_data = [
        # North America
        ("EMP-001", "Amir Alimov", "amir.alimov@company.com", "Core Banking", "Senior Engineer", "Employee", "Office", "New York", "USA"),
        ("EMP-002", "Sarah Jenkins", "sarah.jenkins@company.com", "Payments & Clearing", "Security Analyst", "Employee", "Office", "Toronto", "Canada"),
        ("EMP-003", "Marcus Vance", "marcus.vance@company.com", "Fraud Operations", "Lead Investigator", "Employee", "Remote", "Austin", "USA"),
        ("EMP-004", "David Kim", "david.kim@company.com", "DevSecOps", "Platform Engineer", "Employee", "Office", "San Francisco", "USA"),
        ("EMP-005", "Kevin Chen", "kevin.chen@company.com", "Cloud Infrastructure", "Cloud Architect", "Employee", "Remote", "Seattle", "USA"),
        ("EMP-006", "Liam O'Connor", "liam.oconnor@company.com", "Mobile Engineering", "iOS Developer", "Employee", "Office", "Boston", "USA"),
        ("EMP-007", "Daniel Novak", "daniel.novak@company.com", "Risk & Compliance", "Compliance Officer", "Employee", "Remote", "Chicago", "USA"),
        ("EMP-008", "Jessica Martinez", "jessica.martinez@company.com", "Treasury", "Financial Analyst", "Employee", "Office", "New York", "USA"),
        ("EMP-009", "Robert Taylor", "robert.taylor@company.com", "Core Banking", "Backend Engineer", "Employee", "Office", "Toronto", "Canada"),
        ("EMP-010", "Jennifer Wu", "jennifer.wu@company.com", "Payments & Clearing", "QA Engineer", "Employee", "Remote", "Vancouver", "Canada"),

        # Europe
        ("EMP-011", "Elena Rostova", "elena.rostova@company.com", "Core Banking", "Principal Engineer", "Employee", "Office", "London", "UK"),
        ("EMP-012", "Nadia Mansour", "nadia.mansour@company.com", "Fraud Operations", "Senior Investigator", "Employee", "Remote", "Paris", "France"),
        ("EMP-013", "Tariq Hassan", "tariq.hassan@company.com", "DevSecOps", "Security Engineer", "Employee", "Office", "Berlin", "Germany"),
        ("EMP-014", "Sofia Morales", "sofia.morales@company.com", "Cloud Infrastructure", "SRE", "Employee", "Remote", "Madrid", "Spain"),
        ("EMP-015", "Priya Nair", "priya.nair@company.com", "Mobile Engineering", "Android Developer", "Employee", "Office", "Amsterdam", "Netherlands"),
        ("EMP-016", "Jonas Lindqvist", "jonas.lindqvist@company.com", "Risk & Compliance", "Risk Analyst", "Employee", "Remote", "Stockholm", "Sweden"),
        ("EMP-017", "Fatima Zahra", "fatima.zahra@company.com", "Treasury", "Treasury Manager", "Employee", "Office", "Dublin", "Ireland"),
        ("EMP-018", "Mateo Rossi", "mateo.rossi@company.com", "Core Banking", "Database Admin", "Employee", "Remote", "Milan", "Italy"),
        ("EMP-019", "Katarina Petrovic", "katarina.petrovic@company.com", "Payments & Clearing", "Product Manager", "Employee", "Office", "Zurich", "Switzerland"),
        ("EMP-020", "Henrik Andersen", "henrik.andersen@company.com", "Fraud Operations", "ML Engineer", "Employee", "Remote", "Copenhagen", "Denmark"),

        # Middle East & Africa
        ("EMP-021", "Omar Al-Rashid", "omar.alrashid@company.com", "DevSecOps", "Security Architect", "Employee", "Office", "Dubai", "UAE"),
        ("EMP-022", "Aisha Al-Farsi", "aisha.alfarsi@company.com", "Cloud Infrastructure", "DevOps Engineer", "Employee", "Remote", "Riyadh", "Saudi Arabia"),
        ("EMP-023", "Kwame Asante", "kwame.asante@company.com", "Mobile Engineering", "Flutter Developer", "Employee", "Office", "Accra", "Ghana"),
        ("EMP-024", "Amara Okafor", "amara.okafor@company.com", "Risk & Compliance", "Compliance Lead", "Employee", "Remote", "Lagos", "Nigeria"),
        ("EMP-025", "Yusuf Demir", "yusuf.demir@company.com", "Treasury", "Quant Analyst", "Employee", "Office", "Istanbul", "Turkey"),

        # Asia Pacific
        ("EMP-026", "Wei Zhang", "wei.zhang@company.com", "Core Banking", "Staff Engineer", "Employee", "Office", "Singapore", "Singapore"),
        ("EMP-027", "Mei Lin", "mei.lin@company.com", "Payments & Clearing", "API Specialist", "Employee", "Remote", "Hong Kong", "Hong Kong"),
        ("EMP-028", "Hiroshi Tanaka", "hiroshi.tanaka@company.com", "Fraud Operations", "Data Scientist", "Employee", "Office", "Tokyo", "Japan"),
        ("EMP-029", "Ji-Yeon Park", "jiyeon.park@company.com", "DevSecOps", "Security Researcher", "Employee", "Remote", "Seoul", "South Korea"),
        ("EMP-030", "Arjun Patel", "arjun.patel@company.com", "Cloud Infrastructure", "Kubernetes Admin", "Employee", "Office", "Sydney", "Australia"),
        ("EMP-031", "Siti Rahman", "siti.rahman@company.com", "Mobile Engineering", "React Native Dev", "Employee", "Remote", "Jakarta", "Indonesia"),
        ("EMP-032", "Rajesh Kumar", "rajesh.kumar@company.com", "Risk & Compliance", "Audit Manager", "Employee", "Office", "Mumbai", "India"),
        ("EMP-033", "Chloe Wang", "chloe.wang@company.com", "Treasury", "FX Trader", "Employee", "Remote", "Shanghai", "China"),

        # Latin America
        ("EMP-034", "Carlos Mendoza", "carlos.mendoza@company.com", "Core Banking", "Backend Lead", "Employee", "Office", "Mexico City", "Mexico"),
        ("EMP-035", "Isabela Santos", "isabela.santos@company.com", "Payments & Clearing", "Integration Engineer", "Employee", "Remote", "Sao Paulo", "Brazil"),
        ("EMP-036", "Andres Gutierrez", "andres.gutierrez@company.com", "Fraud Operations", "Case Manager", "Employee", "Office", "Bogota", "Colombia"),
        ("EMP-037", "Gabriela Rojas", "gabriela.rojas@company.com", "DevSecOps", "Penetration Tester", "Employee", "Remote", "Buenos Aires", "Argentina"),
        ("EMP-038", "Diego Fernandez", "diego.fernandez@company.com", "Cloud Infrastructure", "Cloud Engineer", "Employee", "Office", "Santiago", "Chile"),

        # Contingent workers (25% of 75 = ~19)
        ("EMP-039", "Vikram Singh", "vikram.singh@contractor.com", "Core Banking", "Contractor - Backend", "Contingent", "Remote", "Bangalore", "India"),
        ("EMP-040", "Maria Gonzalez", "maria.gonzalez@contractor.com", "Payments & Clearing", "Contractor - QA", "Contingent", "Office", "Madrid", "Spain"),
        ("EMP-041", "James Mitchell", "james.mitchell@contractor.com", "Fraud Operations", "Contractor - Analyst", "Contingent", "Remote", "London", "UK"),
        ("EMP-042", "Anna Kowalski", "anna.kowalski@contractor.com", "DevSecOps", "Contractor - Security", "Contingent", "Office", "Warsaw", "Poland"),
        ("EMP-043", "Thomas Mueller", "thomas.mueller@contractor.com", "Cloud Infrastructure", "Contractor - DevOps", "Contingent", "Remote", "Munich", "Germany"),
        ("EMP-044", "Laura Silva", "laura.silva@contractor.com", "Mobile Engineering", "Contractor - iOS", "Contingent", "Office", "Lisbon", "Portugal"),
        ("EMP-045", "Pierre Dubois", "pierre.dubois@contractor.com", "Risk & Compliance", "Contractor - Audit", "Contingent", "Remote", "Lyon", "France"),
        ("EMP-046", "Sofia Andersson", "sofia.andersson@contractor.com", "Treasury", "Contractor - Analyst", "Contingent", "Office", "Oslo", "Norway"),
        ("EMP-047", "Ravi Sharma", "ravi.sharma@contractor.com", "Core Banking", "Contractor - DB Admin", "Contingent", "Remote", "Delhi", "India"),
        ("EMP-048", "Carmen Herrera", "carmen.herrera@contractor.com", "Payments & Clearing", "Contractor - Support", "Contingent", "Office", "Barcelona", "Spain"),
        ("EMP-049", "Michael Brown", "michael.brown@contractor.com", "Fraud Operations", "Contractor - Investigator", "Contingent", "Remote", "Manchester", "UK"),
        ("EMP-050", "Elena Popescu", "elena.popescu@contractor.com", "DevSecOps", "Contractor - Security", "Contingent", "Office", "Bucharest", "Romania"),
        ("EMP-051", "Ahmed Hassan", "ahmed.hassan@contractor.com", "Cloud Infrastructure", "Contractor - SRE", "Contingent", "Remote", "Cairo", "Egypt"),
        ("EMP-052", "Nina Petrov", "nina.petrov@contractor.com", "Mobile Engineering", "Contractor - Android", "Contingent", "Office", "Sofia", "Bulgaria"),
        ("EMP-053", "Omar Youssef", "omar.youssef@contractor.com", "Risk & Compliance", "Contractor - Compliance", "Contingent", "Remote", "Amman", "Jordan"),
        ("EMP-054", "Paula Oliveira", "paula.oliveira@contractor.com", "Treasury", "Contractor - Operations", "Contingent", "Office", "Porto", "Portugal"),
        ("EMP-055", "Steven Clark", "steven.clark@contractor.com", "Core Banking", "Contractor - Architect", "Contingent", "Remote", "Edinburgh", "UK"),
        ("EMP-056", "Marta Nowak", "marta.nowak@contractor.com", "Payments & Clearing", "Contractor - PM", "Contingent", "Office", "Krakow", "Poland"),
        ("EMP-057", "Lucas Ferreira", "lucas.ferreira@contractor.com", "Fraud Operations", "Contractor - ML", "Contingent", "Remote", "Rio de Janeiro", "Brazil"),

        # Additional employees to reach 75
        ("EMP-058", "Hannah Park", "hannah.park@company.com", "Core Banking", "Senior Engineer", "Employee", "Office", "Seattle", "USA"),
        ("EMP-059", "Mohammed Ali", "mohammed.ali@company.com", "Payments & Clearing", "Engineering Lead", "Employee", "Remote", "Dubai", "UAE"),
        ("EMP-060", "Yuki Sato", "yuki.sato@company.com", "Fraud Operations", "Senior Analyst", "Employee", "Office", "Tokyo", "Japan"),
        ("EMP-061", "Leila Ahmed", "leila.ahmed@company.com", "DevSecOps", "Security Engineer", "Employee", "Remote", "Toronto", "Canada"),
        ("EMP-062", "Pedro Santos", "pedro.santos@company.com", "Cloud Infrastructure", "Platform Engineer", "Employee", "Office", "Lisbon", "Portugal"),
        ("EMP-063", "Greta Johansson", "greta.johansson@company.com", "Mobile Engineering", "Tech Lead", "Employee", "Remote", "Stockholm", "Sweden"),
        ("EMP-064", "Ahmed Benali", "ahmed.benali@company.com", "Risk & Compliance", "Senior Auditor", "Employee", "Office", "Casablanca", "Morocco"),
        ("EMP-065", "Isabel Torres", "isabel.torres@company.com", "Treasury", "Senior Trader", "Employee", "Remote", "Mexico City", "Mexico"),
        ("EMP-066", "Victor Hugo", "victor.hugo@company.com", "Core Banking", "Staff Engineer", "Employee", "Office", "Paris", "France"),
        ("EMP-067", "Nina Kovacs", "nina.kovacs@company.com", "Payments & Clearing", "Backend Engineer", "Employee", "Remote", "Budapest", "Hungary"),
        ("EMP-068", "Oscar Nilsson", "oscar.nilsson@company.com", "Fraud Operations", "Data Engineer", "Employee", "Office", "Gothenburg", "Sweden"),
        ("EMP-069", "Maria Fernandez", "maria.fernandez@company.com", "DevSecOps", "AppSec Engineer", "Employee", "Remote", "Valencia", "Spain"),
        ("EMP-070", "Jakob Meyer", "jakob.meyer@company.com", "Cloud Infrastructure", "Site Reliability Eng", "Employee", "Office", "Hamburg", "Germany"),
        ("EMP-071", "Alicia Chen", "alicia.chen@company.com", "Mobile Engineering", "Senior Developer", "Employee", "Remote", "Melbourne", "Australia"),
        ("EMP-072", "Rashid Khan", "rashid.khan@company.com", "Risk & Compliance", "Risk Manager", "Employee", "Office", "Karachi", "Pakistan"),
        ("EMP-073", "Sofia Andersson", "sofia.andersson2@company.com", "Treasury", "Operations Lead", "Employee", "Remote", "Helsinki", "Finland"),
        ("EMP-074", "Thomas O'Brien", "thomas.obrien@company.com", "Core Banking", "Principal Architect", "Employee", "Office", "Dublin", "Ireland"),
        ("EMP-075", "Yara Mahmoud", "yara.mahmoud@company.com", "Payments & Clearing", "API Gateway Lead", "Employee", "Remote", "Jeddah", "Saudi Arabia"),
    ]

    # Departments for reference
    departments = [
        "Core Banking", "Payments & Clearing", "Fraud Operations",
        "DevSecOps", "Cloud Infrastructure", "Mobile Engineering",
        "Risk & Compliance", "Treasury"
    ]

    # Device types and OS names
    device_types = ["Laptop", "Workstation", "Server", "Mobile"]
    os_names = ["macOS 15.2", "Windows 11 24H2", "Ubuntu 24.04 LTS", "iOS 18.1"]

    # Hostname prefixes by department
    hostname_prefixes = {
        "Core Banking": "FIN",
        "Payments & Clearing": "PAY",
        "Fraud Operations": "SEC",
        "DevSecOps": "SEC",
        "Cloud Infrastructure": "OPS",
        "Mobile Engineering": "MOB",
        "Risk & Compliance": "RISK",
        "Treasury": "TRS"
    }

    # City coordinates (approximate)
    city_coords = {
        "New York": (40.7128, -74.0060), "Toronto": (43.6532, -79.3832),
        "Austin": (30.2672, -97.7431), "San Francisco": (37.7749, -122.4194),
        "Seattle": (47.6062, -122.3321), "Boston": (42.3601, -71.0589),
        "Chicago": (41.8781, -87.6298), "Vancouver": (49.2827, -123.1207),
        "London": (51.5074, -0.1278), "Paris": (48.8566, 2.3522),
        "Berlin": (52.5200, 13.4050), "Madrid": (40.4168, -3.7038),
        "Amsterdam": (52.3676, 4.9041), "Stockholm": (59.3293, 18.0686),
        "Dublin": (53.3498, -6.2603), "Milan": (45.4642, 9.1900),
        "Zurich": (47.3769, 8.5417), "Copenhagen": (55.6761, 12.5683),
        "Dubai": (25.2048, 55.2708), "Riyadh": (24.7136, 46.6753),
        "Accra": (5.6037, -0.1870), "Lagos": (6.5244, 3.3792),
        "Istanbul": (41.0082, 28.9784), "Singapore": (1.3521, 103.8198),
        "Hong Kong": (22.3193, 114.1694), "Tokyo": (35.6762, 139.6503),
        "Seoul": (37.5665, 126.9780), "Sydney": (-33.8688, 151.2093),
        "Jakarta": (-6.2088, 106.8456), "Mumbai": (19.0760, 72.8777),
        "Shanghai": (31.2304, 121.4737), "Mexico City": (19.4326, -99.1332),
        "Sao Paulo": (-23.5505, -46.6333), "Bogota": (4.7110, -74.0721),
        "Buenos Aires": (-34.6037, -58.3816), "Santiago": (-33.4489, -70.6693),
        "Bangalore": (12.9716, 77.5946), "Warsaw": (52.2297, 21.0122),
        "Munich": (48.1351, 11.5820), "Lisbon": (38.7223, -9.1393),
        "Lyon": (45.7640, 4.8357), "Oslo": (59.9139, 10.7522),
        "Delhi": (28.7041, 77.1025), "Barcelona": (41.3851, 2.1734),
        "Manchester": (53.4808, -2.2426), "Bucharest": (44.4268, 26.1025),
        "Cairo": (30.0444, 31.2357), "Sofia": (42.6977, 23.3219),
        "Amman": (31.9454, 35.9284), "Porto": (41.1579, -8.6291),
        "Edinburgh": (55.9533, -3.1883), "Krakow": (50.0647, 19.9450),
        "Rio de Janeiro": (-22.9068, -43.1729), "Casablanca": (33.5731, -7.5898),
        "Budapest": (47.4979, 19.0402), "Gothenburg": (57.7089, 11.9746),
        "Valencia": (39.4699, -0.3763), "Hamburg": (53.5511, 9.9937),
        "Melbourne": (-37.8136, 144.9631), "Karachi": (24.8607, 67.0011),
        "Helsinki": (60.1699, 24.9384), "Jeddah": (21.4858, 39.1925),
    }

    # Generate random data with controlled distributions
    random.seed(42)  # Reproducible results

    # 75% training completion rate
    training_completed_flags = [True] * 56 + [False] * 19  # 56/75 = 74.6%
    random.shuffle(training_completed_flags)

    # Compliance distribution: 58% Compliant, 24% Exceptions, 18% Non-Compliant
    compliance_statuses = (["Compliant"] * 58) + (["Exceptions"] * 24) + (["Non-Compliant"] * 18)
    # We need 110 devices, so scale up
    compliance_statuses = compliance_statuses * 2  # 200 items
    random.shuffle(compliance_statuses)

    # EDR statuses
    edr_statuses = ["Protected"] * 85 + ["Outdated Agent"] * 15 + ["Tamper Alert"] * 10
    random.shuffle(edr_statuses)

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()

        # Insert employees
        for i, (emp_id, full_name, email, dept, role, emp_type, work_mode, city, country) in enumerate(employee_data):
            risk_score = random.randint(5, 45)  # Most employees low risk
            if emp_type == "Contingent":
                risk_score += random.randint(0, 20)  # Contractors slightly higher
            status = "ACTIVE"
            training_done = training_completed_flags[i]

            cursor.execute('''
                INSERT INTO employees (
                    employee_id, full_name, email, department, role,
                    employment_type, work_mode, city, country,
                    training_completed, risk_score, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (emp_id, full_name, email, dept, role, emp_type, work_mode,
                  city, country, training_done, risk_score, status))

        # Insert devices (110 devices for 75 employees)
        device_count = 0
        for emp_id, full_name, email, dept, role, emp_type, work_mode, city, country in employee_data:
            # Each employee gets 1-2 devices
            num_devices = 1 if device_count >= 100 else random.choices([1, 2], weights=[0.4, 0.6])[0]
            if device_count + num_devices > 110:
                num_devices = 110 - device_count

            prefix = hostname_prefixes.get(dept, "GEN")

            for j in range(num_devices):
                if device_count >= 110:
                    break

                device_id = f"DEV-{device_count + 1:04d}"
                hostname = f"{prefix}-{random.choice(['MBP', 'WIN', 'LNX', 'MBP', 'WIN'])}-{random.randint(1000, 9999)}"
                device_type = random.choice(device_types)
                os_name = random.choice(os_names)
                ip_address = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
                lat, lon = city_coords.get(city, (0.0, 0.0))
                # Add small random offset for devices in same city
                lat += random.uniform(-0.01, 0.01)
                lon += random.uniform(-0.01, 0.01)

                compliance_status = compliance_statuses[device_count]
                edr_status = edr_statuses[device_count] if device_count < len(edr_statuses) else "Protected"
                isolated = False

                cursor.execute('''
                    INSERT INTO devices (
                        device_id, hostname, employee_id, employee_name,
                        device_type, os_name, employment_type, work_mode,
                        ip_address, city, country, lat, lon,
                        compliance_status, edr_status, isolated
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    device_id, hostname, emp_id, full_name,
                    device_type, os_name, emp_type, work_mode,
                    ip_address, city, country, lat, lon,
                    compliance_status, edr_status, isolated
                ))

                device_count += 1

        # Add a few extra devices for some employees to reach 110
        extra_devices_needed = 110 - device_count
        for i in range(extra_devices_needed):
            emp = random.choice(employee_data)
            emp_id, full_name, email, dept, role, emp_type, work_mode, city, country = emp
            prefix = hostname_prefixes.get(dept, "GEN")

            device_id = f"DEV-{device_count + 1:04d}"
            hostname = f"{prefix}-{random.choice(['MBP', 'WIN', 'LNX'])}-{random.randint(1000, 9999)}"
            device_type = random.choice(device_types)
            os_name = random.choice(os_names)
            ip_address = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            lat, lon = city_coords.get(city, (0.0, 0.0))
            lat += random.uniform(-0.01, 0.01)
            lon += random.uniform(-0.01, 0.01)

            compliance_status = compliance_statuses[device_count] if device_count < len(compliance_statuses) else "Compliant"
            edr_status = edr_statuses[device_count] if device_count < len(edr_statuses) else "Protected"
            isolated = False

            cursor.execute('''
                INSERT INTO devices (
                    device_id, hostname, employee_id, employee_name,
                    device_type, os_name, employment_type, work_mode,
                    ip_address, city, country, lat, lon,
                    compliance_status, edr_status, isolated
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                device_id, hostname, emp_id, full_name,
                device_type, os_name, emp_type, work_mode,
                ip_address, city, country, lat, lon,
                compliance_status, edr_status, isolated
            ))

            device_count += 1

        conn.commit()

    return (75, 110)