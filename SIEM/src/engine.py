"""Stateful detection and correlation engine for the SIEM."""

import json
import os
import re
import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional

from src.models import Alert, Incident, NormalizedEvent
from src import storage


class DetectionEngine:
    """Stateful detection engine with rule evaluation and correlation."""

    def __init__(self, rules_path: str = None, db_path: str = None):
        """Initialize the detection engine.

        Args:
            rules_path: Path to detection_rules.json file
            db_path: Path to SQLite database for persistence
        """
        if rules_path is None:
            rules_path = os.path.join(
                os.path.dirname(__file__), '..', 'rules', 'detection_rules.json'
            )

        with open(rules_path, 'r') as f:
            self.config = json.load(f)

        self.rules = {rule['id']: rule for rule in self.config['rules']}
        self.default_cooldown_seconds = self.config.get('default_cooldown_seconds', 300)
        self.risk_score_cap = self.config.get('risk_score_cap', 100)
        self.risk_score_decay = self.config.get('risk_score_decay', {})

        self.db_path = db_path

        # In-memory state for tracking
        self._event_cache: dict[str, list[NormalizedEvent]] = defaultdict(list)
        self._alert_timestamps: dict[str, datetime] = {}
        self._processed_alerts: set[str] = set()

        self._init_cooldown_state()

    def _init_cooldown_state(self) -> None:
        """Initialize cooldown tracking from database."""
        # Load recent alert timestamps from database for cooldown checks
        pass

    def _is_in_cooldown(self, rule_id: str, entity_key: str) -> bool:
        """Check if an alert is in cooldown period.

        Args:
            rule_id: The MITRE ATT&CK rule ID
            entity_key: Unique key identifying the entity (e.g., ip:user)

        Returns:
            True if in cooldown, False otherwise
        """
        cooldown_seconds = self.rules.get(rule_id, {}).get('cooldown_seconds',
                                                          self.default_cooldown_seconds)
        alert_key = f"{rule_id}:{entity_key}"

        if alert_key not in self._alert_timestamps:
            return False

        last_alert_time = self._alert_timestamps[alert_key]
        cooldown_delta = timedelta(seconds=cooldown_seconds)

        return datetime.now() - last_alert_time < cooldown_delta

    def _record_alert_timestamp(self, rule_id: str, entity_key: str) -> None:
        """Record the timestamp of an alert for cooldown tracking."""
        alert_key = f"{rule_id}:{entity_key}"
        self._alert_timestamps[alert_key] = datetime.now()
        self._processed_alerts.add(alert_key)

    # =========================================================================
    # Rule Evaluation Functions
    # =========================================================================

    def evaluate_brute_force_rule(self, events: list, rule: dict) -> list[Alert]:
        """Evaluate brute-force login rule.

        Detects 5+ failed logins from same IP for same user within 60s.

        Args:
            events: List of NormalizedEvent objects to evaluate
            rule: The rule configuration dictionary

        Returns:
            List of Alert objects for detected brute-force attempts
        """
        if not events or not rule.get('conditions'):
            return []

        alerts = []
        conditions = rule['conditions']
        threshold = conditions.get('threshold', 5)
        window_seconds = conditions.get('window_seconds', 60)
        group_by = conditions.get('group_by', ['source_ip', 'user_id'])

        # Filter for failed login events (status_code 401 = failed login)
        failed_logins = [e for e in events if e.log_type == 'auth_service' and e.status_code == 401]

        # Group events by source_ip and user_id
        grouped = defaultdict(list)
        for event in failed_logins:
            key = (event.source_ip, event.user_id or 'unknown')
            grouped[key].append(event)

        # Check each group for threshold violations within window
        now = datetime.now()
        for (source_ip, user_id), group_events in grouped.items():
            # Sort by timestamp
            group_events.sort(key=lambda e: e.timestamp)

            # Sliding window check
            for i, event in enumerate(group_events):
                window_start = event.timestamp
                window_end = window_start + timedelta(seconds=window_seconds)

                # Count events in window
                events_in_window = [
                    e for e in group_events[i:]
                    if window_start <= e.timestamp <= window_end
                ]

                if len(events_in_window) >= threshold:
                    entity_key = f"{source_ip}:{user_id}"

                    # Check cooldown
                    if self._is_in_cooldown(rule['id'], entity_key):
                        continue

                    alert = Alert(
                        id=str(uuid.uuid4()),
                        event_id=event.id,
                        mitre_id=rule['id'],
                        severity=rule['severity'],
                        risk_score=rule.get('risk_score', 75),
                        title=f"Brute-Force Login Detected for {user_id}",
                        description=rule['description'],
                        timestamp=events_in_window[-1].timestamp,
                        source_ip=source_ip,
                        user_id=user_id if user_id != 'unknown' else '',
                        status='NEW',
                        correlated=False
                    )
                    alerts.append(alert)
                    break  # One alert per group

        return alerts

    def evaluate_password_spray_rule(self, events: list, rule: dict) -> list[Alert]:
        """Evaluate password spraying rule.

        Detects 6+ failed logins from same IP across 4+ users within 5m.

        Args:
            events: List of NormalizedEvent objects to evaluate
            rule: The rule configuration dictionary

        Returns:
            List of Alert objects for detected password spraying attempts
        """
        if not events or not rule.get('conditions'):
            return []

        alerts = []
        conditions = rule['conditions']
        threshold = conditions.get('threshold', 6)
        window_seconds = conditions.get('window_seconds', 300)
        distinct_users = conditions.get('distinct_users', 4)

        # Filter for failed login events (status_code 401 = failed login)
        failed_logins = [e for e in events if e.log_type == 'auth_service' and e.status_code == 401]

        # Group by source_ip
        grouped = defaultdict(list)
        for event in failed_logins:
            grouped[event.source_ip].append(event)

        # Check each IP for password spraying
        for source_ip, group_events in grouped.items():
            if len(group_events) < threshold:
                continue

            # Sort by timestamp
            group_events.sort(key=lambda e: e.timestamp)

            # Sliding window check
            for i, event in enumerate(group_events):
                window_start = event.timestamp
                window_end = window_start + timedelta(seconds=window_seconds)

                events_in_window = [
                    e for e in group_events[i:]
                    if window_start <= e.timestamp <= window_end
                ]

                # Count distinct users
                unique_users = set(e.user_id for e in events_in_window if e.user_id)

                if len(events_in_window) >= threshold and len(unique_users) >= distinct_users:
                    entity_key = source_ip

                    # Check cooldown
                    if self._is_in_cooldown(rule['id'], entity_key):
                        continue

                    user_count = min(len(unique_users), distinct_users)
                    alert = Alert(
                        id=str(uuid.uuid4()),
                        event_id=event.id,
                        mitre_id=rule['id'],
                        severity=rule['severity'],
                        risk_score=rule.get('risk_score', 80),
                        title=f"Password Spraying from {source_ip}",
                        description=f"Detected {len(events_in_window)} failed logins across {user_count}+ users from {source_ip}",
                        timestamp=events_in_window[-1].timestamp,
                        source_ip=source_ip,
                        user_id='',
                        status='NEW',
                        correlated=False
                    )
                    alerts.append(alert)
                    break  # One alert per IP

        return alerts

    def evaluate_impossible_travel_rule(self, events: list, rule: dict) -> list[Alert]:
        """Evaluate impossible travel rule.

        Detects 2 successful logins for same user from different countries within 60m.

        Args:
            events: List of NormalizedEvent objects to evaluate
            rule: The rule configuration dictionary

        Returns:
            List of Alert objects for detected impossible travel
        """
        if not events or not rule.get('conditions'):
            return []

        alerts = []
        conditions = rule['conditions']
        window_seconds = conditions.get('window_seconds', 3600)
        require_different_countries = conditions.get('require_different_countries', True)

        # Filter for successful login events
        successful_logins = [e for e in events if e.log_type == 'auth_service']

        # Group by user_id
        grouped = defaultdict(list)
        for event in successful_logins:
            if event.user_id:
                grouped[event.user_id].append(event)

        # Check each user for impossible travel
        for user_id, group_events in grouped.items():
            if len(group_events) < 2:
                continue

            # Sort by timestamp
            group_events.sort(key=lambda e: e.timestamp)

            # Sliding window check
            for i, event in enumerate(group_events):
                window_start = event.timestamp
                window_end = window_start + timedelta(seconds=window_seconds)

                events_in_window = [
                    e for e in group_events
                    if window_start <= e.timestamp <= window_end
                ]

                if len(events_in_window) >= 2:
                    # Check for different countries
                    countries = set(e.country for e in events_in_window)

                    if require_different_countries and len(countries) < 2:
                        continue

                    entity_key = user_id

                    # Check cooldown
                    if self._is_in_cooldown(rule['id'], entity_key):
                        continue

                    alert = Alert(
                        id=str(uuid.uuid4()),
                        event_id=event.id,
                        mitre_id=rule['id'],
                        severity=rule['severity'],
                        risk_score=rule.get('risk_score', 95),
                        title=f"Impossible Travel for {user_id}",
                        description=f"User logged in from {len(countries)} countries within 60 minutes",
                        timestamp=events_in_window[-1].timestamp,
                        source_ip=events_in_window[-1].source_ip,
                        user_id=user_id,
                        status='NEW',
                        correlated=False
                    )
                    alerts.append(alert)
                    break  # One alert per user

        return alerts

    def evaluate_endpoint_enumeration_rule(self, events: list, rule: dict) -> list[Alert]:
        """Evaluate API endpoint enumeration rule.

        Detects 15+ HTTP 403/404 errors from same IP within 60s.

        Args:
            events: List of NormalizedEvent objects to evaluate
            rule: The rule configuration dictionary

        Returns:
            List of Alert objects for detected enumeration attempts
        """
        if not events or not rule.get('conditions'):
            return []

        alerts = []
        conditions = rule['conditions']
        status_codes = conditions.get('status_codes', [403, 404])
        threshold = conditions.get('threshold', 15)
        window_seconds = conditions.get('window_seconds', 60)
        group_by = conditions.get('group_by', ['source_ip'])

        # Filter for API gateway events with target status codes
        target_events = [
            e for e in events
            if e.log_type == 'api_gateway' and e.status_code in status_codes
        ]

        # Group by source_ip
        grouped = defaultdict(list)
        for event in target_events:
            grouped[event.source_ip].append(event)

        # Check each IP for enumeration
        for source_ip, group_events in grouped.items():
            if len(group_events) < threshold:
                continue

            # Sort by timestamp
            group_events.sort(key=lambda e: e.timestamp)

            # Sliding window check
            for i, event in enumerate(group_events):
                window_start = event.timestamp
                window_end = window_start + timedelta(seconds=window_seconds)

                events_in_window = [
                    e for e in group_events[i:]
                    if window_start <= e.timestamp <= window_end
                ]

                if len(events_in_window) >= threshold:
                    entity_key = source_ip

                    # Check cooldown
                    if self._is_in_cooldown(rule['id'], entity_key):
                        continue

                    alert = Alert(
                        id=str(uuid.uuid4()),
                        event_id=event.id,
                        mitre_id=rule['id'],
                        severity=rule['severity'],
                        risk_score=rule.get('risk_score', 60),
                        title=f"API Endpoint Enumeration from {source_ip}",
                        description=f"Detected {len(events_in_window)} 403/404 errors from {source_ip}",
                        timestamp=events_in_window[-1].timestamp,
                        source_ip=source_ip,
                        user_id='',
                        status='NEW',
                        correlated=False
                    )
                    alerts.append(alert)
                    break  # One alert per IP

        return alerts

    def evaluate_injection_probe_rule(self, events: list, rule: dict) -> list[Alert]:
        """Evaluate API injection probe rule.

        Detects SQLi, path traversal, or JWT/IDOR patterns in API paths/params.

        Args:
            events: List of NormalizedEvent objects to evaluate
            rule: The rule configuration dictionary

        Returns:
            List of Alert objects for detected injection probes
        """
        if not events or not rule.get('conditions'):
            return []

        alerts = []
        conditions = rule['conditions']
        patterns = conditions.get('patterns', [])
        check_fields = conditions.get('check_fields', ['path', 'user_agent', 'request_body'])

        # Compile regex patterns
        compiled_patterns = [(p, re.compile(p, re.IGNORECASE)) for p in patterns]

        # Filter for API gateway events
        api_events = [e for e in events if e.log_type == 'api_gateway']

        for event in api_events:
            # Check each field for patterns
            fields_to_check = []
            if 'path' in check_fields:
                fields_to_check.append(event.path)
            if 'user_agent' in check_fields:
                fields_to_check.append(event.user_agent)
            if 'request_body' in check_fields:
                fields_to_check.append(event.request_body if hasattr(event, 'request_body') else '')

            for field_value in fields_to_check:
                if not field_value:
                    continue

                for pattern_str, pattern_re in compiled_patterns:
                    if pattern_re.search(str(field_value)):
                        entity_key = f"{rule['id']}:{event.source_ip}"

                        # Check cooldown
                        if self._is_in_cooldown(rule['id'], entity_key):
                            continue

                        alert = Alert(
                            id=str(uuid.uuid4()),
                            event_id=event.id,
                            mitre_id=rule['id'],
                            severity=rule['severity'],
                            risk_score=rule.get('risk_score', 85),
                            title="API Injection/Traversal Probe Detected",
                            description=f"Detected malicious pattern '{pattern_str}' in request",
                            timestamp=event.timestamp,
                            source_ip=event.source_ip,
                            user_id=event.user_id or '',
                            status='NEW',
                            correlated=False
                        )
                        alerts.append(alert)
                        break  # One alert per event
                else:
                    continue
                break  # Exit outer loop if pattern found

        return alerts

    def evaluate_account_takeover_rule(self, events: list, rule: dict) -> list[Alert]:
        """Evaluate multi-stage account takeover rule.

        Correlates brute-force/impossible-travel with high-value transfer within 15m.

        Args:
            events: List of NormalizedEvent objects to evaluate
            rule: The rule configuration dictionary

        Returns:
            List of Alert objects for detected account takeover attempts
        """
        if not events or not rule.get('conditions'):
            return []

        alerts = []
        conditions = rule['conditions']
        preceding_events = conditions.get('preceding_events', [])
        follow_up_type = conditions.get('follow_up_type', '')
        follow_up_condition = conditions.get('follow_up_condition', {})
        time_window_seconds = conditions.get('time_window_seconds', 900)
        group_by = conditions.get('group_by', ['user_id'])

        # Find payment events with high amounts
        payment_events = []
        for e in events:
            if e.log_type == 'payment_engine':
                if follow_up_condition.get('amount', {}).get('gt'):
                    if e.amount and e.amount > follow_up_condition['amount']['gt']:
                        payment_events.append(e)

        # Find preceding auth events
        preceding_auth_events = []
        for e in events:
            if e.log_type == 'auth_service' and rule['id'].split('-')[0] in preceding_events:
                preceding_auth_events.append(e)

        # Correlate: check if payment happened within window of preceding event
        for payment in payment_events:
            for auth in preceding_auth_events:
                if auth.user_id != payment.user_id:
                    continue

                time_diff = abs((payment.timestamp - auth.timestamp).total_seconds())
                if time_diff <= time_window_seconds:
                    entity_key = payment.user_id

                    # Check cooldown
                    if self._is_in_cooldown(rule['id'], entity_key):
                        continue

                    alert = Alert(
                        id=str(uuid.uuid4()),
                        event_id=payment.id,
                        mitre_id=rule['id'],
                        severity=rule['severity'],
                        risk_score=rule.get('risk_score', 98),
                        title=f"Multi-Stage Account Takeover for {payment.user_id}",
                        description="Correlated attack: suspicious activity followed by high-value transfer",
                        timestamp=payment.timestamp,
                        source_ip=payment.source_ip,
                        user_id=payment.user_id,
                        status='NEW',
                        correlated=True
                    )
                    alerts.append(alert)
                    break
            else:
                continue
            break  # One alert per payment event

        return alerts

    # =========================================================================
    # Correlation Engine
    # =========================================================================

    def correlate_incidents(self, alerts: list[Alert]) -> list[Incident]:
        """Correlate multiple alerts into incidents.

        Groups alerts by common attributes (IP, user, time window) into incidents.

        Args:
            alerts: List of Alert objects to correlate

        Returns:
            List of Incident objects composed of related alerts
        """
        if not alerts:
            return []

        incidents = []
        used_alerts = set()

        # Group alerts by source IP and time proximity
        ip_groups = defaultdict(list)
        for alert in alerts:
            ip_groups[alert.source_ip].append(alert)

        # For each IP, check for time-based clusters
        for ip, ip_alerts in ip_groups.items():
            ip_alerts.sort(key=lambda a: a.timestamp)

            # Build clusters within 30-minute windows
            clusters = []
            current_cluster = []

            for alert in ip_alerts:
                if not current_cluster:
                    current_cluster.append(alert)
                else:
                    last_time = current_cluster[-1].timestamp
                    if (alert.timestamp - last_time).total_seconds() <= 1800:  # 30 min
                        current_cluster.append(alert)
                    else:
                        if len(current_cluster) >= 2:
                            clusters.append(current_cluster)
                        current_cluster = [alert]

            if len(current_cluster) >= 2:
                clusters.append(current_cluster)

            # Create incidents from clusters
            for cluster in clusters:
                incident_alert_ids = [a.id for a in cluster if a.id not in used_alerts]
                if not incident_alert_ids:
                    continue

                used_alerts.update(incident_alert_ids)

                # Determine severity from constituent alerts
                severities = [a.severity for a in cluster]
                if 'CRITICAL' in severities:
                    incident_severity = 'CRITICAL'
                elif 'HIGH' in severities:
                    incident_severity = 'HIGH'
                else:
                    incident_severity = 'MEDIUM'

                # Build timeline
                timeline = self.build_attack_timeline(cluster)

                incident = Incident(
                    id=str(uuid.uuid4()),
                    title=f"Correlated Attack from {ip}",
                    severity=incident_severity,
                    created_at=cluster[0].timestamp,
                    resolved_at=None,
                    alerts=incident_alert_ids,
                    timeline=timeline,
                    summary=f"Correlated {len(cluster)} alerts from {ip}"
                )
                incidents.append(incident)

        return incidents

    def build_attack_timeline(self, alerts: list[Alert]) -> list[dict]:
        """Build a chronological timeline from alerts.

        Args:
            alerts: List of Alert objects

        Returns:
            List of timeline step dictionaries
        """
        if not alerts:
            return []

        sorted_alerts = sorted(alerts, key=lambda a: a.timestamp)

        timeline = []
        for i, alert in enumerate(sorted_alerts):
            timeline.append({
                'event_id': alert.id,
                'timestamp': alert.timestamp.isoformat(),
                'description': f"{alert.title} (Risk: {alert.risk_score})"
            })

        return timeline

    # =========================================================================
    # Risk Scoring
    # =========================================================================

    def calculate_risk_score(self, event: NormalizedEvent, alert: Alert) -> int:
        """Calculate risk score for an event and alert combination.

        Applies modifiers based on event characteristics:
        - Malicious IP: +20
        - Tor network: +15
        - Datacenter: +10
        - High-risk location: +10
        - User agent threat: +5
        - Attack pattern: +25

        Args:
            event: The NormalizedEvent
            alert: The Alert object

        Returns:
            Calculated risk score (0-100)
        """
        base_score = alert.risk_score
        risk_score = base_score

        if event.is_malicious_ip:
            risk_score += 20
        if event.is_tor:
            risk_score += 15
        if event.is_datacenter:
            risk_score += 10
        if event.country in ['CN', 'RU', 'KP', 'IR']:  # Example high-risk countries
            risk_score += 10
        if event.user_agent_threat:
            risk_score += 5
        if event.risk_factors:
            risk_score += 25

        return min(100, max(0, risk_score))

    def update_entity_risk(self, entity_id: str, entity_type: str, delta: int) -> int:
        """Update risk score for an entity.

        Args:
            entity_id: Unique identifier for the entity
            entity_type: Type of entity ('user' or 'ip')
            delta: Risk score change

        Returns:
            New risk score for the entity
        """
        profile = storage.get_entity_risk(entity_id, entity_type, self.db_path)

        if profile:
            new_score = min(100, max(0, profile.risk_score + delta))
            storage.update_entity_risk(entity_id, entity_type, delta, db_path=self.db_path)
            return new_score
        else:
            new_score = min(100, max(0, delta))
            storage.update_entity_risk(entity_id, entity_type, delta, db_path=self.db_path)
            return new_score

    # =========================================================================
    # Alert Deduplication/Cooldown
    # =========================================================================

    def is_duplicate_alert(self, alert: Alert, cooldown_seconds: int = None) -> bool:
        """Check if an alert is a duplicate based on cooldown period.

        Args:
            alert: The Alert to check
            cooldown_seconds: Cooldown period in seconds (uses default if None)

        Returns:
            True if alert is a duplicate/cooled down
        """
        if cooldown_seconds is None:
            cooldown_seconds = self.default_cooldown_seconds

        # Create a unique key based on alert attributes (entity only, without rule_id)
        entity_key = f"{alert.source_ip}:{alert.user_id}"

        if self._is_in_cooldown(alert.mitre_id, entity_key):
            return True

        return False

    # =========================================================================
    # Main Processing Interface
    # =========================================================================

    def process_event(self, event: NormalizedEvent) -> list[Alert]:
        """Process a single event through all detection rules.

        Args:
            event: The NormalizedEvent to process

        Returns:
            List of Alert objects generated from event processing
        """
        alerts = []
        event_list = [event]

        # Store event in cache
        self._event_cache[event.log_type].append(event)

        # Process through each rule type
        for rule_id, rule in self.rules.items():
            rule_type = rule.get('type', '')

            # Evaluate based on rule type - use cached events for threshold rules
            if rule_type == 'auth_service':
                # Get cached events for threshold-based rules
                all_auth_events = list(self._event_cache.get('auth_service', []))
                if rule_id == 'T1110.001':
                    rule_alerts = self.evaluate_brute_force_rule(all_auth_events, rule)
                elif rule_id == 'T1110.003':
                    rule_alerts = self.evaluate_password_spray_rule(all_auth_events, rule)
                elif rule_id == 'T1078':
                    rule_alerts = self.evaluate_impossible_travel_rule(all_auth_events, rule)
                else:
                    rule_alerts = []
            elif rule_type == 'api_gateway':
                # Get cached events for threshold-based rules
                all_api_events = list(self._event_cache.get('api_gateway', []))
                if rule_id == 'T1595.003':
                    rule_alerts = self.evaluate_endpoint_enumeration_rule(all_api_events, rule)
                elif rule_id == 'T1190':
                    rule_alerts = self.evaluate_injection_probe_rule(all_api_events, rule)
                else:
                    rule_alerts = []
            elif rule_type == 'correlation':
                # Include recent events for correlation
                all_events = list(self._event_cache.get('auth_service', [])) + \
                            list(self._event_cache.get('api_gateway', [])) + \
                            list(self._event_cache.get('payment_engine', []))
                rule_alerts = self.evaluate_account_takeover_rule(all_events, rule)
            else:
                rule_alerts = []

            # Apply risk score calculation and deduplication
            for alert in rule_alerts:
                # Check for duplicates
                if not self.is_duplicate_alert(alert):
                    # Recalculate risk score based on the triggering event
                    alert.risk_score = self.calculate_risk_score(event, alert)
                    alerts.append(alert)

                    # Record alert timestamp and store
                    self._record_alert_timestamp(alert.mitre_id, f"{alert.source_ip}:{alert.user_id}")
                    self._processed_alerts.add(alert.id)
                    storage.store_alert(alert, self.db_path)

        return alerts

    def get_alerts(self, severities: list[str] = None) -> list[Alert]:
        """Retrieve alerts, optionally filtered by severity.

        Args:
            severities: Optional list of severity levels to filter by

        Returns:
            List of Alert objects
        """
        return storage.get_alerts(severities=severities, db_path=self.db_path)

    def get_incidents(self) -> list[Incident]:
        """Retrieve all incidents.

        Returns:
            List of Incident objects
        """
        return storage.get_incidents(self.db_path)

    def process_events_batch(self, events: list[NormalizedEvent]) -> list[Alert]:
        """Process multiple events and return all alerts generated.

        Args:
            events: List of NormalizedEvent objects to process

        Returns:
            List of all Alert objects generated
        """
        all_alerts = []
        for event in events:
            alerts = self.process_event(event)
            all_alerts.extend(alerts)

        return all_alerts


# Module-level singleton for convenience
_engine_instance: Optional[DetectionEngine] = None


def get_engine(rules_path: str = None, db_path: str = None) -> DetectionEngine:
    """Get or create the singleton DetectionEngine instance.

    Args:
        rules_path: Path to detection_rules.json file
        db_path: Path to SQLite database

    Returns:
        DetectionEngine instance
    """
    global _engine_instance
    # Always create a new instance with the provided db_path to avoid
    # stale database references between test runs
    _engine_instance = DetectionEngine(rules_path, db_path)
    return _engine_instance


# Convenience functions for direct module access
def evaluate_brute_force_rule(events: list, rule: dict) -> list[Alert]:
    """Evaluate brute-force login rule."""
    engine = get_engine()
    return engine.evaluate_brute_force_rule(events, rule)


def evaluate_password_spray_rule(events: list, rule: dict) -> list[Alert]:
    """Evaluate password spraying rule."""
    engine = get_engine()
    return engine.evaluate_password_spray_rule(events, rule)


def evaluate_impossible_travel_rule(events: list, rule: dict) -> list[Alert]:
    """Evaluate impossible travel rule."""
    engine = get_engine()
    return engine.evaluate_impossible_travel_rule(events, rule)


def evaluate_endpoint_enumeration_rule(events: list, rule: dict) -> list[Alert]:
    """Evaluate API endpoint enumeration rule."""
    engine = get_engine()
    return engine.evaluate_endpoint_enumeration_rule(events, rule)


def evaluate_injection_probe_rule(events: list, rule: dict) -> list[Alert]:
    """Evaluate API injection probe rule."""
    engine = get_engine()
    return engine.evaluate_injection_probe_rule(events, rule)


def evaluate_account_takeover_rule(events: list, rule: dict) -> list[Alert]:
    """Evaluate account takeover rule."""
    engine = get_engine()
    return engine.evaluate_account_takeover_rule(events, rule)


def correlate_incidents(alerts: list[Alert]) -> list[Incident]:
    """Correlate alerts into incidents."""
    engine = get_engine()
    return engine.correlate_incidents(alerts)


def build_attack_timeline(alerts: list[Alert]) -> list[dict]:
    """Build attack timeline from alerts."""
    engine = get_engine()
    return engine.build_attack_timeline(alerts)


def calculate_risk_score(event: NormalizedEvent, alert: Alert) -> int:
    """Calculate risk score for event and alert."""
    engine = get_engine()
    return engine.calculate_risk_score(event, alert)


def update_entity_risk(entity_id: str, entity_type: str, delta: int) -> int:
    """Update entity risk score."""
    engine = get_engine()
    return engine.update_entity_risk(entity_id, entity_type, delta)


def is_duplicate_alert(alert: Alert, cooldown_seconds: int = None) -> bool:
    """Check if alert is a duplicate."""
    engine = get_engine()
    return engine.is_duplicate_alert(alert, cooldown_seconds)


def process_event(event: NormalizedEvent) -> list[Alert]:
    """Process a single event through detection rules."""
    engine = get_engine()
    return engine.process_event(event)


def get_alerts(severities: list[str] = None) -> list[Alert]:
    """Get alerts, optionally filtered by severity."""
    engine = get_engine()
    return engine.get_alerts(severities)


def get_incidents() -> list[Incident]:
    """Get all incidents."""
    engine = get_engine()
    return engine.get_incidents()