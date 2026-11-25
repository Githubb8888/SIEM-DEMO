"""Log Collector & Normalizer for Fintech Mini-SIEM."""

import json
import time
import signal
import sys
import random
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, Callable, List
from uuid import uuid4

from .models import NormalizedEvent
from .storage import get_employees, get_devices, seed_realistic_environment


class LogCollector:
    """Collects and normalizes log events from multiple fintech telemetry streams."""

    def __init__(self):
        self.running = False
        self._shutdown = False
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle graceful shutdown signals."""
        self._shutdown = True
        self.running = False

    def parse_auth_log(self, line: str) -> Optional[NormalizedEvent]:
        """
        Parse auth_service log line (JSON) and normalize to NormalizedEvent.

        Args:
            line: JSON log line from auth service

        Returns:
            NormalizedEvent or None if parsing fails
        """
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        # Validate required fields
        required_fields = ["timestamp", "source_ip", "user_id", "event_type", "method", "status_code"]
        for field in required_fields:
            if field not in data:
                return None

        try:
            timestamp = datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return None

        return NormalizedEvent(
            id=str(uuid4()),
            log_type="auth_service",
            timestamp=timestamp,
            source_ip=data["source_ip"],
            user_id=data.get("user_id"),
            target_user=None,
            method=data.get("method", "unknown"),
            path="/auth",
            status_code=data.get("status_code", 0),
            user_agent=data.get("user_agent", ""),
            country="",
            asn="",
            is_tor=False,
            is_datacenter=False,
            is_malicious_ip=False,
            user_agent_threat="",
            amount=0.0,
            currency="",
            recipient="",
            risk_factors=[]
        )

    def parse_api_gateway_log(self, line: str) -> Optional[NormalizedEvent]:
        """
        Parse api_gateway log line (JSON) and normalize to NormalizedEvent.

        Args:
            line: JSON log line from API gateway

        Returns:
            NormalizedEvent or None if parsing fails
        """
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        # Validate required fields
        required_fields = ["timestamp", "source_ip", "user_id", "method", "path", "status_code"]
        for field in required_fields:
            if field not in data:
                return None

        try:
            timestamp = datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return None

        return NormalizedEvent(
            id=str(uuid4()),
            log_type="api_gateway",
            timestamp=timestamp,
            source_ip=data["source_ip"],
            user_id=data.get("user_id"),
            target_user=None,
            method=data.get("method", "unknown"),
            path=data.get("path", "/"),
            status_code=data.get("status_code", 0),
            user_agent=data.get("user_agent", ""),
            country="",
            asn="",
            is_tor=False,
            is_datacenter=False,
            is_malicious_ip=False,
            user_agent_threat="",
            amount=0.0,
            currency="",
            recipient="",
            risk_factors=[]
        )

    def parse_payment_log(self, line: str) -> Optional[NormalizedEvent]:
        """
        Parse payment_engine log line (JSON) and normalize to NormalizedEvent.

        Args:
            line: JSON log line from payment engine

        Returns:
            NormalizedEvent or None if parsing fails
        """
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        # Validate required fields
        required_fields = ["timestamp", "source_ip", "user_id", "transaction_id", "type", "amount", "currency", "status"]
        for field in required_fields:
            if field not in data:
                return None

        try:
            timestamp = datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return None

        return NormalizedEvent(
            id=str(uuid4()),
            log_type="payment_engine",
            timestamp=timestamp,
            source_ip=data["source_ip"],
            user_id=data.get("user_id"),
            target_user=data.get("recipient_account"),
            method=data.get("type", "unknown"),
            path="/payment",
            status_code=200 if data.get("status") == "SUCCESS" else 400,
            user_agent=data.get("device_id", ""),
            country="",
            asn="",
            is_tor=False,
            is_datacenter=False,
            is_malicious_ip=False,
            user_agent_threat="",
            amount=float(data.get("amount", 0)),
            currency=data.get("currency", "USD"),
            recipient=data.get("recipient_account", ""),
            risk_factors=[]
        )

    def _detect_log_type(self, line: str) -> Optional[str]:
        """Auto-detect log type from JSON content."""
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        # Check for payment_engine fields
        if "transaction_id" in data and "type" in data and "amount" in data:
            return "payment_engine"

        # Check for api_gateway fields
        if "path" in data and "method" in data and "status_code" in data and "latency_ms" in data:
            return "api_gateway"

        # Check for auth_service fields
        if "event_type" in data and "method" in data and "status_code" in data:
            return "auth_service"

        return None

    def parse_jsonl_file(self, filepath: str, log_type: str = None) -> List[NormalizedEvent]:
        """
        Parse entire JSONL file and return list of normalized events.

        Args:
            filepath: Path to JSONL file
            log_type: Optional log type override

        Returns:
            List of NormalizedEvent objects
        """
        events = []
        path = Path(filepath)

        if not path.exists():
            raise FileNotFoundError(f"File not found: {filepath}")

        with open(path, "r") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                detected_type = log_type or self._detect_log_type(line)

                event = None
                if detected_type == "auth_service":
                    event = self.parse_auth_log(line)
                elif detected_type == "api_gateway":
                    event = self.parse_api_gateway_log(line)
                elif detected_type == "payment_engine":
                    event = self.parse_payment_log(line)

                if event:
                    events.append(event)

        return events

    def batch_ingest(self, events: List[NormalizedEvent], batch_size: int = 100) -> int:
        """
        Ingest events in batches. Returns count of successfully ingested events.

        Args:
            events: List of NormalizedEvent objects
            batch_size: Number of events per batch

        Returns:
            Count of successfully ingested events
        """
        if not events:
            return 0

        # In a real implementation, this would write to a database/queue
        # For now, we just simulate successful ingestion
        count = 0
        for i in range(0, len(events), batch_size):
            batch = events[i:i + batch_size]
            # Simulate batch processing
            count += len(batch)

        return count

    def follow_file(self, filepath: str, callback: Callable = None, max_lines: int = None, seek_to_end: bool = True) -> None:
        """
        Live tail mode for monitoring log files.

        Args:
            filepath: Path to JSONL file to follow
            callback: Function to call with each new event
            max_lines: Maximum lines to process (None for unlimited)
            seek_to_end: If True, start from end of file; if False, process from beginning
        """
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {filepath}")

        self.running = True
        self._shutdown = False
        line_count = 0
        consecutive_empty = 0
        max_empty_reads = 10  # Stop after 10 consecutive empty reads (1 second)

        with open(path, "r") as f:
            # Seek to end or beginning of file based on parameter
            if seek_to_end:
                f.seek(0, 2)
            else:
                f.seek(0)

            while self.running and not self._shutdown:
                line = f.readline()
                if not line:
                    if seek_to_end:
                        consecutive_empty += 1
                        if max_lines and line_count >= max_lines:
                            break
                        if consecutive_empty >= max_empty_reads:
                            break  # No new content after reasonable wait
                        time.sleep(0.1)
                    else:
                        break
                    continue

                consecutive_empty = 0
                line = line.strip()
                if not line:
                    continue

                event = None
                detected_type = self._detect_log_type(line)

                if detected_type == "auth_service":
                    event = self.parse_auth_log(line)
                elif detected_type == "api_gateway":
                    event = self.parse_api_gateway_log(line)
                elif detected_type == "payment_engine":
                    event = self.parse_payment_log(line)

                if event and callback:
                    callback(event)

                line_count += 1
                if max_lines and line_count >= max_lines:
                    break


def _load_db_entities():
    """Load employees and devices from database, seeding if empty."""
    employees = get_employees()
    devices = get_devices()

    if not employees or not devices:
        print("Database empty, seeding with realistic environment...")
        seed_realistic_environment()
        employees = get_employees()
        devices = get_devices()

    return employees, devices


def _get_devices_for_employee(employee_id: str, devices: list) -> list:
    """Get all devices for an employee."""
    return [d for d in devices if d.employee_id == employee_id]


def generate_sample_traffic(count: int = 1000, output_path: str = "sample_logs/fintech_stream.jsonl", attack_ratio: float = 0.3) -> int:
    """
    Generate realistic fintech traffic with normal and attack patterns.
    Uses real employee and device data from the seeded database.
    Ensures all 6 MITRE ATT&CK attack types are included and linked to real entities.

    Args:
        count: Number of events to generate
        output_path: Path to output JSONL file
        attack_ratio: Ratio of attack traffic (0.0-1.0)

    Returns:
        Count of events generated
    """
    # Load real employees and devices from database
    employees, devices = _load_db_entities()

    if not employees or not devices:
        raise RuntimeError("Failed to load employees and devices from database")

    # Separate employees by type for attack targeting
    regular_employees = [e for e in employees if e.employment_type == "Employee"]
    contingent_employees = [e for e in employees if e.employment_type == "Contingent"]
    all_employees = regular_employees + contingent_employees

    # Get device info for each employee
    employee_devices = {}
    for emp in all_employees:
        employee_devices[emp.employee_id] = _get_devices_for_employee(emp.employee_id, devices)

    # Attack IPs (external threat actor IPs)
    attack_ips = {
        "brute_force": "203.0.113.100",
        "password_spray": "203.0.113.101",
        "impossible_travel_1": "198.51.100.10",
        "impossible_travel_2": "198.51.100.20",
        "api_enum": "203.0.113.102",
        "sql_injection": "203.0.113.103",
        "high_value_transfer": "203.0.113.104"
    }

    # Methods and paths
    auth_methods = ["password", "mfa", "totp", "sms"]
    auth_events = ["LOGIN_SUCCESS", "LOGIN_FAILED", "MFA_CHALLENGE", "PASSWORD_RESET"]
    http_methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]
    api_paths = [
        "/api/v1/users", "/api/v1/accounts", "/api/v1/transactions",
        "/api/v1/cards", "/api/v1/transfers", "/api/v1/settings",
        "/api/v1/admin", "/api/v1/audit", "/api/v1/reports"
    ]
    payment_types = ["CARD_PAYMENT", "P2P_TRANSFER", "REFUND", "WIRE_TRANSFER", "ACH_TRANSFER"]
    payment_statuses = ["SUCCESS", "FAILED", "PENDING"]
    currencies = ["USD", "EUR", "GBP"]

    # User agents matching device OS types
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
        "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36"
    ]

    # Normal IPs for regular traffic (corporate network ranges)
    normal_ips = [f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}" for _ in range(50)]

    output_dir = Path(output_path).parent
    output_dir.mkdir(parents=True, exist_ok=True)

    generated = 0
    base_time = datetime.now(timezone.utc) - timedelta(hours=2)  # Start 2 hours ago

    # Ensure all 6 attack types are always included with real employee/device data
    attack_types = [
        "brute_force", "password_spray", "impossible_travel",
        "api_enum", "sql_injection", "high_value_transfer"
    ]

    # Pick real employees for attack scenarios
    # Brute force: target a specific employee (high-value target like finance/treasury)
    brute_force_victim = random.choice([e for e in all_employees if e.department in ["Treasury", "Payments & Clearing", "Core Banking"]])
    brute_force_victim_devices = employee_devices.get(brute_force_victim.employee_id, [])
    brute_force_device = random.choice(brute_force_victim_devices) if brute_force_victim_devices else None

    # Password spray: target multiple employees across departments
    spray_targets = random.sample(all_employees, min(12, len(all_employees)))

    # Impossible travel: target an employee who travels (remote worker or different country)
    travel_victim = random.choice([e for e in all_employees if e.work_mode == "Remote" or e.country != "USA"])
    travel_victim_devices = employee_devices.get(travel_victim.employee_id, [])
    travel_device = random.choice(travel_victim_devices) if travel_victim_devices else None

    # API enumeration: target a dev/engineer
    enum_actor = random.choice([e for e in all_employees if e.department in ["DevSecOps", "Cloud Infrastructure", "Mobile Engineering", "Core Banking"]])
    enum_devices = employee_devices.get(enum_actor.employee_id, [])
    enum_device = random.choice(enum_devices) if enum_devices else None

    # SQL injection: target an employee with API access
    sql_actor = random.choice([e for e in all_employees if e.department in ["DevSecOps", "Core Banking", "Payments & Clearing"]])
    sql_devices = employee_devices.get(sql_actor.employee_id, [])
    sql_device = random.choice(sql_devices) if sql_devices else None

    # High-value transfer: multi-stage - compromise an employee first, then transfer
    # Stage 1: Credential theft (brute force or phishing simulation)
    # Stage 2: High-value wire transfer
    hvf_victim = random.choice([e for e in all_employees if e.department in ["Treasury", "Payments & Clearing", "Core Banking", "Fraud Operations"]])
    hvf_victim_devices = employee_devices.get(hvf_victim.employee_id, [])
    hvf_device = random.choice(hvf_victim_devices) if hvf_victim_devices else None

    with open(output_path, "w") as f:
        # First, generate guaranteed attacks for each type using REAL employee/device data
        # Only generate guaranteed attacks if attack_ratio > 0
        if attack_ratio > 0:
            for attack_type in attack_types:
                if attack_type == "brute_force":
                    # T1110.001: Brute-Force Login - 10+ failed logins from same IP for same user within 60s
                    # Target: real employee from finance/treasury
                    victim = brute_force_victim
                    device = brute_force_device

                    for j in range(12):
                        timestamp = base_time + timedelta(seconds=j * 5)
                        log = {
                            "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
                            "source_ip": attack_ips["brute_force"],
                            "user_id": victim.employee_id,
                            "event_type": "LOGIN_FAILED",
                            "method": random.choice(auth_methods),
                            "status_code": 401,
                            "device_id": device.device_id if device else "unknown",
                            "user_agent": random.choice(user_agents),
                            "employee_name": victim.full_name,
                            "employee_email": victim.email,
                            "employee_department": victim.department,
                            "device_hostname": device.hostname if device else "unknown",
                            "device_ip": device.ip_address if device else "unknown"
                        }
                        f.write(json.dumps(log) + "\n")
                        generated += 1

                    # One successful login after brute force (credential compromised)
                    timestamp = base_time + timedelta(seconds=65)
                    log = {
                        "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
                        "source_ip": attack_ips["brute_force"],
                        "user_id": victim.employee_id,
                        "event_type": "LOGIN_SUCCESS",
                        "method": "password",
                        "status_code": 200,
                        "device_id": device.device_id if device else "unknown",
                        "user_agent": random.choice(user_agents),
                        "employee_name": victim.full_name,
                        "employee_email": victim.email,
                        "employee_department": victim.department,
                        "device_hostname": device.hostname if device else "unknown",
                        "device_ip": device.ip_address if device else "unknown"
                    }
                    f.write(json.dumps(log) + "\n")
                    generated += 1

                elif attack_type == "password_spray":
                    # T1110.003: Password Spraying - 6+ failed logins from same IP across 4+ users within 5m
                    for user in spray_targets:
                        user_devices = employee_devices.get(user.employee_id, [])
                        user_device = random.choice(user_devices) if user_devices else None

                        timestamp = base_time + timedelta(seconds=random.randint(0, 240))
                        log = {
                            "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
                            "source_ip": attack_ips["password_spray"],
                            "user_id": user.employee_id,
                            "event_type": "LOGIN_FAILED",
                            "method": "password",
                            "status_code": 401,
                            "device_id": user_device.device_id if user_device else "unknown",
                            "user_agent": random.choice(user_agents),
                            "employee_name": user.full_name,
                            "employee_email": user.email,
                            "employee_department": user.department,
                            "device_hostname": user_device.hostname if user_device else "unknown",
                            "device_ip": user_device.ip_address if user_device else "unknown"
                        }
                        f.write(json.dumps(log) + "\n")
                        generated += 1

                elif attack_type == "impossible_travel":
                    # T1078: Impossible Travel - 2 successful logins from different countries within 60m
                    victim = travel_victim
                    device = travel_device

                    # First login from home country
                    t1 = base_time
                    log = {
                        "timestamp": t1.isoformat().replace("+00:00", "Z"),
                        "source_ip": attack_ips["impossible_travel_1"],
                        "user_id": victim.employee_id,
                        "event_type": "LOGIN_SUCCESS",
                        "method": "password",
                        "status_code": 200,
                        "device_id": device.device_id if device else "unknown",
                        "user_agent": random.choice(user_agents),
                        "employee_name": victim.full_name,
                        "employee_email": victim.email,
                        "employee_department": victim.department,
                        "device_hostname": device.hostname if device else "unknown",
                        "device_ip": device.ip_address if device else "unknown",
                        "country": victim.country,
                        "city": victim.city
                    }
                    f.write(json.dumps(log) + "\n")
                    generated += 1

                    # Second login from different country (impossible travel)
                    t2 = base_time + timedelta(minutes=45)
                    # Pick a different country for the attack IP
                    other_countries = ["UK", "Germany", "France", "Japan", "Singapore", "Australia", "Brazil", "UAE"]
                    attack_country = random.choice([c for c in other_countries if c != victim.country])

                    log = {
                        "timestamp": t2.isoformat().replace("+00:00", "Z"),
                        "source_ip": attack_ips["impossible_travel_2"],
                        "user_id": victim.employee_id,
                        "event_type": "LOGIN_SUCCESS",
                        "method": "password",
                        "status_code": 200,
                        "device_id": device.device_id if device else "unknown",
                        "user_agent": random.choice(user_agents),
                        "employee_name": victim.full_name,
                        "employee_email": victim.email,
                        "employee_department": victim.department,
                        "device_hostname": device.hostname if device else "unknown",
                        "device_ip": device.ip_address if device else "unknown",
                        "country": attack_country,
                        "city": "Unknown"
                    }
                    f.write(json.dumps(log) + "\n")
                    generated += 1

                elif attack_type == "api_enum":
                    # T1595.003: API Endpoint Enumeration - 15+ HTTP 403/404 errors from same IP within 60s
                    actor = enum_actor
                    device = enum_device

                    for j in range(22):
                        timestamp = base_time + timedelta(seconds=j * 2)
                        # Enumerate various API endpoints
                        enum_path = random.choice(api_paths) + f"/{random.randint(1, 1000)}"
                        log = {
                            "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
                            "source_ip": attack_ips["api_enum"],
                            "user_id": actor.employee_id,
                            "method": random.choice(http_methods),
                            "path": enum_path,
                            "status_code": random.choice([403, 404]),
                            "user_agent": random.choice(user_agents),
                            "latency_ms": random.randint(50, 200),
                            "request_size": random.randint(100, 1000),
                            "response_size": random.randint(100, 500),
                            "device_id": device.device_id if device else "unknown",
                            "employee_name": actor.full_name,
                            "employee_email": actor.email,
                            "employee_department": actor.department,
                            "device_hostname": device.hostname if device else "unknown",
                            "device_ip": device.ip_address if device else "unknown"
                        }
                        f.write(json.dumps(log) + "\n")
                        generated += 1

                elif attack_type == "sql_injection":
                    # T1190: SQLi/Payload Injection Probe - SQLi, path traversal, or JWT/IDOR patterns
                    actor = sql_actor
                    device = sql_device

                    sql_payloads = [
                        "' OR '1'='1", "'; DROP TABLE users; --",
                        "1 UNION SELECT * FROM passwords", "' OR 1=1 --",
                        "admin'--", "' OR '1'='1' --",
                        "../etc/passwd", "..\\windows\\system32",
                        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",  # JWT tampering
                        "'; INSERT INTO transactions (amount) VALUES (999999); --",
                        "1; SELECT * FROM accounts WHERE balance > 100000; --"
                    ]
                    for j in range(15):
                        timestamp = base_time + timedelta(seconds=j * 3)
                        payload = random.choice(sql_payloads)
                        log = {
                            "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
                            "source_ip": attack_ips["sql_injection"],
                            "user_id": actor.employee_id,
                            "method": "POST",
                            "path": "/api/v1/search",
                            "status_code": random.choice([400, 422, 500]),
                            "user_agent": random.choice(user_agents),
                            "latency_ms": random.randint(100, 500),
                            "request_size": random.randint(200, 2000),
                            "response_size": random.randint(200, 1000),
                            "request_body": {"query": payload},
                            "response_body": {"error": "Invalid query"},
                            "device_id": device.device_id if device else "unknown",
                            "employee_name": actor.full_name,
                            "employee_email": actor.email,
                            "employee_department": actor.department,
                            "device_hostname": device.hostname if device else "unknown",
                            "device_ip": device.ip_address if device else "unknown"
                        }
                        f.write(json.dumps(log) + "\n")
                        generated += 1

                elif attack_type == "high_value_transfer":
                    # T1078 + T1657: Multi-Stage Account Takeover & High-Value Wire Fraud (CRITICAL)
                    # Stage 1: Credential compromise (simulated via brute force on treasury employee)
                    # Stage 2: High-value wire transfers to attacker accounts
                    victim = hvf_victim
                    device = hvf_device

                    # Stage 1: Failed login attempts (credential stuffing)
                    for j in range(8):
                        timestamp = base_time + timedelta(minutes=j * 2)
                        log = {
                            "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
                            "source_ip": attack_ips["high_value_transfer"],
                            "user_id": victim.employee_id,
                            "event_type": "LOGIN_FAILED",
                            "method": "password",
                            "status_code": 401,
                            "device_id": device.device_id if device else "unknown",
                            "user_agent": random.choice(user_agents),
                            "employee_name": victim.full_name,
                            "employee_email": victim.email,
                            "employee_department": victim.department,
                            "device_hostname": device.hostname if device else "unknown",
                            "device_ip": device.ip_address if device else "unknown"
                        }
                        f.write(json.dumps(log) + "\n")
                        generated += 1

                    # Stage 1b: Successful login (credentials compromised)
                    timestamp = base_time + timedelta(minutes=18)
                    log = {
                        "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
                        "source_ip": attack_ips["high_value_transfer"],
                        "user_id": victim.employee_id,
                        "event_type": "LOGIN_SUCCESS",
                        "method": "password",
                        "status_code": 200,
                        "device_id": device.device_id if device else "unknown",
                        "user_agent": random.choice(user_agents),
                        "employee_name": victim.full_name,
                        "employee_email": victim.email,
                        "employee_department": victim.department,
                        "device_hostname": device.hostname if device else "unknown",
                        "device_ip": device.ip_address if device else "unknown"
                    }
                    f.write(json.dumps(log) + "\n")
                    generated += 1

                    # Stage 2: High-value wire transfers
                    for j in range(5):
                        timestamp = base_time + timedelta(minutes=20 + j * 10)
                        amount = round(random.uniform(25000, 150000), 2)  # High-value transfers
                        log = {
                            "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
                            "source_ip": attack_ips["high_value_transfer"],
                            "user_id": victim.employee_id,
                            "transaction_id": f"txn-{random.randint(100000, 999999)}",
                            "type": "WIRE_TRANSFER",
                            "amount": amount,
                            "currency": "USD",
                            "status": "SUCCESS",
                            "recipient_account": f"attacker-acct-{random.randint(10000, 99999)}",
                            "card_bin": "",
                            "device_id": device.device_id if device else "unknown",
                            "risk_score": random.randint(85, 99),
                            "employee_name": victim.full_name,
                            "employee_email": victim.email,
                            "employee_department": victim.department,
                            "device_hostname": device.hostname if device else "unknown",
                            "device_ip": device.ip_address if device else "unknown"
                        }
                        f.write(json.dumps(log) + "\n")
                        generated += 1

        # Fill remaining with normal traffic and additional random attacks
        remaining = count - generated

        # Track which attack types we've already generated extra events for
        extra_attacks_generated = {at: 0 for at in attack_types}

        for i in range(remaining):
            # 70% normal, 30% attack
            is_attack = random.random() < attack_ratio

            if is_attack:
                # Pick an attack pattern
                attack_type = random.choice(attack_types)

                # Limit extra attacks per type to keep variety
                if extra_attacks_generated[attack_type] >= 3:
                    # Pick a different attack type
                    other_types = [at for at in attack_types if extra_attacks_generated[at] < 3]
                    if other_types:
                        attack_type = random.choice(other_types)
                    else:
                        is_attack = False

                if is_attack:
                    extra_attacks_generated[attack_type] += 1

                    if attack_type == "brute_force":
                        # Target random employee
                        victim = random.choice(all_employees)
                        victim_devices = employee_devices.get(victim.employee_id, [])
                        device = random.choice(victim_devices) if victim_devices else None

                        for j in range(random.randint(10, 15)):
                            timestamp = base_time + timedelta(hours=random.randint(0, 2), seconds=j * 5)
                            log = {
                                "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
                                "source_ip": attack_ips["brute_force"],
                                "user_id": victim.employee_id,
                                "event_type": "LOGIN_FAILED",
                                "method": random.choice(auth_methods),
                                "status_code": 401,
                                "device_id": device.device_id if device else "unknown",
                                "user_agent": random.choice(user_agents),
                                "employee_name": victim.full_name,
                                "employee_email": victim.email,
                                "employee_department": victim.department,
                                "device_hostname": device.hostname if device else "unknown",
                                "device_ip": device.ip_address if device else "unknown"
                            }
                            f.write(json.dumps(log) + "\n")
                            generated += 1

                    elif attack_type == "password_spray":
                        # Target multiple random employees
                        targets = random.sample(all_employees, min(random.randint(6, 12), len(all_employees)))
                        for user in targets:
                            user_devices = employee_devices.get(user.employee_id, [])
                            user_device = random.choice(user_devices) if user_devices else None

                            timestamp = base_time + timedelta(hours=random.randint(0, 2), seconds=random.randint(0, 60))
                            log = {
                                "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
                                "source_ip": attack_ips["password_spray"],
                                "user_id": user.employee_id,
                                "event_type": "LOGIN_FAILED",
                                "method": "password",
                                "status_code": 401,
                                "device_id": user_device.device_id if user_device else "unknown",
                                "user_agent": random.choice(user_agents),
                                "employee_name": user.full_name,
                                "employee_email": user.email,
                                "employee_department": user.department,
                                "device_hostname": user_device.hostname if user_device else "unknown",
                                "device_ip": user_device.ip_address if user_device else "unknown"
                            }
                            f.write(json.dumps(log) + "\n")
                            generated += 1

                    elif attack_type == "impossible_travel":
                        victim = random.choice([e for e in all_employees if e.work_mode == "Remote"])
                        victim_devices = employee_devices.get(victim.employee_id, [])
                        device = random.choice(victim_devices) if victim_devices else None

                        t1 = base_time + timedelta(hours=random.randint(0, 2))
                        t2 = t1 + timedelta(minutes=random.randint(30, 55))

                        for ip, t, country in [(attack_ips["impossible_travel_1"], t1, victim.country),
                                                (attack_ips["impossible_travel_2"], t2, random.choice(["UK", "Germany", "Japan", "Singapore"]))]:
                            log = {
                                "timestamp": t.isoformat().replace("+00:00", "Z"),
                                "source_ip": ip,
                                "user_id": victim.employee_id,
                                "event_type": "LOGIN_SUCCESS",
                                "method": "password",
                                "status_code": 200,
                                "device_id": device.device_id if device else "unknown",
                                "user_agent": random.choice(user_agents),
                                "employee_name": victim.full_name,
                                "employee_email": victim.email,
                                "employee_department": victim.department,
                                "device_hostname": device.hostname if device else "unknown",
                                "device_ip": device.ip_address if device else "unknown",
                                "country": country,
                                "city": victim.city if country == victim.country else "Unknown"
                            }
                            f.write(json.dumps(log) + "\n")
                            generated += 1

                    elif attack_type == "api_enum":
                        actor = random.choice([e for e in all_employees if e.department in ["DevSecOps", "Cloud Infrastructure", "Core Banking"]])
                        actor_devices = employee_devices.get(actor.employee_id, [])
                        device = random.choice(actor_devices) if actor_devices else None

                        for j in range(random.randint(20, 30)):
                            timestamp = base_time + timedelta(hours=random.randint(0, 2), seconds=j * 2)
                            log = {
                                "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
                                "source_ip": attack_ips["api_enum"],
                                "user_id": actor.employee_id,
                                "method": random.choice(http_methods),
                                "path": random.choice(api_paths) + f"/{random.randint(1, 1000)}",
                                "status_code": random.choice([403, 404]),
                                "user_agent": random.choice(user_agents),
                                "latency_ms": random.randint(50, 200),
                                "request_size": random.randint(100, 1000),
                                "response_size": random.randint(100, 500),
                                "device_id": device.device_id if device else "unknown",
                                "employee_name": actor.full_name,
                                "employee_email": actor.email,
                                "employee_department": actor.department,
                                "device_hostname": device.hostname if device else "unknown",
                                "device_ip": device.ip_address if device else "unknown"
                            }
                            f.write(json.dumps(log) + "\n")
                            generated += 1

                    elif attack_type == "sql_injection":
                        actor = random.choice([e for e in all_employees if e.department in ["DevSecOps", "Core Banking", "Payments & Clearing"]])
                        actor_devices = employee_devices.get(actor.employee_id, [])
                        device = random.choice(actor_devices) if actor_devices else None

                        sql_payloads = [
                            "' OR '1'='1", "'; DROP TABLE users; --",
                            "1 UNION SELECT * FROM passwords", "' OR 1=1 --",
                            "admin'--", "' OR '1'='1' --"
                        ]
                        for j in range(random.randint(10, 20)):
                            timestamp = base_time + timedelta(hours=random.randint(0, 2), seconds=j * 3)
                            payload = random.choice(sql_payloads)
                            log = {
                                "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
                                "source_ip": attack_ips["sql_injection"],
                                "user_id": actor.employee_id,
                                "method": "POST",
                                "path": "/api/v1/search",
                                "status_code": random.choice([400, 422, 500]),
                                "user_agent": random.choice(user_agents),
                                "latency_ms": random.randint(100, 500),
                                "request_size": random.randint(200, 2000),
                                "response_size": random.randint(200, 1000),
                                "request_body": {"query": payload},
                                "response_body": {"error": "Invalid query"},
                                "device_id": device.device_id if device else "unknown",
                                "employee_name": actor.full_name,
                                "employee_email": actor.email,
                                "employee_department": actor.department,
                                "device_hostname": device.hostname if device else "unknown",
                                "device_ip": device.ip_address if device else "unknown"
                            }
                            f.write(json.dumps(log) + "\n")
                            generated += 1

                    elif attack_type == "high_value_transfer":
                        victim = random.choice([e for e in all_employees if e.department in ["Treasury", "Payments & Clearing", "Core Banking"]])
                        victim_devices = employee_devices.get(victim.employee_id, [])
                        device = random.choice(victim_devices) if victim_devices else None

                        # Simplified: just the transfer events (assume already compromised)
                        for j in range(random.randint(3, 6)):
                            timestamp = base_time + timedelta(hours=random.randint(0, 2), minutes=j * 10)
                            amount = round(random.uniform(20000, 100000), 2)
                            log = {
                                "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
                                "source_ip": attack_ips["high_value_transfer"],
                                "user_id": victim.employee_id,
                                "transaction_id": f"txn-{random.randint(100000, 999999)}",
                                "type": "WIRE_TRANSFER",
                                "amount": amount,
                                "currency": "USD",
                                "status": "SUCCESS",
                                "recipient_account": f"attacker-acct-{random.randint(10000, 99999)}",
                                "card_bin": "",
                                "device_id": device.device_id if device else "unknown",
                                "risk_score": random.randint(80, 95),
                                "employee_name": victim.full_name,
                                "employee_email": victim.email,
                                "employee_department": victim.department,
                                "device_hostname": device.hostname if device else "unknown",
                                "device_ip": device.ip_address if device else "unknown"
                            }
                            f.write(json.dumps(log) + "\n")
                            generated += 1
            else:
                # Normal traffic using real employees and devices
                log_type = random.choice(["auth_service", "api_gateway", "payment_engine"])
                timestamp = base_time + timedelta(seconds=random.randint(0, 7200))  # Within 2 hours

                # Pick a random employee and their device
                employee = random.choice(all_employees)
                emp_devices = employee_devices.get(employee.employee_id, [])
                device = random.choice(emp_devices) if emp_devices else None
                source_ip = device.ip_address if device else random.choice(normal_ips)

                if log_type == "auth_service":
                    # Normal auth: mostly success, some failures
                    event_type = random.choices(auth_events, weights=[75, 15, 5, 5])[0]
                    status_code = 200 if event_type == "LOGIN_SUCCESS" else 401

                    log = {
                        "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
                        "source_ip": source_ip,
                        "user_id": employee.employee_id,
                        "event_type": event_type,
                        "method": random.choice(auth_methods),
                        "status_code": status_code,
                        "device_id": device.device_id if device else "unknown",
                        "user_agent": random.choice(user_agents),
                        "employee_name": employee.full_name,
                        "employee_email": employee.email,
                        "employee_department": employee.department,
                        "device_hostname": device.hostname if device else "unknown",
                        "device_ip": device.ip_address if device else "unknown"
                    }
                elif log_type == "api_gateway":
                    log = {
                        "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
                        "source_ip": source_ip,
                        "user_id": employee.employee_id,
                        "method": random.choice(http_methods),
                        "path": random.choice(api_paths),
                        "status_code": random.choices([200, 201, 400, 401, 403, 404, 500], weights=[65, 10, 5, 5, 5, 5, 5])[0],
                        "user_agent": random.choice(user_agents),
                        "latency_ms": random.randint(50, 300),
                        "request_size": random.randint(100, 2000),
                        "response_size": random.randint(200, 5000),
                        "request_body": {"param": "value"},
                        "response_body": {"data": "..."},
                        "device_id": device.device_id if device else "unknown",
                        "employee_name": employee.full_name,
                        "employee_email": employee.email,
                        "employee_department": employee.department,
                        "device_hostname": device.hostname if device else "unknown",
                        "device_ip": device.ip_address if device else "unknown"
                    }
                else:  # payment_engine
                    log = {
                        "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
                        "source_ip": source_ip,
                        "user_id": employee.employee_id,
                        "transaction_id": f"txn-{random.randint(100000, 999999)}",
                        "type": random.choice(payment_types),
                        "amount": round(random.uniform(10, 5000), 2),
                        "currency": random.choice(currencies),
                        "status": random.choices(payment_statuses, weights=[90, 5, 5])[0],
                        "recipient_account": f"acc-{random.randint(1000, 9999)}",
                        "card_bin": "411111" if random.random() < 0.7 else "",
                        "device_id": device.device_id if device else "unknown",
                        "risk_score": random.randint(0, 25),
                        "employee_name": employee.full_name,
                        "employee_email": employee.email,
                        "employee_department": employee.department,
                        "device_hostname": device.hostname if device else "unknown",
                        "device_ip": device.ip_address if device else "unknown"
                    }

                f.write(json.dumps(log) + "\n")
                generated += 1

    return generated


# Convenience functions for direct module usage
_collector = LogCollector()

def parse_auth_log(line: str) -> Optional[NormalizedEvent]:
    return _collector.parse_auth_log(line)

def parse_api_gateway_log(line: str) -> Optional[NormalizedEvent]:
    return _collector.parse_api_gateway_log(line)

def parse_payment_log(line: str) -> Optional[NormalizedEvent]:
    return _collector.parse_payment_log(line)

def parse_jsonl_file(filepath: str, log_type: str = None) -> List[NormalizedEvent]:
    return _collector.parse_jsonl_file(filepath, log_type)

def batch_ingest(events: List[NormalizedEvent], batch_size: int = 100) -> int:
    return _collector.batch_ingest(events, batch_size)

def follow_file(filepath: str, callback: Callable = None, max_lines: int = None, seek_to_end: bool = True) -> None:
    return _collector.follow_file(filepath, callback, max_lines, seek_to_end)


def main():
    """CLI entry point for generating sample traffic."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate fintech traffic with attack patterns for SIEM testing"
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=1000,
        help="Number of events to generate (default: 1000)"
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default="sample_logs/fintech_stream.jsonl",
        help="Output file path (default: sample_logs/fintech_stream.jsonl)"
    )
    parser.add_argument(
        "--attack-ratio",
        type=float,
        default=0.3,
        help="Ratio of attack traffic (0.0-1.0, default: 0.3)"
    )
    parser.add_argument(
        "--seed-db",
        action="store_true",
        help="Seed the database with 75 employees and 110 devices before generating traffic"
    )
    parser.add_argument(
        "--reset-db",
        action="store_true",
        help="Reset the database before seeding (use with --seed-db)"
    )

    args = parser.parse_args()

    if not 0 <= args.attack_ratio <= 1:
        print("Error: attack-ratio must be between 0.0 and 1.0")
        sys.exit(1)

    # Seed database if requested
    if args.seed_db or args.reset_db:
        print("Seeding database with 75 employees and 110 devices...")
        emp_count, dev_count = seed_realistic_environment(reset=args.reset_db)
        print(f"Seeded {emp_count} employees and {dev_count} devices")

    # Verify database has data
    employees = get_employees()
    devices = get_devices()
    if not employees or not devices:
        print("Error: Database not seeded. Run with --seed-db first.")
        sys.exit(1)

    print(f"Database has {len(employees)} employees and {len(devices)} devices")
    print(f"Generating {args.count} events with {args.attack_ratio*100:.0f}% attack traffic...")
    print(f"Output: {args.output}")

    count = generate_sample_traffic(args.count, args.output, args.attack_ratio)

    print(f"Generated {count} events successfully!")


if __name__ == "__main__":
    main()