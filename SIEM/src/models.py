"""Data models for the Fintech Mini-SIEM."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class NormalizedEvent:
    """Represents a normalized security event from various log sources."""

    id: str
    log_type: str
    timestamp: datetime
    source_ip: str
    user_id: Optional[str]
    target_user: Optional[str]
    method: str
    path: str
    status_code: int
    user_agent: str
    country: str
    asn: str
    is_tor: bool
    is_datacenter: bool
    is_malicious_ip: bool
    user_agent_threat: str
    amount: float
    currency: str
    recipient: str
    risk_factors: list[str] = field(default_factory=list)


@dataclass
class Alert:
    """Represents a security alert generated from event analysis."""

    id: str
    event_id: str
    mitre_id: str
    severity: str
    risk_score: int
    title: str
    description: str
    timestamp: datetime
    source_ip: str
    user_id: str
    status: str
    correlated: bool


@dataclass
class Incident:
    """Represents a security incident composed of multiple alerts."""

    id: str
    title: str
    severity: str
    created_at: datetime
    resolved_at: Optional[datetime]
    alerts: list[str]
    timeline: list[dict]
    summary: str


@dataclass
class PlaybookAction:
    """Represents an automated security response action."""

    id: str
    action_type: str
    target: str
    reason: str
    performed_by: str
    timestamp: datetime
    details: dict = field(default_factory=dict)


@dataclass
class EntityProfile:
    """Represents risk profile for a user or IP entity."""

    entity_id: str
    entity_type: str
    risk_score: int
    last_updated: datetime
    risk_factors: list[str] = field(default_factory=list)
    associated_events: int = 0


@dataclass
class Employee:
    """Represents a corporate employee with security posture data."""
    employee_id: str
    full_name: str
    email: str
    department: str  # Core Banking, Payments & Clearing, Fraud Operations, DevSecOps, Cloud Infrastructure, Mobile Engineering, Risk & Compliance, Treasury
    role: str
    employment_type: str  # Employee or Contingent
    work_mode: str  # Office or Remote
    city: str
    country: str
    training_completed: bool
    risk_score: int  # 0-100
    status: str  # ACTIVE or FROZEN


@dataclass
class Device:
    """Represents a corporate device with security posture data."""
    device_id: str
    hostname: str  # Realistic corporate formats like FIN-MBP-4821, PAY-WIN-9034, SEC-LNX-1172, OPS-MBP-6309
    employee_id: str
    employee_name: str
    device_type: str  # Laptop, Workstation, Server, Mobile
    os_name: str  # macOS 15.2, Windows 11 24H2, Ubuntu 24.04 LTS, iOS 18.1
    employment_type: str  # Employee or Contingent
    work_mode: str  # Office or Remote
    ip_address: str
    city: str
    country: str
    lat: float
    lon: float
    compliance_status: str  # Compliant, Exceptions, Non-Compliant
    edr_status: str  # Protected, Outdated Agent, Tamper Alert
    isolated: bool