"""Fintech Mini-SIEM & SOAR Web Console"""

from .models import NormalizedEvent, Alert, Incident, PlaybookAction, EntityProfile, Employee, Device
from .collector import LogCollector, parse_jsonl_file, batch_ingest, generate_sample_traffic, follow_file
from .enrichment import load_threat_intel, check_ip_threats, check_user_agent_threats, enrich_event
from .storage import (
    init_db, get_db_path, store_event, get_event,
    store_alert, get_alerts, store_incident, get_incidents,
    update_entity_risk, get_entity_risk,
    block_ip, freeze_account, revoke_sessions,
    get_blocked_ips, get_frozen_accounts, get_audit_log, log_audit_action
)
from .engine import DetectionEngine, get_engine
import src.soar as soar

__all__ = [
    # Models
    "NormalizedEvent", "Alert", "Incident", "PlaybookAction", "EntityProfile", "Employee", "Device",
    # Collector
    "LogCollector", "parse_jsonl_file", "batch_ingest", "generate_sample_traffic", "follow_file",
    # Enrichment
    "load_threat_intel", "check_ip_threats", "check_user_agent_threats", "enrich_event",
    # Storage
    "init_db", "get_db_path", "store_event", "get_event",
    "store_alert", "get_alerts", "store_incident", "get_incidents",
    "update_entity_risk", "get_entity_risk",
    "block_ip", "freeze_account", "revoke_sessions",
    "get_blocked_ips", "get_frozen_accounts", "get_audit_log", "log_audit_action",
    # Engine
    "DetectionEngine", "get_engine",
    # SOAR
    "soar",
]
__version__ = "0.1.0"