"""Threat intelligence enrichment functions for the Fintech Mini-SIEM."""

import ipaddress
import json
from typing import Optional

from src.models import NormalizedEvent


def load_threat_intel(filepath: str = "threat_intel/local_iocs.json") -> dict:
    """Load IOC data from JSON file.

    Args:
        filepath: Path to the IOCs JSON file.

    Returns:
        Dictionary containing threat intelligence data.
    """
    with open(filepath, 'r') as f:
        return json.load(f)


def check_ip_threats(ip: str, ioc_data: dict) -> dict:
    """Check if IP is malicious, Tor, or datacenter.

    Args:
        ip: IP address to check.
        ioc_data: Dictionary containing threat intelligence data.

    Returns:
        Dictionary with is_malicious, is_tor, is_datacenter, threat_category.
    """
    result = {
        'is_malicious': False,
        'is_tor': False,
        'is_datacenter': False,
        'threat_category': ''
    }

    # Safely get IOC lists, default to empty if ioc_data is not a dict
    if not isinstance(ioc_data, dict):
        return result

    malicious_ips = ioc_data.get('malicious_ips', [])
    tor_exit_nodes = ioc_data.get('tor_exit_nodes', [])
    datacenter_ranges = ioc_data.get('datacenter_ranges', [])

    ip_obj = ipaddress.ip_address(ip)

    # Check if IP is malicious
    if ip in malicious_ips:
        result['is_malicious'] = True
        result['threat_category'] = 'malicious'
        return result

    # Check if IP is a Tor exit node
    if ip in tor_exit_nodes:
        result['is_tor'] = True
        result['threat_category'] = 'tor_exit'
        return result

    # Check if IP is in datacenter range
    for cidr in datacenter_ranges:
        network = ipaddress.ip_network(cidr, strict=False)
        if ip_obj in network:
            result['is_datacenter'] = True
            result['threat_category'] = 'datacenter'
            return result

    return result


def check_user_agent_threats(user_agent: str, ioc_data: dict) -> str:
    """Check for suspicious user agent strings.

    Args:
        user_agent: User agent string to check.
        ioc_data: Dictionary containing threat intelligence data.

    Returns:
        Name of suspicious tool detected, or empty string if none found.
    """
    if not user_agent:
        return ''

    # Safely get IOC lists, default to empty if ioc_data is not a dict
    if not isinstance(ioc_data, dict):
        return ''

    suspicious_agents = ioc_data.get('suspicious_user_agents', [])

    user_agent_lower = user_agent.lower()

    for agent in suspicious_agents:
        if agent.lower() in user_agent_lower:
            return agent.lower()

    return ''


def enrich_event(event: NormalizedEvent, ioc_data: dict) -> NormalizedEvent:
    """Enrich event with geolocation, threat intel, and risk factors.

    Args:
        event: NormalizedEvent to enrich.
        ioc_data: Dictionary containing threat intelligence data.

    Returns:
        Enriched NormalizedEvent with threat intel and risk factors.
    """
    # Get IP threat information
    ip_threats = check_ip_threats(event.source_ip, ioc_data)

    # Get user agent threat information
    user_agent_threat = check_user_agent_threats(event.user_agent, ioc_data)

    # Initialize risk factors list
    risk_factors = []

    # Build country string based on threat intel
    # For offline mode, we derive country from IP type
    country = event.country
    asn = event.asn

    # Determine risk factors based on threat intel
    if ip_threats['is_malicious']:
        risk_factors.append('malicious_ip')
        country = 'UNKNOWN'
        asn = 'UNKNOWN'

    if ip_threats['is_tor']:
        risk_factors.append('tor_exit')

    if ip_threats['is_datacenter']:
        risk_factors.append('datacenter')

    if user_agent_threat:
        risk_factors.append('suspicious_user_agent')

    # Create enriched event with updated fields
    enriched_event = NormalizedEvent(
        id=event.id,
        log_type=event.log_type,
        timestamp=event.timestamp,
        source_ip=event.source_ip,
        user_id=event.user_id,
        target_user=event.target_user,
        method=event.method,
        path=event.path,
        status_code=event.status_code,
        user_agent=event.user_agent,
        country=country,
        asn=asn,
        is_tor=ip_threats['is_tor'],
        is_datacenter=ip_threats['is_datacenter'],
        is_malicious_ip=ip_threats['is_malicious'],
        user_agent_threat=user_agent_threat,
        amount=event.amount,
        currency=event.currency,
        recipient=event.recipient,
        risk_factors=risk_factors
    )

    return enriched_event