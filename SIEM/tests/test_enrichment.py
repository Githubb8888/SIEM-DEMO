"""Tests for the enrichment module."""

import pytest
from datetime import datetime
from unittest.mock import patch

from src.enrichment import (
    load_threat_intel,
    check_ip_threats,
    check_user_agent_threats,
    enrich_event
)
from src.models import NormalizedEvent


class TestLoadThreatIntel:
    """Tests for load_threat_intel function."""

    def test_load_threat_intel_returns_dict(self):
        """Verify load_threat_intel returns a dictionary."""
        ioc_data = load_threat_intel()
        assert isinstance(ioc_data, dict)

    def test_load_threat_intel_has_required_keys(self):
        """Verify loaded IOC data has all required keys."""
        ioc_data = load_threat_intel()
        required_keys = [
            'malicious_ips',
            'tor_exit_nodes',
            'datacenter_ranges',
            'suspicious_user_agents',
            'suspicious_asns',
            'disposable_email_domains',
            'suspicious_card_bins'
        ]
        for key in required_keys:
            assert key in ioc_data, f"Missing key: {key}"

    def test_load_threat_intel_malicious_ips_is_list(self):
        """Verify malicious_ips is a list."""
        ioc_data = load_threat_intel()
        assert isinstance(ioc_data['malicious_ips'], list)

    def test_load_threat_intel_datacenter_ranges_is_list(self):
        """Verify datacenter_ranges is a list."""
        ioc_data = load_threat_intel()
        assert isinstance(ioc_data['datacenter_ranges'], list)

    def test_load_threat_intel_default_path(self):
        """Test loading with default path."""
        ioc_data = load_threat_intel("threat_intel/local_iocs.json")
        assert 'malicious_ips' in ioc_data


class TestCheckIpThreats:
    """Tests for check_ip_threats function."""

    @pytest.fixture
    def ioc_data(self):
        """Load IOC data for tests."""
        return load_threat_intel()

    def test_malicious_ip_detected(self, ioc_data):
        """Test detection of malicious IP."""
        result = check_ip_threats('198.51.100.10', ioc_data)
        assert result['is_malicious'] is True
        assert result['is_tor'] is False
        assert result['is_datacenter'] is False
        assert result['threat_category'] == 'malicious'

    def test_tor_exit_node_detected(self, ioc_data):
        """Test detection of Tor exit node."""
        result = check_ip_threats('192.0.2.50', ioc_data)
        assert result['is_malicious'] is False
        assert result['is_tor'] is True
        assert result['is_datacenter'] is False
        assert result['threat_category'] == 'tor_exit'

    def test_datacenter_ip_detected(self, ioc_data):
        """Test detection of datacenter IP."""
        result = check_ip_threats('13.107.1.50', ioc_data)
        assert result['is_malicious'] is False
        assert result['is_tor'] is False
        assert result['is_datacenter'] is True
        assert result['threat_category'] == 'datacenter'

    def test_datacenter_ip_in_52_range(self, ioc_data):
        """Test detection of datacenter IP in 52.0.0.0/8 range."""
        result = check_ip_threats('52.100.50.100', ioc_data)
        assert result['is_datacenter'] is True
        assert result['threat_category'] == 'datacenter'

    def test_benign_ip_returns_false(self, ioc_data):
        """Test that benign IP returns all False."""
        result = check_ip_threats('8.8.8.8', ioc_data)
        assert result['is_malicious'] is False
        assert result['is_tor'] is False
        assert result['is_datacenter'] is False
        assert result['threat_category'] == ''

    def test_malicious_ip_takes_precedence_over_tor(self, ioc_data):
        """Test that malicious IP takes precedence if IP is in both lists."""
        # 198.51.100.20 is in both malicious_ips and tor_exit_nodes
        result = check_ip_threats('198.51.100.20', ioc_data)
        assert result['is_malicious'] is True
        assert result['threat_category'] == 'malicious'


class TestCheckUserAgentThreats:
    """Tests for check_user_agent_threats function."""

    @pytest.fixture
    def ioc_data(self):
        """Load IOC data for tests."""
        return load_threat_intel()

    def test_sqlmap_detected(self, ioc_data):
        """Test detection of sqlmap user agent."""
        result = check_user_agent_threats('sqlmap/1.4.7', ioc_data)
        assert result == 'sqlmap'

    def test_nikto_detected(self, ioc_data):
        """Test detection of nikto user agent."""
        result = check_user_agent_threats('Nikto/2.1.6', ioc_data)
        assert result == 'nikto'

    def test_nmap_detected(self, ioc_data):
        """Test detection of nmap user agent."""
        result = check_user_agent_threats('Nmap Scripting Engine', ioc_data)
        assert result == 'nmap'

    def test_burp_detected(self, ioc_data):
        """Test detection of burp user agent."""
        result = check_user_agent_threats('Burp Suite', ioc_data)
        assert result == 'burp'

    def test_python_requests_detected(self, ioc_data):
        """Test detection of python-requests user agent."""
        result = check_user_agent_threats('python-requests/2.28.0', ioc_data)
        assert result == 'python-requests'

    def test_curl_detected(self, ioc_data):
        """Test detection of curl user agent."""
        result = check_user_agent_threats('curl/7.68.0', ioc_data)
        assert result == 'curl'

    def test_wget_detected(self, ioc_data):
        """Test detection of wget user agent."""
        result = check_user_agent_threats('Wget/1.20.3', ioc_data)
        assert result == 'wget'

    def test_normal_user_agent_returns_empty(self, ioc_data):
        """Test that normal user agent returns empty string."""
        result = check_user_agent_threats('Mozilla/5.0 (Windows NT 10.0; Win64; x64)', ioc_data)
        assert result == ''

    def test_empty_string_returns_empty(self, ioc_data):
        """Test that empty user agent returns empty string."""
        result = check_user_agent_threats('', ioc_data)
        assert result == ''

    def test_none_user_agent_returns_empty(self, ioc_data):
        """Test that None user agent returns empty string."""
        result = check_user_agent_threats(None, ioc_data)
        assert result == ''

    def test_case_insensitive_detection(self, ioc_data):
        """Test detection is case insensitive."""
        result = check_user_agent_threats('SQLMAP/1.4.7', ioc_data)
        assert result == 'sqlmap'


class TestEnrichEvent:
    """Tests for enrich_event function."""

    @pytest.fixture
    def ioc_data(self):
        """Load IOC data for tests."""
        return load_threat_intel()

    @pytest.fixture
    def base_event(self, ioc_data):
        """Create a base event for testing."""
        return NormalizedEvent(
            id='test-event-123',
            log_type='auth_service',
            timestamp=datetime(2024, 1, 15, 10, 30, 0),
            source_ip='198.51.100.10',
            user_id='user456',
            target_user='target789',
            method='LOGIN',
            path='/api/auth/login',
            status_code=401,
            user_agent='sqlmap/1.4.7',
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

    def test_enriches_malicious_ip(self, base_event, ioc_data):
        """Test enrichment marks malicious IP correctly."""
        enriched = enrich_event(base_event, ioc_data)
        assert enriched.is_malicious_ip is True

    def test_enriches_tor_detected(self, base_event, ioc_data):
        """Test enrichment marks Tor exit node correctly."""
        # Create event with Tor IP
        tor_event = NormalizedEvent(
            id='test-event-tor',
            log_type='auth_service',
            timestamp=datetime(2024, 1, 15, 10, 30, 0),
            source_ip='192.0.2.50',
            user_id='user456',
            target_user='target789',
            method='GET',
            path='/api/data',
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
        enriched = enrich_event(tor_event, ioc_data)
        assert enriched.is_tor is True
        assert 'tor_exit' in enriched.risk_factors

    def test_enriches_datacenter_detected(self, base_event, ioc_data):
        """Test enrichment marks datacenter IP correctly."""
        dc_event = NormalizedEvent(
            id='test-event-dc',
            log_type='api_gateway',
            timestamp=datetime(2024, 1, 15, 10, 30, 0),
            source_ip='13.107.1.50',
            user_id='user456',
            target_user='target789',
            method='GET',
            path='/api/data',
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
        enriched = enrich_event(dc_event, ioc_data)
        assert enriched.is_datacenter is True
        assert 'datacenter' in enriched.risk_factors

    def test_enriches_user_agent_threat(self, base_event, ioc_data):
        """Test enrichment detects suspicious user agent."""
        enriched = enrich_event(base_event, ioc_data)
        assert enriched.user_agent_threat == 'sqlmap'
        assert 'suspicious_user_agent' in enriched.risk_factors

    def test_enriches_multiple_risk_factors(self, ioc_data):
        """Test enrichment with multiple risk factors."""
        multi_event = NormalizedEvent(
            id='test-event-multi',
            log_type='auth_service',
            timestamp=datetime(2024, 1, 15, 10, 30, 0),
            source_ip='192.0.2.50',
            user_id='user456',
            target_user='target789',
            method='LOGIN',
            path='/api/auth/login',
            status_code=401,
            user_agent='nmap script',
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
        enriched = enrich_event(multi_event, ioc_data)
        assert enriched.is_tor is True
        assert enriched.user_agent_threat == 'nmap'
        assert 'tor_exit' in enriched.risk_factors
        assert 'suspicious_user_agent' in enriched.risk_factors

    def test_enriches_benign_event(self, ioc_data):
        """Test enrichment of benign event adds no risk factors."""
        benign_event = NormalizedEvent(
            id='test-event-benign',
            log_type='api_gateway',
            timestamp=datetime(2024, 1, 15, 10, 30, 0),
            source_ip='1.1.1.1',
            user_id='user456',
            target_user='target789',
            method='GET',
            path='/api/data',
            status_code=200,
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
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
        enriched = enrich_event(benign_event, ioc_data)
        assert enriched.is_malicious_ip is False
        assert enriched.is_tor is False
        assert enriched.is_datacenter is False
        assert enriched.user_agent_threat == ''
        assert enriched.risk_factors == []

    def test_enriches_preserves_original_fields(self, base_event, ioc_data):
        """Test that enrichment preserves original event fields."""
        enriched = enrich_event(base_event, ioc_data)
        assert enriched.id == base_event.id
        assert enriched.log_type == base_event.log_type
        assert enriched.timestamp == base_event.timestamp
        assert enriched.source_ip == base_event.source_ip
        assert enriched.method == base_event.method
        assert enriched.path == base_event.path
        assert enriched.status_code == base_event.status_code
        assert enriched.amount == base_event.amount
        assert enriched.currency == base_event.currency
        assert enriched.recipient == base_event.recipient

    def test_enriches_updates_country_for_malicious(self, ioc_data):
        """Test that country is set to UNKNOWN for malicious IP."""
        malicious_event = NormalizedEvent(
            id='test-event-malicious',
            log_type='auth_service',
            timestamp=datetime(2024, 1, 15, 10, 30, 0),
            source_ip='198.51.100.10',
            user_id='user456',
            target_user='target789',
            method='LOGIN',
            path='/api/auth/login',
            status_code=401,
            user_agent='curl/7.68.0',
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
        enriched = enrich_event(malicious_event, ioc_data)
        assert enriched.country == 'UNKNOWN'

    def test_enriches_null_user_id_preserved(self, ioc_data):
        """Test that None user_id is preserved during enrichment."""
        null_user_event = NormalizedEvent(
            id='test-event-null-user',
            log_type='api_gateway',
            timestamp=datetime(2024, 1, 15, 10, 30, 0),
            source_ip='1.1.1.1',
            user_id=None,
            target_user='target789',
            method='GET',
            path='/api/data',
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
        enriched = enrich_event(null_user_event, ioc_data)
        assert enriched.user_id is None


class TestEdgeCases:
    """Tests for edge cases in enrichment functions."""

    @pytest.fixture
    def ioc_data(self):
        """Load IOC data for tests."""
        return load_threat_intel()

    def test_check_ip_threats_invalid_ip_format(self, ioc_data):
        """Test check_ip_threats with invalid IP format."""
        # Python ipaddress module will raise ValueError for invalid IP
        with pytest.raises(ValueError):
            check_ip_threats('not-a-valid-ip', ioc_data)

    def test_check_user_agent_threats_case_insensitive(self, ioc_data):
        """Test user agent detection is case insensitive."""
        result = check_user_agent_threats('CURL/7.68.0', ioc_data)
        # curl/ is in the list, so either 'curl' or 'curl/' could be returned
        assert result in ['curl', 'curl/']

    def test_enrich_event_with_all_suspicious_indicators(self, ioc_data):
        """Test enrichment with multiple suspicious indicators."""
        event = NormalizedEvent(
            id='test-event-all-suspicious',
            log_type='auth_service',
            timestamp=datetime(2024, 1, 15, 10, 30, 0),
            source_ip='198.51.100.10',
            user_id='user456',
            target_user='target789',
            method='POST',
            path='/api/auth/login',
            status_code=401,
            user_agent='sqlmap/1.4.7',
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
        enriched = enrich_event(event, ioc_data)
        assert enriched.is_malicious_ip is True
        assert enriched.user_agent_threat == 'sqlmap'
        assert enriched.country == 'UNKNOWN'
        assert enriched.risk_factors == ['malicious_ip', 'suspicious_user_agent']

    def test_empty_ioc_data(self):
        """Test functions handle empty IOC data gracefully."""
        empty_ioc = {
            'malicious_ips': [],
            'tor_exit_nodes': [],
            'datacenter_ranges': [],
            'suspicious_user_agents': [],
            'suspicious_asns': [],
            'disposable_email_domains': [],
            'suspicious_card_bins': []
        }

        result = check_ip_threats('1.1.1.1', empty_ioc)
        assert result['is_malicious'] is False
        assert result['is_tor'] is False
        assert result['is_datacenter'] is False

        result_ua = check_user_agent_threats('Mozilla/5.0', empty_ioc)
        assert result_ua == ''