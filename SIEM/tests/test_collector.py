"""Tests for log collector module."""

import json
import pytest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

from src.collector import (
    parse_auth_log,
    parse_api_gateway_log,
    parse_payment_log,
    parse_jsonl_file,
    batch_ingest,
    follow_file,
    generate_sample_traffic,
    LogCollector,
)
from src.models import NormalizedEvent


class TestAuthLogParser:
    """Test parse_auth_log function."""

    def test_valid_auth_log(self):
        log_line = json.dumps({
            "timestamp": "2024-01-15T10:00:00Z",
            "source_ip": "192.168.1.100",
            "user_id": "user123",
            "event_type": "LOGIN_SUCCESS",
            "method": "password",
            "status_code": 200,
            "device_id": "device-abc123",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        })

        event = parse_auth_log(log_line)

        assert event is not None
        assert isinstance(event, NormalizedEvent)
        assert event.log_type == "auth_service"
        assert event.source_ip == "192.168.1.100"
        assert event.user_id == "user123"
        assert event.method == "password"
        assert event.status_code == 200
        assert event.user_agent == "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

    def test_invalid_json(self):
        assert parse_auth_log("not a json string") is None

    def test_missing_required_fields(self):
        # Missing user_id
        log_line = json.dumps({
            "timestamp": "2024-01-15T10:00:00Z",
            "source_ip": "192.168.1.100",
            "event_type": "LOGIN_SUCCESS",
            "method": "password",
            "status_code": 200
        })
        assert parse_auth_log(log_line) is None

    def test_invalid_timestamp(self):
        log_line = json.dumps({
            "timestamp": "invalid-timestamp",
            "source_ip": "192.168.1.100",
            "user_id": "user123",
            "event_type": "LOGIN_SUCCESS",
            "method": "password",
            "status_code": 200
        })
        assert parse_auth_log(log_line) is None


class TestApiGatewayLogParser:
    """Test parse_api_gateway_log function."""

    def test_valid_api_gateway_log(self):
        log_line = json.dumps({
            "timestamp": "2024-01-15T10:00:00Z",
            "source_ip": "10.0.0.1",
            "user_id": "user456",
            "method": "GET",
            "path": "/api/v1/users/123",
            "status_code": 200,
            "user_agent": "Mozilla/5.0...",
            "latency_ms": 150,
            "request_size": 1024,
            "response_size": 2048,
            "request_body": {"param": "value"},
            "response_body": {"data": "..."}
        })

        event = parse_api_gateway_log(log_line)

        assert event is not None
        assert isinstance(event, NormalizedEvent)
        assert event.log_type == "api_gateway"
        assert event.source_ip == "10.0.0.1"
        assert event.user_id == "user456"
        assert event.method == "GET"
        assert event.path == "/api/v1/users/123"
        assert event.status_code == 200

    def test_invalid_json(self):
        assert parse_api_gateway_log("invalid json") is None

    def test_missing_required_fields(self):
        # Missing path
        log_line = json.dumps({
            "timestamp": "2024-01-15T10:00:00Z",
            "source_ip": "10.0.0.1",
            "user_id": "user456",
            "method": "GET",
            "status_code": 200
        })
        assert parse_api_gateway_log(log_line) is None


class TestPaymentLogParser:
    """Test parse_payment_log function."""

    def test_valid_payment_log(self):
        log_line = json.dumps({
            "timestamp": "2024-01-15T10:00:00Z",
            "source_ip": "192.168.1.200",
            "user_id": "user789",
            "transaction_id": "txn-abc123",
            "type": "CARD_PAYMENT",
            "amount": 99.99,
            "currency": "USD",
            "status": "SUCCESS",
            "recipient_account": "acc-recipient-123",
            "card_bin": "411111",
            "device_id": "device-xyz789",
            "risk_score": 25
        })

        event = parse_payment_log(log_line)

        assert event is not None
        assert isinstance(event, NormalizedEvent)
        assert event.log_type == "payment_engine"
        assert event.source_ip == "192.168.1.200"
        assert event.user_id == "user789"
        assert event.amount == 99.99
        assert event.currency == "USD"
        assert event.recipient == "acc-recipient-123"
        assert event.status_code == 200

    def test_failed_payment_status_code(self):
        log_line = json.dumps({
            "timestamp": "2024-01-15T10:00:00Z",
            "source_ip": "192.168.1.200",
            "user_id": "user789",
            "transaction_id": "txn-abc123",
            "type": "CARD_PAYMENT",
            "amount": 99.99,
            "currency": "USD",
            "status": "FAILED",
            "recipient_account": "acc-recipient-123"
        })

        event = parse_payment_log(log_line)
        assert event is not None
        assert event.status_code == 400

    def test_invalid_json(self):
        assert parse_payment_log("invalid json") is None

    def test_missing_required_fields(self):
        # Missing transaction_id
        log_line = json.dumps({
            "timestamp": "2024-01-15T10:00:00Z",
            "source_ip": "192.168.1.200",
            "user_id": "user789",
            "type": "CARD_PAYMENT",
            "amount": 99.99,
            "currency": "USD",
            "status": "SUCCESS"
        })
        assert parse_payment_log(log_line) is None


class TestJsonlParsing:
    """Test JSONL file parsing and auto-detection."""

    def test_parse_jsonl_file_auto_detect(self, tmp_path):
        # Create a sample JSONL file with mixed logs
        log_file = tmp_path / "test_logs.jsonl"
        logs = [
            {
                "timestamp": "2024-01-15T10:00:00Z",
                "source_ip": "192.168.1.100",
                "user_id": "user123",
                "event_type": "LOGIN_SUCCESS",
                "method": "password",
                "status_code": 200
            },
            {
                "timestamp": "2024-01-15T10:01:00Z",
                "source_ip": "10.0.0.1",
                "user_id": "user456",
                "method": "GET",
                "path": "/api/v1/users",
                "status_code": 200,
                "latency_ms": 100
            },
            {
                "timestamp": "2024-01-15T10:02:00Z",
                "source_ip": "192.168.1.200",
                "user_id": "user789",
                "transaction_id": "txn-1",
                "type": "CARD_PAYMENT",
                "amount": 50.0,
                "currency": "USD",
                "status": "SUCCESS"
            }
        ]

        with open(log_file, "w") as f:
            for log in logs:
                f.write(json.dumps(log) + "\n")

        events = parse_jsonl_file(str(log_file))

        assert len(events) == 3
        assert events[0].log_type == "auth_service"
        assert events[1].log_type == "api_gateway"
        assert events[2].log_type == "payment_engine"

    def test_parse_jsonl_file_explicit_type(self, tmp_path):
        log_file = tmp_path / "test_auth.jsonl"
        logs = [
            {
                "timestamp": "2024-01-15T10:00:00Z",
                "source_ip": "192.168.1.100",
                "user_id": "user123",
                "event_type": "LOGIN_SUCCESS",
                "method": "password",
                "status_code": 200
            }
        ]

        with open(log_file, "w") as f:
            for log in logs:
                f.write(json.dumps(log) + "\n")

        events = parse_jsonl_file(str(log_file), log_type="auth_service")

        assert len(events) == 1
        assert events[0].log_type == "auth_service"

    def test_nonexistent_file(self):
        with pytest.raises(FileNotFoundError):
            parse_jsonl_file("non_existent_file.jsonl")


class TestBatchIngest:
    """Test batch ingestion logic."""

    def test_batch_ingest(self):
        event = NormalizedEvent(
            id="1",
            log_type="auth_service",
            timestamp=datetime.now(timezone.utc),
            source_ip="127.0.0.1",
            user_id="user1",
            target_user=None,
            method="password",
            path="/auth",
            status_code=200,
            user_agent="test",
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

        events = [event] * 250
        count = batch_ingest(events, batch_size=100)

        assert count == 250

    def test_empty_batch(self):
        assert batch_ingest([]) == 0


class TestFollowFile:
    """Test live follow mode."""

    def test_follow_file_seeking_to_end(self, tmp_path):
        """Test that follow_file seeks to end by default (skips existing content)."""
        log_file = tmp_path / "live.jsonl"

        # Write initial content
        log_data = {
            "timestamp": "2024-01-15T10:00:00Z",
            "source_ip": "192.168.1.100",
            "user_id": "user123",
            "event_type": "LOGIN_SUCCESS",
            "method": "password",
            "status_code": 200
        }

        with open(log_file, "w") as f:
            f.write(json.dumps(log_data) + "\n")

        collector = LogCollector()
        mock_callback = MagicMock()

        # Run follow with max_lines=1 and seek_to_end=True (default)
        # This should read 0 lines since we're seeking to end
        collector.follow_file(str(log_file), callback=mock_callback, max_lines=1, seek_to_end=True)

        # Callback should not have been called since file was seek to end
        mock_callback.assert_not_called()

    def test_follow_file_with_seek_to_start(self, tmp_path):
        """Test that follow_file reads existing content when seek_to_end=False."""
        log_file = tmp_path / "live.jsonl"

        # Write initial content
        log_data = {
            "timestamp": "2024-01-15T10:00:00Z",
            "source_ip": "192.168.1.100",
            "user_id": "user123",
            "event_type": "LOGIN_SUCCESS",
            "method": "password",
            "status_code": 200
        }

        with open(log_file, "w") as f:
            f.write(json.dumps(log_data) + "\n")

        collector = LogCollector()
        mock_callback = MagicMock()

        # Run follow with seek_to_end=False, max_lines=1
        collector.follow_file(str(log_file), callback=mock_callback, max_lines=1, seek_to_end=False)

        # Callback should have been called once
        mock_callback.assert_called_once()
        call_args = mock_callback.call_args[0][0]
        assert isinstance(call_args, NormalizedEvent)
        assert call_args.log_type == "auth_service"

    def test_follow_file_max_lines(self, tmp_path):
        """Test that follow_file respects max_lines limit."""
        log_file = tmp_path / "live.jsonl"

        collector = LogCollector()
        mock_callback = MagicMock()

        # Write multiple lines
        with open(log_file, "w") as f:
            for i in range(5):
                log_data = {
                    "timestamp": f"2024-01-15T10:0{i}:00Z",
                    "source_ip": f"192.168.1.{i}",
                    "user_id": f"user{i}",
                    "event_type": "LOGIN_SUCCESS",
                    "method": "password",
                    "status_code": 200
                }
                f.write(json.dumps(log_data) + "\n")

        # Run follow with max_lines=2
        collector.follow_file(str(log_file), callback=mock_callback, max_lines=2, seek_to_end=False)

        # Callback should have been called exactly 2 times
        assert mock_callback.call_count == 2

    def test_follow_file_not_found(self):
        """Test that follow_file raises FileNotFoundError for missing file."""
        collector = LogCollector()
        with pytest.raises(FileNotFoundError):
            collector.follow_file("non_existent_file.jsonl", seek_to_end=False)


class TestGenerateSampleTraffic:
    """Test sample traffic generation."""

    def test_generate_sample_traffic(self, tmp_path):
        output_file = tmp_path / "sample.jsonl"
        count = generate_sample_traffic(count=50, output_path=str(output_file))

        assert count > 0
        assert output_file.exists()

        # Verify lines are valid JSON
        with open(output_file, "r") as f:
            lines = f.readlines()
            assert len(lines) == count
            for line in lines:
                data = json.loads(line)
                assert "timestamp" in data
                assert "source_ip" in data
