"""
Unit tests for canonical SecurityEvent schema and timestamp parsing.
"""

from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from investigation_engine.models import (
    EventSeverity,
    EventType,
    SecurityEvent,
)


class TestSecurityEventSchema:
    def test_valid_minimal_event(self):
        """Verify that event with only required fields instantiates cleanly."""
        data = {
            "event_id": "min-001",
            "timestamp": "2026-10-18T10:30:00Z",
            "event_type": "AUTHENTICATION",
            "source": "simulated_syslog",
            "original_event_data": {"raw": "some raw message"},
        }
        event = SecurityEvent(**data)
        assert event.event_id == "min-001"
        assert event.timestamp == datetime(2026, 10, 18, 10, 30, 0, tzinfo=timezone.utc)
        assert event.event_type == EventType.AUTHENTICATION
        assert event.source == "simulated_syslog"
        assert event.severity == EventSeverity.INFORMATIONAL
        assert event.is_suspicious is False
        # Optional fields default to None
        assert event.host_id is None
        assert event.user_id is None
        assert event.source_ip is None
        assert event.session_id is None
        assert event.process_id is None
        assert event.file_path is None
        # Fallback for source_event_id defaults to event_id if no inner ID found
        assert event.source_event_id == "min-001"
        assert event.original_event_data == {"raw": "some raw message"}

    def test_source_event_id_extraction_from_raw_record(self):
        """Verify source_event_id falls back to original_event_data id/record_id if omitted."""
        data = {
            "event_id": "norm-999",
            "timestamp": "2026-10-18T10:30:00Z",
            "event_type": "PROCESS_EXECUTION",
            "source": "simulated_auditd",
            "original_event_data": {"record_id": "audit-88123", "command": "ls"},
        }
        event = SecurityEvent(**data)
        assert event.source_event_id == "audit-88123"

    def test_missing_required_fields(self):
        """Verify ValidationError when mandatory fields are omitted."""
        # Missing event_id
        with pytest.raises(ValidationError) as exc:
            SecurityEvent(
                timestamp="2026-10-18T10:00:00Z",
                event_type=EventType.AUTHENTICATION,
                source="test",
                original_event_data={"raw": "test"},
            )
        assert "event_id" in str(exc.value)

        # Missing source
        with pytest.raises(ValidationError) as exc:
            SecurityEvent(
                event_id="evt-1",
                timestamp="2026-10-18T10:00:00Z",
                event_type=EventType.AUTHENTICATION,
                original_event_data={"raw": "test"},
            )
        assert "source" in str(exc.value)

        # Missing original_event_data (critical for evidence provenance)
        with pytest.raises(ValidationError) as exc:
            SecurityEvent(
                event_id="evt-1",
                timestamp="2026-10-18T10:00:00Z",
                event_type=EventType.AUTHENTICATION,
                source="test",
            )
        assert "original_event_data" in str(exc.value)


class TestTimestampParsing:
    def test_parse_iso_with_z(self):
        event = SecurityEvent(
            event_id="t-1",
            timestamp="2026-10-18T14:22:30Z",
            event_type="AUTHENTICATION",
            source="test",
            original_event_data={},
        )
        assert event.timestamp == datetime(2026, 10, 18, 14, 22, 30, tzinfo=timezone.utc)

    def test_parse_iso_with_timezone_offset(self):
        # 14:00 with +02:00 is 12:00 UTC
        event = SecurityEvent(
            event_id="t-2",
            timestamp="2026-10-18T14:00:00+02:00",
            event_type="FILE_AUDIT",
            source="test",
            original_event_data={},
        )
        assert event.timestamp.tzinfo == timezone.utc
        assert event.timestamp.hour == 12

    def test_parse_epoch_seconds(self):
        # Epoch timestamp 1760788800 is 2025-10-18T12:00:00 UTC
        epoch_ts = 1760788800
        event = SecurityEvent(
            event_id="t-3",
            timestamp=epoch_ts,
            event_type="NETWORK_CONNECTION",
            source="test",
            original_event_data={},
        )
        assert event.timestamp.tzinfo == timezone.utc
        assert int(event.timestamp.timestamp()) == epoch_ts

    def test_parse_epoch_milliseconds(self):
        epoch_ms = 1760788800000
        event = SecurityEvent(
            event_id="t-4",
            timestamp=epoch_ms,
            event_type="NETWORK_CONNECTION",
            source="test",
            original_event_data={},
        )
        assert event.timestamp.tzinfo == timezone.utc
        assert int(event.timestamp.timestamp()) == 1760788800

    def test_parse_native_datetime(self):
        dt = datetime(2026, 10, 18, 9, 15, tzinfo=timezone.utc)
        event = SecurityEvent(
            event_id="t-5",
            timestamp=dt,
            event_type="PROCESS_EXECUTION",
            source="test",
            original_event_data={},
        )
        assert event.timestamp == dt

    def test_invalid_timestamp_string(self):
        with pytest.raises(ValidationError) as exc:
            SecurityEvent(
                event_id="t-bad",
                timestamp="this-is-not-a-timestamp",
                event_type="AUTHENTICATION",
                source="test",
                original_event_data={},
            )
        assert "Unable to parse timestamp" in str(exc.value)

    def test_empty_timestamp_string(self):
        with pytest.raises(ValidationError) as exc:
            SecurityEvent(
                event_id="t-empty",
                timestamp="   ",
                event_type="AUTHENTICATION",
                source="test",
                original_event_data={},
            )
        assert "Timestamp string cannot be empty" in str(exc.value)


class TestEnumValidation:
    def test_valid_event_types(self):
        for et in EventType:
            event = SecurityEvent(
                event_id=f"evt-{et.value}",
                timestamp="2026-10-18T10:00:00Z",
                event_type=et,
                source="test",
                original_event_data={},
            )
            assert event.event_type == et

    def test_invalid_event_type_raises(self):
        with pytest.raises(ValidationError):
            SecurityEvent(
                event_id="evt-invalid-type",
                timestamp="2026-10-18T10:00:00Z",
                event_type="INVALID_SECURITY_EVENT_TYPE",
                source="test",
                original_event_data={},
            )
