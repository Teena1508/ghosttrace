"""
Unit tests for event validation logic, deduplication, and malformed record detection.
"""

import json
from pathlib import Path
import pytest

from investigation_engine.models import ValidationSeverity
from investigation_engine.validation import (
    validate_event_batch,
    validate_raw_record,
)


class TestEventValidation:
    def test_validate_valid_record(self, valid_event_dict):
        event, issues = validate_raw_record(valid_event_dict)
        assert event is not None
        assert len(issues) == 0
        assert event.event_id == valid_event_dict["event_id"]

    def test_validate_null_record(self):
        event, issues = validate_raw_record(None)
        assert event is None
        assert len(issues) == 1
        assert "null" in issues[0].message.lower()

    def test_validate_non_dict_primitive(self):
        event, issues = validate_raw_record(12345)
        assert event is None
        assert len(issues) == 1
        assert "must be a json object" in issues[0].message.lower()

    def test_validate_malformed_json_string(self):
        event, issues = validate_raw_record("{ invalid json string")
        assert event is None
        assert len(issues) == 1
        assert "malformed json string" in issues[0].message.lower()

    def test_validate_json_string_payload(self, valid_event_dict):
        """String containing valid JSON should parse cleanly."""
        raw_json = json.dumps(valid_event_dict)
        event, issues = validate_raw_record(raw_json)
        assert event is not None
        assert len(issues) == 0
        assert event.event_id == valid_event_dict["event_id"]


class TestBatchValidationAndDeduplication:
    def test_duplicate_event_id_detected(self, valid_event_dict):
        # Create batch with 2 records having the same event_id
        record1 = dict(valid_event_dict)
        record2 = dict(valid_event_dict)
        # Record 2 has different timestamp but same event_id
        record2["timestamp"] = "2026-10-18T10:05:00Z"

        valid_events, result = validate_event_batch([record1, record2], deduplicate=True)
        assert result.events_processed == 2
        assert result.duplicate_events_count == 1
        assert len(valid_events) == 1
        assert not result.is_valid

        # Check duplicate issue detail
        dup_issues = [i for i in result.issues if i.field == "event_id"]
        assert len(dup_issues) == 1
        assert "duplicate event_id" in dup_issues[0].message.lower()

    def test_duplicate_without_dropping(self, valid_event_dict):
        record1 = dict(valid_event_dict)
        record2 = dict(valid_event_dict)
        valid_events, result = validate_event_batch([record1, record2], deduplicate=False)
        assert result.events_processed == 2
        assert result.duplicate_events_count == 1
        assert len(valid_events) == 2  # Not dropped when deduplicate=False

    def test_duplicate_source_event_id_detected(self, valid_event_dict):
        record1 = dict(valid_event_dict)
        record2 = dict(valid_event_dict)
        record2["event_id"] = "test-evt-002"  # Different event_id
        # Same source ('simulated_auth_log') and source_event_id ('raw-auth-999')

        valid_events, result = validate_event_batch([record1, record2])
        assert result.duplicate_events_count == 1
        # Check source_event_id issue
        source_dup_issues = [i for i in result.issues if i.field == "source_event_id"]
        assert len(source_dup_issues) == 1
        assert "duplicate source event" in source_dup_issues[0].message.lower()


class TestMalformedCasesFixtureFile:
    def test_malformed_test_cases_from_file(self, fixtures_dir: Path):
        test_file = fixtures_dir / "malformed_test_cases.json"
        assert test_file.is_file()

        with test_file.open("r", encoding="utf-8") as f:
            cases = json.load(f)

        for case in cases:
            record = case["record"]
            expected_err = case["expected_error"]
            event, issues = validate_raw_record(record)

            if expected_err is None:
                assert event is not None, f"Expected valid record for case '{case['description']}'"
                assert len(issues) == 0
            else:
                assert event is None, f"Expected error for case '{case['description']}'"
                assert len(issues) > 0
                matching = [i for i in issues if expected_err.lower() in (i.field or "").lower() or expected_err.lower() in i.message.lower()]
                assert len(matching) > 0, f"Expected error mentioning '{expected_err}', got: {[i.message for i in issues]}"
