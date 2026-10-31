"""
Validation engine for GhostTrace security events.
Provides schema validation, timestamp parsing checks, duplicate event detection,
and robust handling of malformed records.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import ValidationError

from investigation_engine.models import (
    SecurityEvent,
    ValidationIssue,
    ValidationResult,
    ValidationSeverity,
)


def validate_raw_record(record: Any) -> Tuple[Optional[SecurityEvent], List[ValidationIssue]]:
    """
    Validate a single raw record against the canonical SecurityEvent schema.
    Returns (SecurityEvent, []) if valid, or (None, [issues]) if invalid.
    """
    issues: List[ValidationIssue] = []

    if record is None:
        issues.append(
            ValidationIssue(
                field=None,
                message="Record is null / empty",
                severity=ValidationSeverity.ERROR,
            )
        )
        return None, issues

    # If passed as string, attempt JSON deserialization
    if isinstance(record, str):
        try:
            record = json.loads(record)
        except Exception as exc:
            issues.append(
                ValidationIssue(
                    field=None,
                    message=f"Malformed JSON string: {exc}",
                    severity=ValidationSeverity.ERROR,
                )
            )
            return None, issues

    if not isinstance(record, dict):
        issues.append(
            ValidationIssue(
                field=None,
                message=f"Record must be a JSON object / dict, got {type(record).__name__}",
                severity=ValidationSeverity.ERROR,
            )
        )
        return None, issues

    raw_id = str(record.get("event_id") or record.get("id") or "<unknown>")

    try:
        event = SecurityEvent(**record)
        return event, issues
    except ValidationError as val_err:
        for err in val_err.errors():
            loc = ".".join(str(p) for p in err["loc"])
            issues.append(
                ValidationIssue(
                    field=loc,
                    message=err["msg"],
                    severity=ValidationSeverity.ERROR,
                    raw_record_id=raw_id,
                )
            )
        return None, issues
    except Exception as exc:
        issues.append(
            ValidationIssue(
                field=None,
                message=f"Unexpected parsing error: {exc}",
                severity=ValidationSeverity.ERROR,
                raw_record_id=raw_id,
            )
        )
        return None, issues


def validate_event_batch(
    records: List[Any],
    deduplicate: bool = True,
) -> Tuple[List[SecurityEvent], ValidationResult]:
    """
    Validate and parse a batch of events.
    Checks for:
    - Malformed records
    - Missing required fields
    - Invalid timestamps
    - Duplicate event IDs or duplicate source_event_id for the same source
    """
    valid_events: List[SecurityEvent] = []
    all_issues: List[ValidationIssue] = []
    seen_event_ids: Set[str] = set()
    seen_source_pairs: Set[Tuple[str, str]] = set()

    total_processed = len(records)
    duplicate_count = 0
    malformed_count = 0

    for idx, raw_record in enumerate(records):
        parsed_event, issues = validate_raw_record(raw_record)

        if issues or parsed_event is None:
            malformed_count += 1
            for issue in issues:
                if not issue.raw_record_id or issue.raw_record_id == "<unknown>":
                    issue.raw_record_id = f"index-{idx}"
            all_issues.extend(issues)
            continue

        is_duplicate = False

        # Check for duplicate event_id
        if parsed_event.event_id in seen_event_ids:
            is_duplicate = True
            all_issues.append(
                ValidationIssue(
                    field="event_id",
                    message=f"Duplicate event_id '{parsed_event.event_id}' detected",
                    severity=ValidationSeverity.WARNING if not deduplicate else ValidationSeverity.ERROR,
                    raw_record_id=parsed_event.event_id,
                )
            )
            if deduplicate:
                duplicate_count += 1
                continue

        # Check for duplicate source_event_id within same telemetry source
        if parsed_event.source_event_id:
            source_pair = (parsed_event.source, parsed_event.source_event_id)
            if source_pair in seen_source_pairs:
                is_duplicate = True
                all_issues.append(
                    ValidationIssue(
                        field="source_event_id",
                        message=(
                            f"Duplicate source event '{parsed_event.source_event_id}' "
                            f"for source '{parsed_event.source}' detected"
                        ),
                        severity=ValidationSeverity.WARNING,
                        raw_record_id=parsed_event.event_id,
                    )
                )
            else:
                seen_source_pairs.add(source_pair)

        if is_duplicate:
            duplicate_count += 1

        seen_event_ids.add(parsed_event.event_id)
        valid_events.append(parsed_event)

    is_valid = (malformed_count == 0) and (duplicate_count == 0 or not deduplicate)

    result = ValidationResult(
        is_valid=is_valid,
        events_processed=total_processed,
        valid_events_count=len(valid_events),
        duplicate_events_count=duplicate_count,
        malformed_events_count=malformed_count,
        issues=all_issues,
    )

    return valid_events, result
