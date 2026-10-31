"""
Local Log Import Engine for GhostTrace.
Supports validated local log file import across multiple forensic formats:
- JSON & JSONL Security Telemetry
- Windows Event Log XML (Event Viewer / wevtutil / PowerShell)
- Windows Event Log JSON (Winlogbeat / Elastic / Forwarder)
- Linux Authentication Logs (syslog, auth.log, secure)

Safety & Security Constraints:
1. Untrusted data: Logs are parsed strictly with structured decoders, never evaluated or executed.
2. Resource boundaries: Enforces strict payload size limit (max 2MB) and record count limit (max 500).
3. Chain of custody: Preserves original raw event payloads and source provenance.
4. Robust parsing: Reports malformed records and unsupported fields without crashing.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from investigation_engine.models import SecurityEvent, ValidationIssue, ValidationResult, ValidationSeverity
from investigation_engine.parsers.dispatcher import MAX_IMPORT_BYTES, MAX_IMPORT_RECORDS, parse_and_normalize_logs


class ImportLogResult(BaseModel):
    """Result of importing security logs across supported formats."""
    format_detected: str = Field(..., description="Detected format: JSON, JSONL, WINDOWS_XML, WINDOWS_JSON, LINUX_AUTH_LOG")
    source_filename: Optional[str] = Field(default=None, description="Original uploaded filename if provided")
    total_records_read: int
    valid_events_count: int
    malformed_count: int
    duplicate_count: int
    unsupported_fields: List[str] = Field(
        default_factory=list,
        description="Fields present in raw logs that could not be mapped to canonical schema, preserved in original_event_data"
    )
    parsing_warnings: List[str] = Field(
        default_factory=list,
        description="Parser warnings and notifications"
    )
    events: List[SecurityEvent] = Field(default_factory=list)
    validation_status: ValidationResult


def parse_and_import_logs(
    raw_content: str,
    filename: Optional[str] = None,
    deduplicate: bool = True,
    max_records: int = MAX_IMPORT_RECORDS,
) -> ImportLogResult:
    """
    Parse a raw string containing security logs in any supported format,
    normalize supported fields into canonical SecurityEvents, preserve raw payload,
    and report any malformed or unsupported fields.
    """
    parser_res, valid_events, val_result = parse_and_normalize_logs(
        raw_content=raw_content,
        filename=filename,
        deduplicate=deduplicate,
        max_records=max_records,
    )

    return ImportLogResult(
        format_detected=parser_res.format_name,
        source_filename=filename,
        total_records_read=parser_res.raw_records_count,
        valid_events_count=len(valid_events),
        malformed_count=val_result.malformed_events_count,
        duplicate_count=val_result.duplicate_events_count,
        unsupported_fields=parser_res.unsupported_fields,
        parsing_warnings=parser_res.parsing_warnings,
        events=valid_events,
        validation_status=val_result,
    )
