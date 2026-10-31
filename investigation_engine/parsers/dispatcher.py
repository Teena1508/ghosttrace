"""
Multi-format Log Dispatcher for GhostTrace.
Coordinates format auto-detection, parsing, field normalization, and canonical validation.
"""

from __future__ import annotations

from typing import List, Optional, Tuple
from investigation_engine.models import SecurityEvent, ValidationIssue, ValidationResult, ValidationSeverity
from investigation_engine.parsers.base import BaseLogParser, ParserResult
from investigation_engine.parsers.windows_xml import WindowsXmlParser
from investigation_engine.parsers.windows_json import WindowsJsonParser
from investigation_engine.parsers.linux_auth import LinuxAuthParser
from investigation_engine.parsers.json_importer import JsonLogParser
from investigation_engine.validation import validate_event_batch

MAX_IMPORT_BYTES = 2 * 1024 * 1024  # 2 MB
MAX_IMPORT_RECORDS = 500


def get_available_parsers() -> List[BaseLogParser]:
    """Return ordered list of parsers from most specific to general."""
    return [
        WindowsXmlParser(),
        WindowsJsonParser(),
        LinuxAuthParser(),
        JsonLogParser(),
    ]


def detect_parser(content: str, filename: Optional[str] = None) -> Optional[BaseLogParser]:
    """Select the first parser capable of handling the content."""
    for parser in get_available_parsers():
        if parser.can_parse(content, filename):
            return parser
    return None


def parse_and_normalize_logs(
    raw_content: str,
    filename: Optional[str] = None,
    deduplicate: bool = True,
    max_records: int = MAX_IMPORT_RECORDS,
) -> Tuple[ParserResult, List[SecurityEvent], ValidationResult]:
    """
    Auto-detect format, parse raw records, track unsupported fields and warnings,
    and validate events against canonical SecurityEvent schema.
    """
    if len(raw_content.encode("utf-8")) > MAX_IMPORT_BYTES:
        raise ValueError(
            f"Import payload exceeds maximum permitted size of {MAX_IMPORT_BYTES // (1024 * 1024)} MB."
        )

    content_str = raw_content.strip()
    if not content_str:
        empty_val = ValidationResult(
            is_valid=False,
            events_processed=0,
            valid_events_count=0,
            duplicate_events_count=0,
            malformed_events_count=0,
            issues=[
                ValidationIssue(
                    message="Import content is empty.",
                    severity=ValidationSeverity.ERROR,
                )
            ],
        )
        empty_res = ParserResult(
            format_name="EMPTY",
            raw_records_count=0,
            parsed_events=[],
            unsupported_fields=[],
            parsing_warnings=["No content provided"],
            issues=empty_val.issues,
        )
        return empty_res, [], empty_val

    parser = detect_parser(content_str, filename)
    if not parser:
        # Default fallback to JsonLogParser
        parser = JsonLogParser()

    parser_res = parser.parse(content_str, filename=filename, max_records=max_records)

    # Validate parsed dicts into SecurityEvent instances
    valid_events, val_result = validate_event_batch(
        parser_res.parsed_events,
        deduplicate=deduplicate,
    )

    # Merge parser issues into validation issues
    all_issues = list(parser_res.issues) + list(val_result.issues)
    val_result.issues = all_issues
    val_result.malformed_events_count += len([i for i in parser_res.issues if i.severity == ValidationSeverity.ERROR])

    return parser_res, valid_events, val_result
