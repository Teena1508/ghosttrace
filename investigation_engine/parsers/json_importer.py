"""
JSON and JSONL Security Telemetry Parser for GhostTrace.
Handles single JSON objects, JSON event arrays, or newline-delimited JSON (JSONL).
Strictly preserves raw payload in original_event_data and reports unsupported fields.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Set, Tuple

from investigation_engine.models import SecurityEvent, ValidationIssue, ValidationSeverity
from investigation_engine.parsers.base import BaseLogParser, ParserResult

CANONICAL_FIELD_NAMES = {
    "event_id",
    "timestamp",
    "event_type",
    "host_id",
    "user_id",
    "source_ip",
    "session_id",
    "process_id",
    "file_path",
    "severity",
    "source",
    "original_event_data",
    "source_event_id",
    "description",
    "is_suspicious",
    "mitre_attack_id",
    "destination_ip",
    "destination_port",
    "process_name",
    "command_line",
    "action",
}


class JsonLogParser(BaseLogParser):
    """
    Parser for structured JSON and JSONL telemetry.
    """

    @property
    def format_name(self) -> str:
        return "JSON"

    @property
    def supported_extensions(self) -> List[str]:
        return [".json", ".jsonl"]

    def can_parse(self, content: str, filename: Optional[str] = None) -> bool:
        if filename and filename.lower().endswith((".json", ".jsonl")):
            return True
        stripped = content.strip()
        return (
            (stripped.startswith("[") and stripped.endswith("]"))
            or (stripped.startswith("{") and stripped.endswith("}"))
        )

    def parse(
        self,
        content: str,
        filename: Optional[str] = None,
        max_records: int = 500,
    ) -> ParserResult:
        content_clean = content.strip()
        warnings: List[str] = []
        issues: List[ValidationIssue] = []
        parsed_records: List[Dict[str, Any]] = []
        unsupported_fields_set: Set[str] = set()

        raw_list: List[Any] = []
        format_detected = "JSON"

        # Check top-level JSON
        is_top_json = False
        if (content_clean.startswith("[") and content_clean.endswith("]")) or (
            content_clean.startswith("{") and content_clean.endswith("}")
        ):
            try:
                parsed = json.loads(content_clean)
                if isinstance(parsed, list):
                    raw_list = parsed
                    is_top_json = True
                elif isinstance(parsed, dict):
                    if "events" in parsed and isinstance(parsed["events"], list):
                        raw_list = parsed["events"]
                    elif "records" in parsed and isinstance(parsed["records"], list):
                        raw_list = parsed["records"]
                    else:
                        raw_list = [parsed]
                    is_top_json = True
            except json.JSONDecodeError:
                is_top_json = False

        if not is_top_json:
            format_detected = "JSONL"
            lines = content_clean.splitlines()
            for idx, line in enumerate(lines):
                line_str = line.strip()
                if not line_str:
                    continue
                try:
                    rec = json.loads(line_str)
                    raw_list.append(rec)
                except json.JSONDecodeError as err:
                    issues.append(
                        ValidationIssue(
                            raw_record_id=f"line-{idx + 1}",
                            message=f"JSONL parse error on line {idx + 1}: {err}",
                            severity=ValidationSeverity.ERROR,
                        )
                    )

        raw_records_count = len(raw_list)
        if raw_records_count > max_records:
            issues.append(
                ValidationIssue(
                    message=f"Payload contains {raw_records_count} records, exceeding maximum allowed of {max_records}.",
                    severity=ValidationSeverity.ERROR,
                )
            )
            raw_list = raw_list[:max_records]

        for idx, rec in enumerate(raw_list):
            if not isinstance(rec, dict):
                issues.append(
                    ValidationIssue(
                        raw_record_id=f"record-{idx + 1}",
                        message=f"Record at index {idx + 1} is not a valid JSON dictionary.",
                        severity=ValidationSeverity.ERROR,
                    )
                )
                continue

            r_copy = rec.copy()
            # Preserve raw payload if not present
            if "original_event_data" not in r_copy or not r_copy["original_event_data"]:
                r_copy["original_event_data"] = rec.copy()
            if filename and "source_file" not in r_copy["original_event_data"]:
                r_copy["original_event_data"]["source_file"] = filename

            if not r_copy.get("source"):
                r_copy["source"] = f"imported_{format_detected.lower()}"

            # Track unsupported fields
            record_keys = set(rec.keys())
            unsupported = record_keys - CANONICAL_FIELD_NAMES
            unsupported_fields_set.update(unsupported)

            parsed_records.append(r_copy)

        return ParserResult(
            format_name=format_detected,
            raw_records_count=raw_records_count,
            parsed_events=parsed_records,
            unsupported_fields=sorted(list(unsupported_fields_set)),
            parsing_warnings=warnings,
            issues=issues,
        )
