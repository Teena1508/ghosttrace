"""
Windows Event Log JSON Parser for GhostTrace.
Parses JSON exports from Winlogbeat, Elastic Agent, PowerShell ConvertTo-Json,
or custom Windows Event Forwarder JSON pipelines.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from investigation_engine.models import EventSeverity, EventType, ValidationIssue, ValidationSeverity
from investigation_engine.parsers.base import BaseLogParser, ParserResult


class WindowsJsonParser(BaseLogParser):
    """
    Parser for Windows Event Log JSON representations.
    """

    @property
    def format_name(self) -> str:
        return "WINDOWS_JSON"

    @property
    def supported_extensions(self) -> List[str]:
        return [".json", ".jsonl"]

    def can_parse(self, content: str, filename: Optional[str] = None) -> bool:
        if filename and ("win" in filename.lower() or "eventlog" in filename.lower()):
            if filename.lower().endswith((".json", ".jsonl")):
                return True
        # Check snippet for Windows event signatures
        sample = content[:2048]
        if '"winlog"' in sample or '"EventID"' in sample or '"EventRecordID"' in sample or '"EventData"' in sample:
            return True
        return False

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
        # Attempt to parse as JSON array/object or JSONL
        if (content_clean.startswith("[") and content_clean.endswith("]")) or (content_clean.startswith("{") and content_clean.endswith("}")):
            try:
                parsed = json.loads(content_clean)
                if isinstance(parsed, list):
                    raw_list = parsed
                elif isinstance(parsed, dict):
                    if "events" in parsed and isinstance(parsed["events"], list):
                        raw_list = parsed["events"]
                    elif "records" in parsed and isinstance(parsed["records"], list):
                        raw_list = parsed["records"]
                    else:
                        raw_list = [parsed]
            except json.JSONDecodeError:
                raw_list = []

        if not raw_list:
            # Parse line by line (JSONL)
            for idx, line in enumerate(content_clean.splitlines()):
                line_str = line.strip()
                if not line_str:
                    continue
                try:
                    raw_list.append(json.loads(line_str))
                except json.JSONDecodeError as err:
                    issues.append(
                        ValidationIssue(
                            raw_record_id=f"line-{idx + 1}",
                            message=f"Windows JSON line parse error: {err}",
                            severity=ValidationSeverity.ERROR,
                        )
                    )

        raw_records_count = len(raw_list)
        if raw_records_count > max_records:
            issues.append(
                ValidationIssue(
                    message=f"Payload contains {raw_records_count} records, exceeding maximum of {max_records}.",
                    severity=ValidationSeverity.ERROR,
                )
            )
            raw_list = raw_list[:max_records]

        for idx, rec in enumerate(raw_list):
            if not isinstance(rec, dict):
                issues.append(
                    ValidationIssue(
                        raw_record_id=f"win-json-{idx + 1}",
                        message="Record is not a valid JSON dictionary.",
                        severity=ValidationSeverity.ERROR,
                    )
                )
                continue
            try:
                normalized, unsupp = self._normalize_record(rec, idx, filename or "windows_event.json")
                parsed_records.append(normalized)
                unsupported_fields_set.update(unsupp)
            except Exception as exc:
                issues.append(
                    ValidationIssue(
                        raw_record_id=f"win-json-{idx + 1}",
                        message=f"Error normalizing Windows JSON record {idx + 1}: {exc}",
                        severity=ValidationSeverity.ERROR,
                    )
                )

        return ParserResult(
            format_name=self.format_name,
            raw_records_count=raw_records_count,
            parsed_events=parsed_records,
            unsupported_fields=sorted(list(unsupported_fields_set)),
            parsing_warnings=warnings,
            issues=issues,
        )

    def _normalize_record(
        self,
        raw: Dict[str, Any],
        index: int,
        source_name: str,
    ) -> Tuple[Dict[str, Any], Set[str]]:
        """Normalize Winlogbeat, EventViewer JSON, or flat Windows JSON structure."""
        # 1. Unnest winlog if present
        winlog_data = raw.get("winlog") or {}
        event_wrapper = raw.get("Event") or {}
        system_data = event_wrapper.get("System") or {}
        event_data = winlog_data.get("event_data") or event_wrapper.get("EventData") or raw.get("EventData") or {}

        # 2. Extract Event ID
        event_id_val = (
            winlog_data.get("event_id")
            or system_data.get("EventID")
            or raw.get("EventID")
            or raw.get("event_id")
            or 0
        )
        try:
            event_id_int = int(event_id_val)
        except ValueError:
            event_id_int = 0

        # 3. Extract Timestamp
        time_created = system_data.get("TimeCreated")
        time_created_str = (
            time_created.get("@SystemTime") if isinstance(time_created, dict) else time_created
        )
        ts_val = (
            raw.get("@timestamp")
            or time_created_str
            or raw.get("TimeCreated")
            or raw.get("timestamp")
            or datetime.now(timezone.utc).isoformat()
        )

        # 4. Extract Computer / Host
        host_obj = raw.get("host")
        host_name = host_obj.get("name") if isinstance(host_obj, dict) else host_obj
        computer = (
            winlog_data.get("computer_name")
            or system_data.get("Computer")
            or raw.get("Computer")
            or host_name
        )

        # 5. Record ID
        record_id = (
            winlog_data.get("record_id")
            or system_data.get("EventRecordID")
            or raw.get("EventRecordID")
            or f"winjson-{index + 1}"
        )
        canonical_event_id = f"winjson_{event_id_int}_{record_id}"

        # Combine all flat and event_data keys for extraction
        merged_data: Dict[str, Any] = {}
        for k, v in raw.items():
            if k not in ("winlog", "Event", "original_event_data"):
                merged_data[k] = v
        merged_data.update(event_data)

        mapped_keys: Set[str] = set()

        event_type = EventType.PROCESS_EXECUTION
        action = f"WIN_EVENT_{event_id_int}"
        severity = EventSeverity.INFORMATIONAL
        user_id = None
        source_ip = None
        destination_ip = None
        destination_port = None
        process_id = None
        process_name = None
        command_line = None
        session_id = None
        description = None

        if event_id_int == 4624:
            event_type = EventType.AUTHENTICATION
            action = "LOGON_SUCCESS"
            severity = EventSeverity.INFORMATIONAL
            target_user = merged_data.get("TargetUserName")
            user_id = target_user if target_user and not target_user.endswith("$") else merged_data.get("SubjectUserName")
            ip = merged_data.get("IpAddress")
            if ip and ip not in ("-", "::1", "127.0.0.1"):
                source_ip = ip
            port_val = merged_data.get("IpPort")
            if port_val and str(port_val).isdigit() and str(port_val) != "0":
                destination_port = int(port_val)
            session_id = merged_data.get("TargetLogonId")
            description = f"Successful Windows logon for user {user_id or 'unknown'} on {computer or 'host'}"
            mapped_keys.update(["TargetUserName", "SubjectUserName", "IpAddress", "IpPort", "TargetLogonId", "LogonType"])

        elif event_id_int == 4625:
            event_type = EventType.AUTHENTICATION
            action = "LOGON_FAILURE"
            severity = EventSeverity.MEDIUM
            user_id = merged_data.get("TargetUserName") or merged_data.get("SubjectUserName")
            ip = merged_data.get("IpAddress")
            if ip and ip not in ("-", "::1", "127.0.0.1"):
                source_ip = ip
            description = f"Failed Windows logon for user {user_id or 'unknown'} from {source_ip or 'local'}"
            mapped_keys.update(["TargetUserName", "SubjectUserName", "IpAddress", "Status", "SubStatus"])

        elif event_id_int == 4688:
            event_type = EventType.PROCESS_EXECUTION
            action = "PROCESS_CREATE"
            severity = EventSeverity.INFORMATIONAL
            user_id = merged_data.get("SubjectUserName")
            process_name = merged_data.get("NewProcessName")
            command_line = merged_data.get("CommandLine") or process_name
            pid_raw = merged_data.get("NewProcessId")
            if pid_raw:
                try:
                    process_id = int(pid_raw, 16) if str(pid_raw).startswith("0x") else int(pid_raw)
                except ValueError:
                    process_id = str(pid_raw)
            description = f"Process spawned: {process_name or 'unknown'}"
            if command_line:
                description += f" (Command: {command_line})"
            mapped_keys.update(["SubjectUserName", "NewProcessName", "CommandLine", "NewProcessId", "ParentProcessName"])

        elif event_id_int == 7045:
            event_type = EventType.PROCESS_EXECUTION
            action = "SERVICE_INSTALL"
            severity = EventSeverity.MEDIUM
            service_name = merged_data.get("ServiceName")
            image_path = merged_data.get("ImagePath")
            process_name = service_name
            command_line = image_path
            user_id = merged_data.get("AccountName")
            description = f"Windows service installed: {service_name} executing '{image_path}'"
            mapped_keys.update(["ServiceName", "ImagePath", "AccountName", "ServiceType", "StartType"])

        elif event_id_int == 4104:
            event_type = EventType.PROCESS_EXECUTION
            action = "POWERSHELL_SCRIPTBLOCK"
            severity = EventSeverity.INFORMATIONAL
            command_line = str(merged_data.get("ScriptBlockText", ""))[:1024]
            process_name = "powershell.exe"
            description = "PowerShell script block executed"
            mapped_keys.update(["ScriptBlockText", "Path"])

        else:
            user_id = merged_data.get("TargetUserName") or merged_data.get("SubjectUserName") or merged_data.get("user")
            description = f"Windows Event {event_id_int} on {computer or 'host'}"

        # Standard canonical keys mapped
        standard_keys = {"@timestamp", "timestamp", "EventID", "event_id", "Computer", "host", "Channel", "channel"}
        mapped_keys.update(standard_keys)

        unsupported = set(merged_data.keys()) - mapped_keys

        normalized: Dict[str, Any] = {
            "event_id": canonical_event_id,
            "source_event_id": str(record_id),
            "timestamp": ts_val,
            "event_type": event_type.value,
            "severity": severity.value,
            "host_id": computer,
            "user_id": user_id,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "destination_port": destination_port,
            "process_id": process_id,
            "process_name": process_name,
            "command_line": command_line,
            "session_id": session_id,
            "action": action,
            "description": description,
            "source": f"windows_event_json:{winlog_data.get('channel', 'Security')}",
            "original_event_data": raw,
        }

        return normalized, unsupported
