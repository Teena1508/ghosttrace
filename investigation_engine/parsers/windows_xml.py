"""
Windows Event Log XML Parser for GhostTrace.
Parses native XML exports from Windows Event Viewer, wevtutil, or PowerShell.
Safely extracts EventID, SystemTime, Computer, and EventData fields.
Supported Event IDs:
- 4624: Successful Logon
- 4625: Failed Logon
- 4688: Process Creation (with CommandLine and ParentProcess)
- 7045: New Service Installed
- 4104: PowerShell Script Block Logging
- 4672: Special Privileges Assigned
- 5156: Network Connection (Windows Filtering Platform)
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from investigation_engine.models import EventSeverity, EventType, ValidationIssue, ValidationSeverity
from investigation_engine.parsers.base import BaseLogParser, ParserResult


class WindowsXmlParser(BaseLogParser):
    """
    Parser for Windows Event Log XML representations.
    """

    @property
    def format_name(self) -> str:
        return "WINDOWS_XML"

    @property
    def supported_extensions(self) -> List[str]:
        return [".xml"]

    def can_parse(self, content: str, filename: Optional[str] = None) -> bool:
        if filename and filename.lower().endswith(".xml"):
            return True
        stripped = content.strip()
        if stripped.startswith("<") and ("<Event" in content or "<Events" in content):
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

        # Wrap multiple <Event> roots in <Events> if needed
        xml_to_parse = content_clean
        if not xml_to_parse.startswith("<Events") and xml_to_parse.count("<Event") > 1:
            xml_to_parse = f"<Events>{xml_to_parse}</Events>"
        elif not xml_to_parse.startswith("<Events") and not xml_to_parse.startswith("<Event"):
            # Try to locate start of first <Event
            idx = xml_to_parse.find("<Event")
            if idx != -1:
                xml_to_parse = f"<Events>{xml_to_parse[idx:]}</Events>"

        try:
            # Safe XML parsing: defused from entities by default in Python 3.11+ ET
            root = ET.fromstring(xml_to_parse)
        except ET.ParseError as err:
            issues.append(
                ValidationIssue(
                    message=f"XML syntax error: {err}",
                    severity=ValidationSeverity.ERROR,
                )
            )
            return ParserResult(
                format_name=self.format_name,
                raw_records_count=0,
                parsed_events=[],
                unsupported_fields=[],
                parsing_warnings=["Failed to parse XML content"],
                issues=issues,
            )

        # Find all Event elements, ignoring namespace
        event_nodes = []
        if root.tag.endswith("Event"):
            event_nodes = [root]
        else:
            for elem in root.iter():
                if elem.tag.endswith("Event") and elem != root:
                    event_nodes.append(elem)

        raw_records_count = len(event_nodes)
        if raw_records_count > max_records:
            issues.append(
                ValidationIssue(
                    message=f"XML contains {raw_records_count} events, exceeding limit of {max_records}.",
                    severity=ValidationSeverity.ERROR,
                )
            )
            event_nodes = event_nodes[:max_records]

        for idx, event_elem in enumerate(event_nodes):
            try:
                rec, unsupp = self._parse_single_event(event_elem, idx, filename or "windows_event.xml")
                parsed_records.append(rec)
                unsupported_fields_set.update(unsupp)
            except Exception as exc:
                issues.append(
                    ValidationIssue(
                        raw_record_id=f"xml-event-{idx + 1}",
                        message=f"Failed to normalize Windows XML event {idx + 1}: {exc}",
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

    def _parse_single_event(
        self,
        event_elem: ET.Element,
        index: int,
        source_name: str,
    ) -> Tuple[Dict[str, Any], Set[str]]:
        """Extract and normalize a single Windows XML event."""
        # Helper to strip namespace from tags
        def strip_ns(tag: str) -> str:
            return tag.split("}")[-1] if "}" in tag else tag

        system_data: Dict[str, Any] = {}
        event_data: Dict[str, Any] = {}
        raw_xml_dict: Dict[str, Any] = {}

        for child in event_elem:
            tag_name = strip_ns(child.tag)
            if tag_name == "System":
                for sys_child in child:
                    s_tag = strip_ns(sys_child.tag)
                    if s_tag == "TimeCreated":
                        system_data["TimeCreated"] = sys_child.attrib.get("SystemTime", "")
                    elif s_tag == "Provider":
                        system_data["Provider"] = sys_child.attrib.get("Name", "")
                    elif s_tag == "Execution":
                        system_data["ProcessID"] = sys_child.attrib.get("ProcessID")
                        system_data["ThreadID"] = sys_child.attrib.get("ThreadID")
                    else:
                        system_data[s_tag] = (sys_child.text or "").strip()
            elif tag_name in ("EventData", "UserData"):
                for data_child in child:
                    name_attr = data_child.attrib.get("Name")
                    val_text = (data_child.text or "").strip()
                    if name_attr:
                        event_data[name_attr] = val_text
                    elif data_child.text:
                        # Unnamed data element
                        event_data[f"Data_{len(event_data)}"] = val_text

        raw_xml_dict["System"] = system_data
        raw_xml_dict["EventData"] = event_data
        raw_xml_dict["source_file"] = source_name

        event_id_str = system_data.get("EventID", "0")
        try:
            event_id_int = int(event_id_str)
        except ValueError:
            event_id_int = 0

        # Timestamp parsing
        ts_str = system_data.get("TimeCreated")
        if not ts_str:
            ts_val = datetime.now(timezone.utc).isoformat()
        else:
            ts_val = ts_str

        # Hostname
        computer = system_data.get("Computer")

        # Record identifiers
        record_id = system_data.get("EventRecordID") or f"win-xml-{index + 1}"
        canonical_event_id = f"winxml_{event_id_int}_{record_id}"

        # Default classification
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
        file_path = None
        session_id = None
        description = None

        mapped_event_data_keys: Set[str] = set()

        if event_id_int == 4624:
            # Successful Logon
            event_type = EventType.AUTHENTICATION
            action = "LOGON_SUCCESS"
            severity = EventSeverity.INFORMATIONAL
            target_user = event_data.get("TargetUserName")
            user_id = target_user if target_user and not target_user.endswith("$") else event_data.get("SubjectUserName")
            
            ip = event_data.get("IpAddress")
            if ip and ip not in ("-", "::1", "127.0.0.1"):
                source_ip = ip
            
            port_str = event_data.get("IpPort")
            if port_str and port_str.isdigit() and port_str != "0":
                destination_port = int(port_str)

            session_id = event_data.get("TargetLogonId")
            logon_type = event_data.get("LogonType")
            description = f"Successful Windows logon (Type {logon_type}) for user {user_id or 'unknown'} on {computer or 'host'}"

            mapped_event_data_keys.update(["TargetUserName", "SubjectUserName", "IpAddress", "IpPort", "TargetLogonId", "LogonType"])

        elif event_id_int == 4625:
            # Failed Logon
            event_type = EventType.AUTHENTICATION
            action = "LOGON_FAILURE"
            severity = EventSeverity.MEDIUM
            user_id = event_data.get("TargetUserName") or event_data.get("SubjectUserName")
            
            ip = event_data.get("IpAddress")
            if ip and ip not in ("-", "::1", "127.0.0.1"):
                source_ip = ip

            status = event_data.get("Status")
            sub_status = event_data.get("SubStatus")
            description = f"Failed Windows logon for user {user_id or 'unknown'} from {source_ip or 'local'} (Status: {status}, SubStatus: {sub_status})"
            mapped_event_data_keys.update(["TargetUserName", "SubjectUserName", "IpAddress", "Status", "SubStatus"])

        elif event_id_int == 4688:
            # Process Creation
            event_type = EventType.PROCESS_EXECUTION
            action = "PROCESS_CREATE"
            severity = EventSeverity.INFORMATIONAL
            user_id = event_data.get("SubjectUserName")
            process_name = event_data.get("NewProcessName")
            command_line = event_data.get("CommandLine") or process_name
            
            pid_raw = event_data.get("NewProcessId")
            if pid_raw:
                try:
                    process_id = int(pid_raw, 16) if str(pid_raw).startswith("0x") else int(pid_raw)
                except ValueError:
                    process_id = str(pid_raw)

            description = f"Process spawned: {process_name or 'unknown'}"
            if command_line:
                description += f" (Command: {command_line})"
            
            mapped_event_data_keys.update(["SubjectUserName", "NewProcessName", "CommandLine", "NewProcessId", "ParentProcessName"])

        elif event_id_int == 7045:
            # Service Installed
            event_type = EventType.PROCESS_EXECUTION
            action = "SERVICE_INSTALL"
            severity = EventSeverity.MEDIUM
            service_name = event_data.get("ServiceName")
            image_path = event_data.get("ImagePath")
            process_name = service_name
            command_line = image_path
            user_id = event_data.get("AccountName")
            description = f"Windows service installed: {service_name} executing '{image_path}'"
            mapped_event_data_keys.update(["ServiceName", "ImagePath", "AccountName", "ServiceType", "StartType"])

        elif event_id_int == 4104:
            # PowerShell Scriptblock
            event_type = EventType.PROCESS_EXECUTION
            action = "POWERSHELL_SCRIPTBLOCK"
            severity = EventSeverity.INFORMATIONAL
            script_block = event_data.get("ScriptBlockText", "")
            command_line = script_block[:1024] if script_block else None
            process_name = "powershell.exe"
            description = "PowerShell script block executed"
            mapped_event_data_keys.update(["ScriptBlockText", "Path", "MessageTotal", "MessageNumber"])

        elif event_id_int == 4672:
            # Special Privileges Assigned
            event_type = EventType.AUTHENTICATION
            action = "PRIVILEGE_ASSIGNED"
            severity = EventSeverity.INFORMATIONAL
            user_id = event_data.get("SubjectUserName")
            description = f"Special privileges assigned to user {user_id}"
            mapped_event_data_keys.update(["SubjectUserName", "SubjectUserSid", "PrivilegeList"])

        elif event_id_int == 5156:
            # Network connection
            event_type = EventType.NETWORK_CONNECTION
            action = "NETWORK_CONNECT"
            severity = EventSeverity.INFORMATIONAL
            source_ip = event_data.get("SourceAddress")
            destination_ip = event_data.get("DestAddress")
            dest_port_raw = event_data.get("DestPort")
            if dest_port_raw and str(dest_port_raw).isdigit():
                destination_port = int(dest_port_raw)
            process_name = event_data.get("Application")
            description = f"Outbound network connection to {destination_ip}:{destination_port}"
            mapped_event_data_keys.update(["SourceAddress", "DestAddress", "DestPort", "SourcePort", "Application"])

        else:
            # General fallback mapping
            user_id = event_data.get("TargetUserName") or event_data.get("SubjectUserName") or event_data.get("User")
            description = f"Windows Security Event {event_id_int} on {computer or 'host'}"

        # Determine unsupported fields
        unsupported = set(event_data.keys()) - mapped_event_data_keys

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
            "file_path": file_path,
            "session_id": session_id,
            "action": action,
            "description": description,
            "source": f"windows_event_log:{system_data.get('Channel', 'Security')}",
            "original_event_data": raw_xml_dict,
        }

        return normalized, unsupported
