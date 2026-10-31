"""
Linux Authentication and Syslog Parser for GhostTrace.
Parses /var/log/auth.log and /var/log/secure log lines (sshd, sudo, pam, su, systemd-logind).
Preserves raw unmanipulated log lines in original_event_data for evidentiary lineage.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from investigation_engine.models import EventSeverity, EventType, ValidationIssue, ValidationSeverity
from investigation_engine.parsers.base import BaseLogParser, ParserResult


# Regex for RFC 3164 (e.g. "Oct 19 04:12:01 host proc[123]: msg") or RFC 5424 ISO timestamps
SYSLOG_LINE_RE = re.compile(
    r"^(?P<timestamp>(?:[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})|(?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?))\s+"
    r"(?P<host>[^\s:]+)\s+"
    r"(?P<program>[a-zA-Z0-9_\-\.\/]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

# SSH patterns
SSH_ACCEPTED_RE = re.compile(r"Accepted\s+(?:password|publickey|keyboard-interactive)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)")
SSH_FAILED_RE = re.compile(r"Failed\s+(?:password|publickey)\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)")
SSH_INVALID_USER_RE = re.compile(r"Invalid\s+user\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)(?:\s+port\s+(?P<port>\d+))?")
SSH_SESSION_OPEN_RE = re.compile(r"session\s+opened\s+for\s+user\s+(?P<user>\S+?)(?:\(uid=\d+\))?\s+by\s+(?P<by_user>\S+)")
SSH_SESSION_CLOSE_RE = re.compile(r"session\s+closed\s+for\s+user\s+(?P<user>\S+)")

# Sudo patterns
SUDO_CMD_RE = re.compile(r"^\s*(?P<invoking_user>\S+)\s*:\s*TTY=(?P<tty>\S*)\s*;\s*PWD=(?P<pwd>\S*)\s*;\s*USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<command>.*)$")


class LinuxAuthParser(BaseLogParser):
    """
    Parser for Linux authentication and security event logs.
    """

    @property
    def format_name(self) -> str:
        return "LINUX_AUTH_LOG"

    @property
    def supported_extensions(self) -> List[str]:
        return [".log", ".txt", "auth.log", "secure"]

    def can_parse(self, content: str, filename: Optional[str] = None) -> bool:
        if filename and ("auth" in filename.lower() or "secure" in filename.lower() or "syslog" in filename.lower()):
            return True
        # Check first few lines for typical syslog auth patterns
        lines = [line.strip() for line in content.splitlines()[:10] if line.strip()]
        matches = 0
        for line in lines:
            if "sshd[" in line or "sudo:" in line or "pam_unix" in line or "systemd-logind" in line:
                matches += 1
        return matches >= 1

    def parse(
        self,
        content: str,
        filename: Optional[str] = None,
        max_records: int = 500,
    ) -> ParserResult:
        warnings: List[str] = []
        issues: List[ValidationIssue] = []
        parsed_records: List[Dict[str, Any]] = []
        unsupported_fields_set: Set[str] = set()

        lines = content.splitlines()
        raw_records_count = 0

        current_year = datetime.now(timezone.utc).year

        for idx, line in enumerate(lines):
            line_str = line.strip()
            if not line_str:
                continue

            raw_records_count += 1
            if raw_records_count > max_records:
                issues.append(
                    ValidationIssue(
                        message=f"Log contains more than {max_records} records; remaining records truncated.",
                        severity=ValidationSeverity.WARNING,
                    )
                )
                break

            parsed_dict, unsupp, issue = self._parse_line(line_str, idx, filename or "auth.log", current_year)
            if issue:
                issues.append(issue)
            if parsed_dict:
                parsed_records.append(parsed_dict)
                unsupported_fields_set.update(unsupp)

        return ParserResult(
            format_name=self.format_name,
            raw_records_count=raw_records_count,
            parsed_events=parsed_records,
            unsupported_fields=sorted(list(unsupported_fields_set)),
            parsing_warnings=warnings,
            issues=issues,
        )

    def _parse_line(
        self,
        line: str,
        index: int,
        source_name: str,
        current_year: int,
    ) -> Tuple[Optional[Dict[str, Any]], Set[str], Optional[ValidationIssue]]:
        """Parse a single Linux syslog line into canonical normalized dict."""
        m = SYSLOG_LINE_RE.match(line)
        if not m:
            # Line does not match standard syslog header
            issue = ValidationIssue(
                raw_record_id=f"line-{index + 1}",
                message=f"Line does not conform to standard syslog header: {line[:60]}...",
                severity=ValidationSeverity.WARNING,
            )
            # Create a fallback record preserving raw line
            event_dict = {
                "event_id": f"linux_log_{index + 1}",
                "source_event_id": str(index + 1),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": EventType.PROCESS_EXECUTION.value,
                "severity": EventSeverity.INFORMATIONAL.value,
                "description": line[:256],
                "source": "linux_auth_log:unstructured",
                "original_event_data": {"raw_line": line, "line_number": index + 1, "source_file": source_name},
            }
            return event_dict, set(), issue

        ts_str = m.group("timestamp")
        host = m.group("host")
        program = m.group("program")
        pid_str = m.group("pid")
        message = m.group("message")

        # Parse timestamp
        timestamp_dt = None
        if "T" in ts_str or "-" in ts_str:
            # ISO timestamp
            try:
                timestamp_dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                if timestamp_dt.tzinfo is None:
                    timestamp_dt = timestamp_dt.replace(tzinfo=timezone.utc)
            except Exception:
                pass

        if not timestamp_dt:
            # RFC 3164 (e.g. "Oct 19 04:12:01")
            try:
                parsed_ts = datetime.strptime(f"{current_year} {ts_str}", "%Y %b %d %H:%M:%S")
                timestamp_dt = parsed_ts.replace(tzinfo=timezone.utc)
            except Exception:
                timestamp_dt = datetime.now(timezone.utc)

        pid_val = int(pid_str) if pid_str and pid_str.isdigit() else None

        canonical_event_id = f"linux_auth_{index + 1}_{pid_str or '0'}"
        source_event_id = str(index + 1)

        raw_data = {
            "raw_line": line,
            "line_number": index + 1,
            "source_file": source_name,
            "program": program,
            "pid": pid_val,
            "host": host,
            "message": message,
        }

        unsupported_fields: Set[str] = set()

        event_type = EventType.AUTHENTICATION
        severity = EventSeverity.INFORMATIONAL
        action = f"{program.upper()}_ACTIVITY"
        user_id = None
        source_ip = None
        destination_port = None
        process_name = program
        command_line = None
        file_path = None
        description = f"{program}: {message}"

        # Match specific programs
        if "sshd" in program.lower():
            event_type = EventType.AUTHENTICATION
            acc_m = SSH_ACCEPTED_RE.search(message)
            fail_m = SSH_FAILED_RE.search(message)
            inv_m = SSH_INVALID_USER_RE.search(message)
            sess_m = SSH_SESSION_OPEN_RE.search(message)
            close_m = SSH_SESSION_CLOSE_RE.search(message)

            if acc_m:
                action = "LOGON_SUCCESS"
                severity = EventSeverity.INFORMATIONAL
                user_id = acc_m.group("user")
                source_ip = acc_m.group("ip")
                destination_port = int(acc_m.group("port"))
                description = f"SSH authentication accepted for {user_id} from {source_ip}:{destination_port}"
            elif fail_m:
                action = "LOGON_FAILURE"
                severity = EventSeverity.MEDIUM
                user_id = fail_m.group("user")
                source_ip = fail_m.group("ip")
                destination_port = int(fail_m.group("port"))
                description = f"SSH authentication failed for {user_id} from {source_ip}:{destination_port}"
            elif inv_m:
                action = "LOGON_FAILURE_INVALID_USER"
                severity = EventSeverity.MEDIUM
                user_id = inv_m.group("user")
                source_ip = inv_m.group("ip")
                port_grp = inv_m.group("port")
                if port_grp:
                    destination_port = int(port_grp)
                description = f"SSH invalid user connection attempt for {user_id} from {source_ip}"
            elif sess_m:
                action = "SESSION_OPEN"
                user_id = sess_m.group("user")
                description = f"SSH session opened for {user_id}"
            elif close_m:
                action = "SESSION_CLOSE"
                user_id = close_m.group("user")
                description = f"SSH session closed for {user_id}"
            else:
                action = "SSHD_NOTICE"

        elif "sudo" in program.lower():
            sudo_cmd_m = SUDO_CMD_RE.search(message)
            if sudo_cmd_m:
                event_type = EventType.PROCESS_EXECUTION
                action = "SUDO_EXEC"
                severity = EventSeverity.MEDIUM
                user_id = sudo_cmd_m.group("invoking_user")
                target_user = sudo_cmd_m.group("target_user")
                cmd = sudo_cmd_m.group("command")
                tty = sudo_cmd_m.group("tty")
                pwd = sudo_cmd_m.group("pwd")
                command_line = cmd
                process_name = cmd.split()[0] if cmd else "sudo"
                description = f"User {user_id} executed '{cmd}' via sudo as {target_user}"
                if tty:
                    raw_data["tty"] = tty
                    unsupported_fields.add("tty")
                if pwd:
                    raw_data["pwd"] = pwd
                    unsupported_fields.add("pwd")
            elif "session opened" in message:
                event_type = EventType.AUTHENTICATION
                action = "SUDO_SESSION_OPEN"
                severity = EventSeverity.INFORMATIONAL
                description = f"Sudo session opened: {message}"
            else:
                event_type = EventType.PROCESS_EXECUTION
                action = "SUDO_ACTIVITY"
                description = f"Sudo activity: {message}"

        elif "systemd-logind" in program.lower():
            event_type = EventType.AUTHENTICATION
            action = "SYSTEMD_SESSION"
            severity = EventSeverity.INFORMATIONAL
            description = message

        normalized: Dict[str, Any] = {
            "event_id": canonical_event_id,
            "source_event_id": source_event_id,
            "timestamp": timestamp_dt.isoformat(),
            "event_type": event_type.value,
            "severity": severity.value,
            "host_id": host,
            "user_id": user_id,
            "source_ip": source_ip,
            "destination_port": destination_port,
            "process_id": pid_val,
            "process_name": process_name,
            "command_line": command_line,
            "file_path": file_path,
            "action": action,
            "description": description,
            "source": f"linux_syslog:{program}",
            "original_event_data": raw_data,
        }

        return normalized, unsupported_fields, None
