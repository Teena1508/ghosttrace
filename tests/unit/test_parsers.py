"""
Unit tests for GhostTrace multi-format log parsers:
Windows XML, Windows JSON, Linux auth.log, and JSON/JSONL.
"""

import pytest
from datetime import datetime, timezone

from investigation_engine.importer import parse_and_import_logs
from investigation_engine.parsers.windows_xml import WindowsXmlParser
from investigation_engine.parsers.windows_json import WindowsJsonParser
from investigation_engine.parsers.linux_auth import LinuxAuthParser
from investigation_engine.parsers.json_importer import JsonLogParser
from investigation_engine.parsers.dispatcher import parse_and_normalize_logs


class TestWindowsXmlParser:
    def test_parse_windows_security_xml_events(self):
        xml_content = """<Events>
            <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
                <System>
                    <Provider Name="Microsoft-Windows-Security-Auditing" />
                    <EventID>4624</EventID>
                    <TimeCreated SystemTime="2026-10-18T10:14:22.000Z" />
                    <EventRecordID>1001</EventRecordID>
                    <Computer>CORP-DC01.corp.internal</Computer>
                </System>
                <EventData>
                    <Data Name="SubjectUserName">CORP-DC01$</Data>
                    <Data Name="TargetUserName">analyst_bob</Data>
                    <Data Name="IpAddress">192.168.10.45</Data>
                    <Data Name="IpPort">52123</Data>
                    <Data Name="LogonType">3</Data>
                    <Data Name="TargetLogonId">0x3fa12</Data>
                    <Data Name="ExtraAuditTag">CustomVendorParam</Data>
                </EventData>
            </Event>
            <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
                <System>
                    <EventID>4688</EventID>
                    <TimeCreated SystemTime="2026-10-18T10:15:30.000Z" />
                    <EventRecordID>1002</EventRecordID>
                    <Computer>CORP-DC01.corp.internal</Computer>
                </System>
                <EventData>
                    <Data Name="SubjectUserName">analyst_bob</Data>
                    <Data Name="NewProcessId">0x14a0</Data>
                    <Data Name="NewProcessName">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
                    <Data Name="CommandLine">powershell.exe -NoProfile -Command "Get-Process"</Data>
                    <Data Name="ParentProcessName">C:\\Windows\\explorer.exe</Data>
                </EventData>
            </Event>
        </Events>"""

        result = parse_and_import_logs(xml_content, filename="security_export.xml")
        assert result.format_detected == "WINDOWS_XML"
        assert result.total_records_read == 2
        assert result.valid_events_count == 2
        assert len(result.events) == 2

        evt1 = result.events[0]
        assert evt1.event_type.value == "AUTHENTICATION"
        assert evt1.action == "LOGON_SUCCESS"
        assert evt1.user_id == "analyst_bob"
        assert evt1.source_ip == "192.168.10.45"
        assert evt1.destination_port == 52123
        assert evt1.host_id == "CORP-DC01.corp.internal"
        assert evt1.source_event_id == "1001"
        assert "ExtraAuditTag" in result.unsupported_fields

        evt2 = result.events[1]
        assert evt2.event_type.value == "PROCESS_EXECUTION"
        assert evt2.action == "PROCESS_CREATE"
        assert evt2.user_id == "analyst_bob"
        assert "powershell.exe" in (evt2.command_line or "")

    def test_parse_windows_failed_logon_4625(self):
        xml_content = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
                <EventID>4625</EventID>
                <TimeCreated SystemTime="2026-10-18T11:00:00.000Z" />
                <EventRecordID>1003</EventRecordID>
                <Computer>DESKTOP-HR02</Computer>
            </System>
            <EventData>
                <Data Name="TargetUserName">administrator</Data>
                <Data Name="IpAddress">203.0.113.88</Data>
                <Data Name="Status">0xC000006D</Data>
                <Data Name="SubStatus">0xC000006A</Data>
            </EventData>
        </Event>"""

        result = parse_and_import_logs(xml_content, filename="failed_logon.xml")
        assert result.valid_events_count == 1
        evt = result.events[0]
        assert evt.action == "LOGON_FAILURE"
        assert evt.user_id == "administrator"
        assert evt.source_ip == "203.0.113.88"
        assert evt.severity.value == "MEDIUM"


class TestWindowsJsonParser:
    def test_parse_winlogbeat_format(self):
        json_content = """[
            {
                "@timestamp": "2026-10-18T12:00:00.000Z",
                "winlog": {
                    "channel": "Security",
                    "event_id": "4624",
                    "record_id": 8801,
                    "computer_name": "WIN-SRV-APP01",
                    "event_data": {
                        "TargetUserName": "svc_backup",
                        "IpAddress": "10.0.1.20",
                        "IpPort": "49200",
                        "TargetLogonId": "0x9812",
                        "UnmappedTelemetryProp": "SomeValue"
                    }
                }
            }
        ]"""
        result = parse_and_import_logs(json_content, filename="winlogbeat.json")
        assert result.format_detected == "WINDOWS_JSON"
        assert result.valid_events_count == 1
        evt = result.events[0]
        assert evt.event_type.value == "AUTHENTICATION"
        assert evt.user_id == "svc_backup"
        assert evt.source_ip == "10.0.1.20"
        assert evt.host_id == "WIN-SRV-APP01"
        assert "UnmappedTelemetryProp" in result.unsupported_fields


class TestLinuxAuthParser:
    def test_parse_linux_sshd_and_sudo(self):
        syslog_content = """Oct 19 04:12:01 edge-gateway sshd[14201]: Failed password for invalid user admin from 198.51.100.99 port 58442 ssh2
Oct 19 04:12:05 edge-gateway sshd[14205]: Accepted password for deploy from 198.51.100.99 port 58444 ssh2
Oct 19 04:12:06 edge-gateway sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/cat /etc/shadow
"""
        result = parse_and_import_logs(syslog_content, filename="auth.log")
        assert result.format_detected == "LINUX_AUTH_LOG"
        assert result.total_records_read == 3
        assert result.valid_events_count == 3

        # Event 1: Failed password
        evt1 = result.events[0]
        assert evt1.event_type.value == "AUTHENTICATION"
        assert evt1.action == "LOGON_FAILURE"
        assert evt1.user_id == "admin"
        assert evt1.source_ip == "198.51.100.99"
        assert evt1.destination_port == 58442

        # Event 2: Accepted password
        evt2 = result.events[1]
        assert evt2.event_type.value == "AUTHENTICATION"
        assert evt2.action == "LOGON_SUCCESS"
        assert evt2.user_id == "deploy"

        # Event 3: Sudo exec
        evt3 = result.events[2]
        assert evt3.event_type.value == "PROCESS_EXECUTION"
        assert evt3.action == "SUDO_EXEC"
        assert evt3.user_id == "deploy"
        assert evt3.command_line == "/bin/cat /etc/shadow"
        assert "raw_line" in evt3.original_event_data


class TestJsonImporter:
    def test_unsupported_fields_captured(self):
        payload = """[
            {
                "event_id": "evt-test-99",
                "timestamp": "2026-10-18T10:00:00Z",
                "event_type": "AUTHENTICATION",
                "host_id": "host-01",
                "user_id": "alice",
                "source": "audit",
                "custom_edr_score": 85,
                "vendor_signature": "SIG_XYZ"
            }
        ]"""
        result = parse_and_import_logs(payload, filename="custom_edr.json")
        assert result.valid_events_count == 1
        assert "custom_edr_score" in result.unsupported_fields
        assert "vendor_signature" in result.unsupported_fields
        assert result.events[0].original_event_data["custom_edr_score"] == 85
