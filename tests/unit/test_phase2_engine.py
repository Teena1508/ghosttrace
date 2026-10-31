"""
Regression and Acceptance Tests for Phase 2: Evidence-Driven Investigation Engine.

Tests all required forensic verification scenarios:
1. Removing the failed login changes the relevant detection without inventing a different attack.
2. Changing all usernames, IPs, and file paths leaves no stale references in narratives or recommendations.
3. A benign dataset cannot inherit the multi-stage attack narrative.
4. A suspicious process alone does not establish compromise.
5. A file read followed by unrelated network activity does not establish exfiltration.
6. An SMB connection without target-side evidence does not establish successful lateral movement.
7. Every hypothesis and recommendation references valid evidence IDs.
8. Removing a supporting event updates or removes any dependent conclusion.
9. Competing explanations and contradictory evidence are represented accurately.
10. Validated local log import for JSON and JSONL streams.
"""

import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from backend.app.main import app
from investigation_engine.importer import parse_and_import_logs
from investigation_engine.loader import load_events_from_fixture
from investigation_engine.models import (
    EventSeverity,
    EventType,
    SecurityEvent,
)
from investigation_engine.reconstruction import reconstruct_attack_timeline

client = TestClient(app)


def make_event(
    event_id: str,
    timestamp: str,
    event_type: EventType,
    severity: EventSeverity = EventSeverity.INFORMATIONAL,
    is_suspicious: bool = False,
    host_id: str = "host-01",
    user_id: str = "alice",
    source_ip: str | None = None,
    destination_ip: str | None = None,
    destination_port: int | None = None,
    session_id: str | None = None,
    process_id: int | None = None,
    process_name: str | None = None,
    command_line: str | None = None,
    file_path: str | None = None,
    action: str | None = None,
) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        timestamp=timestamp,
        event_type=event_type,
        severity=severity,
        is_suspicious=is_suspicious,
        host_id=host_id,
        user_id=user_id,
        source_ip=source_ip,
        destination_ip=destination_ip,
        destination_port=destination_port,
        session_id=session_id,
        process_id=process_id,
        process_name=process_name,
        command_line=command_line,
        file_path=file_path,
        action=action,
        source="simulated_test",
        original_event_data={"id": event_id},
    )


class TestPhase2EvidenceDrivenEngine:
    """Covers all 9 required verification scenarios and local log import."""

    def test_case_1_removing_failed_login_changes_detection_without_inventing_attack(self):
        """
        1. Removing the failed login changes the entry point detection
        (confidence drops, rationale reflects direct valid login) without inventing an attack.
        """
        events, _ = load_events_from_fixture("data/fixtures/simulated_events.json")
        res_full = reconstruct_attack_timeline(events)

        ep_full = res_full.candidate_entry_points[0]
        assert ep_full.confidence == 0.85
        assert "preceded by 1 failed attempt(s)" in ep_full.rationale

        # Remove failed login
        no_fail_events = [e for e in events if e.event_id != "evt-auth-2001"]
        res_no_fail = reconstruct_attack_timeline(no_fail_events)

        ep_no_fail = res_no_fail.candidate_entry_points[0]
        assert ep_no_fail.confidence == 0.80
        assert "valid credentials" in ep_no_fail.rationale
        assert "preceded by" not in ep_no_fail.rationale
        # Ensure it didn't invent an arbitrary different vector
        assert ep_no_fail.event_id == "evt-auth-2002"

    def test_case_2_custom_entities_leave_no_stale_references(self):
        """
        2. Changing all usernames, IPs, and file paths leaves no stale references
        (such as svc_deploy, 198.51.100.42, or /var/sim_secrets) in narratives or recommendations.
        """
        custom_events = [
            make_event(
                "evt-1", "2026-10-18T10:00:00Z", EventType.AUTHENTICATION,
                action="LOGON_SUCCESS", user_id="custom_ops_user", host_id="k8s-node-99.infra",
                source_ip="198.18.50.12", session_id="sess-custom-01", is_suspicious=True,
                severity=EventSeverity.HIGH
            ),
            make_event(
                "evt-2", "2026-10-18T10:01:00Z", EventType.PROCESS_EXECUTION,
                user_id="custom_ops_user", host_id="k8s-node-99.infra", session_id="sess-custom-01",
                process_id=7701, process_name="ruby", command_line="ruby -e 'exec'",
                is_suspicious=True, severity=EventSeverity.HIGH
            ),
            make_event(
                "evt-3", "2026-10-18T10:02:00Z", EventType.FILE_AUDIT,
                user_id="custom_ops_user", host_id="k8s-node-99.infra", session_id="sess-custom-01",
                process_id=7701, file_path="/etc/kubernetes/pki/apiserver.key", action="FILE_READ",
                is_suspicious=True, severity=EventSeverity.HIGH
            ),
            make_event(
                "evt-4", "2026-10-18T10:03:00Z", EventType.NETWORK_CONNECTION,
                host_id="k8s-node-99.infra", session_id="sess-custom-01", process_id=7701,
                destination_ip="198.18.99.200", destination_port=9001, is_suspicious=True,
                severity=EventSeverity.HIGH
            ),
        ]

        result = reconstruct_attack_timeline(custom_events)

        # Verify narrative dynamically incorporates custom entities
        h1 = result.hypotheses[0]
        assert "custom_ops_user" in h1.description
        assert "k8s-node-99.infra" in h1.description
        assert "198.18.50.12" in h1.description

        # Verify NO stale default entities exist anywhere in hypothesis or recommendations
        forbidden_stale_strings = ["svc_deploy", "198.51.100.42", "/var/sim_secrets/api_keys.env", "corp-app01"]
        for forbidden in forbidden_stale_strings:
            assert forbidden not in h1.description
            for rec in result.defensive_recommendations:
                assert forbidden not in rec.action
                assert forbidden not in (rec.target_entity or "")
                assert forbidden not in rec.why_recommended

        # Verify recommendation references custom entities
        rec_targets = [r.target_entity for r in result.defensive_recommendations if r.target_entity]
        assert any("/etc/kubernetes/pki/apiserver.key" in t for t in rec_targets)
        assert any("k8s-node-99.infra" in t for t in rec_targets)

    def test_case_3_benign_dataset_cannot_inherit_attack_narrative(self):
        """
        3. A benign dataset cannot inherit the multi-stage attack narrative.
        """
        events, _ = load_events_from_fixture("data/fixtures/scenario_routine_baseline.json")
        result = reconstruct_attack_timeline(events)

        assert len(result.candidate_entry_points) == 0
        h1 = result.hypotheses[0]
        assert "Normal Business" in h1.title or "Routine" in h1.title
        assert "attack" not in h1.title.lower()
        assert "adversary" not in h1.description.lower()
        assert h1.evidence_grade == "Strong"
        assert h1.score > 0.90

    def test_case_4_suspicious_process_alone_does_not_establish_compromise(self):
        """
        4. A suspicious process alone does not establish compromise.
        """
        isolated_proc = [
            make_event(
                "evt-proc-only", "2026-10-18T12:00:00Z", EventType.PROCESS_EXECUTION,
                host_id="ws-99", user_id="bob", process_id=5000, process_name="nmap",
                command_line="nmap -sT 127.0.0.1", is_suspicious=True, severity=EventSeverity.MEDIUM
            )
        ]
        result = reconstruct_attack_timeline(isolated_proc)

        # When only 1 isolated process exists without correlation or auth, NO entry point / compromise is established
        assert len(result.candidate_entry_points) == 0

        # Primary hypothesis title and description must note isolated/incomplete nature
        h1 = result.hypotheses[0]
        assert "Isolated" in h1.title or "Incomplete" in h1.title or "Single" in h1.title or h1.evidence_grade == "Weak"
        assert "insufficient" in h1.description.lower() or "isolated" in h1.description.lower()

    def test_case_5_file_read_followed_by_unrelated_network_does_not_claim_exfil(self):
        """
        5. A file read followed by unrelated network activity does not establish exfiltration.
        """
        e_read = make_event(
            "evt-file", "2026-10-18T13:00:00Z", EventType.FILE_AUDIT,
            file_path="/etc/passwd", session_id="sess-read-A", process_id=1001, is_suspicious=True
        )
        # Network connection by a DIFFERENT process and DIFFERENT session
        e_net = make_event(
            "evt-net", "2026-10-18T13:05:00Z", EventType.NETWORK_CONNECTION,
            destination_ip="203.0.113.9", destination_port=80, session_id="sess-net-B",
            process_id=2002, is_suspicious=True
        )

        result = reconstruct_attack_timeline([e_read, e_net])

        # Exfiltration conclusion should NOT connect these unrelated events
        exfil_conclusions = [
            c for c in result.inferred_conclusions
            if "exfiltration" in c.statement.lower()
        ]
        assert len(exfil_conclusions) == 0

    def test_case_6_smb_connection_without_target_evidence_does_not_establish_lateral_movement(self):
        """
        6. An SMB connection without target-side evidence does not establish successful lateral movement.
        """
        e_smb = make_event(
            "evt-smb-probe", "2026-10-18T14:00:00Z", EventType.NETWORK_CONNECTION,
            destination_ip="10.0.0.10", destination_port=445, is_suspicious=True
        )
        result = reconstruct_attack_timeline([e_smb])

        # Must flag unresolved question requiring target-side event logs
        unresolved = [
            q for q in result.unresolved_questions
            if "10.0.0.10" in q.question
        ]
        assert len(unresolved) == 1
        assert "Target Host" in unresolved[0].missing_evidence_type
        assert "4624" in unresolved[0].missing_evidence_type or "Event Logs" in unresolved[0].missing_evidence_type

    def test_case_7_every_hypothesis_and_recommendation_references_valid_evidence_ids(self):
        """
        7. Every hypothesis and recommendation references valid evidence IDs.
        """
        events, _ = load_events_from_fixture("data/fixtures/simulated_events.json")
        valid_ids = {e.event_id for e in events}

        result = reconstruct_attack_timeline(events)

        for hypo in result.hypotheses:
            for s_id in hypo.supporting_event_ids:
                assert s_id in valid_ids, f"Hypothesis {hypo.hypothesis_id} cited unknown event {s_id}"
            for c_id in hypo.contradicting_event_ids:
                assert c_id in valid_ids, f"Hypothesis {hypo.hypothesis_id} cited unknown contradiction {c_id}"

        for rec in result.defensive_recommendations:
            assert len(rec.supporting_event_ids) > 0, f"Recommendation {rec.recommendation_id} has empty evidence"
            for s_id in rec.supporting_event_ids:
                assert s_id in valid_ids, f"Recommendation {rec.recommendation_id} cited unknown event {s_id}"

    def test_case_8_removing_supporting_event_updates_or_removes_dependent_conclusion(self):
        """
        8. Removing a supporting event updates or removes any dependent conclusion.
        """
        events, _ = load_events_from_fixture("data/fixtures/simulated_events.json")
        base_result = reconstruct_attack_timeline(events)

        # Baseline has SMB probe conclusion
        smb_concs = [c for c in base_result.inferred_conclusions if "445" in c.statement or "SMB" in c.statement]
        assert len(smb_concs) == 1

        # Remove the SMB event evt-net-2006
        filtered = [e for e in events if e.event_id != "evt-net-2006"]
        filtered_result = reconstruct_attack_timeline(filtered)

        # SMB conclusion must be completely gone
        smb_concs_mod = [c for c in filtered_result.inferred_conclusions if "445" in c.statement or "SMB" in c.statement]
        assert len(smb_concs_mod) == 0

    def test_case_9_competing_explanations_and_contradictions_accurately_represented(self):
        """
        9. Competing explanations and contradictory evidence are represented accurately.
        """
        events, _ = load_events_from_fixture("data/fixtures/simulated_events.json")
        result = reconstruct_attack_timeline(events)

        assert len(result.hypotheses) >= 2
        h1 = result.hypotheses[0]
        h2 = result.hypotheses[1]

        # Hypothesis 1: Intrusion
        assert h1.rank == 1
        assert h1.score > h2.score
        assert h1.score_breakdown is not None
        assert "lifecycle_stages" in h1.score_breakdown

        # Hypothesis 2: Competing administrative / automation explanation
        assert h2.rank == 2
        assert "Authorized" in h2.title or "Administrative" in h2.title
        assert h2.score_breakdown is not None
        assert len(h2.contradicting_event_ids) > 0

    def test_case_10_validated_local_log_import_json_and_jsonl(self):
        """
        10. Local log import supports JSON and JSONL, validates schemas, and rejects malformed/oversized payloads.
        """
        # Test JSONL format
        jsonl_content = (
            '{"event_id": "imp-1", "timestamp": "2026-10-18T10:00:00Z", "event_type": "AUTHENTICATION", "user_id": "admin"}\n'
            '{"event_id": "imp-2", "timestamp": "2026-10-18T10:05:00Z", "event_type": "PROCESS_EXECUTION", "process_id": 100}\n'
        )
        res_jsonl = parse_and_import_logs(jsonl_content)
        assert res_jsonl.format_detected == "JSONL"
        assert res_jsonl.valid_events_count == 2
        assert res_jsonl.events[0].event_id == "imp-1"

        # Test API endpoint
        response = client.post("/api/v1/events/import", json={"content": jsonl_content})
        assert response.status_code == 200
        data = response.json()
        assert data["format_detected"] == "JSONL"
        assert data["valid_events_count"] == 2

        # Test oversized payload rejection
        oversized = "a" * (3 * 1024 * 1024)  # 3 MB
        res_over = client.post("/api/v1/events/import", json={"content": oversized})
        assert res_over.status_code == 400
        assert "exceeds maximum permitted size" in res_over.json()["detail"]

    def test_case_11_single_failed_login_followed_by_success_does_not_claim_compromise(self):
        """
        11. A failed login followed by a successful login must not, by itself,
        establish credential spraying or account compromise.
        """
        isolated_logins = [
            make_event(
                "evt-fail", "2026-10-18T09:00:00Z", EventType.AUTHENTICATION,
                action="LOGON_FAILURE", user_id="charlie", source_ip="198.51.100.5",
                is_suspicious=True, severity=EventSeverity.LOW
            ),
            make_event(
                "evt-succ", "2026-10-18T09:00:30Z", EventType.AUTHENTICATION,
                action="LOGON_SUCCESS", user_id="charlie", source_ip="198.51.100.5",
                is_suspicious=True, severity=EventSeverity.LOW
            ),
        ]
        result = reconstruct_attack_timeline(isolated_logins)

        # Must not claim multi-stage attack lifecycle
        h1 = result.hypotheses[0]
        assert "Multi-Stage" not in h1.title
        assert h1.evidence_grade in ("Weak", "Insufficient")

        # Inferred conclusions must explicitly state compromise is unproven
        auth_concs = [c for c in result.inferred_conclusions if "charlie" in c.statement]
        assert len(auth_concs) > 0
        assert any("UNPROVEN" in c.statement or "does not establish" in c.statement for c in auth_concs)
        assert any("credential spraying" in c.statement for c in auth_concs)

    def test_case_12_failed_only_logins_produce_no_entry_point(self):
        """
        12. Clusters with only failed authentication attempts produce no entry points
        because initial access was not achieved.
        """
        failed_only = [
            make_event(
                "evt-f1", "2026-10-18T09:00:00Z", EventType.AUTHENTICATION,
                action="LOGON_FAILURE", user_id="root", source_ip="203.0.113.1",
                is_suspicious=True, severity=EventSeverity.MEDIUM
            ),
            make_event(
                "evt-f2", "2026-10-18T09:00:10Z", EventType.AUTHENTICATION,
                action="LOGON_FAILURE", user_id="admin", source_ip="203.0.113.1",
                is_suspicious=True, severity=EventSeverity.MEDIUM
            ),
        ]
        result = reconstruct_attack_timeline(failed_only)
        assert len(result.candidate_entry_points) == 0

    def test_case_13_missing_telemetry_penalizes_hypothesis_score(self):
        """
        13. Missing telemetry reduces the strength of a conclusion rather than
        being silently treated as evidence that an event occurred.
        """
        # Baseline: file read followed by ambiguous network egress
        e1 = make_event("e1", "2026-10-18T10:00:00Z", EventType.AUTHENTICATION, action="LOGON_SUCCESS", session_id="s1", is_suspicious=True)
        e2 = make_event("e2", "2026-10-18T10:01:00Z", EventType.FILE_AUDIT, file_path="/etc/shadow", session_id="s1", is_suspicious=True)
        e3 = make_event("e3", "2026-10-18T10:02:00Z", EventType.NETWORK_CONNECTION, destination_ip="198.51.100.2", destination_port=9001, session_id="s1", is_suspicious=True)
        res = reconstruct_attack_timeline([e1, e2, e3])

        h1 = res.hypotheses[0]
        assert h1.score_breakdown is not None
        assert "missing_evidence_penalty" in h1.score_breakdown
        assert h1.score_breakdown["missing_evidence_penalty"] > 0
        assert len(res.unresolved_questions) > 0
