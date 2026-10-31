"""
Unit tests for GhostTrace Correlation Engine.
Verifies shared identifier correlations, causation rules, timestamp independence,
and contradictory evidence detection.
"""

from datetime import datetime, timezone, timedelta
import pytest

from investigation_engine.correlation import correlate_events
from investigation_engine.models import (
    EventType,
    EventSeverity,
    SecurityEvent,
)


def create_event(
    event_id: str,
    timestamp_iso: str,
    event_type: EventType,
    session_id: str | None = None,
    process_id: int | None = None,
    user_id: str | None = None,
    host_id: str | None = None,
    source_ip: str | None = None,
    action: str | None = None,
    is_suspicious: bool = False,
    file_path: str | None = None,
    destination_ip: str | None = None,
    destination_port: int | None = None,
) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        timestamp=timestamp_iso,
        event_type=event_type,
        session_id=session_id,
        process_id=process_id,
        user_id=user_id,
        host_id=host_id,
        source_ip=source_ip,
        action=action,
        is_suspicious=is_suspicious,
        file_path=file_path,
        destination_ip=destination_ip,
        destination_port=destination_port,
        source="test_telemetry",
        original_event_data={"raw_id": event_id},
    )


class TestCorrelationEngine:
    def test_shared_session_correlation(self):
        """Events sharing identical session_id must form a causal correlation link."""
        e1 = create_event("evt-1", "2026-10-18T10:00:00Z", EventType.AUTHENTICATION, session_id="sess-alpha", user_id="bob", host_id="app01")
        e2 = create_event("evt-2", "2026-10-18T10:02:00Z", EventType.PROCESS_EXECUTION, session_id="sess-alpha", user_id="bob", host_id="app01", process_id=100)
        e3 = create_event("evt-3", "2026-10-18T10:03:00Z", EventType.FILE_AUDIT, session_id="sess-alpha", user_id="bob", host_id="app01", file_path="/etc/hosts")

        res = correlate_events([e1, e2, e3])
        assert len(res.clusters) == 1
        assert len(res.clusters[0].events) == 3

        # Check links
        session_links = [l for l in res.all_links if l.link_type == "SAME_SESSION_EXECUTION"]
        assert len(session_links) >= 2
        for link in session_links:
            assert link.is_causal is True
            assert link.shared_identifiers["session_id"] == "sess-alpha"

    def test_timestamps_alone_do_not_establish_causation(self):
        """
        CRITICAL TEST: Events occurring close in time but having different users, hosts,
        sessions, and processes must NOT have a causal link.
        """
        e1 = create_event("evt-user-a", "2026-10-18T10:00:00Z", EventType.AUTHENTICATION, user_id="user_a", host_id="host_a", session_id="sess-a")
        # e2 occurs only 1 second later, but belongs to user_b on host_b
        e2 = create_event("evt-user-b", "2026-10-18T10:00:01Z", EventType.PROCESS_EXECUTION, user_id="user_b", host_id="host_b", session_id="sess-b")

        res = correlate_events([e1, e2])

        # They must belong to separate clusters or unrelated events
        assert len(res.clusters) == 2 or (len(res.unrelated_events) > 0)
        # There must be NO causal link between them
        causal_links = [l for l in res.all_links if l.is_causal]
        assert not any(
            (l.source_event_id == "evt-user-a" and l.target_event_id == "evt-user-b")
            or (l.source_event_id == "evt-user-b" and l.target_event_id == "evt-user-a")
            for l in causal_links
        )

    def test_shared_process_context_on_host(self):
        """Process execution followed by file audit sharing PID on same host must link causally."""
        e1 = create_event("proc-1", "2026-10-18T11:00:00Z", EventType.PROCESS_EXECUTION, host_id="srv-1", process_id=4500)
        e2 = create_event("file-1", "2026-10-18T11:01:00Z", EventType.FILE_AUDIT, host_id="srv-1", process_id=4500, file_path="/var/log/audit.log")

        res = correlate_events([e1, e2])
        proc_links = [l for l in res.all_links if "PROCESS" in l.link_type]
        assert len(proc_links) >= 1
        assert proc_links[0].is_causal is True
        assert proc_links[0].shared_identifiers["process_id"] == "4500"

    def test_contradictory_evidence_activity_without_successful_auth(self):
        """Logon failure followed by active session commands without success must flag contradiction."""
        e1 = create_event("auth-fail", "2026-10-18T09:00:00Z", EventType.AUTHENTICATION, user_id="admin", action="LOGON_FAILURE", host_id="srv-1")
        e2 = create_event("proc-cmd", "2026-10-18T09:01:00Z", EventType.PROCESS_EXECUTION, user_id="admin", session_id="ghost-session", host_id="srv-1")

        res = correlate_events([e1, e2])
        assert len(res.contradictions) > 0
        conflict = res.contradictions[0]
        assert conflict.conflict_type == "ACTIVITY_AFTER_LOGON_FAILURE_WITHOUT_SUCCESS"
        assert "auth-fail" in conflict.event_ids
        assert "proc-cmd" in conflict.event_ids

    def test_unrelated_routine_activity_isolated(self):
        """Routine maintenance on host-1 must not contaminate attack cluster on host-2."""
        # Attack events on host-app01
        a1 = create_event("atk-1", "2026-10-18T12:00:00Z", EventType.AUTHENTICATION, session_id="atk-sess", host_id="host-app01", is_suspicious=True)
        a2 = create_event("atk-2", "2026-10-18T12:01:00Z", EventType.PROCESS_EXECUTION, session_id="atk-sess", host_id="host-app01", is_suspicious=True)
        # Independent routine maintenance on host-dc01
        r1 = create_event("rtn-1", "2026-10-18T12:00:30Z", EventType.PROCESS_EXECUTION, host_id="host-dc01", process_id=12, is_suspicious=False)

        res = correlate_events([a1, a2, r1])

        # Attack events should form a suspicious cluster, while r1 is either an unrelated event or separate routine cluster
        suspicious_clusters = [c for c in res.clusters if c.is_suspicious]
        assert len(suspicious_clusters) == 1
        cluster_event_ids = {e.event_id for e in suspicious_clusters[0].events}
        assert "atk-1" in cluster_event_ids
        assert "atk-2" in cluster_event_ids
        assert "rtn-1" not in cluster_event_ids
