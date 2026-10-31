"""
GhostTrace Correlation Engine.
Correlates security events into coherent incident clusters using shared identifiers
(session IDs, process IDs, user IDs, host IDs, IP addresses, and file/network relationships).

CRITICAL FORENSIC RULES:
1. Timestamps alone NEVER establish causation. Causal links require shared execution contexts
   (e.g., shared session ID, parent/child process lineage, or explicit network/file binds).
2. Unrelated routine activity is isolated from incident clusters.
3. Contradictory evidence (e.g. actions without authentication, conflicting sessions) is flagged.
4. Source event IDs and evidence provenance are preserved on all correlation links.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple
from collections import defaultdict
from pydantic import BaseModel, Field

from investigation_engine.models import (
    EventType,
    EventSeverity,
    SecurityEvent,
)


class CorrelationLink(BaseModel):
    """Represents a validated correlation link between two security events."""
    source_event_id: str = Field(..., description="ID of the initiating or prior event")
    target_event_id: str = Field(..., description="ID of the related or subsequent event")
    link_type: str = Field(..., description="Forensic correlation type")
    shared_identifiers: Dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    rationale: str = ""
    is_causal: bool = Field(default=False, description="True only if strict execution/session lineage exists")


class Contradiction(BaseModel):
    """Flags contradictory, conflicting, or inconsistent evidence in telemetry."""
    contradiction_id: str
    event_ids: List[str]
    conflict_type: str
    description: str


class CorrelatedCluster(BaseModel):
    """A cluster of forensic events connected by shared identifiers."""
    cluster_id: str
    title: str
    events: List[SecurityEvent]
    links: List[CorrelationLink] = Field(default_factory=list)
    contradictions: List[Contradiction] = Field(default_factory=list)
    primary_host: Optional[str] = None
    primary_user: Optional[str] = None
    primary_ip: Optional[str] = None
    is_suspicious: bool = False


class CorrelationResult(BaseModel):
    clusters: List[CorrelatedCluster] = Field(default_factory=list)
    unrelated_events: List[SecurityEvent] = Field(default_factory=list)
    all_links: List[CorrelationLink] = Field(default_factory=list)
    contradictions: List[Contradiction] = Field(default_factory=list)


def correlate_events(
    events: List[SecurityEvent],
    correlation_window_seconds: int = 3600,
) -> CorrelationResult:
    """
    Correlates a collection of SecurityEvents into coherent incident or activity clusters.

    Uses deterministic rule-based correlation based on:
    - Session ID binding (high confidence, causal execution context)
    - Process lineage / PID on the same host (causal)
    - User and Host within temporal window (contextual correlation, non-causal unless session matches)
    - Source IP activity (actor correlation)
    """
    if not events:
        return CorrelationResult()

    # Chronological sort while preserving original objects
    sorted_events = sorted(events, key=lambda e: e.timestamp)

    links: List[CorrelationLink] = []
    contradictions: List[Contradiction] = []
    contradiction_counter = 0

    # Indexing maps for efficient identifier lookup
    session_map: Dict[str, List[SecurityEvent]] = defaultdict(list)
    proc_map: Dict[Tuple[str, Any], List[SecurityEvent]] = defaultdict(list)
    user_host_map: Dict[Tuple[str, str], List[SecurityEvent]] = defaultdict(list)
    ip_map: Dict[str, List[SecurityEvent]] = defaultdict(list)

    for evt in sorted_events:
        if evt.session_id:
            session_map[evt.session_id].append(evt)
        if evt.host_id and evt.process_id is not None:
            proc_map[(evt.host_id, str(evt.process_id))].append(evt)
        if evt.user_id and evt.host_id:
            user_host_map[(evt.user_id, evt.host_id)].append(evt)
        if evt.source_ip:
            ip_map[evt.source_ip].append(evt)

    # 1. Correlate by Session ID (Strongest Causal Link)
    for session_id, s_events in session_map.items():
        if len(s_events) > 1:
            for i in range(len(s_events) - 1):
                e1 = s_events[i]
                e2 = s_events[i + 1]
                # Same session indicates causal continuity within user session
                links.append(
                    CorrelationLink(
                        source_event_id=e1.event_id,
                        target_event_id=e2.event_id,
                        link_type="SAME_SESSION_EXECUTION",
                        shared_identifiers={"session_id": session_id},
                        confidence=0.95,
                        rationale=f"Events executed within identical session '{session_id}' on host '{e1.host_id or e2.host_id}'",
                        is_causal=True,
                    )
                )

    # 2. Correlate by Process ID on Host (Process Activity Link)
    for (host_id, pid_str), p_events in proc_map.items():
        if len(p_events) > 1:
            for i in range(len(p_events) - 1):
                e1 = p_events[i]
                e2 = p_events[i + 1]
                # Avoid duplicate links if already linked by session
                if e1.session_id and e1.session_id == e2.session_id:
                    continue

                relation_label = "SHARED_PROCESS_CONTEXT"
                if e1.event_type == EventType.PROCESS_EXECUTION and e2.event_type == EventType.FILE_AUDIT:
                    relation_label = "PROCESS_ACCESSED_FILE"
                elif e1.event_type == EventType.PROCESS_EXECUTION and e2.event_type == EventType.NETWORK_CONNECTION:
                    relation_label = "PROCESS_OPENED_NETWORK_CONNECTION"

                links.append(
                    CorrelationLink(
                        source_event_id=e1.event_id,
                        target_event_id=e2.event_id,
                        link_type=relation_label,
                        shared_identifiers={"host_id": host_id, "process_id": pid_str},
                        confidence=0.90,
                        rationale=f"Events associated with identical PID {pid_str} on host '{host_id}'",
                        is_causal=True,
                    )
                )

    # 3. Correlate Authentication Spray / Brute Force (Shared Actor IP & User Target)
    for ip, ip_events in ip_map.items():
        # Check for multiple auth attempts from same source IP
        auth_events = [e for e in ip_events if e.event_type == EventType.AUTHENTICATION]
        if len(auth_events) > 1:
            for i in range(len(auth_events) - 1):
                e1 = auth_events[i]
                e2 = auth_events[i + 1]
                time_delta = abs((e2.timestamp - e1.timestamp).total_seconds())
                if time_delta <= correlation_window_seconds:
                    links.append(
                        CorrelationLink(
                            source_event_id=e1.event_id,
                            target_event_id=e2.event_id,
                            link_type="SOURCE_IP_AUTHENTICATION_STREAM",
                            shared_identifiers={"source_ip": ip, "target_user": e2.user_id},
                            confidence=0.85,
                            rationale=f"Sequential authentication requests originating from external IP '{ip}'",
                            is_causal=False,  # Temporal co-occurrence from same origin, not causation
                        )
                    )

    # 4. Check for Contradictory Evidence
    # Contradiction Type 1: Session activity with no prior successful authentication
    for session_id, s_events in session_map.items():
        auth_successes = [
            e for e in s_events
            if e.event_type == EventType.AUTHENTICATION and e.action == "LOGON_SUCCESS"
        ]
        non_auth_events = [e for e in s_events if e.event_type != EventType.AUTHENTICATION]
        # If there are failed logons with the same user/IP but no success recorded in dataset
        if non_auth_events and not auth_successes:
            # Check if there is an explicit failed logon for this session or user
            related_failures = [
                e for e in sorted_events
                if e.event_type == EventType.AUTHENTICATION
                and e.action == "LOGON_FAILURE"
                and e.user_id == non_auth_events[0].user_id
            ]
            if related_failures:
                contradiction_counter += 1
                contradictions.append(
                    Contradiction(
                        contradiction_id=f"contra-{contradiction_counter}",
                        event_ids=[related_failures[0].event_id, non_auth_events[0].event_id],
                        conflict_type="ACTIVITY_AFTER_LOGON_FAILURE_WITHOUT_SUCCESS",
                        description=(
                            f"Session activity observed for user '{non_auth_events[0].user_id}' "
                            f"in session '{session_id}', but preceding authentication log recorded LOGON_FAILURE. "
                            f"Missing evidence of successful credential exchange or session hijacking."
                        ),
                    )
                )

    # Contradiction Type 2: Same Process ID executing concurrent operations on different hosts
    for (host_id, pid_str), p_events in proc_map.items():
        for other_evt in sorted_events:
            if (
                other_evt.process_id is not None
                and str(other_evt.process_id) == pid_str
                and other_evt.host_id
                and other_evt.host_id != host_id
                and other_evt.session_id
                and other_evt.session_id in [e.session_id for e in p_events if e.session_id]
            ):
                contradiction_counter += 1
                contradictions.append(
                    Contradiction(
                        contradiction_id=f"contra-{contradiction_counter}",
                        event_ids=[p_events[0].event_id, other_evt.event_id],
                        conflict_type="IMPOSSIBLE_CROSS_HOST_PID_AFFINITY",
                        description=(
                            f"Identical session '{other_evt.session_id}' and PID '{pid_str}' reported "
                            f"across distinct hosts '{host_id}' and '{other_evt.host_id}' without intervening network transfer."
                        ),
                    )
                )

    # 5. Form Clusters using Disjoint Set / Connected Components over Causal/Contextual Links
    # We group events that share correlation links into clusters
    parent: Dict[str, str] = {e.event_id: e.event_id for e in events}

    def find(x: str) -> str:
        if parent[x] != x:
            parent[x] = find(parent[x])
        return parent[x]

    def union(x: str, y: str):
        rx, ry = find(x), find(y)
        if rx != ry:
            parent[rx] = ry

    for link in links:
        union(link.source_event_id, link.target_event_id)

    # Group into clusters
    cluster_groups: Dict[str, List[SecurityEvent]] = defaultdict(list)
    event_by_id = {e.event_id: e for e in events}

    for evt in events:
        root = find(evt.event_id)
        cluster_groups[root].append(evt)

    clusters: List[CorrelatedCluster] = []
    unrelated_events: List[SecurityEvent] = []
    cluster_num = 0

    for root_id, c_events in cluster_groups.items():
        # Chronological sort within cluster
        c_events.sort(key=lambda e: e.timestamp)

        # If a single event has no links to any other event, it is classified as an unrelated event
        c_links = [
            l for l in links
            if l.source_event_id in {e.event_id for e in c_events}
            or l.target_event_id in {e.event_id for e in c_events}
        ]

        if len(c_events) == 1 and not c_links:
            unrelated_events.append(c_events[0])
            continue

        cluster_num += 1
        is_suspicious_cluster = any(
            e.is_suspicious
            or e.severity in (EventSeverity.HIGH, EventSeverity.CRITICAL)
            or (e.event_type == EventType.AUTHENTICATION and e.action in ("LOGON_FAILURE", "FAILED"))
            for e in c_events
        )

        # Primary attributes
        hosts = [e.host_id for e in c_events if e.host_id]
        users = [e.user_id for e in c_events if e.user_id]
        ips = [e.source_ip for e in c_events if e.source_ip]

        primary_host = max(set(hosts), key=hosts.count) if hosts else None
        primary_user = max(set(users), key=users.count) if users else None
        primary_ip = max(set(ips), key=ips.count) if ips else None

        cluster_title = (
            f"Suspicious Intrusion Activity ({primary_user or 'unknown'} on {primary_host or 'multiple hosts'})"
            if is_suspicious_cluster
            else f"Routine Operations Thread ({primary_user or 'system'} on {primary_host or 'local'})"
        )

        cluster_contradictions = [
            c for c in contradictions
            if any(eid in {e.event_id for e in c_events} for eid in c.event_ids)
        ]

        clusters.append(
            CorrelatedCluster(
                cluster_id=f"cluster-{cluster_num}",
                title=cluster_title,
                events=c_events,
                links=c_links,
                contradictions=cluster_contradictions,
                primary_host=primary_host,
                primary_user=primary_user,
                primary_ip=primary_ip,
                is_suspicious=is_suspicious_cluster,
            )
        )

    return CorrelationResult(
        clusters=clusters,
        unrelated_events=unrelated_events,
        all_links=links,
        contradictions=contradictions,
    )
