"""
Investigation Graph representation using NetworkX.
Enables modeling forensic events and related entities (hosts, users, processes, files, IPs)
and serializing to Cytoscape.js compatible formats for the React frontend.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
import networkx as nx

from investigation_engine.models import SecurityEvent


class InvestigationGraph:
    """
    Forensic investigation graph backed by NetworkX MultiDiGraph.
    Represents events, entities, and relationships for timeline reconstruction
    and attack path correlation.
    """

    def __init__(self, name: str = "GhostTrace-Investigation"):
        self.name = name
        self.graph: nx.MultiDiGraph = nx.MultiDiGraph(name=name)

    def add_event(self, event: SecurityEvent) -> str:
        """
        Add a SecurityEvent node to the graph and link it to its associated entities.
        Returns the event node ID.
        """
        event_node_id = f"evt:{event.event_id}"

        # Add event node
        self.graph.add_node(
            event_node_id,
            node_type="event",
            label=event.event_type.value,
            event_id=event.event_id,
            timestamp=event.timestamp.isoformat(),
            severity=event.severity.value,
            source=event.source,
            source_event_id=event.source_event_id,
            is_suspicious=event.is_suspicious,
            description=event.description or "",
            mitre_attack_id=event.mitre_attack_id or "",
            action=event.action or "",
        )

        # Entity links: Session
        if event.session_id:
            sess_node_id = f"sess:{event.session_id}"
            if not self.graph.has_node(sess_node_id):
                self.graph.add_node(
                    sess_node_id,
                    node_type="session",
                    label=f"Sess: {event.session_id}",
                    session_id=event.session_id,
                    user_id=event.user_id or "",
                    host_id=event.host_id or "",
                    is_suspicious=event.is_suspicious,
                    importance_reason="User logon / authentication session boundary for forensic correlation",
                )
            self.graph.add_edge(
                event_node_id,
                sess_node_id,
                relation="IN_SESSION",
                inferred=False,
                supporting_event_ids=[event.event_id],
                rationale=f"Event executed within session '{event.session_id}'",
                limitations="Session boundaries depend on telemetry authentication state.",
            )

        # Entity links: Host
        if event.host_id:
            host_node_id = f"host:{event.host_id}"
            if not self.graph.has_node(host_node_id):
                self.graph.add_node(
                    host_node_id,
                    node_type="host",
                    label=event.host_id,
                    name=event.host_id,
                    importance_reason=f"Target or execution host endpoint '{event.host_id}'",
                )
            self.graph.add_edge(
                event_node_id,
                host_node_id,
                relation="OCCURRED_ON",
                inferred=False,
                supporting_event_ids=[event.event_id],
                rationale=f"Telemetry recorded on host '{event.host_id}'",
                limitations="Direct observed host context.",
            )

        # Entity links: User
        if event.user_id:
            user_node_id = f"user:{event.user_id}"
            if not self.graph.has_node(user_node_id):
                self.graph.add_node(
                    user_node_id,
                    node_type="user",
                    label=event.user_id,
                    name=event.user_id,
                    importance_reason=f"Security principal / user account '{event.user_id}'",
                )
            self.graph.add_edge(
                user_node_id,
                event_node_id,
                relation="INITIATED",
                inferred=False,
                supporting_event_ids=[event.event_id],
                rationale=f"Principal '{event.user_id}' associated with event initiation",
                limitations="Observed user identity from security audit log.",
            )

        # Entity links: Source IP
        if event.source_ip:
            ip_node_id = f"ip:{event.source_ip}"
            if not self.graph.has_node(ip_node_id):
                is_external = not event.source_ip.startswith("10.") and not event.source_ip.startswith("192.168.")
                self.graph.add_node(
                    ip_node_id,
                    node_type="ip",
                    label=event.source_ip,
                    ip=event.source_ip,
                    is_suspicious=is_external or event.is_suspicious,
                    importance_reason=f"{'Untrusted external' if is_external else 'Internal'} source network address",
                )
            self.graph.add_edge(
                ip_node_id,
                event_node_id,
                relation="ORIGINATED_FROM",
                inferred=False,
                supporting_event_ids=[event.event_id],
                rationale=f"Network traffic or authentication originated from IP '{event.source_ip}'",
                limitations="Observed socket origin address.",
            )

        # Entity links: Destination IP
        if event.destination_ip:
            dest_ip_node_id = f"ip:{event.destination_ip}"
            if not self.graph.has_node(dest_ip_node_id):
                is_external = not event.destination_ip.startswith("10.") and not event.destination_ip.startswith("192.168.")
                self.graph.add_node(
                    dest_ip_node_id,
                    node_type="ip",
                    label=event.destination_ip,
                    ip=event.destination_ip,
                    is_suspicious=is_external or event.is_suspicious,
                    importance_reason=f"{'External destination / potential C2' if is_external else 'Internal destination'} endpoint",
                )
            self.graph.add_edge(
                event_node_id,
                dest_ip_node_id,
                relation="COMMUNICATED_WITH",
                inferred=False,
                supporting_event_ids=[event.event_id],
                rationale=f"Socket connection established to '{event.destination_ip}:{event.destination_port or ''}'",
                limitations="Direct network flow observation.",
            )

        # Entity links: File
        if event.file_path:
            file_node_id = f"file:{event.file_path}"
            if not self.graph.has_node(file_node_id):
                is_sensitive = any(s in event.file_path.lower() for s in ("secret", "shadow", "passwd", "key", "cred"))
                self.graph.add_node(
                    file_node_id,
                    node_type="file",
                    label=event.file_path.split("/")[-1] or event.file_path,
                    path=event.file_path,
                    is_suspicious=is_sensitive,
                    importance_reason=f"{'Sensitive credential/secret asset' if is_sensitive else 'Target file system artifact'}",
                )
            self.graph.add_edge(
                event_node_id,
                file_node_id,
                relation="ACCESSED_FILE",
                inferred=False,
                supporting_event_ids=[event.event_id],
                rationale=f"File {event.action or 'access'} performed on '{event.file_path}'",
                limitations="File audit system call observation.",
            )

        # Entity links: Process
        if event.process_id is not None or event.process_name:
            proc_label = event.process_name or f"PID:{event.process_id}"
            proc_node_id = f"proc:{event.host_id or 'unknown'}:{event.process_id or proc_label}"
            if not self.graph.has_node(proc_node_id):
                self.graph.add_node(
                    proc_node_id,
                    node_type="process",
                    label=proc_label,
                    process_id=event.process_id,
                    process_name=event.process_name or "",
                    command_line=event.command_line or "",
                    is_suspicious=event.is_suspicious,
                    importance_reason="Executing process image on host endpoint",
                )
            self.graph.add_edge(
                proc_node_id,
                event_node_id,
                relation="EXECUTED",
                inferred=False,
                supporting_event_ids=[event.event_id],
                rationale=f"Process {proc_label} generated event",
                limitations="Kernel process execution telemetry.",
            )

            # Parent-child process relationship
            parent_pid = (
                event.original_event_data.get("ParentProcessId")
                or event.original_event_data.get("parent_process_id")
                or event.original_event_data.get("ppid")
            )
            if parent_pid and event.process_id is not None and str(parent_pid) != str(event.process_id):
                parent_proc_node_id = f"proc:{event.host_id or 'unknown'}:{parent_pid}"
                if not self.graph.has_node(parent_proc_node_id):
                    self.graph.add_node(
                        parent_proc_node_id,
                        node_type="process",
                        label=f"Parent PID:{parent_pid}",
                        process_id=parent_pid,
                        importance_reason=f"Parent process PID {parent_pid} identified from execution metadata",
                    )
                if not self.graph.has_edge(parent_proc_node_id, proc_node_id):
                    self.graph.add_edge(
                        parent_proc_node_id,
                        proc_node_id,
                        relation="SPAWNED_PROCESS",
                        inferred=False,
                        supporting_event_ids=[event.event_id],
                        rationale=f"Parent process {parent_pid} spawned child process {event.process_id}",
                        limitations="Observed parent process ID from process creation telemetry.",
                    )

        return event_node_id

    def add_hypothesis_node(self, hypothesis: Any) -> str:
        """Add an incident hypothesis node and connect supporting events."""
        hypo_node_id = f"hypo:{hypothesis.hypothesis_id}"
        self.graph.add_node(
            hypo_node_id,
            node_type="hypothesis",
            label=f"H{hypothesis.rank}: {hypothesis.title[:24]}...",
            title=hypothesis.title,
            rank=hypothesis.rank,
            score=hypothesis.score,
            confidence=hypothesis.confidence,
            confidence_explanation=hypothesis.confidence_explanation,
            is_suspicious=True,
            importance_reason=f"Candidate incident hypothesis (Rank {hypothesis.rank}, Score {(hypothesis.score*100):.0f}%)",
        )

        for supporting_id in hypothesis.supporting_event_ids:
            evt_node = f"evt:{supporting_id}"
            if self.graph.has_node(evt_node):
                self.graph.add_edge(
                    evt_node,
                    hypo_node_id,
                    relation="SUPPORTS_HYPOTHESIS",
                    inferred=True,
                    supporting_event_ids=[supporting_id],
                    confidence=hypothesis.score,
                    rationale=f"Event {supporting_id} corroborates hypothesis: {hypothesis.title}",
                    limitations="Inferred hypothesis correlation based on multi-source evidence pattern.",
                )
        return hypo_node_id

    def build_from_events(self, events: List[SecurityEvent], include_hypotheses: Optional[List[Any]] = None) -> None:
        """Populate the graph from a list of SecurityEvents and optional hypotheses."""
        # Sort chronologically
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        previous_event_id: Optional[str] = None

        for event in sorted_events:
            current_event_node = self.add_event(event)
            # Add sequential temporal edge between events on the same host or user if applicable
            if previous_event_id:
                prev_id_clean = previous_event_id.replace("evt:", "")
                curr_id_clean = current_event_node.replace("evt:", "")
                self.graph.add_edge(
                    previous_event_id,
                    current_event_node,
                    relation="PRECEDES_TEMPORALLY",
                    inferred=True,
                    supporting_event_ids=[prev_id_clean, curr_id_clean],
                    confidence=0.6,
                    rationale="Events observed in chronological succession on telemetry stream",
                    limitations="Temporal proximity alone does NOT establish causation without shared execution context.",
                )
            previous_event_id = current_event_node

        if include_hypotheses:
            for hypo in include_hypotheses:
                self.add_hypothesis_node(hypo)

    def to_cytoscape_elements(self) -> List[Dict[str, Any]]:
        """
        Export graph in standard Cytoscape.js elements JSON format:
        [
          { "group": "nodes", "data": { "id": "...", "label": "...", ... } },
          { "group": "edges", "data": { "id": "...", "source": "...", "target": "...", "relation": "..." } }
        ]
        """
        elements: List[Dict[str, Any]] = []

        # Nodes
        for node_id, attrs in self.graph.nodes(data=True):
            node_data = {"id": str(node_id), **attrs}
            elements.append({"group": "nodes", "data": node_data})

        # Edges
        edge_counter = 0
        for u, v, key, attrs in self.graph.edges(keys=True, data=True):
            edge_counter += 1
            edge_id = f"edge_{u}_{v}_{key}_{edge_counter}"
            edge_data = {
                "id": edge_id,
                "source": str(u),
                "target": str(v),
                **attrs,
            }
            elements.append({"group": "edges", "data": edge_data})

        return elements

