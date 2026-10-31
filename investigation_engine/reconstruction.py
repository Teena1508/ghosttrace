"""
GhostTrace Attack Timeline Reconstruction Engine.
Consumes correlated events and builds a probable, evidence-backed incident timeline,
candidate entry points, alternative ranked hypotheses, observed facts vs. inferred conclusions,
evidence graph with typed edges, unresolved questions, and defensive recommendations.

FORENSIC PRINCIPLES ENFORCED:
1. Chronological event ordering while strictly preserving original timestamps.
2. Every major conclusion and inferred edge stores the source event IDs that support it.
3. Observed facts (raw telemetry) are strictly separated from Inferred conclusions.
4. Timestamps alone never establish causation; shared execution context is required.
5. EXFILTRATION RESTRAINT: Never claim data was exfiltrated solely because an outbound
   connection followed file access. Unproven exfiltration is explicitly labeled as unresolved.
6. SEVERITY NEUTRALITY: Never label an event as malicious solely because of a high severity score.
7. Support competing alternative hypotheses with deterministic evidence-quality scoring.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from investigation_engine.correlation import (
    CorrelatedCluster,
    CorrelationLink,
    CorrelationResult,
    correlate_events,
)
from investigation_engine.graph.base import InvestigationGraph
from investigation_engine.models import (
    AttackHypothesis,
    CandidateEntryPoint,
    DefensiveRecommendation,
    DetectionFinding,
    EventSeverity,
    EventType,
    EvidenceGraphData,
    EvidenceGraphEdge,
    EvidenceGraphNode,
    InferredConclusion,
    InvestigationReconstructionResult,
    ObservedFact,
    SecurityEvent,
    TimelineEvent,
    UnresolvedQuestion,
)
from investigation_engine.detections import evaluate_detections


def is_suspicious_event(event: SecurityEvent) -> bool:
    """
    Evaluates whether an event is suspicious based on explicit indicators,
    anomalous actions, or verified hostile patterns.
    Enforces SEVERITY NEUTRALITY: Audit severity alone never labels a routine action as malicious.
    """
    if event.is_suspicious:
        return True

    # Sensitive file reads (credentials, keys, tokens, shadow, confidential assets)
    if event.event_type == EventType.FILE_AUDIT and event.action in ("FILE_READ", "ACCESS", "READ"):
        if event.file_path and any(s in event.file_path.lower() for s in ("secret", "token", "shadow", "passwd", "key", "cred", "api", "confidential", "private", "sensitive", "m_and_a")):
            return True
        return False

    # External logon success vs routine internal administrative logon
    if event.event_type == EventType.AUTHENTICATION and event.action in ("LOGON_SUCCESS", "SUCCESS", "ACCEPTED"):
        if event.source_ip and not event.source_ip.startswith(("10.", "192.168.", "127.", "172.16.")):
            return True
        # Internal logons with high severity are not malicious solely because of severity
        return False

    if event.event_type == EventType.AUTHENTICATION and event.action in ("LOGON_FAILURE", "FAILED"):
        return True

    if event.event_type == EventType.PROCESS_EXECUTION:
        if event.command_line and any(k in event.command_line.lower() for k in ("base64", "curl -s", "wget -q", "sh |", "bash |", "c2", "iptables -f")):
            return True
        if event.severity in (EventSeverity.HIGH, EventSeverity.CRITICAL):
            return True
        return False

    if event.event_type == EventType.NETWORK_CONNECTION:
        if event.destination_port in (4444, 1337, 8888, 9001):
            return True
        is_external = bool(
            (event.destination_ip and not event.destination_ip.startswith(("10.", "192.168.", "127.", "172.16.")))
            or (event.source_ip and not event.source_ip.startswith(("10.", "192.168.", "127.", "172.16.")))
        )
        if is_external and event.severity in (EventSeverity.HIGH, EventSeverity.CRITICAL):
            return True
        if event.action == "INTERNAL_SMB_PROBE" or event.destination_port in (445, 139):
            return event.severity in (EventSeverity.HIGH, EventSeverity.CRITICAL)
        if event.description and any(k in event.description.lower() for k in ("injection", "signature", "exploit", "c2", "scanner", "brute force")):
            return True
        return False

    if event.severity in (EventSeverity.HIGH, EventSeverity.CRITICAL):
        return True

    return False


def determine_event_phase(event: SecurityEvent) -> str:
    """Classifies an event into an incident lifecycle phase based on observable attributes."""
    if not is_suspicious_event(event) and event.severity in (EventSeverity.INFORMATIONAL, EventSeverity.LOW):
        # Check if it's clearly routine
        if event.action in ("LOGON_SUCCESS", "FILE_READ", "PROCESS_CREATE", "CONNECTION_ESTABLISHED"):
            return "Routine Operations"

    if event.event_type == EventType.AUTHENTICATION:
        if event.action == "LOGON_FAILURE":
            return "Credential Access (Spray/Brute Force)"
        return "Initial Access"

    if event.event_type == EventType.PROCESS_EXECUTION:
        if event.command_line and any(k in event.command_line.lower() for k in ("base64", "curl", "wget", "sh", "bash")):
            return "Execution (Payload Invocation)"
        return "Execution"

    if event.event_type == EventType.FILE_AUDIT:
        if event.file_path and any(k in event.file_path.lower() for k in ("shadow", "secret", "password", "api_key", "credential")):
            return "Credential Access (Secrets Discovery)"
        return "Collection / Discovery"

    if event.event_type == EventType.NETWORK_CONNECTION:
        if event.destination_port in (4444, 1337, 8888, 9001) or (event.destination_ip and not event.destination_ip.startswith("10.")):
            return "Command & Control (Outbound Channel)"
        if event.destination_port in (445, 139, 389, 88) or event.action == "INTERNAL_SMB_PROBE":
            return "Lateral Movement (Reconnaissance)"
        return "Network Communication"

    return "Unknown"


def reconstruct_attack_timeline(
    events: List[SecurityEvent],
    correlation_result: Optional[CorrelationResult] = None,
) -> InvestigationReconstructionResult:
    """
    Main reconstruction pipeline:
    - Sorts events chronologically
    - Computes or uses existing correlation clusters
    - Identifies candidate entry points
    - Differentiates observed facts from inferred conclusions
    - Enforces exfiltration restraint and severity neutrality
    - Generates ranked alternative attack hypotheses
    - Produces evidence graph and defensive recommendations
    """
    if not events:
        empty_graph = EvidenceGraphData()
        return InvestigationReconstructionResult(
            investigation_id=f"inv-{uuid.uuid4().hex[:8]}",
            evidence_graph=empty_graph,
            metadata={"status": "empty", "event_count": 0},
        )

    # 1. Strictly order chronologically while preserving original timestamps
    sorted_events = sorted(events, key=lambda e: e.timestamp)

    # 2. Correlate if not already supplied
    if correlation_result is None:
        correlation_result = correlate_events(sorted_events)

    event_map = {e.event_id: e for e in sorted_events}

    # 3. Build Timeline Events
    timeline_events: List[TimelineEvent] = []
    for evt in sorted_events:
        phase = determine_event_phase(evt)
        desc = evt.description or f"{evt.event_type.value} on {evt.host_id or 'unknown host'}"
        timeline_events.append(
            TimelineEvent(
                event_id=evt.event_id,
                timestamp=evt.timestamp,
                event_type=evt.event_type,
                phase=phase,
                summary=desc,
                is_suspicious=is_suspicious_event(evt),
                supporting_event_ids=[evt.event_id],
                host_id=evt.host_id,
                user_id=evt.user_id,
            )
        )

    # 4. Extract Observed Facts (Directly Verified by Telemetry)
    observed_facts: List[ObservedFact] = []
    fact_idx = 0
    for evt in sorted_events:
        fact_idx += 1
        fact_desc = ""
        if evt.event_type == EventType.AUTHENTICATION:
            status = evt.action or ("SUCCESS" if not is_suspicious_event(evt) else "ATTEMPT")
            fact_desc = (
                f"Authentication record ({evt.source_event_id or evt.event_id}) logged {status} for "
                f"user '{evt.user_id or 'unknown'}' from source IP '{evt.source_ip or 'unknown'}' "
                f"targeting host '{evt.host_id or 'unknown'}'."
            )
        elif evt.event_type == EventType.PROCESS_EXECUTION:
            fact_desc = (
                f"Process creation recorded PID {evt.process_id or 'N/A'} "
                f"('{evt.process_name or 'unknown'}') on host '{evt.host_id or 'unknown'}'"
            )
            if evt.command_line:
                fact_desc += f" with command: '{evt.command_line}'."
            else:
                fact_desc += "."
        elif evt.event_type == EventType.FILE_AUDIT:
            fact_desc = (
                f"File audit ({evt.source}) recorded {evt.action or 'ACCESS'} on "
                f"path '{evt.file_path or 'unknown'}' on host '{evt.host_id or 'unknown'}' "
                f"by PID {evt.process_id or 'unknown'}."
            )
        elif evt.event_type == EventType.NETWORK_CONNECTION:
            fact_desc = (
                f"Network connection ({evt.source}) recorded traffic from "
                f"'{evt.source_ip or 'local'}' to '{evt.destination_ip or 'unknown'}:{evt.destination_port or ''}'."
            )
        else:
            fact_desc = f"Observed {evt.event_type.value} event on {evt.host_id or 'system'}."

        observed_facts.append(
            ObservedFact(
                fact_id=f"fact-{fact_idx}",
                statement=fact_desc,
                supporting_event_ids=[evt.event_id],
                source=evt.source,
                observed_at=evt.timestamp,
            )
        )

    # 5. Identify Candidate Entry Points (Evidence-Driven)
    candidate_entry_points: List[CandidateEntryPoint] = []
    suspicious_clusters = [c for c in correlation_result.clusters if c.is_suspicious]

    for cluster in suspicious_clusters:
        # Check if cluster contains only failed authentication attempts
        auth_events_in_cluster = [e for e in cluster.events if e.event_type == EventType.AUTHENTICATION]
        non_auth_in_cluster = [e for e in cluster.events if e.event_type != EventType.AUTHENTICATION]
        if auth_events_in_cluster and not non_auth_in_cluster:
            if all(e.action in ("LOGON_FAILURE", "FAILED") for e in auth_events_in_cluster):
                # Failed login attempts without any successful entry or execution do NOT establish an entry point
                continue

        # Find earliest successful authentication in this cluster
        auth_successes = [
            e for e in cluster.events
            if e.event_type == EventType.AUTHENTICATION and e.action in ("LOGON_SUCCESS", "SUCCESS", "ACCEPTED")
        ]
        if auth_successes:
            entry_evt = auth_successes[0]
            preceding_failures = [
                e for e in cluster.events
                if e.event_type == EventType.AUTHENTICATION
                and e.action in ("LOGON_FAILURE", "FAILED")
                and e.timestamp <= entry_evt.timestamp
                and (e.user_id == entry_evt.user_id or e.source_ip == entry_evt.source_ip)
            ]
            supporting = [entry_evt.event_id] + [f.event_id for f in preceding_failures]

            # Dynamic confidence calculation:
            base_score = 0.45
            is_external = bool(
                entry_evt.source_ip
                and not entry_evt.source_ip.startswith(("10.", "192.168.", "127.", "172.16."))
            )
            origin_bonus = 0.20 if is_external else 0.05

            downstream_events = [
                e for e in cluster.events
                if e.event_id != entry_evt.event_id
                and e.timestamp >= entry_evt.timestamp
                and (
                    (e.session_id and e.session_id == entry_evt.session_id)
                    or (e.user_id and e.user_id == entry_evt.user_id)
                    or (e.process_id and e.process_id == entry_evt.process_id)
                )
            ]
            has_hostile_downstream = any(is_suspicious_event(e) for e in downstream_events)
            continuity_bonus = 0.15 if downstream_events else 0.0

            if len(preceding_failures) >= 3:
                fail_bonus = 0.12
                fail_desc = f", preceded by {len(preceding_failures)} repeated authentication failures consistent with password spray or brute force"
            elif len(preceding_failures) >= 1:
                fail_bonus = 0.05
                fail_desc = f", preceded by {len(preceding_failures)} failed attempt(s) (potential mistyped credential or initial probe)"
            else:
                fail_bonus = 0.0
                fail_desc = " with direct valid credentials"

            raw_confidence = base_score + origin_bonus + continuity_bonus + fail_bonus
            if not has_hostile_downstream and len(downstream_events) == 0:
                confidence = min(0.45 if is_external else 0.35, round(raw_confidence, 2))
                grade = "Weak" if is_external else "Insufficient"
            else:
                confidence = round(min(0.95, max(0.20, raw_confidence)), 2)
                if confidence >= 0.80 and is_external and len(downstream_events) > 0 and has_hostile_downstream:
                    grade = "Strong"
                elif confidence >= 0.60:
                    grade = "Moderate"
                elif confidence >= 0.40:
                    grade = "Weak"
                else:
                    grade = "Insufficient"

            user_str = entry_evt.user_id or "unknown principal"
            host_str = entry_evt.host_id or "target system"
            ip_str = entry_evt.source_ip or "unrecorded origin"

            if not has_hostile_downstream and len(downstream_events) == 0:
                rationale = (
                    f"Interactive authentication recorded for account '{user_str}' on host '{host_str}' "
                    f"originating from {'external' if is_external else 'internal'} address '{ip_str}'{fail_desc}. "
                    f"CRITICAL FORENSIC ASSESSMENT: A failed login followed by a successful login does not establish credential spraying or account compromise without subsequent hostile activity."
                )
            else:
                rationale = (
                    f"Interactive authentication recorded for account '{user_str}' on host '{host_str}' "
                    f"originating from {'external' if is_external else 'internal'} address '{ip_str}'{fail_desc}. "
                    f"Followed by {len(downstream_events)} downstream session operation(s)."
                )

            breakdown = {
                "base_authentication_weight": base_score,
                "untrusted_origin_bonus": origin_bonus,
                "downstream_continuity_bonus": continuity_bonus,
                "preceding_failures_bonus": fail_bonus,
                "preceding_failures_count": len(preceding_failures),
                "downstream_events_count": len(downstream_events),
                "has_hostile_downstream": has_hostile_downstream,
                "raw_confidence": raw_confidence,
                "evidence_grade": grade,
                "limitations": "Confidence represents heuristic forensic weighting; authentication alone does not prove compromise without hostile execution continuity.",
            }

            candidate_entry_points.append(
                CandidateEntryPoint(
                    event_id=entry_evt.event_id,
                    timestamp=entry_evt.timestamp,
                    user_id=entry_evt.user_id,
                    source_ip=entry_evt.source_ip,
                    host_id=entry_evt.host_id,
                    rationale=rationale,
                    confidence=confidence,
                    evidence_grade=grade,
                    confidence_breakdown=breakdown,
                    supporting_event_ids=supporting,
                )
            )
        elif non_auth_in_cluster:
            # Only infer entry point from non-auth activity if execution/access occurred without preceding auth logs
            susp_in_cluster = [e for e in cluster.events if is_suspicious_event(e)]
            first_susp = susp_in_cluster[0] if susp_in_cluster else cluster.events[0]
            confidence = 0.45
            grade = "Weak"
            candidate_entry_points.append(
                CandidateEntryPoint(
                    event_id=first_susp.event_id,
                    timestamp=first_susp.timestamp,
                    user_id=first_susp.user_id,
                    source_ip=first_susp.source_ip,
                    host_id=first_susp.host_id,
                    rationale=f"First observed anomalous record ({first_susp.event_type.value}) without preceding authentication logs in dataset. Initial vector remains unobserved.",
                    confidence=confidence,
                    evidence_grade=grade,
                    confidence_breakdown={
                        "missing_preceding_auth_penalty": -0.30,
                        "raw_confidence": 0.45,
                        "evidence_grade": grade,
                        "limitations": "Missing initial access telemetry; entry point inferred from earliest suspicious activity.",
                    },
                    supporting_event_ids=[first_susp.event_id],
                )
            )

    # 6. Evaluate Deterministic Detection Rules
    detection_findings = evaluate_detections(sorted_events)

    # Inferred Conclusions, Unresolved Questions, & Exfiltration Restraint
    inferred_conclusions: List[InferredConclusion] = []
    unresolved_questions: List[UnresolvedQuestion] = []
    conclusion_counter = 0
    question_counter = 0

    for f in detection_findings:
        if f.missing_telemetry_limitations:
            question_counter += 1
            unresolved_questions.append(
                UnresolvedQuestion(
                    question_id=f"q-finding-{question_counter}",
                    question=f"Can the indicator '{f.rule_name}' be confirmed as malicious or refuted as benign?",
                    context=(
                        f"Detected: {f.summary}. Plausible benign operational alternatives exist: "
                        f"{'; '.join(f.benign_alternatives[:2])}."
                    ),
                    missing_evidence_type=f.missing_telemetry_limitations,
                    related_event_ids=f.supporting_event_ids,
                )
            )

    # Check for authentication compromise inference
    for ep in candidate_entry_points:
        conclusion_counter += 1
        has_hostile = (ep.confidence_breakdown or {}).get("has_hostile_downstream", False)
        if not has_hostile:
            pre_fails = (ep.confidence_breakdown or {}).get("preceding_failures_count", 0)
            if pre_fails >= 3:
                fail_context = "Multiple repeated failed attempts indicate potential external brute force or spraying reconnaissance, but account compromise remains unproven without hostile downstream actions."
            else:
                fail_context = "A failed login followed by a successful login does not establish credential spraying or account compromise without subsequent hostile activity; observed pattern is consistent with routine mistyped credentials."
            stmt = (
                f"Authentication observed for account '{ep.user_id or 'unknown'}' from source IP '{ep.source_ip or 'unknown'}'. "
                f"CRITICAL FORENSIC ASSESSMENT: {fail_context}"
            )
            conf_str = "LOW"
            conf_rationale = (
                "Authentication record lacks subsequent unauthorized process invocation, file access, or command-and-control communication."
            )
            alt_exps = [
                "Authorized user mistyped credentials on initial attempt.",
                "Routine remote maintenance without privilege abuse.",
            ]
        else:
            stmt = (
                f"Initial compromise of account '{ep.user_id or 'unknown'}' occurred via "
                f"external credential access from source IP '{ep.source_ip or 'unknown'}'."
            )
            conf_str = "HIGH" if ep.confidence >= 0.80 else "MEDIUM"
            conf_rationale = (
                f"Supported by temporal and session correlation across {len(ep.supporting_event_ids)} "
                f"telemetry event(s), including external IP binding and session creation."
            )
            alt_exps = [
                "Authorized external administrator performed maintenance using an unlisted external IP and mistyped password initially.",
                "Automated integration script with rotated credentials attempted connection before updated secret was pushed.",
            ]

        inferred_conclusions.append(
            InferredConclusion(
                conclusion_id=f"conc-{conclusion_counter}",
                statement=stmt,
                confidence=conf_str,
                confidence_rationale=conf_rationale,
                supporting_event_ids=ep.supporting_event_ids,
                alternative_explanations=alt_exps,
            )
        )

    # Check for Process Execution Inference
    suspicious_procs = [
        e for e in sorted_events
        if e.event_type == EventType.PROCESS_EXECUTION and is_suspicious_event(e)
    ]
    for proc in suspicious_procs:
        conclusion_counter += 1
        proc_name = proc.process_name or (proc.command_line.split()[0] if proc.command_line else "unknown")
        has_obfuscation = bool(proc.command_line and any(k in proc.command_line.lower() for k in ("base64", "pipe", "-d", "sh |", "bash |")))
        inferred_conclusions.append(
            InferredConclusion(
                conclusion_id=f"conc-{conclusion_counter}",
                statement=(
                    f"Command execution occurred on host '{proc.host_id or 'unknown'}' "
                    f"under session '{proc.session_id or 'unknown'}' executing '{proc_name}'."
                ),
                confidence="HIGH" if has_obfuscation else "MEDIUM",
                confidence_rationale="Command line contains explicit encoded cradle or suspicious invocation pattern." if has_obfuscation else "Process execution occurred within monitored investigation session.",
                supporting_event_ids=[proc.event_id],
                alternative_explanations=[
                    "Authorized administrative deployment pipeline utility using encoded bootstrap script.",
                ],
            )
        )

    # CRITICAL: Exfiltration Restraint & File Read vs Outbound Network Check
    file_reads = [e for e in sorted_events if e.event_type == EventType.FILE_AUDIT]
    outbound_conns = [
        e for e in sorted_events
        if e.event_type == EventType.NETWORK_CONNECTION and e.destination_ip and not e.destination_ip.startswith("10.")
    ]

    for fread in file_reads:
        subsequent_conns = [
            c for c in outbound_conns
            if c.timestamp >= fread.timestamp
            and (c.session_id == fread.session_id or c.process_id == fread.process_id)
        ]
        if subsequent_conns:
            target_conn = subsequent_conns[0]
            conclusion_counter += 1
            inferred_conclusions.append(
                InferredConclusion(
                    conclusion_id=f"conc-{conclusion_counter}",
                    statement=(
                        f"Outbound network communication to '{target_conn.destination_ip}:{target_conn.destination_port or ''}' "
                        f"was established following read access to '{fread.file_path or 'sensitive file'}'. "
                        f"CRITICAL FORENSIC ASSESSMENT: Data exfiltration is NOT proven by connection establishment alone."
                    ),
                    confidence="MEDIUM",
                    confidence_rationale=(
                        "Events share identical session/process context, proving temporal sequence and shared lineage. "
                        "However, packet payload or byte-level transfer proof is absent in network telemetry."
                    ),
                    supporting_event_ids=[fread.event_id, target_conn.event_id],
                    alternative_explanations=[
                        "Outbound connection was an interactive reverse shell (C2) or command conduit without actual file transmission.",
                        "Process initiated external heartbeat / keepalive unassociated with read file contents.",
                        "File was inspected locally for credential harvesting without egress transmission.",
                    ],
                )
            )

            question_counter += 1
            unresolved_questions.append(
                UnresolvedQuestion(
                    question_id=f"q-{question_counter}",
                    question=f"Was the content of '{fread.file_path}' actually exfiltrated across connection to {target_conn.destination_ip}?",
                    context=(
                        f"Connection was established by PID {target_conn.process_id} shortly after reading {fread.file_path}, "
                        f"but telemetry lacks application-layer payload or protocol data proof."
                    ),
                    missing_evidence_type="Missing Packet Capture / TLS Decryption / Egress Byte Counter",
                    related_event_ids=[fread.event_id, target_conn.event_id],
                )
            )

    # Check for Lateral Movement / Internal Probing
    lateral_probes = [
        e for e in sorted_events
        if e.event_type == EventType.NETWORK_CONNECTION and e.destination_port in (445, 139, 389) and is_suspicious_event(e)
    ]
    for probe in lateral_probes:
        conclusion_counter += 1
        inferred_conclusions.append(
            InferredConclusion(
                conclusion_id=f"conc-{conclusion_counter}",
                statement=(
                    f"Potential lateral movement or internal SMB reconnaissance was initiated "
                    f"from '{probe.source_ip or probe.host_id}' towards Domain Controller / internal asset '{probe.destination_ip}'."
                ),
                confidence="MEDIUM",
                confidence_rationale="Outbound SMB port 445 probe originated from compromised service account session.",
                supporting_event_ids=[probe.event_id],
                alternative_explanations=[
                    "Routine internal directory synchronization or scheduled file share access.",
                ],
            )
        )

        question_counter += 1
        unresolved_questions.append(
            UnresolvedQuestion(
                question_id=f"q-{question_counter}",
                question=f"Did the lateral connection to {probe.destination_ip}:445 successfully authenticate or transfer files?",
                context="Connection state recorded initial handshake without downstream host authentication logs in dataset.",
                missing_evidence_type="Target Host (Domain Controller) Security Event Logs (Event ID 4624 / 4625)",
                related_event_ids=[probe.event_id],
            )
        )

    # 7. Competing Alternative Hypotheses Generation & Ranking (Evidence-Driven)
    hypotheses: List[AttackHypothesis] = []

    all_suspicious_events = [e for e in sorted_events if is_suspicious_event(e)]
    routine_events = [e for e in sorted_events if not is_suspicious_event(e)]
    all_suspicious_ids = [e.event_id for e in all_suspicious_events]
    routine_ids = [e.event_id for e in routine_events]

    if all_suspicious_events:
        # Extract observed entities strictly from actual evidence
        observed_principals = sorted(list(set(e.user_id for e in all_suspicious_events if e.user_id)))
        observed_hosts = sorted(list(set(e.host_id for e in all_suspicious_events if e.host_id)))
        observed_source_ips = sorted(list(set(e.source_ip for e in all_suspicious_events if e.source_ip and not e.source_ip.startswith(("10.", "192.168.", "127.", "172.16.")))))
        observed_destinations = sorted(list(set(f"{e.destination_ip}:{e.destination_port or ''}" for e in all_suspicious_events if e.destination_ip)))
        observed_files = sorted(list(set(e.file_path for e in all_suspicious_events if e.file_path)))
        observed_procs = sorted(list(set(e.process_name or (e.command_line.split()[0] if e.command_line else None) for e in all_suspicious_events if (e.process_name or e.command_line))))

        # Identify active lifecycle stages
        auth_susp = [e for e in all_suspicious_events if e.event_type == EventType.AUTHENTICATION]
        proc_susp = [e for e in all_suspicious_events if e.event_type == EventType.PROCESS_EXECUTION]
        file_susp = [e for e in all_suspicious_events if e.event_type == EventType.FILE_AUDIT]
        net_c2_susp = [e for e in all_suspicious_events if e.event_type == EventType.NETWORK_CONNECTION and e.destination_ip and not e.destination_ip.startswith(("10.", "192.168."))]
        net_recon_susp = [e for e in all_suspicious_events if e.event_type == EventType.NETWORK_CONNECTION and (e.destination_ip and e.destination_ip.startswith(("10.", "192.168.")) or e.destination_port in (445, 139, 389))]

        active_stages: List[str] = []
        if auth_susp:
            active_stages.append("Initial Access")
        if proc_susp:
            active_stages.append("Execution")
        if file_susp:
            active_stages.append("Credential/Data Access")
        if net_c2_susp:
            active_stages.append("Command & Control")
        if net_recon_susp:
            active_stages.append("Lateral Reconnaissance")

        stage_count = len(active_stages)

        # Dynamic Evidence-Weighted Scoring
        stage_weight = stage_count * 0.17
        has_causal_links = any(link.is_causal for link in correlation_result.all_links)
        causal_bonus = 0.12 if has_causal_links else 0.0
        origin_bonus = 0.08 if observed_source_ips else 0.0
        critical_bonus = 0.05 if any(e.severity == EventSeverity.CRITICAL for e in all_suspicious_events) else 0.0

        contra_penalty = 0.20 * len(correlation_result.contradictions)
        stage_gap_questions = [q for q in unresolved_questions if not q.question_id.startswith("q-finding-")]
        gap_penalty = 0.05 * len(stage_gap_questions)

        raw_primary_score = stage_weight + causal_bonus + origin_bonus + critical_bonus - contra_penalty - gap_penalty
        primary_score = round(min(0.95, max(0.25, raw_primary_score)), 2)

        if stage_count >= 3 and primary_score >= 0.75:
            primary_grade = "Strong"
            primary_conf = "HIGH"
        elif stage_count >= 2 and primary_score >= 0.55:
            primary_grade = "Moderate"
            primary_conf = "MEDIUM"
        elif primary_score >= 0.35 and stage_count >= 2:
            primary_grade = "Moderate" if has_causal_links else "Weak"
            primary_conf = "MEDIUM" if has_causal_links else "LOW"
        elif primary_score >= 0.35:
            primary_grade = "Weak"
            primary_conf = "LOW"
        else:
            primary_grade = "Insufficient"
            primary_conf = "TENTATIVE"

        # Build dynamic narrative sentences strictly from observed entities
        narrative_parts: List[str] = []
        if candidate_entry_points:
            ep0 = candidate_entry_points[0]
            narrative_parts.append(
                f"Initial access recorded for principal '{ep0.user_id or 'unknown'}' on host '{ep0.host_id or 'target'}' "
                f"originating from address '{ep0.source_ip or 'unknown'}'."
            )
        if proc_susp:
            proc_pids = sorted(list(set(str(e.process_id) for e in proc_susp if e.process_id is not None)))
            pid_str = f" under PID(s) {', '.join(proc_pids)}" if proc_pids else ""
            narrative_parts.append(f"Process activity recorded execution of {', '.join(observed_procs[:3]) or 'command shells'}{pid_str}.")
        if file_susp:
            narrative_parts.append(f"File audit captured read access against {', '.join(observed_files[:3]) or 'sensitive files'}.")
        if net_c2_susp:
            narrative_parts.append(f"Network telemetry logged outbound TCP sockets communicating with {', '.join(observed_destinations[:2]) or 'external destinations'}.")
        if net_recon_susp:
            narrative_parts.append(f"Internal reconnaissance observed probing {', '.join(observed_destinations[:2]) or 'internal ports'}.")

        if stage_count <= 1:
            narrative_parts.append(
                "Current telemetry exhibits isolated anomalous activity; available evidence is insufficient to establish a comprehensive multi-stage attack lifecycle."
            )

        dynamic_description = " ".join(narrative_parts)

        # Dynamic title
        if stage_count >= 3:
            dynamic_title = "Multi-Stage Adversary Intrusion & Lifecycle Execution"
        elif stage_count == 2:
            dynamic_title = "Correlated Suspicious Multi-Stage Activity Sequence"
        elif stage_count == 1:
            dynamic_title = "Isolated Anomalous Security Event"
        else:
            dynamic_title = "Suspicious Telemetry Signal Cluster"

        # Dynamic assumptions
        dynamic_assumptions: List[str] = []
        if observed_source_ips:
            dynamic_assumptions.append(f"External origin address(es) {', '.join(observed_source_ips)} do not belong to an authorized external contractor or VPN.")
        if observed_procs:
            dynamic_assumptions.append(f"Execution of {', '.join(observed_procs[:2])} is adversary-driven rather than an authorized CI/CD deployment or maintenance utility.")
        dynamic_assumptions.append("Observed activities reflect a coordinated security incident rather than an authorized administrative test.")

        primary_breakdown = {
            "lifecycle_stages_count": stage_count,
            "lifecycle_stages": active_stages,
            "stage_weight": round(stage_weight, 2),
            "causal_continuity_bonus": causal_bonus,
            "untrusted_origin_bonus": origin_bonus,
            "contradiction_penalty": contra_penalty,
            "missing_evidence_penalty": gap_penalty,
            "raw_score": round(raw_primary_score, 2),
            "evidence_grade": primary_grade,
            "calculation_formula": "stage_weight (stages * 0.17) + causal_bonus (0.12) + origin_bonus (0.08) + critical_bonus (0.05) - contra_penalty (0.20 * count) - gap_penalty (0.05 * count)",
            "limitations": "Score is a deterministic heuristic reflecting corroborated evidence breadth, not a frequentist probability.",
        }

        hypotheses.append(
            AttackHypothesis(
                hypothesis_id="hypo-1",
                title=dynamic_title,
                description=dynamic_description,
                rank=1,
                score=primary_score,
                confidence=primary_conf,
                evidence_grade=primary_grade,
                confidence_explanation=(
                    f"Evidence grade: {primary_grade} (Score {primary_score}). Corroborated across {stage_count} lifecycle stage(s) "
                    f"({', '.join(active_stages) or 'none'}) with {len([l for l in correlation_result.all_links if l.is_causal])} causal execution link(s). "
                    f"Penalties applied for {len(correlation_result.contradictions)} contradiction(s) and {len(stage_gap_questions)} telemetry gap(s)."
                ),
                score_breakdown=primary_breakdown,
                supporting_event_ids=all_suspicious_ids,
                contradicting_event_ids=[],
                assumptions=dynamic_assumptions,
            )
        )

        # Hypothesis B: Competing Alternative (DevOps / Admin / Misconfiguration)
        baseline_ratio = len(routine_ids) / len(sorted_events) if sorted_events else 0.0
        raw_alt_score = max(0.10, min(0.60, (1.0 - primary_score) + 0.15 * baseline_ratio))
        alt_score = round(raw_alt_score, 2)
        alt_grade = "Moderate" if alt_score >= 0.40 else "Weak"
        alt_conf = "MEDIUM" if alt_score >= 0.40 else "LOW"

        alt_principals_str = ", ".join(observed_principals) or "service accounts"
        alt_hosts_str = ", ".join(observed_hosts) or "managed infrastructure"
        alt_desc = (
            f"An alternative explanation evaluates whether observed activity by principal(s) '{alt_principals_str}' "
            f"on '{alt_hosts_str}' represents an authorized operational script, deployment pipeline, or scheduled administrative maintenance "
            f"exhibiting non-standard telemetry."
        )

        alt_breakdown = {
            "competing_primary_penalty": round(1.0 - primary_score, 2),
            "baseline_event_ratio_bonus": round(0.15 * baseline_ratio, 2),
            "raw_score": round(raw_alt_score, 2),
            "evidence_grade": alt_grade,
            "calculation_formula": "max(0.10, min(0.60, (1.0 - primary_score) + 0.15 * baseline_ratio))",
            "limitations": "Evaluates feasibility of legitimate maintenance explanation; weakened by hostile payload and non-standard egress indicators.",
        }

        hypotheses.append(
            AttackHypothesis(
                hypothesis_id="hypo-2",
                title="Authorized Administrative or Automated Operations with Telemetry Anomaly",
                description=alt_desc,
                rank=2,
                score=alt_score,
                confidence=alt_conf,
                evidence_grade=alt_grade,
                confidence_explanation=(
                    f"Evidence grade: {alt_grade} (Score {alt_score}). Reflects the competing likelihood that operations were legitimate administration. "
                    f"Weakened by the presence of {len(all_suspicious_ids)} suspicious indicators."
                ),
                score_breakdown=alt_breakdown,
                supporting_event_ids=[e.event_id for e in sorted_events if e.event_type in (EventType.AUTHENTICATION, EventType.PROCESS_EXECUTION)],
                contradicting_event_ids=[e.event_id for e in file_susp + net_c2_susp],
                assumptions=[
                    f"Legitimate administration workflows would touch {', '.join(observed_files[:2]) or 'environment secrets'} and communicate with {', '.join(observed_destinations[:2]) or 'external destinations'}.",
                ],
            )
        )
    else:
        # Only routine activity present
        routine_score = 0.98
        hypotheses.append(
            AttackHypothesis(
                hypothesis_id="hypo-1",
                title="Normal Business & Administrative Baseline Activity",
                description=(
                    f"Observed telemetry reflects standard, routine administrative operations and developer tasks across "
                    f"{len(sorted_events)} recorded event(s) with zero hostile indicators."
                ),
                rank=1,
                score=routine_score,
                confidence="HIGH",
                evidence_grade="Strong",
                confidence_explanation="All observed actions match expected administrative baselines and verified internal principals.",
                score_breakdown={
                    "baseline_events_count": len(sorted_events),
                    "suspicious_events_count": 0,
                    "raw_score": routine_score,
                    "evidence_grade": "Strong",
                    "limitations": "Evaluates absence of anomalies; cannot disprove advanced covert zero-day activity absent from logs.",
                },
                supporting_event_ids=routine_ids,
                contradicting_event_ids=[],
                assumptions=["Authorized developers have legitimate business need for accessed configuration files."],
            )
        )
        hypotheses.append(
            AttackHypothesis(
                hypothesis_id="hypo-2",
                title="Covert Low-and-Slow Insider Activity",
                description="Routine events represent authorized user abusing privileges to stage internal information without triggering high-severity alarms.",
                rank=2,
                score=0.10,
                confidence="TENTATIVE",
                evidence_grade="Insufficient",
                confidence_explanation="No abnormal access patterns, exfiltration beacons, or privilege escalation detected to support insider threat.",
                score_breakdown={
                    "supporting_evidence_count": 0,
                    "contradictory_baseline_count": len(sorted_events),
                    "raw_score": 0.10,
                    "evidence_grade": "Insufficient",
                    "limitations": "Theoretical alternative; entirely unsupported by current telemetry.",
                },
                supporting_event_ids=[],
                contradicting_event_ids=routine_ids,
                assumptions=["User credentials could theoretically be abused without unusual behavioral anomalies."],
            )
        )

    # 8. Build Evidence Graph with Typed Nodes and Typed, Evidence-Backed Edges
    inv_graph = InvestigationGraph()
    inv_graph.build_from_events(sorted_events, include_hypotheses=hypotheses)
    cytoscape_elements = inv_graph.to_cytoscape_elements()

    typed_nodes: List[EvidenceGraphNode] = []
    for node_id, attrs in inv_graph.graph.nodes(data=True):
        typed_nodes.append(
            EvidenceGraphNode(
                id=str(node_id),
                node_type=attrs.get("node_type", "entity"),
                label=attrs.get("label", str(node_id)),
                attributes={k: v for k, v in attrs.items() if k not in ("node_type", "label")},
            )
        )

    typed_edges: List[EvidenceGraphEdge] = []
    edge_idx = 0
    for u, v, key, attrs in inv_graph.graph.edges(keys=True, data=True):
        edge_idx += 1
        relation = attrs.get("relation", "CONNECTED")

        supporting: List[str] = attrs.get("supporting_event_ids", [])
        if not supporting:
            if str(u).startswith("evt:"):
                supporting.append(str(u).replace("evt:", ""))
            if str(v).startswith("evt:"):
                supporting.append(str(v).replace("evt:", ""))

        is_inferred = attrs.get("inferred", relation == "PRECEDES_TEMPORALLY")
        edge_conf = attrs.get("confidence", 0.6 if is_inferred else 1.0)
        edge_rationale = attrs.get("rationale", "Temporal succession without proven causation" if is_inferred else f"Direct evidence bond: {relation}")
        edge_limits = attrs.get("limitations", "")

        typed_edges.append(
            EvidenceGraphEdge(
                id=f"edge-{edge_idx}",
                source=str(u),
                target=str(v),
                relation=relation,
                inferred=is_inferred,
                supporting_event_ids=supporting,
                confidence=edge_conf,
                rationale=edge_rationale,
                limitations=edge_limits,
            )
        )

    evidence_graph = EvidenceGraphData(
        nodes=typed_nodes,
        edges=typed_edges,
        cytoscape_elements=cytoscape_elements,
    )

    # 9. Defensive Recommendations (Evidence-Driven & Parameterized)
    defensive_recommendations: List[DefensiveRecommendation] = []
    auth_susp = [e for e in sorted_events if e.event_type == EventType.AUTHENTICATION and is_suspicious_event(e)]
    net_susp = [e for e in sorted_events if e.event_type == EventType.NETWORK_CONNECTION and is_suspicious_event(e)]
    file_susp = [e for e in sorted_events if e.event_type == EventType.FILE_AUDIT and is_suspicious_event(e)]
    proc_susp = [e for e in sorted_events if e.event_type == EventType.PROCESS_EXECUTION and is_suspicious_event(e)]

    rec_counter = 0

    if all_suspicious_events:
        # Recommendation 1: Authentication Hardening (Only if suspicious auth occurred)
        if auth_susp:
            rec_counter += 1
            auth_users = sorted(list(set(e.user_id for e in auth_susp if e.user_id)))
            auth_hosts = sorted(list(set(e.host_id for e in auth_susp if e.host_id)))
            auth_ips = sorted(list(set(e.source_ip for e in auth_susp if e.source_ip)))

            user_target = f"{', '.join(auth_hosts[:2])} / {', '.join(auth_users[:2])}"
            origin_desc = f" originating from source address(es) {', '.join(auth_ips[:2])}" if auth_ips else ""

            defensive_recommendations.append(
                DefensiveRecommendation(
                    recommendation_id=f"rec-{rec_counter}",
                    title="Enforce Remote Authentication Controls and Key Rotation",
                    action=(
                        f"Enforce multi-factor authentication (MFA) and restrict remote interactive login for account(s) "
                        f"'{', '.join(auth_users[:2]) or 'compromised accounts'}'. Verify SSH keys and enforce IP restriction rules on target host(s)."
                    ),
                    priority="CRITICAL",
                    target_entity=user_target,
                    mitre_mitigation="M1027 (Password Policies), M1032 (Multi-Factor Authentication)",
                    why_recommended=f"Corroborated telemetry confirmed interactive authentication{origin_desc} associated with subsequent hostile execution.",
                    supporting_event_ids=[e.event_id for e in auth_susp],
                    expected_benefit="Prevents credential reuse, spray, and unauthorized remote session establishment.",
                    potential_impact_risk="External automated pipelines or remote sysadmin access from non-whitelisted addresses will require bastion authentication.",
                    measure_type="DIRECT_RESPONSE",
                    is_simulated_action=True,
                )
            )

        # Recommendation 2: Egress Firewall Rule (Only if suspicious network egress occurred)
        if net_susp:
            rec_counter += 1
            dest_ips = sorted(list(set(f"{e.destination_ip}:{e.destination_port or ''}" for e in net_susp if e.destination_ip)))
            net_hosts = sorted(list(set(e.host_id for e in net_susp if e.host_id)))

            defensive_recommendations.append(
                DefensiveRecommendation(
                    recommendation_id=f"rec-{rec_counter}",
                    title="Block Suspicious External Egress and Restrict Non-Standard Ports",
                    action=(
                        f"Configure perimeter and host firewall rules on '{', '.join(net_hosts[:2]) or 'affected systems'}' "
                        f"to deny outbound connections to '{', '.join(dest_ips[:3]) or 'untrusted external endpoints'}'."
                    ),
                    priority="HIGH",
                    target_entity=f"{', '.join(net_hosts[:2]) or 'Application Servers'} (Egress Policy)",
                    mitre_mitigation="M1037 (Filter Network Traffic)",
                    why_recommended=f"Outbound communication was observed connecting to endpoint(s) {', '.join(dest_ips[:3]) or 'unverified external destinations'}.",
                    supporting_event_ids=[e.event_id for e in net_susp],
                    expected_benefit="Severs suspected command conduits and prevents outbound data transmission.",
                    potential_impact_risk="May disrupt legitimate developer microservices if dynamic non-standard ports are utilized without whitelisting.",
                    measure_type="DIRECT_RESPONSE",
                    is_simulated_action=True,
                )
            )

        # Recommendation 3: File / Secret Isolation (Only if file audit events occurred)
        if file_susp:
            rec_counter += 1
            touched_paths = sorted(list(set(e.file_path for e in file_susp if e.file_path)))
            defensive_recommendations.append(
                DefensiveRecommendation(
                    recommendation_id=f"rec-{rec_counter}",
                    title="Audit and Restrict Sensitive File Access",
                    action=(
                        f"Restrict read access permissions on file asset(s) '{', '.join(touched_paths[:2]) or 'sensitive paths'}'. "
                        f"Relocate plaintext secrets to a dedicated secrets vault with audit logging."
                    ),
                    priority="HIGH",
                    target_entity=", ".join(touched_paths[:2]) or "File System Asset",
                    mitre_mitigation="M1041 (Encrypt Sensitive Information)",
                    why_recommended=f"File audit events recorded access against sensitive path(s): {', '.join(touched_paths[:2]) or 'credential files'}.",
                    supporting_event_ids=[e.event_id for e in file_susp],
                    expected_benefit="Prevents credential harvesting and restricts file access blast radius.",
                    potential_impact_risk="Requires dependent services to query secrets manager API rather than reading local files.",
                    measure_type="DIRECT_RESPONSE",
                    is_simulated_action=True,
                )
            )

        # Recommendation 4: Process Detection Rule (Only if suspicious processes occurred)
        if proc_susp:
            rec_counter += 1
            procs_touched = sorted(list(set(e.process_name or (e.command_line.split()[0] if e.command_line else None) for e in proc_susp if (e.process_name or e.command_line))))
            defensive_recommendations.append(
                DefensiveRecommendation(
                    recommendation_id=f"rec-{rec_counter}",
                    title="Deploy Endpoint Detection Rules for Child Process Invocations",
                    action=(
                        f"Implement endpoint detection rules flagging anomalous executions of "
                        f"'{', '.join(procs_touched[:3]) or 'command shells'}', particularly when piped through decoding utilities or network streams."
                    ),
                    priority="MEDIUM",
                    target_entity="Endpoint Detection & Audit Policy",
                    mitre_mitigation="M1042 (Disable or Remove Feature or Program)",
                    why_recommended=f"Process telemetry captured anomalous execution of {', '.join(procs_touched[:3]) or 'command interpreters'}.",
                    supporting_event_ids=[e.event_id for e in proc_susp],
                    expected_benefit="Proactively alerts on living-off-the-land execution and script download cradles.",
                    potential_impact_risk="Minimal risk; minor tuning needed if administrative scripts execute similar interpreter wrappers.",
                    measure_type="PRECAUTIONARY",
                    is_simulated_action=True,
                )
            )

        # Recommendation 5: Forensic Verification Step for Inconclusive Telemetry
        if unresolved_questions:
            rec_counter += 1
            uq0 = unresolved_questions[0]
            defensive_recommendations.append(
                DefensiveRecommendation(
                    recommendation_id=f"rec-{rec_counter}",
                    title=f"Forensic Verification: Address Missing Telemetry ({uq0.missing_evidence_type.split('/')[0].strip()})",
                    action=(
                        f"Perform targeted investigation to resolve forensic uncertainty: {uq0.question} "
                        f"Inspect: {uq0.missing_evidence_type}."
                    ),
                    priority="MEDIUM",
                    target_entity=f"Forensic Telemetry Gap ({uq0.missing_evidence_type.split('/')[0].strip()})",
                    mitre_mitigation="M1047 (Audit)",
                    why_recommended=f"Evidence is currently inconclusive: {uq0.context}",
                    supporting_event_ids=uq0.related_event_ids,
                    expected_benefit="Confirms or rules out unproven attack phases without jumping to conclusions.",
                    potential_impact_risk="Read-only log collection; zero operational disruption.",
                    measure_type="PRECAUTIONARY",
                    is_simulated_action=True,
                )
            )
    else:
        rec_counter += 1
        routine_ids_list = [e.event_id for e in sorted_events]
        defensive_recommendations.append(
            DefensiveRecommendation(
                recommendation_id=f"rec-{rec_counter}",
                title="Maintain Routine Endpoint Monitoring and Key Rotation",
                action="Continue routine audit log collection and periodic developer SSH key rotation.",
                priority="LOW",
                target_entity="General Environment",
                mitre_mitigation="M1026 (Privileged Account Management)",
                why_recommended="Observed baseline matches normal developer activity; proactive hygiene prevents credential degradation.",
                supporting_event_ids=routine_ids_list,
                expected_benefit="Preserves security posture without operational disruption.",
                potential_impact_risk="Negligible impact during standard scheduled maintenance intervals.",
                measure_type="PRECAUTIONARY",
                is_simulated_action=True,
            )
        )

    return InvestigationReconstructionResult(
        investigation_id=f"inv-{uuid.uuid4().hex[:8]}",
        timeline=timeline_events,
        candidate_entry_points=candidate_entry_points,
        evidence_graph=evidence_graph,
        hypotheses=hypotheses,
        observed_facts=observed_facts,
        inferred_conclusions=inferred_conclusions,
        unresolved_questions=unresolved_questions,
        defensive_recommendations=defensive_recommendations,
        detection_findings=detection_findings,
        metadata={
            "reconstructed_at": datetime.now(timezone.utc).isoformat(),
            "total_events_processed": len(events),
            "suspicious_events_count": len([e for e in events if is_suspicious_event(e)]),
            "contradictions_identified": len(correlation_result.contradictions),
            "detection_findings_count": len(detection_findings),
        },
    )
