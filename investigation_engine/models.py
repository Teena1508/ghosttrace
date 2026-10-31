"""
Core Security Event models and schemas for GhostTrace.
Defines the canonical schema used across the investigation engine, backend API,
and serialized to frontend clients.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union
import re
from pydantic import BaseModel, Field, field_validator, model_validator


class EventType(str, Enum):
    AUTHENTICATION = "AUTHENTICATION"
    PROCESS_EXECUTION = "PROCESS_EXECUTION"
    FILE_AUDIT = "FILE_AUDIT"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"


class EventSeverity(str, Enum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ValidationSeverity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class ValidationIssue(BaseModel):
    field: Optional[str] = None
    message: str
    severity: ValidationSeverity = ValidationSeverity.ERROR
    raw_record_id: Optional[str] = None


class ValidationResult(BaseModel):
    is_valid: bool
    events_processed: int = 0
    valid_events_count: int = 0
    duplicate_events_count: int = 0
    malformed_events_count: int = 0
    issues: List[ValidationIssue] = Field(default_factory=list)


class SecurityEvent(BaseModel):
    """
    Canonical normalized security event schema for GhostTrace.

    Preserves source event ID and raw original event data for forensic
    traceability back to original evidence. All environment-specific identifiers
    are optional if unavailable from the originating log.
    """
    event_id: str = Field(..., max_length=128, description="Unique canonical event identifier")
    timestamp: datetime = Field(..., description="Normalized UTC timestamp of when the event occurred")
    event_type: EventType = Field(..., description="Forensic event category")
    host_id: Optional[str] = Field(default=None, max_length=128, description="Identifier of the host/workstation/server")
    user_id: Optional[str] = Field(default=None, max_length=128, description="Username or security principal identifier")
    source_ip: Optional[str] = Field(default=None, max_length=128, description="Originating IPv4 or IPv6 address")
    session_id: Optional[str] = Field(default=None, max_length=128, description="Logon or correlation session identifier")
    process_id: Optional[Union[int, str]] = Field(default=None, description="PID of initiating or target process")
    file_path: Optional[str] = Field(default=None, max_length=1024, description="Canonical path to accessed or modified file")
    severity: EventSeverity = Field(default=EventSeverity.INFORMATIONAL, description="Assessed event severity level")
    source: str = Field(..., max_length=128, description="Telemetry source component (e.g., simulated_auditd, simulated_auth_log)")
    original_event_data: Dict[str, Any] = Field(
        ...,
        description="Preserved raw record/unaltered payload for cryptographic and forensic provenance"
    )

    # Optional forensic extensions
    source_event_id: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Original event ID from source telemetry stream, preserving evidence chain"
    )
    description: Optional[str] = Field(default=None, max_length=4096, description="Human-readable description of event activity")
    is_suspicious: bool = Field(default=False, description="Explicit fictional ground-truth label for evaluation")
    mitre_attack_id: Optional[str] = Field(default=None, max_length=64, description="Simulated MITRE ATT&CK technique reference")
    destination_ip: Optional[str] = Field(default=None, max_length=128, description="Destination IPv4 or IPv6 address")
    destination_port: Optional[int] = Field(default=None, ge=0, le=65535, description="Destination network port")
    process_name: Optional[str] = Field(default=None, max_length=256, description="Binary or executable image name")
    command_line: Optional[str] = Field(default=None, max_length=4096, description="Full process execution invocation line")
    action: Optional[str] = Field(default=None, max_length=128, description="Specific sub-action (e.g. LOGON_SUCCESS, FILE_WRITE)")

    @field_validator("process_id", mode="before")
    @classmethod
    def validate_process_id(cls, value: Any) -> Optional[Union[int, str]]:
        if value is None:
            return None
        if isinstance(value, int):
            if value < 0 or value > 4194304:
                raise ValueError("Process ID out of valid numeric range (0 - 4194304)")
            return value
        if isinstance(value, str):
            if len(value) > 64:
                raise ValueError("Process ID string representation exceeds 64 characters")
            return value
        raise ValueError("Process ID must be an integer or string")

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, value: Any) -> datetime:
        """
        Robust parser supporting ISO 8601 strings, UNIX epoch timestamps (seconds & milliseconds),
        and native datetime objects. Ensures normalized UTC datetime output.
        """
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc)

        if isinstance(value, (int, float)):
            # Distinguish seconds vs milliseconds (epoch > 10^11 is ms)
            if value > 1e11:
                return datetime.fromtimestamp(value / 1000.0, tz=timezone.utc)
            return datetime.fromtimestamp(value, tz=timezone.utc)

        if isinstance(value, str):
            val_str = value.strip()
            if not val_str:
                raise ValueError("Timestamp string cannot be empty")

            # Try numeric string (e.g. "1718500000" or "1718500000.123")
            try:
                numeric_val = float(val_str)
                if numeric_val > 1e11:
                    return datetime.fromtimestamp(numeric_val / 1000.0, tz=timezone.utc)
                return datetime.fromtimestamp(numeric_val, tz=timezone.utc)
            except ValueError:
                pass

            # Handle ISO 8601 variations (e.g. 2026-10-18T10:00:00Z)
            # Python 3.11+ datetime.fromisoformat handles 'Z' and offsets
            try:
                # Replace 'Z' with '+00:00' if needed for older parsers
                iso_str = val_str.replace("Z", "+00:00")
                parsed_dt = datetime.fromisoformat(iso_str)
                if parsed_dt.tzinfo is None:
                    return parsed_dt.replace(tzinfo=timezone.utc)
                return parsed_dt.astimezone(timezone.utc)
            except Exception as exc:
                raise ValueError(
                    f"Unable to parse timestamp '{value}'. Expected ISO 8601 format or UNIX epoch timestamp."
                ) from exc

        raise ValueError(f"Invalid timestamp type '{type(value).__name__}'. Expected str, int, float, or datetime.")

    @model_validator(mode="after")
    def populate_source_event_id_fallback(self) -> SecurityEvent:
        """
        If source_event_id is not explicitly provided, attempt to extract it
        from original_event_data or fallback to event_id to maintain evidence trace.
        """
        if not self.source_event_id and self.original_event_data:
            extracted = (
                self.original_event_data.get("id")
                or self.original_event_data.get("record_id")
                or self.original_event_data.get("event_id")
                or self.original_event_data.get("RecordNumber")
            )
            if extracted is not None:
                self.source_event_id = str(extracted)
            else:
                self.source_event_id = self.event_id
        elif not self.source_event_id:
            self.source_event_id = self.event_id
        return self


# ==============================================================================
# Phase 2 & 3: Correlation, Timeline Reconstruction & Investigation Hypotheses
# ==============================================================================


class EvidenceGraphEdge(BaseModel):
    id: str
    source: str
    target: str
    relation: str
    inferred: bool = False
    supporting_event_ids: List[str] = Field(default_factory=list)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    rationale: str = ""
    limitations: str = ""


class EvidenceGraphNode(BaseModel):
    id: str
    node_type: str = Field(..., description="Node type: event, host, user, ip, process, file")
    label: str
    attributes: Dict[str, Any] = Field(default_factory=dict)


class EvidenceGraphData(BaseModel):
    nodes: List[EvidenceGraphNode] = Field(default_factory=list)
    edges: List[EvidenceGraphEdge] = Field(default_factory=list)
    cytoscape_elements: List[Dict[str, Any]] = Field(default_factory=list)


class TimelineEvent(BaseModel):
    event_id: str
    timestamp: datetime
    event_type: EventType
    phase: str = Field(..., description="Incident phase (e.g. Initial Access, Execution, Persistence, Command & Control, Routine)")
    summary: str
    is_suspicious: bool = False
    supporting_event_ids: List[str] = Field(default_factory=list)
    cluster_id: Optional[str] = None
    host_id: Optional[str] = None
    user_id: Optional[str] = None


class CandidateEntryPoint(BaseModel):
    event_id: str
    timestamp: datetime
    user_id: Optional[str] = None
    source_ip: Optional[str] = None
    host_id: Optional[str] = None
    rationale: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    evidence_grade: Optional[str] = Field(default="Moderate", description="Strong, Moderate, Weak, or Insufficient")
    confidence_breakdown: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Transparent calculation components")
    supporting_event_ids: List[str] = Field(default_factory=list)


class AttackHypothesis(BaseModel):
    hypothesis_id: str
    title: str
    description: str
    rank: int
    score: float
    confidence: str = Field(..., description="Confidence label: HIGH, MEDIUM, LOW, TENTATIVE")
    evidence_grade: Optional[str] = Field(default="Moderate", description="Strong, Moderate, Weak, or Insufficient")
    confidence_explanation: str
    score_breakdown: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Transparent calculation components")
    supporting_event_ids: List[str] = Field(default_factory=list)
    contradicting_event_ids: List[str] = Field(default_factory=list)
    assumptions: List[str] = Field(default_factory=list)


class ObservedFact(BaseModel):
    fact_id: str
    statement: str
    supporting_event_ids: List[str] = Field(default_factory=list)
    source: str
    observed_at: datetime


class InferredConclusion(BaseModel):
    conclusion_id: str
    statement: str
    confidence: str = Field(..., description="HIGH, MEDIUM, LOW, TENTATIVE")
    confidence_rationale: str
    supporting_event_ids: List[str] = Field(default_factory=list)
    alternative_explanations: List[str] = Field(default_factory=list)


class UnresolvedQuestion(BaseModel):
    question_id: str
    question: str
    context: str
    missing_evidence_type: str
    related_event_ids: List[str] = Field(default_factory=list)


class DefensiveRecommendation(BaseModel):
    recommendation_id: str
    title: str
    action: str
    priority: str = Field(..., description="CRITICAL, HIGH, MEDIUM, LOW")
    target_entity: Optional[str] = None
    mitre_mitigation: Optional[str] = None
    why_recommended: str = Field(default="", description="Forensic rationale for this recommendation")
    supporting_event_ids: List[str] = Field(default_factory=list, description="Evidence event IDs linking to this recommendation")
    expected_benefit: str = Field(default="", description="Defensive benefit of applying this action")
    potential_impact_risk: str = Field(default="", description="Operational friction, downtime, or risk considerations")
    measure_type: str = Field(default="PRECAUTIONARY", description="'DIRECT_RESPONSE' (to proven threat) or 'PRECAUTIONARY' (defense-in-depth)")
    is_simulated_action: bool = Field(default=True, description="Explicit disclaimer that this action is advisory / simulated")



class DetectionFinding(BaseModel):
    """
    Explainable, deterministic detection finding citing exact source events and providing
    benign alternatives and missing evidence limitations.
    """
    finding_id: str = Field(..., description="Unique ID for this finding")
    rule_id: str = Field(..., description="Stable identifier of the detection rule")
    rule_name: str = Field(..., description="Human-readable rule name")
    severity: EventSeverity = Field(..., description="Severity level")
    category: str = Field(..., description="Tactic category: INITIAL_ACCESS, EXECUTION, PRIVILEGE_ESCALATION, CREDENTIAL_ACCESS, LATERAL_MOVEMENT, EXFILTRATION, ANOMALY")
    mitre_attack_id: Optional[str] = Field(default=None, description="MITRE ATT&CK technique reference")
    summary: str = Field(..., description="Summary explanation of the indicator detected")
    observed_indicators: List[str] = Field(default_factory=list, description="Direct facts extracted from the logs")
    benign_alternatives: List[str] = Field(default_factory=list, description="Legitimate administrative/operational explanations")
    supporting_event_ids: List[str] = Field(default_factory=list, description="Exact event IDs citing the evidence")
    confidence_assessment: str = Field(default="SUSPICIOUS_INDICATOR", description="INDICATOR_ONLY, SUSPICIOUS, or CORROBORATED")
    missing_telemetry_limitations: Optional[str] = Field(default=None, description="What missing logs or context would refute or confirm this finding")


class InvestigationReconstructionResult(BaseModel):
    investigation_id: str
    timeline: List[TimelineEvent] = Field(default_factory=list)
    candidate_entry_points: List[CandidateEntryPoint] = Field(default_factory=list)
    evidence_graph: EvidenceGraphData
    hypotheses: List[AttackHypothesis] = Field(default_factory=list)
    observed_facts: List[ObservedFact] = Field(default_factory=list)
    inferred_conclusions: List[InferredConclusion] = Field(default_factory=list)
    unresolved_questions: List[UnresolvedQuestion] = Field(default_factory=list)
    defensive_recommendations: List[DefensiveRecommendation] = Field(default_factory=list)
    detection_findings: List[DetectionFinding] = Field(default_factory=list, description="Explainable deterministic detection rule findings")
    metadata: Dict[str, Any] = Field(default_factory=dict)


