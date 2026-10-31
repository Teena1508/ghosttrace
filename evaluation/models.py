"""
Evaluation models for GhostTrace Phase 6: Hidden-Attack Challenge and Evaluation.

Defines:
- GroundTruthScenario: Complete ground-truth record kept strictly isolated from the engine.
- EvaluationMetrics: Granular forensic scoring metrics.
- ScenarioEvaluationResult: Full evaluation result container.
"""

from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field


class GroundTruthScenario(BaseModel):
    """
    Ground truth record for a synthetic forensic scenario.
    Kept strictly separated from the reconstruction engine during evaluation.
    """
    scenario_id: str = Field(..., description="Unique scenario identifier")
    name: str = Field(..., description="Internal scenario name (for reporting only)")
    description: str = Field(..., description="Context of the simulated scenario")
    expected_entry_point_id: Optional[str] = Field(
        default=None,
        description="Event ID of the genuine attack entry point, or None if benign"
    )
    incident_event_ids: Set[str] = Field(
        default_factory=set,
        description="Event IDs genuinely associated with malicious or incident activity"
    )
    routine_event_ids: Set[str] = Field(
        default_factory=set,
        description="Event IDs representing legitimate background activity"
    )
    expected_chronological_order: List[str] = Field(
        default_factory=list,
        description="Strictly ordered list of incident event IDs representing the true temporal progression"
    )
    expected_relationships: List[Tuple[str, str, str]] = Field(
        default_factory=list,
        description="List of (source_id, target_id, relation_type) relationships that genuinely exist"
    )
    unrelated_event_pairs: List[Tuple[str, str]] = Field(
        default_factory=list,
        description="Pairs of event IDs from distinct incidents that must NOT be correlated"
    )
    explicitly_unknown_facts: List[str] = Field(
        default_factory=list,
        description="Facts that cannot be proven from available telemetry (e.g. 'data_exfiltrated')"
    )
    is_ambiguous: bool = Field(
        default=False,
        description="Whether this scenario has multiple plausible competing explanations"
    )
    plausible_explanations: List[str] = Field(
        default_factory=list,
        description="List of legitimate alternative explanations that should be formulated"
    )
    raw_events: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="All generated events before blind anonymization and shuffling"
    )


class EvaluationMetrics(BaseModel):
    """
    Granular forensic evaluation metrics calculated by comparing the reconstruction result
    against the ground-truth record.
    """
    entry_point_accuracy: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="1.0 if entry point matches ground truth (or correctly identified as none), 0.0 otherwise"
    )
    relevant_event_precision: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Precision of incident/suspicious event identification: TP / (TP + FP)"
    )
    relevant_event_recall: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Recall of incident/suspicious event identification: TP / (TP + FN)"
    )
    relevant_event_f1: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Harmonic mean of relevant event precision and recall"
    )
    timeline_ordering_accuracy: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Pairwise relative ordering accuracy for events with known ground-truth order"
    )
    relationship_precision: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Precision of reconstructed evidence graph edges matching ground-truth relationships"
    )
    relationship_recall: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Recall of expected ground-truth relationships identified in the evidence graph"
    )
    source_event_traceability: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Fraction of conclusions, hypotheses, and recommendations that reference valid source event IDs"
    )
    unsupported_claim_rate: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Fraction of explicitly unknown facts where the engine made an unsupported certainty claim"
    )
    ambiguity_handling_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Score measuring whether competing alternative explanations were formulated when appropriate"
    )
    unrelated_isolation_accuracy: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Fraction of unrelated suspicious event pairs correctly kept in separate incident clusters"
    )
    details: Dict[str, Any] = Field(
        default_factory=dict,
        description="Granular evaluation details (TP, FP, FN, matches, missed, unsupported claims)"
    )


class ScenarioEvaluationResult(BaseModel):
    """
    Complete evaluation run result for a single scenario.
    """
    scenario_id: str
    scenario_name: str
    seed: int
    metrics: EvaluationMetrics
    execution_time_ms: float
    reconstructed_investigation_id: str
    total_events_evaluated: int
    incident_events_count: int
    routine_events_count: int
    timestamp: str
