"""
FastAPI Evaluation Router for GhostTrace Phase 6.

Provides endpoints for:
1. Listing blind challenge scenarios with strict zero-leakage metadata.
2. Executing blind challenge reconstruction and evaluation.
3. Revealing isolated ground truth and generating forensic comparison reports.
"""

from typing import Any, Dict, List, Optional
import time
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from evaluation.evaluator import evaluate_reconstruction
from evaluation.generator import generate_evaluation_suite
from evaluation.models import EvaluationMetrics, GroundTruthScenario, ScenarioEvaluationResult
from investigation_engine.models import (
    InvestigationReconstructionResult,
    SecurityEvent,
)
from investigation_engine.reconstruction import reconstruct_attack_timeline

router = APIRouter(prefix="/api/v1/evaluation", tags=["Evaluation & Challenges"])

# Neutral presentation map to prevent answer leakage in UI/API responses
NEUTRAL_CHALLENGE_MAP = {
    "scenario_account_compromise_chain": {
        "title": "Challenge Alpha: Multi-Stage Telemetry Stream",
        "description": "Sequential telemetry log from application server tier with mixed event types.",
    },
    "scenario_interleaved_heavy_baseline": {
        "title": "Challenge Beta: Heavy Baseline Interleaved Stream",
        "description": "High-volume developer environment telemetry containing routine and anomalous records.",
    },
    "scenario_multiple_unrelated_incidents": {
        "title": "Challenge Gamma: Multi-Asset Distributed Telemetry",
        "description": "Network and host logs spanning multiple distinct network segments.",
    },
    "scenario_missing_conflicting_identifiers": {
        "title": "Challenge Delta: Degraded Telemetry & Partial Records",
        "description": "Corpus containing missing identifiers, null session attributes, and hostname variations.",
    },
    "scenario_unusual_egress_exfiltration_restraint": {
        "title": "Challenge Epsilon: Outbound Egress & File Activity",
        "description": "Telemetry sequence containing file audit records followed by outbound network sockets.",
    },
    "scenario_ambiguous_administrative_anomaly": {
        "title": "Challenge Zeta: Off-Hours Activity & System Mod",
        "description": "Off-hours administrative activity with competing potential explanations.",
    },
    "scenario_held_out_blind_challenge": {
        "title": "Challenge Eta: Held-Out Blind Evaluation",
        "description": "Unseen multi-stage challenge dataset reserved for zero-leakage validation.",
    },
    "scenario_hackathon_judge_demo": {
        "title": "Judge Live Demo: Service Account Access & TLS Key Socket",
        "description": "Standardized live evaluation stream: anomalous deployment authentication, shell spawn, key access, and outbound socket.",
    },
}


class BlindScenarioSummary(BaseModel):
    scenario_id: str
    title: str
    description: str
    event_count: int


import re

class RunEvaluationRequest(BaseModel):
    scenario_id: str = Field(..., max_length=64, pattern=r"^[a-zA-Z0-9_\-]+$", description="Target challenge scenario ID")
    seed: int = Field(default=42, ge=0, le=1000000, description="Reproducibility seed for event shuffling")


class RunEvaluationResponse(BaseModel):
    scenario_id: str
    seed: int
    execution_time_ms: float
    reconstruction: InvestigationReconstructionResult
    metrics: EvaluationMetrics
    evaluated_at: str


class GroundTruthComparisonResponse(BaseModel):
    scenario_id: str
    ground_truth: GroundTruthScenario
    comparison: Dict[str, Any]


@router.get("/scenarios", response_model=List[BlindScenarioSummary])
def list_blind_scenarios(seed: int = Query(42, description="Reproducibility seed")):
    """
    Lists available challenge scenarios with ZERO ground-truth answer leakage.
    Scenario names, expected answers, and ground-truth labels are excluded.
    """
    suite = generate_evaluation_suite(seed=seed)
    summaries: List[BlindScenarioSummary] = []

    for sc_id, (blind_events, _) in suite.items():
        meta = NEUTRAL_CHALLENGE_MAP.get(
            sc_id,
            {"title": f"Challenge: {sc_id}", "description": "Synthetic forensic challenge dataset"}
        )
        summaries.append(
            BlindScenarioSummary(
                scenario_id=sc_id,
                title=meta["title"],
                description=meta["description"],
                event_count=len(blind_events),
            )
        )

    return summaries


@router.post("/run", response_model=RunEvaluationResponse)
def run_evaluation(request: RunEvaluationRequest):
    """
    Executes a blind challenge evaluation:
    1. Fetches blinded, shuffled events without ground-truth labels.
    2. Passes ONLY the blind events into the reconstruction engine.
    3. Evaluates reconstructed output against the isolated ground truth.
    4. Returns reconstruction results and forensic scoring metrics.
    """
    suite = generate_evaluation_suite(seed=request.seed)
    if request.scenario_id not in suite:
        raise HTTPException(
            status_code=404,
            detail=f"Challenge scenario '{request.scenario_id}' not found.",
        )

    blind_events, ground_truth = suite[request.scenario_id]

    sec_events = [SecurityEvent(**e) for e in blind_events]

    # Measure execution time
    start_time = time.perf_counter()
    reconstruction = reconstruct_attack_timeline(sec_events)
    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

    # Score reconstruction against isolated ground truth
    metrics = evaluate_reconstruction(reconstruction, ground_truth)

    return RunEvaluationResponse(
        scenario_id=request.scenario_id,
        seed=request.seed,
        execution_time_ms=round(elapsed_ms, 2),
        reconstruction=reconstruction,
        metrics=metrics,
        evaluated_at=ground_truth.name,
    )


@router.get("/ground-truth/{scenario_id}", response_model=GroundTruthComparisonResponse)
def get_scenario_ground_truth(
    scenario_id: str,
    seed: int = Query(42, ge=0, le=1000000, description="Reproducibility seed"),
):
    """
    Reveals ground truth for a scenario only when explicitly requested after evaluation.
    Provides detailed diff comparing ground truth against reconstruction expectations.
    """
    if not re.match(r"^[a-zA-Z0-9_\-]+$", scenario_id):
        raise HTTPException(
            status_code=400,
            detail="Invalid scenario identifier.",
        )
    suite = generate_evaluation_suite(seed=seed)
    if scenario_id not in suite:
        raise HTTPException(
            status_code=404,
            detail=f"Scenario '{scenario_id}' not found.",
        )

    blind_events, ground_truth = suite[scenario_id]
    sec_events = [SecurityEvent(**e) for e in blind_events]
    reconstruction = reconstruct_attack_timeline(sec_events)
    metrics = evaluate_reconstruction(reconstruction, ground_truth)

    comparison = {
        "entry_point_match": metrics.entry_point_accuracy == 1.0,
        "entry_point_details": metrics.details.get("entry_point_status"),
        "true_positives": metrics.details.get("tp_events", []),
        "false_positives": metrics.details.get("fp_events", []),
        "false_negatives": metrics.details.get("fn_events", []),
        "ordering_accuracy": metrics.timeline_ordering_accuracy,
        "relationship_recall": metrics.relationship_recall,
        "unsupported_claims": metrics.details.get("unsupported_claims", []),
        "forensic_restraint_preserved": metrics.unsupported_claim_rate == 0.0,
        "ambiguity_handled": metrics.ambiguity_handling_score > 0.0 or not ground_truth.is_ambiguous,
        "unrelated_isolation_accuracy": metrics.unrelated_isolation_accuracy,
    }

    return GroundTruthComparisonResponse(
        scenario_id=scenario_id,
        ground_truth=ground_truth,
        comparison=comparison,
    )
