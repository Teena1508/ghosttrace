"""
Unit tests for GhostTrace Phase 6: Hidden-Attack Challenge and Evaluation Engine.

Tests:
1. Zero answer leakage and ground-truth separation.
2. Synthetic scenario generation across all benchmark categories.
3. Metric calculations (entry point, precision, recall, ordering, traceability, restraint).
4. Exfiltration restraint enforcement and unsupported-claim rate.
5. Evaluation runner execution and summary formatting.
6. Evaluation API endpoints (/scenarios, /run, /ground-truth/{id}).
"""

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from evaluation.evaluator import evaluate_reconstruction
from evaluation.generator import generate_evaluation_suite
from evaluation.models import GroundTruthScenario
from evaluation.runner import format_text_summary, run_evaluation_suite, run_scenario
from investigation_engine.models import (
    EventType,
    EventSeverity,
    InferredConclusion,
    InvestigationReconstructionResult,
    SecurityEvent,
)
from investigation_engine.reconstruction import reconstruct_attack_timeline


@pytest.fixture
def api_client():
    return TestClient(app)


class TestGroundTruthSeparationAndLeakage:
    """Verifies that ground truth is strictly isolated from reconstruction."""

    def test_blind_events_contain_no_ground_truth_labels(self):
        suite = generate_evaluation_suite(seed=123)
        assert len(suite) >= 7

        forbidden_keys = {"is_suspicious", "ground_truth_label", "intended_incident_id"}

        for sc_id, (blind_events, gt) in suite.items():
            assert isinstance(gt, GroundTruthScenario)
            for evt in blind_events:
                for key in forbidden_keys:
                    assert key not in evt, f"Leakage detected: key '{key}' found in blind event of {sc_id}"

    def test_reproducible_shuffling_changes_event_order(self):
        suite = generate_evaluation_suite(seed=999)
        _, gt = suite["scenario_account_compromise_chain"]
        raw_ids = [e["event_id"] for e in gt.raw_events]

        blind_events, _ = suite["scenario_account_compromise_chain"]
        blind_ids = [e["event_id"] for e in blind_events]

        assert set(blind_ids) == set(raw_ids)
        # Verify that deterministic seed produces a reproducible order
        suite2 = generate_evaluation_suite(seed=999)
        blind_events2, _ = suite2["scenario_account_compromise_chain"]
        blind_ids2 = [e["event_id"] for e in blind_events2]
        assert blind_ids == blind_ids2


class TestForensicEvaluationScoring:
    """Tests automated scoring calculations."""

    def test_perfect_reconstruction_scores(self):
        suite = generate_evaluation_suite(seed=42)
        blind_events, gt = suite["scenario_account_compromise_chain"]

        sec_events = [SecurityEvent(**e) for e in blind_events]
        reconstruction = reconstruct_attack_timeline(sec_events)
        metrics = evaluate_reconstruction(reconstruction, gt)

        assert metrics.relevant_event_recall == 1.0
        assert metrics.relevant_event_precision == 1.0
        assert metrics.relevant_event_f1 == 1.0
        assert metrics.timeline_ordering_accuracy == 1.0
        assert metrics.source_event_traceability == 1.0
        assert metrics.unsupported_claim_rate == 0.0

    def test_exfiltration_restraint_detection(self):
        """
        Verify that unsupported claims regarding unproven exfiltration are detected and penalized.
        """
        suite = generate_evaluation_suite(seed=42)
        blind_events, gt = suite["scenario_unusual_egress_exfiltration_restraint"]
        sec_events = [SecurityEvent(**e) for e in blind_events]
        reconstruction = reconstruct_attack_timeline(sec_events)

        # Baseline: GhostTrace reconstructor maintains restraint
        clean_metrics = evaluate_reconstruction(reconstruction, gt)
        assert clean_metrics.unsupported_claim_rate == 0.0

        # Simulate a flawed engine that prematurely asserts exfiltration
        flawed_reconstruction = reconstruction.model_copy(deep=True)
        flawed_reconstruction.inferred_conclusions.append(
            InferredConclusion(
                conclusion_id="conc-flawed-exfil",
                statement="Confidential credentials were definitely exfiltrated off the network.",
                confidence="HIGH",
                confidence_rationale="Connection established after read.",
                supporting_event_ids=["sc5-evt-01", "sc5-evt-03"],
            )
        )

        penalized_metrics = evaluate_reconstruction(flawed_reconstruction, gt)
        assert penalized_metrics.unsupported_claim_rate > 0.0
        assert "unsupported_claims" in penalized_metrics.details
        assert len(penalized_metrics.details["unsupported_claims"]) > 0


class TestRepeatableRunner:
    """Verifies CLI runner execution across all scenarios."""

    def test_full_evaluation_suite_runs_without_error(self):
        results, summary = run_evaluation_suite(seed=42)
        assert len(results) >= 7
        assert summary["total_scenarios_evaluated"] >= 7
        assert "macro_averages" in summary
        assert summary["macro_averages"]["relevant_event_recall"] == 1.0
        assert summary["macro_averages"]["unsupported_claim_rate"] == 0.0

    def test_target_scenario_filter(self):
        results, summary = run_evaluation_suite(
            seed=42, target_scenario="scenario_held_out_blind_challenge"
        )
        assert len(results) == 1
        assert results[0].scenario_id == "scenario_held_out_blind_challenge"
        assert summary["total_scenarios_evaluated"] == 1

    def test_summary_formatter(self):
        results, summary = run_evaluation_suite(seed=42)
        text = format_text_summary(results, summary)
        assert "GHOSTTRACE PHASE 6: HIDDEN-ATTACK CHALLENGE" in text
        assert "MACRO AVERAGE" in text
        assert "scenario_held_out_blind_challenge" in text


class TestEvaluationAPIEndpoints:
    """Tests FastAPI router endpoints for evaluation demonstration."""

    def test_get_scenarios_zero_leakage(self, api_client):
        resp = api_client.get("/api/v1/evaluation/scenarios")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) >= 7
        for item in data:
            assert "scenario_id" in item
            assert "title" in item
            assert "description" in item
            assert "event_count" in item
            # Ensure ground truth fields are NOT in the scenario list
            assert "expected_entry_point_id" not in item
            assert "incident_event_ids" not in item
            assert "expected_relationships" not in item

    def test_run_blind_evaluation_endpoint(self, api_client):
        payload = {
            "scenario_id": "scenario_account_compromise_chain",
            "seed": 42,
        }
        resp = api_client.post("/api/v1/evaluation/run", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["scenario_id"] == "scenario_account_compromise_chain"
        assert "reconstruction" in data
        assert "metrics" in data
        assert data["metrics"]["relevant_event_precision"] == 1.0
        assert data["metrics"]["relevant_event_recall"] == 1.0

    def test_get_ground_truth_comparison(self, api_client):
        sc_id = "scenario_account_compromise_chain"
        resp = api_client.get(f"/api/v1/evaluation/ground-truth/{sc_id}?seed=42")
        assert resp.status_code == 200
        data = resp.json()
        assert data["scenario_id"] == sc_id
        assert "ground_truth" in data
        assert "comparison" in data
        assert data["comparison"]["entry_point_match"] is True
        assert data["comparison"]["forensic_restraint_preserved"] is True
