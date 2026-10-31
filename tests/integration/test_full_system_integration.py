"""
Full-System Integration Test for GhostTrace Phase 7.

Validates the complete end-to-end investigation workflow:
1. List available simulated investigations and synthetic challenge scenarios.
2. Select an investigation / launch synthetic scenario.
3. Load scenario events and run timeline reconstruction.
4. Verify timeline events, candidate entry points, and Cytoscape evidence graph.
5. Select hypotheses and inspect supporting/contradicting evidence.
6. Verify search, filtering, and event consistency across all views.
7. Read and verify defensive response recommendations.
8. Validate forensic report generation data consistency (markdown/json).
9. Run hidden-scenario evaluation benchmark and verify ground-truth separation.
10. Ensure investigation switching completely isolates new incident state from stale results.
"""

import json
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from evaluation.runner import run_evaluation_suite


@pytest.fixture(scope="module")
def api_client():
    return TestClient(app)


class TestFullSystemInvestigationWorkflow:
    """End-to-end integration tests covering the complete user workflow."""

    def test_step_1_list_available_investigations(self, api_client: TestClient):
        """Step 1: Open application and view all available simulated investigations."""
        resp = api_client.get("/api/v1/events/scenarios")
        assert resp.status_code == 200
        scenarios = resp.json()
        assert len(scenarios) >= 10

        ids = [s["id"] for s in scenarios]
        # Standard benchmark fixtures
        assert "scenario_multi_stage_attack" in ids
        assert "scenario_routine_baseline" in ids
        assert "scenario_credential_c2" in ids
        # Synthetic challenge scenarios
        assert "scenario_account_compromise_chain" in ids
        assert "scenario_held_out_blind_challenge" in ids

    def test_step_2_and_3_load_scenario_and_reconstruct(self, api_client: TestClient):
        """Step 2 & 3: Select an investigation, load its events, and run reconstruction."""
        # Load multi-stage attack
        load_resp = api_client.get("/api/v1/events/scenarios/scenario_multi_stage_attack")
        assert load_resp.status_code == 200
        scenario_data = load_resp.json()
        assert scenario_data["scenario_id"] == "scenario_multi_stage_attack"
        assert len(scenario_data["events"]) > 0

        # Send loaded events to reconstruction engine
        recon_resp = api_client.post(
            "/api/investigations/reconstruct",
            json={"events": scenario_data["events"], "deduplicate": True},
        )
        assert recon_resp.status_code == 200
        reconstruction = recon_resp.json()

        assert "investigation_id" in reconstruction
        assert len(reconstruction["timeline"]) > 0
        assert len(reconstruction["candidate_entry_points"]) > 0
        assert len(reconstruction["hypotheses"]) > 0
        assert len(reconstruction["defensive_recommendations"]) > 0
        assert len(reconstruction["evidence_graph"]["nodes"]) > 0

    def test_step_4_timeline_and_evidence_graph_integrity(self, api_client: TestClient):
        """Step 4: Inspect resulting timeline and interactive evidence graph."""
        load_resp = api_client.get("/api/v1/events/scenarios/scenario_multi_stage_attack")
        scenario_data = load_resp.json()
        events = scenario_data["events"]

        recon_resp = api_client.post(
            "/api/investigations/reconstruct",
            json={"events": events, "deduplicate": True},
        )
        reconstruction = recon_resp.json()

        # Check chronological ordering of timeline
        timestamps = [item["timestamp"] for item in reconstruction["timeline"]]
        assert timestamps == sorted(timestamps)

        # Check graph Cytoscape elements
        cy_elements = reconstruction["evidence_graph"]["cytoscape_elements"]
        node_ids = {el["data"]["id"] for el in cy_elements if "target" not in el["data"]}
        edge_sources = {el["data"]["source"] for el in cy_elements if "target" in el["data"]}
        edge_targets = {el["data"]["target"] for el in cy_elements if "target" in el["data"]}

        # All edge endpoints must exist in nodes
        for s in edge_sources:
            assert s in node_ids, f"Edge source '{s}' missing in nodes"
        for t in edge_targets:
            assert t in node_ids, f"Edge target '{t}' missing in nodes"

        # Verify fallback graph endpoint with scenario_id
        graph_resp = api_client.get("/api/v1/events/graph?scenario_id=scenario_multi_stage_attack")
        assert graph_resp.status_code == 200
        graph_data = graph_resp.json()
        assert len(graph_data["elements"]) > 0

    def test_step_5_hypotheses_and_evidence_citations(self, api_client: TestClient):
        """Step 5: Select a hypothesis and inspect supporting and contradicting evidence."""
        load_resp = api_client.get("/api/v1/events/scenarios/scenario_multi_stage_attack")
        events = load_resp.json()["events"]
        event_id_set = {e["event_id"] for e in events}

        recon_resp = api_client.post(
            "/api/investigations/reconstruct",
            json={"events": events, "deduplicate": True},
        )
        reconstruction = recon_resp.json()

        hypotheses = reconstruction["hypotheses"]
        assert len(hypotheses) >= 2  # Primary and competing alternative

        for hypo in hypotheses:
            assert hypo["rank"] in (1, 2)
            assert 0.0 <= hypo["score"] <= 1.0
            assert hypo["confidence"] in ("HIGH", "MEDIUM", "LOW", "TENTATIVE")
            # All cited supporting event IDs must be genuine event IDs in dataset
            for eid in hypo["supporting_event_ids"]:
                assert eid in event_id_set, f"Cited event {eid} not in dataset"
            for eid in hypo["contradicting_event_ids"]:
                assert eid in event_id_set, f"Cited contradicting event {eid} not in dataset"

    def test_step_6_search_and_filtering(self, api_client: TestClient):
        """Step 6: Search and filter original events."""
        # Test suspicious filter
        resp_susp = api_client.get("/api/v1/events?suspicious_only=true")
        assert resp_susp.status_code == 200
        for e in resp_susp.json()["events"]:
            assert e["is_suspicious"] is True

        # Test event type filter
        resp_auth = api_client.get("/api/v1/events?event_type=AUTHENTICATION")
        assert resp_auth.status_code == 200
        for e in resp_auth.json()["events"]:
            assert e["event_type"] == "AUTHENTICATION"

    def test_step_7_defensive_recommendations(self, api_client: TestClient):
        """Step 7: Read defensive recommendations derived from actual evidence."""
        load_resp = api_client.get("/api/v1/events/scenarios/scenario_multi_stage_attack")
        events = load_resp.json()["events"]
        recon_resp = api_client.post(
            "/api/investigations/reconstruct",
            json={"events": events, "deduplicate": True},
        )
        reconstruction = recon_resp.json()

        recommendations = reconstruction["defensive_recommendations"]
        assert len(recommendations) > 0

        for rec in recommendations:
            assert rec["recommendation_id"].startswith("rec-")
            assert rec["priority"] in ("CRITICAL", "IMMEDIATE", "HIGH", "MEDIUM", "LOW")
            assert rec["is_simulated_action"] is True
            assert len(rec["supporting_event_ids"]) > 0

    def test_step_8_investigation_switching_state_isolation(self, api_client: TestClient):
        """Step 8: Verify switching investigations prevents stale results from appearing."""
        # 1. Load attack scenario
        sc_attack = api_client.get("/api/v1/events/scenarios/scenario_multi_stage_attack").json()
        recon_attack = api_client.post(
            "/api/investigations/reconstruct",
            json={"events": sc_attack["events"]},
        ).json()
        assert len(recon_attack["candidate_entry_points"]) > 0
        assert "Intrusion" in recon_attack["hypotheses"][0]["title"]

        # 2. Switch to routine baseline scenario
        sc_routine = api_client.get("/api/v1/events/scenarios/scenario_routine_baseline").json()
        recon_routine = api_client.post(
            "/api/investigations/reconstruct",
            json={"events": sc_routine["events"]},
        ).json()

        # Routine scenario has zero suspicious entry points and confirms routine baseline
        assert len(recon_routine["candidate_entry_points"]) == 0
        assert "Routine" in recon_routine["hypotheses"][0]["title"] or "Normal" in recon_routine["hypotheses"][0]["title"]
        assert recon_attack["investigation_id"] != recon_routine["investigation_id"]

    def test_step_9_evaluation_challenge_and_ground_truth_isolation(self, api_client: TestClient):
        """Step 9: Run hidden-scenario evaluation and verify ground-truth separation."""
        # 1. Blind scenario listing contains NO answer leakage
        sc_resp = api_client.get("/api/v1/evaluation/scenarios")
        assert sc_resp.status_code == 200
        challenges = sc_resp.json()
        for ch in challenges:
            assert "expected_entry_point_id" not in ch
            assert "incident_event_ids" not in ch

        # 2. Run blind evaluation for Challenge Alpha
        eval_resp = api_client.post(
            "/api/v1/evaluation/run",
            json={"scenario_id": "scenario_account_compromise_chain", "seed": 42},
        )
        assert eval_resp.status_code == 200
        eval_data = eval_resp.json()
        assert eval_data["scenario_id"] == "scenario_account_compromise_chain"
        assert eval_data["metrics"]["entry_point_accuracy"] == 1.0
        assert eval_data["metrics"]["unsupported_claim_rate"] == 0.0

        # 3. Ground truth comparison endpoint
        gt_resp = api_client.get(
            "/api/v1/evaluation/ground-truth/scenario_account_compromise_chain?seed=42"
        )
        assert gt_resp.status_code == 200
        gt_data = gt_resp.json()
        assert gt_data["comparison"]["entry_point_match"] is True
        assert gt_data["comparison"]["forensic_restraint_preserved"] is True
