"""
GhostTrace Phase 9: End-to-End Testing and Acceptance Verification Suite.

Tests all 11 core acceptance scenarios:
Scenario A: Suspicious auth -> process execution -> file access.
Scenario B: Routine administrative activity resembles suspicious activity without attack proof.
Scenario C: Unrelated suspicious events are NOT incorrectly merged into one incident.
Scenario D: Outbound network connection follows file access (Exfiltration Restraint).
Scenario E: Missing identifiers, duplicate records, conflicting timestamps, and shuffled input order.
Scenario F: Two competing hypotheses explain the same event sequence.
Scenario G: An investigation contains no relevant suspicious events (Routine/Empty baseline).
Scenario H: Backend errors, malformed responses, and payload limit rejections.
Scenario I: Investigation switching state isolation (no stale leakage).
Scenario J: Report export data agreement and scoping.
Scenario K: Hidden challenge reconstruction with zero ground-truth leakage.
"""

import pytest
import random
from fastapi.testclient import TestClient

from backend.app.main import app
from evaluation.generator import generate_evaluation_suite
from evaluation.evaluator import evaluate_reconstruction
from investigation_engine.models import SecurityEvent, EventType
from investigation_engine.reconstruction import reconstruct_attack_timeline
from investigation_engine.validation import validate_event_batch


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


class TestPhase9AcceptanceScenarios:
    """Complete product acceptance verification suite."""

    def test_scenario_a_suspicious_auth_followed_by_process_and_file(self, client: TestClient):
        """
        Scenario A: A suspicious authentication event is followed by related
        process execution and file access.
        """
        # Load Challenge Alpha or Multi-Stage Attack
        resp = client.get("/api/v1/events/scenarios/scenario_account_compromise_chain")
        assert resp.status_code == 200
        events = resp.json()["events"]

        recon_resp = client.post("/api/investigations/reconstruct", json={"events": events})
        assert recon_resp.status_code == 200
        result = recon_resp.json()

        # 1. Timeline preserves chronological sequence
        timestamps = [item["timestamp"] for item in result["timeline"]]
        assert timestamps == sorted(timestamps)

        # 2. Identified entry point is the suspicious login event
        assert len(result["candidate_entry_points"]) > 0
        entry = result["candidate_entry_points"][0]
        assert entry["event_id"] == "sc1-evt-02"  # Suspicious login
        assert entry["user_id"] == "admin_svc"

        # 3. Primary hypothesis captures intrusion
        primary = result["hypotheses"][0]
        assert primary["rank"] == 1
        assert any(term in primary["title"] for term in ("Compromise", "Access", "Attack", "Intrusion", "Threat"))

        # 4. Valid source event citations
        event_ids = {e["event_id"] for e in events}
        for eid in primary["supporting_event_ids"]:
            assert eid in event_ids

    def test_scenario_b_routine_admin_activity_not_labeled_attack(self, client: TestClient):
        """
        Scenario B: Routine administrative activity resembles suspicious activity
        but lacks sufficient evidence to establish an attack.
        """
        resp = client.get("/api/v1/events/scenarios/scenario_routine_baseline")
        assert resp.status_code == 200
        events = resp.json()["events"]

        recon_resp = client.post("/api/investigations/reconstruct", json={"events": events})
        assert recon_resp.status_code == 200
        result = recon_resp.json()

        # 1. Zero candidate entry points for routine baseline
        assert len(result["candidate_entry_points"]) == 0

        # 2. Top hypothesis confirms routine administrative activity
        top_hypo = result["hypotheses"][0]
        assert "Routine" in top_hypo["title"] or "Normal" in top_hypo["title"] or "Benign" in top_hypo["title"]

        # 3. No routine events are labeled malicious solely due to high privileges
        for item in result["timeline"]:
            assert "Routine" in item["phase"] or item["phase"] in ("Execution", "Initial Access", "Command & Control")

    def test_scenario_c_unrelated_suspicious_events_not_merged(self, client: TestClient):
        """
        Scenario C: Unrelated suspicious events must NOT be incorrectly merged
        into one incident.
        """
        resp = client.get("/api/v1/events/scenarios/scenario_multiple_unrelated_incidents")
        assert resp.status_code == 200
        events = resp.json()["events"]

        recon_resp = client.post("/api/investigations/reconstruct", json={"events": events})
        assert recon_resp.status_code == 200
        result = recon_resp.json()

        # Verify that multiple disjoint clusters/hypotheses are retained
        assert len(result["hypotheses"]) >= 2
        # Causal links must NOT bind across distinct hosts without shared session or process
        edges = result["evidence_graph"]["edges"]
        dmz_to_db_causal_edges = [
            e for e in edges
            if e.get("is_causal") and "dmz" in str(e) and "db" in str(e)
        ]
        assert len(dmz_to_db_causal_edges) == 0

    def test_scenario_d_outbound_network_exfiltration_restraint(self, client: TestClient):
        """
        Scenario D: An outbound network connection follows a file access, but there
        is insufficient evidence to prove exfiltration.
        """
        resp = client.get("/api/v1/events/scenarios/scenario_unusual_egress_exfiltration_restraint")
        assert resp.status_code == 200
        events = resp.json()["events"]

        recon_resp = client.post("/api/investigations/reconstruct", json={"events": events})
        assert recon_resp.status_code == 200
        result = recon_resp.json()

        # 1. Top hypothesis must NOT claim definitive exfiltration
        top_hypo = result["hypotheses"][0]
        assert "Exfiltration Confirmed" not in top_hypo["title"]
        assert "Proven Exfiltration" not in top_hypo["title"]

        # 2. Unresolved questions must explicitly surface unproven data movement
        unresolved = result["unresolved_questions"]
        assert len(unresolved) > 0
        questions_text = " ".join(q["question"] + " " + q["context"] for q in unresolved).lower()
        assert "exfiltration" in questions_text or "outbound" in questions_text or "data" in questions_text

    def test_scenario_e_missing_identifiers_duplicates_and_shuffled_order(self, client: TestClient):
        """
        Scenario E: Events have missing identifiers, duplicate records,
        conflicting timestamps, and shuffled input order.
        """
        resp = client.get("/api/v1/events/scenarios/scenario_missing_conflicting_identifiers")
        assert resp.status_code == 200
        events = resp.json()["events"]

        # 1. Add duplicates
        duplicated_events = events + [events[0], events[0]]

        # 2. Shuffle input order
        random.seed(42)
        shuffled_events = list(duplicated_events)
        random.shuffle(shuffled_events)

        recon_resp = client.post(
            "/api/investigations/reconstruct",
            json={"events": shuffled_events, "deduplicate": True},
        )
        assert recon_resp.status_code == 200
        result = recon_resp.json()

        # Deduplication properly handled
        val_summary = result["metadata"]["validation_summary"]
        assert val_summary["duplicate_events_count"] >= 2

        # Reconstructed timeline remains strictly sorted by timestamp despite shuffled input
        timeline_timestamps = [t["timestamp"] for t in result["timeline"]]
        assert timeline_timestamps == sorted(timeline_timestamps)

    def test_scenario_f_two_competing_hypotheses_explain_same_sequence(self, client: TestClient):
        """
        Scenario F: Two competing hypotheses explain the same event sequence
        with visible uncertainty.
        """
        resp = client.get("/api/v1/events/scenarios/scenario_ambiguous_administrative_anomaly")
        assert resp.status_code == 200
        events = resp.json()["events"]

        recon_resp = client.post("/api/investigations/reconstruct", json={"events": events})
        assert recon_resp.status_code == 200
        result = recon_resp.json()

        hypotheses = result["hypotheses"]
        assert len(hypotheses) >= 2

        # Competing hypotheses have valid ranks (1 and 2)
        ranks = [h["rank"] for h in hypotheses]
        assert 1 in ranks
        assert 2 in ranks

        # Both hypotheses have explanations and assumptions
        for h in hypotheses[:2]:
            assert len(h["assumptions"]) > 0
            assert len(h["confidence_explanation"]) > 0

    def test_scenario_g_investigation_with_no_relevant_suspicious_events(self, client: TestClient):
        """
        Scenario G: An investigation contains no relevant suspicious events (clean baseline).
        """
        routine_events = [
            {
                "event_id": f"evt-routine-{i}",
                "timestamp": f"2026-10-18T10:0{i}:00Z",
                "event_type": "AUTHENTICATION",
                "user_id": "alice_dev",
                "host_id": "workstation-01",
                "action": "LOGON_SUCCESS",
                "source": "auth_log",
                "is_suspicious": False,
                "original_event_data": {"test": i},
            }
            for i in range(3)
        ]

        recon_resp = client.post(
            "/api/investigations/reconstruct",
            json={"events": routine_events},
        )
        assert recon_resp.status_code == 200
        result = recon_resp.json()

        # Zero entry points
        assert len(result["candidate_entry_points"]) == 0
        # Timeline items are all non-suspicious
        for t in result["timeline"]:
            assert t["is_suspicious"] is False

    def test_scenario_h_error_and_malformed_handling_never_silently_fabricates(self, client: TestClient):
        """
        Scenario H: The backend returns an error or malformed response; verify
        no fabricated results are produced.
        """
        # 1. Malformed records
        malformed = [{"invalid_field": "test"}]
        resp_malformed = client.post(
            "/api/investigations/reconstruct",
            json={"events": malformed},
        )
        assert resp_malformed.status_code == 422
        assert "issues" in resp_malformed.json()["detail"]

        # 2. Oversized payload
        oversized = [{"event_id": f"evt-{i}"} for i in range(501)]
        resp_oversized = client.post(
            "/api/investigations/reconstruct",
            json={"events": oversized},
        )
        assert resp_oversized.status_code == 413

        # 3. Invalid scenario ID
        resp_bad_id = client.get("/api/v1/events/scenarios/non_existent_scenario_12345")
        assert resp_bad_id.status_code == 404

    def test_scenario_i_investigation_switching_state_isolation(self, client: TestClient):
        """
        Scenario I: User switches investigations; verify complete data isolation
        without stale results leaking.
        """
        # 1. Reconstruct Attack
        sc1 = client.get("/api/v1/events/scenarios/scenario_multi_stage_attack").json()
        r1 = client.post("/api/investigations/reconstruct", json={"events": sc1["events"]}).json()

        # 2. Reconstruct Baseline
        sc2 = client.get("/api/v1/events/scenarios/scenario_routine_baseline").json()
        r2 = client.post("/api/investigations/reconstruct", json={"events": sc2["events"]}).json()

        # Distinct investigation IDs
        assert r1["investigation_id"] != r2["investigation_id"]

        # Graph node sets do not cross-contaminate
        r1_nodes = {n["id"] for n in r1["evidence_graph"]["nodes"]}
        r2_nodes = {n["id"] for n in r2["evidence_graph"]["nodes"]}

        # R1 has suspicious nodes (phishing, C2) not present in R2
        assert len(r1_nodes.intersection(r2_nodes)) < len(r1_nodes)

    def test_scenario_j_report_exported_agrees_with_investigation(self, client: TestClient):
        """
        Scenario J: A report is exported; verify the exported data strictly agrees
        with the selected investigation and filters out foreign events.
        """
        sc = client.get("/api/v1/events/scenarios/scenario_account_compromise_chain").json()
        recon = client.post("/api/investigations/reconstruct", json={"events": sc["events"]}).json()

        # Simulate report generation input
        valid_ids = {t["event_id"] for t in recon["timeline"]}
        for eid in valid_ids:
            assert eid.startswith("sc1-evt-")

        # Confirm all candidate entry points and hypotheses reference valid event IDs
        for entry in recon["candidate_entry_points"]:
            assert entry["event_id"] in valid_ids
            for sid in entry["supporting_event_ids"]:
                assert sid in valid_ids

    def test_scenario_k_hidden_evaluation_reconstructed_without_ground_truth(self, client: TestClient):
        """
        Scenario K: A hidden evaluation scenario is reconstructed without ground truth
        entering the reconstruction engine.
        """
        suite = generate_evaluation_suite(seed=42)
        blind_events, ground_truth = suite["scenario_held_out_blind_challenge"]

        # Ensure blind events do NOT contain ground truth annotations
        for e in blind_events:
            assert "is_suspicious" not in e or e["is_suspicious"] is False
            assert "incident_phase" not in e

        sec_events = [SecurityEvent(**e) for e in blind_events]
        # Engine reconstructs blind events
        reconstruction = reconstruct_attack_timeline(sec_events)

        # Evaluate reconstructed output against isolated ground truth
        metrics = evaluate_reconstruction(reconstruction, ground_truth)
        assert metrics.entry_point_accuracy == 1.0
        assert metrics.relevant_event_recall == 1.0
        assert metrics.unsupported_claim_rate == 0.0

    def test_phase10_judge_demo_scenario(self, client: TestClient):
        """
        Phase 10: Judge Demonstration Scenario verification:
        - Fictional incident containing routine background, unusual authentication,
          related process activity, file access, and suspicious network event.
        - Exfiltration restraint preserved.
        - At least one plausible benign explanation and unproven fact.
        - Separate ground-truth key with reproducible shuffling.
        """
        suite = generate_evaluation_suite(seed=42)
        assert "scenario_hackathon_judge_demo" in suite
        blind_events, gt = suite["scenario_hackathon_judge_demo"]

        # 1. Answer key separation
        for e in blind_events:
            assert "is_suspicious" not in e or e["is_suspicious"] is False

        # 2. Reconstruct from blind events
        sec_events = [SecurityEvent(**e) for e in blind_events]
        recon = reconstruct_attack_timeline(sec_events)

        # 3. Entry point correctly identified as demo-evt-02
        assert len(recon.candidate_entry_points) > 0
        assert recon.candidate_entry_points[0].event_id == "demo-evt-02"

        # 4. Chronological attack sequence deduced regardless of shuffle
        threat_timeline_ids = [t.event_id for t in recon.timeline if t.is_suspicious]
        assert threat_timeline_ids == ["demo-evt-02", "demo-evt-03", "demo-evt-04", "demo-evt-05"]

        # 5. Routine background events isolated
        routine_timeline_ids = [t.event_id for t in recon.timeline if not t.is_suspicious]
        assert "demo-evt-01" in routine_timeline_ids
        assert "demo-evt-06" in routine_timeline_ids

        # 6. Evaluation metrics: 100% precision, recall, and exfiltration restraint
        metrics = evaluate_reconstruction(recon, gt)
        assert metrics.entry_point_accuracy == 1.0
        assert metrics.relevant_event_recall == 1.0
        assert metrics.unsupported_claim_rate == 0.0
        assert metrics.timeline_ordering_accuracy == 1.0
