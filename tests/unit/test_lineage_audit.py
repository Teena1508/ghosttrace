"""
Forensic Data Lineage Audit Unit Tests.
Verifies:
1. Changing/removing specific input events dynamically alters the reconstruction output.
2. Changing scenarios changes the actual input event data and the reconstructed investigation results.
"""

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from investigation_engine.loader import load_events_from_fixture
from investigation_engine.reconstruction import reconstruct_attack_timeline

client = TestClient(app)


class TestForensicDataLineage:
    """Audit tests verifying event sensitivity and scenario switching."""

    def test_removing_preceding_failed_auth_changes_entry_point_confidence(self):
        """
        Audit Step: When evt-auth-2001 (failed logon) is present, the entry point
        confidence is 0.90 (spray detection). When removed, it drops to 0.75 (valid credentials).
        """
        all_events, _ = load_events_from_fixture("data/fixtures/simulated_events.json")

        # Baseline with all 10 events
        base_result = reconstruct_attack_timeline(all_events)
        assert len(base_result.candidate_entry_points) == 1
        ep_base = base_result.candidate_entry_points[0]
        assert ep_base.event_id == "evt-auth-2002"
        # Dynamic confidence with 1 preceding failure bonus
        assert ep_base.confidence == 0.85
        assert "preceded by 1 failed attempt(s)" in ep_base.rationale
        assert "evt-auth-2001" in ep_base.supporting_event_ids

        # Remove evt-auth-2001
        modified_events = [e for e in all_events if e.event_id != "evt-auth-2001"]
        mod_result = reconstruct_attack_timeline(modified_events)

        assert len(mod_result.candidate_entry_points) == 1
        ep_mod = mod_result.candidate_entry_points[0]
        assert ep_mod.event_id == "evt-auth-2002"
        # Confidence drops dynamically when failed login is removed
        assert ep_mod.confidence == 0.80
        assert "valid credentials" in ep_mod.rationale
        assert "evt-auth-2001" not in ep_mod.supporting_event_ids

    def test_removing_outbound_network_event_removes_exfiltration_question(self):
        """
        Audit Step: Removing evt-net-2005 (C2 outbound connection) eliminates
        the exfiltration restraint conclusion and unresolved question for api_keys.env.
        """
        all_events, _ = load_events_from_fixture("data/fixtures/simulated_events.json")

        base_result = reconstruct_attack_timeline(all_events)
        # Verify exfiltration question exists in baseline
        exfil_questions = [
            q for q in base_result.unresolved_questions
            if "api_keys.env" in q.question
        ]
        assert len(exfil_questions) == 1

        # Remove outbound C2 event
        modified_events = [e for e in all_events if e.event_id != "evt-net-2005"]
        mod_result = reconstruct_attack_timeline(modified_events)

        # Exfiltration question must now be absent
        mod_exfil_questions = [
            q for q in mod_result.unresolved_questions
            if "api_keys.env" in q.question
        ]
        assert len(mod_exfil_questions) == 0

    def test_scenario_switching_changes_actual_backend_data_and_reconstruction(self):
        """
        Audit Step: Switching between scenario_multi_stage_attack and
        scenario_routine_baseline delivers different events and distinct reconstructions.
        """
        # Fetch Scenario 1
        resp_sc1 = client.get("/api/v1/events/scenarios/scenario_multi_stage_attack")
        assert resp_sc1.status_code == 200
        sc1_data = resp_sc1.json()
        assert sc1_data["event_count"] == 10
        sc1_event_ids = {e["event_id"] for e in sc1_data["events"]}
        assert "evt-auth-2002" in sc1_event_ids

        # Fetch Scenario 2
        resp_sc2 = client.get("/api/v1/events/scenarios/scenario_routine_baseline")
        assert resp_sc2.status_code == 200
        sc2_data = resp_sc2.json()
        assert sc2_data["event_count"] == 4
        sc2_event_ids = {e["event_id"] for e in sc2_data["events"]}
        assert "rtn-auth-01" in sc2_event_ids
        assert "evt-auth-2002" not in sc2_event_ids

        # Reconstruct Scenario 1
        recon1 = client.post("/api/investigations/reconstruct", json=sc1_data["events"])
        assert recon1.status_code == 200
        r1 = recon1.json()
        assert len(r1["candidate_entry_points"]) == 1
        assert "Multi-Stage" in r1["hypotheses"][0]["title"]
        assert r1["hypotheses"][0]["score"] > 0.80

        # Reconstruct Scenario 2
        recon2 = client.post("/api/investigations/reconstruct", json=sc2_data["events"])
        assert recon2.status_code == 200
        r2 = recon2.json()
        assert len(r2["candidate_entry_points"]) == 0
        assert r2["hypotheses"][0]["title"] == "Normal Business & Administrative Baseline Activity"
        assert r2["hypotheses"][0]["score"] == 0.98
