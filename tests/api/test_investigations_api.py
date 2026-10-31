"""
API tests for Investigation Reconstruction endpoints:
- POST /api/investigations/reconstruct
- POST /api/v1/investigations/reconstruct
"""

from pathlib import Path
import json
import pytest
from fastapi.testclient import TestClient


def test_reconstruct_endpoint_with_benchmark_fixtures(client: TestClient, fixtures_dir: Path):
    fixture_file = fixtures_dir / "simulated_events.json"
    with fixture_file.open("r", encoding="utf-8") as f:
        data = json.load(f)
    raw_events = data["events"]

    payload = {"events": raw_events, "deduplicate": True}
    response = client.post("/api/investigations/reconstruct", json=payload)
    assert response.status_code == 200

    result = response.json()
    assert "investigation_id" in result
    assert "timeline" in result
    assert len(result["timeline"]) == len(raw_events)

    # Check candidate entry points
    assert len(result["candidate_entry_points"]) > 0
    ep = result["candidate_entry_points"][0]
    assert "event_id" in ep
    assert "rationale" in ep
    assert "supporting_event_ids" in ep

    # Check evidence graph
    assert "evidence_graph" in result
    graph = result["evidence_graph"]
    assert len(graph["nodes"]) > 0
    assert len(graph["edges"]) > 0
    assert len(graph["cytoscape_elements"]) > 0

    # Check ranked hypotheses
    assert "hypotheses" in result
    assert len(result["hypotheses"]) >= 2
    assert result["hypotheses"][0]["rank"] == 1
    assert result["hypotheses"][1]["rank"] == 2

    # Check observed facts vs inferred conclusions
    assert len(result["observed_facts"]) > 0
    assert len(result["inferred_conclusions"]) > 0

    # Check unresolved questions
    assert len(result["unresolved_questions"]) > 0

    # Check defensive recommendations
    assert len(result["defensive_recommendations"]) > 0


def test_reconstruct_endpoint_with_direct_list_v1(client: TestClient, fixtures_dir: Path):
    fixture_file = fixtures_dir / "simulated_events.json"
    with fixture_file.open("r", encoding="utf-8") as f:
        data = json.load(f)
    raw_events = data["events"][:4]

    # Post as direct list to /api/v1/investigations/reconstruct
    response = client.post("/api/v1/investigations/reconstruct", json=raw_events)
    assert response.status_code == 200
    result = response.json()
    assert len(result["timeline"]) == 4


def test_reconstruct_endpoint_empty_events_returns_400(client: TestClient):
    response = client.post("/api/investigations/reconstruct", json={"events": []})
    assert response.status_code == 400
    assert "cannot be empty" in response.json()["detail"].lower()


def test_reconstruct_endpoint_malformed_records_returns_422(client: TestClient):
    # Pass records that violate mandatory schema requirements (e.g. missing timestamp)
    bad_payload = {
        "events": [
            {"event_id": "bad-1", "source": "test"},
            {"event_id": "bad-2", "source": "test"},
        ]
    }
    response = client.post("/api/investigations/reconstruct", json=bad_payload)
    assert response.status_code == 422
    data = response.json()
    assert "detail" in data
    assert "issues" in data["detail"]
