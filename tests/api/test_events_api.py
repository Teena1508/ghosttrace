"""
API tests for Events and Graph endpoints.
"""

from fastapi.testclient import TestClient


def test_list_events(client: TestClient):
    response = client.get("/api/v1/events")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] > 0
    assert data["count"] > 0
    assert data["suspicious_count"] > 0
    assert len(data["events"]) == data["count"]
    # Check that each event has required fields preserved
    first = data["events"][0]
    assert "event_id" in first
    assert "timestamp" in first
    assert "original_event_data" in first
    assert "source_event_id" in first


def test_filter_suspicious_events(client: TestClient):
    response = client.get("/api/v1/events?suspicious_only=true")
    assert response.status_code == 200
    data = response.json()
    assert all(e["is_suspicious"] is True for e in data["events"])


def test_filter_by_event_type(client: TestClient):
    response = client.get("/api/v1/events?event_type=AUTHENTICATION")
    assert response.status_code == 200
    data = response.json()
    assert all(e["event_type"] == "AUTHENTICATION" for e in data["events"])


def test_get_event_graph(client: TestClient):
    response = client.get("/api/v1/events/graph")
    assert response.status_code == 200
    data = response.json()
    assert data["event_count"] > 0
    assert data["element_count"] > 0
    assert len(data["elements"]) == data["element_count"]


def test_validate_records_endpoint(client: TestClient):
    # Send a valid record and a duplicate
    payload = [
        {
            "event_id": "api-val-001",
            "timestamp": "2026-10-18T12:00:00Z",
            "event_type": "AUTHENTICATION",
            "source": "simulated_auth",
            "original_event_data": {"test": True},
        },
        {
            "event_id": "api-val-001",  # duplicate ID
            "timestamp": "2026-10-18T12:01:00Z",
            "event_type": "AUTHENTICATION",
            "source": "simulated_auth",
            "original_event_data": {"test": True},
        },
    ]
    response = client.post("/api/v1/events/validate?deduplicate=true", json=payload)
    assert response.status_code == 200
    val_data = response.json()
    assert val_data["is_valid"] is False
    assert val_data["events_processed"] == 2
    assert val_data["duplicate_events_count"] == 1
    assert val_data["valid_events_count"] == 1


def test_list_scenarios(client: TestClient):
    response = client.get("/api/v1/events/scenarios")
    assert response.status_code == 200
    scenarios = response.json()
    assert isinstance(scenarios, list)
    assert len(scenarios) >= 3
    scenario_ids = [s["id"] for s in scenarios]
    assert "scenario_multi_stage_attack" in scenario_ids
    assert "scenario_routine_baseline" in scenario_ids
    assert "scenario_credential_c2" in scenario_ids


def test_get_scenario_by_id(client: TestClient):
    response = client.get("/api/v1/events/scenarios/scenario_routine_baseline")
    assert response.status_code == 200
    data = response.json()
    assert data["scenario_id"] == "scenario_routine_baseline"
    assert data["event_count"] >= 4
    assert len(data["events"]) == data["event_count"]
    assert data["validation_status"]["is_valid"] is True


def test_get_scenario_not_found(client: TestClient):
    response = client.get("/api/v1/events/scenarios/non_existent_scenario_xyz")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_graph_edge_limitations_and_sessions(client: TestClient):
    response = client.get("/api/v1/events/graph")
    assert response.status_code == 200
    data = response.json()
    elements = data["elements"]

    # Verify session node presence
    session_nodes = [el for el in elements if el.get("data", {}).get("node_type") == "session"]
    assert len(session_nodes) > 0, "Expected session nodes in investigation graph"

    # Verify temporal edges declare causation limitations
    temporal_edges = [
        el for el in elements
        if el.get("data", {}).get("relation") == "PRECEDES_TEMPORALLY"
    ]
    assert len(temporal_edges) > 0
    first_temporal = temporal_edges[0]["data"]
    assert first_temporal.get("inferred") is True
    assert "causation" in first_temporal.get("limitations", "").lower()

