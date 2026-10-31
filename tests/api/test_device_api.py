"""
API tests for Live Device Telemetry endpoints.
"""

from fastapi.testclient import TestClient


def test_device_status_endpoint(client: TestClient):
    response = client.get("/api/v1/device/status")
    assert response.status_code == 200
    data = response.json()
    assert "hostname" in data
    assert "os" in data
    assert "current_user" in data
    assert data["total_processes"] > 0
    assert data["status"] == "ONLINE_ACTIVE"


def test_device_scan_endpoint(client: TestClient):
    response = client.post("/api/v1/device/scan", json={"max_events": 100})
    assert response.status_code == 200
    data = response.json()
    assert "hypotheses" in data
    assert "evidence_graph" in data
    assert "observed_facts" in data
    assert "detection_findings" in data


def test_device_scan_with_test_threat_probe(client: TestClient):
    response = client.post(
        "/api/v1/device/scan",
        json={"max_events": 100, "include_test_probe": True, "test_probe_type": "reverse_shell"}
    )
    assert response.status_code == 200
    data = response.json()
    findings = data["detection_findings"]
    # Test probe should be detected by rule GT-EXEC-001 or GT-NET-001
    assert any("test_threat_probe" in f["summary"].lower() or "reverse shell" in f["summary"].lower() or "probe" in f["summary"].lower() for f in findings)

