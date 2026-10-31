"""
API tests for FastAPI health check endpoints.
"""

from fastapi.testclient import TestClient


def test_health_endpoint(client: TestClient):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "GhostTrace Investigation Platform"
    assert "version" in data
    assert "timestamp" in data
    assert data["checks"]["investigation_engine"] == "operational"
    assert data["checks"]["fixtures_available"] is True


def test_api_v1_health_endpoint(client: TestClient):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
