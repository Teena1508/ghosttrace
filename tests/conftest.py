"""
Pytest configuration and common fixtures for GhostTrace.
"""

from pathlib import Path
from typing import Any, Dict
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.core.config import settings


@pytest.fixture(scope="session")
def client() -> TestClient:
    """FastAPI TestClient instance."""
    return TestClient(app)


@pytest.fixture
def fixtures_dir() -> Path:
    """Path to test fixtures directory."""
    return settings.fixtures_dir


@pytest.fixture
def valid_event_dict() -> Dict[str, Any]:
    """Baseline valid event dictionary."""
    return {
        "event_id": "test-evt-001",
        "timestamp": "2026-10-18T10:00:00Z",
        "event_type": "AUTHENTICATION",
        "host_id": "workstation-01.sim.local",
        "user_id": "alice",
        "source_ip": "10.0.0.5",
        "session_id": "sess-1234",
        "process_id": 501,
        "file_path": None,
        "severity": "INFORMATIONAL",
        "source": "simulated_auth_log",
        "source_event_id": "raw-auth-999",
        "original_event_data": {
            "record_id": "raw-auth-999",
            "message": "User alice logged in",
            "ip": "10.0.0.5",
        },
        "is_suspicious": False,
        "description": "Routine logon",
    }
