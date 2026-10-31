"""
Health check endpoints for GhostTrace backend.
"""

from datetime import datetime, timezone
from pathlib import Path
from fastapi import APIRouter

from backend.app.core.config import settings
from backend.app.models.event import HealthResponse

router = APIRouter(tags=["Health"])


@router.get("/health", response_model=HealthResponse)
@router.get("/api/v1/health", response_model=HealthResponse)
async def get_health() -> HealthResponse:
    """
    Health check endpoint returning system status, engine readiness,
    and fixture availability.
    """
    fixture_path = settings.fixtures_dir / settings.default_fixture_file
    fixtures_available = fixture_path.is_file()

    checks = {
        "investigation_engine": "operational",
        "fixtures_available": fixtures_available,
        "fixtures_status": "present" if fixtures_available else "missing",
        "networkx_ready": True,
        "fictional_mode_enforced": True,
    }

    return HealthResponse(
        status="healthy",
        service=settings.app_name,
        version=settings.app_version,
        environment=settings.environment,
        timestamp=datetime.now(timezone.utc),
        checks=checks,
    )
