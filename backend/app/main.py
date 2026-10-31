"""
FastAPI Application Entry Point for GhostTrace.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.api.evaluation import router as evaluation_router
from backend.app.api.events import router as events_router
from backend.app.api.health import router as health_router
from backend.app.api.investigations import router as investigations_router
from backend.app.api.device import router as device_router
from backend.app.core.config import settings


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description=(
            "Defensive cybersecurity investigation platform reconstructing "
            "attack timelines from simulated security telemetry."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # CORS configuration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register Routers
    app.include_router(health_router)
    app.include_router(events_router)
    app.include_router(investigations_router)
    app.include_router(evaluation_router)
    app.include_router(device_router)

    # Mount static frontend production build if present
    dist_dir = settings.base_dir / "frontend" / "dist"
    if dist_dir.is_dir():
        from fastapi.staticfiles import StaticFiles
        app.mount("/", StaticFiles(directory=str(dist_dir), html=True), name="static_frontend")

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, reload=True)
