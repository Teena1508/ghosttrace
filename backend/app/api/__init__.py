from backend.app.api.health import router as health_router
from backend.app.api.events import router as events_router
from backend.app.api.investigations import router as investigations_router

__all__ = ["health_router", "events_router", "investigations_router"]
