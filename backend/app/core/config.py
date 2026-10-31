"""
Application configuration for GhostTrace backend.
"""

from pathlib import Path
from pydantic import BaseModel


class Settings(BaseModel):
    app_name: str = "GhostTrace Investigation Platform"
    app_version: str = "0.1.0"
    api_prefix: str = "/api/v1"
    environment: str = "simulation"
    debug: bool = True
    base_dir: Path = Path(__file__).resolve().parent.parent.parent.parent
    fixtures_dir: Path = Path(__file__).resolve().parent.parent.parent.parent / "data" / "fixtures"
    default_fixture_file: str = "simulated_events.json"

    cors_origins: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "*",
    ]


settings = Settings()
