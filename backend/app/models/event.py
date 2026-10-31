"""
API request and response models for GhostTrace backend endpoints.
Re-exports canonical engine schemas and provides response envelopes.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from investigation_engine.models import (
    SecurityEvent,
    EventType,
    EventSeverity,
    ValidationResult,
    ValidationIssue,
)


class HealthResponse(BaseModel):
    status: str = Field(default="healthy", description="Service health state")
    service: str = Field(default="ghosttrace-backend", description="Service identifier")
    version: str = Field(default="0.1.0", description="Backend service version")
    environment: str = Field(default="simulation", description="Deployment environment mode")
    timestamp: datetime = Field(..., description="Current UTC timestamp")
    checks: Dict[str, Any] = Field(default_factory=dict, description="Detailed component health checks")


class EventListResponse(BaseModel):
    total: int
    count: int
    suspicious_count: int
    events: List[SecurityEvent]
    validation_status: ValidationResult


class GraphElementsResponse(BaseModel):
    event_count: int
    element_count: int
    elements: List[Dict[str, Any]]
