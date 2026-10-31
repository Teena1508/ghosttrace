"""
Investigation and Attack Timeline Reconstruction API endpoints for GhostTrace.
"""

from typing import Any, Dict, List, Optional, Union
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from investigation_engine.models import (
    InvestigationReconstructionResult,
    SecurityEvent,
)
from investigation_engine.reconstruction import reconstruct_attack_timeline
from investigation_engine.validation import validate_event_batch

router = APIRouter(tags=["Investigations"])


class ReconstructionRequest(BaseModel):
    events: List[Any] = Field(
        ...,
        description="Collection of normalized or raw security events to correlate and reconstruct into a timeline",
    )
    deduplicate: bool = Field(
        default=True,
        description="Whether to detect and drop duplicate event IDs prior to reconstruction",
    )


@router.post(
    "/api/investigations/reconstruct",
    response_model=InvestigationReconstructionResult,
    status_code=status.HTTP_200_OK,
)
@router.post(
    "/api/v1/investigations/reconstruct",
    response_model=InvestigationReconstructionResult,
    status_code=status.HTTP_200_OK,
)
async def reconstruct_investigation(
    payload: Union[ReconstructionRequest, List[Any]],
) -> InvestigationReconstructionResult:
    """
    Accepts a collection of simulated security events and performs:
    1. Robust validation & deduplication
    2. Shared identifier correlation (session, process, host, user, network)
    3. Chronological timeline reconstruction
    4. Plausible candidate entry point identification
    5. Evidence graph synthesis with typed nodes and edges
    6. Ranked competing hypotheses generation
    7. Observed facts vs. Inferred conclusions separation
    8. Identification of missing evidence / unresolved questions
    9. Actionable defensive recommendations
    """
    # Normalize payload format
    if isinstance(payload, ReconstructionRequest):
        raw_events = payload.events
        deduplicate = payload.deduplicate
    elif isinstance(payload, list):
        raw_events = payload
        deduplicate = True
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid request body. Expected a JSON object with 'events' array or a direct list of events.",
        )

    if not raw_events:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The 'events' collection cannot be empty. Please provide at least one security event.",
        )

    MAX_RECONSTRUCTION_EVENTS = 500
    if len(raw_events) > MAX_RECONSTRUCTION_EVENTS:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Payload too large. Maximum supported event count for reconstruction is {MAX_RECONSTRUCTION_EVENTS}, received {len(raw_events)}.",
        )

    # Validate raw events against canonical schema
    valid_events, val_result = validate_event_batch(raw_events, deduplicate=deduplicate)

    if not valid_events:
        error_details = [
            f"Record {issue.raw_record_id} ({issue.field or 'general'}): {issue.message}"
            for issue in val_result.issues[:5]
        ]
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "No valid security events could be parsed from input.",
                "malformed_count": val_result.malformed_events_count,
                "issues": error_details,
            },
        )

    # Run reconstruction engine
    try:
        result = reconstruct_attack_timeline(valid_events)
        # Attach validation metadata
        result.metadata["validation_summary"] = {
            "events_submitted": val_result.events_processed,
            "valid_events_count": val_result.valid_events_count,
            "duplicate_events_count": val_result.duplicate_events_count,
            "malformed_events_count": val_result.malformed_events_count,
        }
        return result
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Reconstruction processing failed due to internal analysis error.",
        ) from exc
