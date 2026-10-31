"""
Forensic Events API routes for GhostTrace.
Provides access to normalized events, graph representation, and on-demand validation.
"""

from typing import Any, List, Optional
from fastapi import APIRouter, HTTPException, Query

from backend.app.core.config import settings
from backend.app.models.event import (
    EventListResponse,
    GraphElementsResponse,
)
from investigation_engine.graph.base import InvestigationGraph
from investigation_engine.loader import load_events_from_fixture
from investigation_engine.models import (
    EventType,
    SecurityEvent,
    ValidationResult,
)
from investigation_engine.validation import validate_event_batch

router = APIRouter(prefix="/api/v1/events", tags=["Events"])


@router.get("", response_model=EventListResponse)
async def list_events(
    suspicious_only: bool = Query(default=False, description="Filter for suspicious events only"),
    event_type: Optional[EventType] = Query(default=None, description="Filter by event type"),
    limit: int = Query(default=100, ge=1, le=500, description="Max number of events to return"),
) -> EventListResponse:
    """
    Retrieve normalized security events from benchmark fixtures.
    Supports filtering by suspicious status and forensic event type.
    """
    fixture_path = settings.fixtures_dir / settings.default_fixture_file
    if not fixture_path.is_file():
        raise HTTPException(
            status_code=404,
            detail=f"Fixture file '{settings.default_fixture_file}' not found.",
        )

    events, val_result = load_events_from_fixture(fixture_path)

    # Filter
    filtered = events
    if suspicious_only:
        filtered = [e for e in filtered if e.is_suspicious]
    if event_type:
        filtered = [e for e in filtered if e.event_type == event_type]

    # Chronological sort
    filtered.sort(key=lambda e: e.timestamp)

    suspicious_total = sum(1 for e in events if e.is_suspicious)

    return EventListResponse(
        total=len(events),
        count=len(filtered[:limit]),
        suspicious_count=suspicious_total,
        events=filtered[:limit],
        validation_status=val_result,
    )


from investigation_engine.collector import device_collector
from evaluation.generator import generate_evaluation_suite


@router.get("/graph", response_model=GraphElementsResponse)
async def get_event_graph(
    suspicious_only: bool = Query(default=False, description="Filter graph for suspicious events only"),
    scenario_id: Optional[str] = Query(default=None, description="Optional scenario ID to build graph for"),
) -> GraphElementsResponse:
    """
    Export NetworkX investigation graph as Cytoscape.js elements JSON.
    Supports targeting a specific scenario or defaulting to simulated_events.json.
    """
    if scenario_id == "live_device":
        events = device_collector.collect_device_events(max_events=350)
    elif scenario_id:
        scenarios_map = {
            "scenario-1": "simulated_events.json",
            "scenario_multi_stage_attack": "simulated_events.json",
            "scenario-2": "scenario_routine_baseline.json",
            "scenario_routine_baseline": "scenario_routine_baseline.json",
            "scenario-3": "scenario_credential_c2.json",
            "scenario_credential_c2": "scenario_credential_c2.json",
        }
        filename = scenarios_map.get(scenario_id)
        if filename:
            file_path = settings.fixtures_dir / filename
            if not file_path.is_file():
                raise HTTPException(status_code=404, detail="Fixture file not found")
            events, _ = load_events_from_fixture(file_path)
        else:
            suite = generate_evaluation_suite(seed=42)
            if scenario_id in suite:
                blind_events, _ = suite[scenario_id]
                events, _ = validate_event_batch(blind_events, deduplicate=True)
            else:
                raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found.")
    else:
        fixture_path = settings.fixtures_dir / settings.default_fixture_file
        if not fixture_path.is_file():
            raise HTTPException(status_code=404, detail="Fixture file not found")
        events, _ = load_events_from_fixture(fixture_path)

    if suspicious_only:
        events = [e for e in events if e.is_suspicious]

    inv_graph = InvestigationGraph()
    inv_graph.build_from_events(events)
    elements = inv_graph.to_cytoscape_elements()

    return GraphElementsResponse(
        event_count=len(events),
        element_count=len(elements),
        elements=elements,
    )


MAX_EVENT_BATCH_SIZE = 500


@router.post("/validate", response_model=ValidationResult)
async def validate_records(
    records: List[Any],
    deduplicate: bool = Query(default=True, description="Enforce deduplication of event IDs"),
) -> ValidationResult:
    """
    Validate arbitrary security event records against canonical schema.
    Returns validation result with detailed issues, counts, and errors.
    """
    if len(records) > MAX_EVENT_BATCH_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"Payload too large. Maximum allowed records for validation is {MAX_EVENT_BATCH_SIZE}, received {len(records)}.",
        )
    _, result = validate_event_batch(records, deduplicate=deduplicate)
    return result


from pydantic import BaseModel, Field
from investigation_engine.importer import parse_and_import_logs, ImportLogResult


class ImportLogRequest(BaseModel):
    content: str = Field(..., description="Raw log file content string (JSON, JSONL, Windows XML, Windows JSON, Linux auth.log)")
    filename: Optional[str] = Field(default=None, description="Optional uploaded log filename to aid format detection and audit lineage")
    deduplicate: bool = Field(default=True, description="Enforce deduplication of event IDs")


@router.post("/import", response_model=ImportLogResult)
async def import_user_logs(request: ImportLogRequest) -> ImportLogResult:
    """
    Import, parse, and validate user security logs in JSON, JSONL, Windows XML/JSON, or Linux auth.log format.
    Enforces payload safety, normalizes schema, and preserves raw evidence provenance.
    """
    try:
        return parse_and_import_logs(request.content, filename=request.filename, deduplicate=request.deduplicate)
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to parse and import logs: {exc}")


class ScenarioSummary(BaseModel):
    id: str
    name: str
    description: str
    file: str
    is_suspicious: bool


class ScenarioDetailResponse(BaseModel):
    scenario_id: str
    event_count: int
    events: List[SecurityEvent]
    validation_status: ValidationResult


@router.get("/scenarios", response_model=List[ScenarioSummary])
async def list_scenarios() -> List[ScenarioSummary]:
    """
    List available simulated benchmark scenarios for interactive investigation,
    including both standard baseline fixtures and synthetic challenge scenarios.
    """
    return [
        ScenarioSummary(
            id="live_device",
            name="🖥️ Live Host Telemetry (This Device)",
            description=f"Real-time host telemetry: active processes, network sockets, and persistence mechanisms from {device_collector.hostname} ({device_collector.current_user}).",
            file="live_device_collector",
            is_suspicious=False,
        ),
        ScenarioSummary(
            id="scenario_multi_stage_attack",
            name="Scenario 1: Multi-Stage Intrusion (SIM-CORP Enterprise)",
            description="Full multi-stage attack lifecycle: external brute force, compromised credentials, encoded shell execution, secret access, C2 beacon, and lateral SMB probe.",
            file="simulated_events.json",
            is_suspicious=True,
        ),
        ScenarioSummary(
            id="scenario_routine_baseline",
            name="Scenario 2: Routine Administrative Operations Baseline",
            description="Clean operational telemetry: authorized developer SSH, git version control, config reads, and scheduled log rotation.",
            file="scenario_routine_baseline.json",
            is_suspicious=False,
        ),
        ScenarioSummary(
            id="scenario_credential_c2",
            name="Scenario 3: Credential Access & C2 Egress Investigation",
            description="Focused intrusion sequence evaluating exfiltration restraint: unauthorized secret file read followed by external connection.",
            file="scenario_credential_c2.json",
            is_suspicious=True,
        ),
        ScenarioSummary(
            id="scenario_account_compromise_chain",
            name="Synthetic Scenario 1: Account Access -> Process Lineage -> File Read",
            description="Linear credential compromise followed by payload execution and sensitive secret audit.",
            file="evaluation.generator",
            is_suspicious=True,
        ),
        ScenarioSummary(
            id="scenario_interleaved_heavy_baseline",
            name="Synthetic Scenario 2: Interleaved Malicious Hook with Heavy Baseline",
            description="Malicious CI webhook injection interleaved within high-volume routine developer activity.",
            file="evaluation.generator",
            is_suspicious=True,
        ),
        ScenarioSummary(
            id="scenario_multiple_unrelated_incidents",
            name="Synthetic Scenario 3: Multiple Unrelated Suspicious Incidents",
            description="Isolated DMZ port scan vs. internal SQL dictionary attack spanning different network segments.",
            file="evaluation.generator",
            is_suspicious=True,
        ),
        ScenarioSummary(
            id="scenario_missing_conflicting_identifiers",
            name="Synthetic Scenario 4: Missing Session IDs & Conflicting Naming",
            description="Degraded telemetry robustness testing with missing session attributes and hostname variations.",
            file="evaluation.generator",
            is_suspicious=True,
        ),
        ScenarioSummary(
            id="scenario_unusual_egress_exfiltration_restraint",
            name="Synthetic Scenario 5: Egress Following Secret Read (Restraint)",
            description="Outbound network socket following file access to evaluate exfiltration restraint.",
            file="evaluation.generator",
            is_suspicious=True,
        ),
        ScenarioSummary(
            id="scenario_ambiguous_administrative_anomaly",
            name="Synthetic Scenario 6: Ambiguous Off-Hours Administrative Anomaly",
            description="Off-hours root firewall reconfiguration with two plausible competing explanations.",
            file="evaluation.generator",
            is_suspicious=True,
        ),
        ScenarioSummary(
            id="scenario_held_out_blind_challenge",
            name="Synthetic Scenario 7: Held-Out Blind Challenge (RDP -> SMB)",
            description="Held-out blind challenge evaluation dataset testing zero-leakage multi-stage reconstruction.",
            file="evaluation.generator",
            is_suspicious=True,
        ),
        ScenarioSummary(
            id="scenario_hackathon_judge_demo",
            name="★ Live Judge Demonstration: Multi-Stage Intrusion & Restraint",
            description="Controlled hackathon demo benchmark: off-hours SSH, bash cradle, DB key read, non-standard egress, and routine metrics.",
            file="evaluation.generator",
            is_suspicious=True,
        ),
    ]


import re

@router.get("/scenarios/{scenario_id}", response_model=ScenarioDetailResponse)
async def get_scenario(scenario_id: str) -> ScenarioDetailResponse:
    """
    Load events and metadata for a specific simulated benchmark or synthetic challenge scenario.
    """
    if not re.match(r"^[a-zA-Z0-9_\-]+$", scenario_id):
        raise HTTPException(
            status_code=400,
            detail="Invalid scenario identifier. Identifiers must be alphanumeric with dashes or underscores.",
        )
    if scenario_id == "live_device":
        events = device_collector.collect_device_events(max_events=350)
        _, val_result = validate_event_batch([e.model_dump() for e in events], deduplicate=True)
        return ScenarioDetailResponse(
            scenario_id="live_device",
            event_count=len(events),
            events=events,
            validation_status=val_result,
        )

    scenarios_map = {
        "scenario-1": "simulated_events.json",
        "scenario_multi_stage_attack": "simulated_events.json",
        "scenario-2": "scenario_routine_baseline.json",
        "scenario_routine_baseline": "scenario_routine_baseline.json",
        "scenario-3": "scenario_credential_c2.json",
        "scenario_credential_c2": "scenario_credential_c2.json",
    }
    filename = scenarios_map.get(scenario_id)
    if filename:
        file_path = settings.fixtures_dir / filename
        if not file_path.is_file():
            raise HTTPException(status_code=404, detail=f"Scenario file '{filename}' not found.")

        events, val_result = load_events_from_fixture(file_path)
        return ScenarioDetailResponse(
            scenario_id=scenario_id,
            event_count=len(events),
            events=events,
            validation_status=val_result,
        )

    # Check synthetic evaluation suite
    suite = generate_evaluation_suite(seed=42)
    if scenario_id in suite:
        blind_events, _ = suite[scenario_id]
        events, val_result = validate_event_batch(blind_events, deduplicate=True)
        return ScenarioDetailResponse(
            scenario_id=scenario_id,
            event_count=len(events),
            events=events,
            validation_status=val_result,
        )

    raise HTTPException(
        status_code=404,
        detail=f"Scenario '{scenario_id}' not found. Available scenarios: {list(scenarios_map.keys()) + list(suite.keys())}",
    )


