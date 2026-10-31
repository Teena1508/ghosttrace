"""
Fixture and log loader for GhostTrace.
Loads structured JSON security event fixtures, preserving original evidence records
and native source event IDs for chain of custody.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from investigation_engine.models import SecurityEvent, ValidationResult
from investigation_engine.validation import validate_event_batch


def load_raw_fixture_file(file_path: Union[str, Path]) -> List[Dict[str, Any]]:
    """
    Load raw JSON records from a fixture file.
    Supports either a top-level list of events or a wrapper object containing
    an 'events' list.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Fixture file not found: {path}")

    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, list):
        return data
    elif isinstance(data, dict):
        if "events" in data and isinstance(data["events"], list):
            return data["events"]
        # If single event dict wrapped
        return [data]
    else:
        raise ValueError(f"Invalid fixture format in {path}: expected JSON list or dict with 'events'")


def load_events_from_fixture(
    file_path: Union[str, Path],
    deduplicate: bool = True,
) -> Tuple[List[SecurityEvent], ValidationResult]:
    """
    Load, validate, and return normalized SecurityEvents from a JSON fixture file.
    Preserves raw original payloads and source IDs.
    """
    raw_records = load_raw_fixture_file(file_path)
    return validate_event_batch(raw_records, deduplicate=deduplicate)
