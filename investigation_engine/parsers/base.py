"""
Base classes and interfaces for GhostTrace multi-format log parsers.
Enforces untrusted data handling, provenance preservation, and field documentation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

from investigation_engine.models import SecurityEvent, ValidationIssue, ValidationResult, ValidationSeverity


class ParserResult(BaseModel):
    """
    Standardized result from an individual log parser.
    """
    format_name: str
    raw_records_count: int
    parsed_events: List[Dict[str, Any]] = Field(default_factory=list)
    unsupported_fields: List[str] = Field(
        default_factory=list,
        description="List of fields encountered in source logs that have no direct mapping in canonical SecurityEvent schema"
    )
    parsing_warnings: List[str] = Field(
        default_factory=list,
        description="Warnings encountered during parsing (e.g. inferred timestamps, skipped empty lines, missing non-critical attributes)"
    )
    issues: List[ValidationIssue] = Field(
        default_factory=list,
        description="Validation and parsing issues"
    )


class BaseLogParser(ABC):
    """
    Abstract base class for all log parsers in GhostTrace.
    """

    @property
    @abstractmethod
    def format_name(self) -> str:
        """Name of the format (e.g., 'WINDOWS_XML', 'WINDOWS_JSON', 'LINUX_AUTH_LOG', 'JSON', 'JSONL')."""
        pass

    @property
    @abstractmethod
    def supported_extensions(self) -> List[str]:
        """File extensions typically associated with this format."""
        pass

    @abstractmethod
    def can_parse(self, content: str, filename: Optional[str] = None) -> bool:
        """
        Fast heuristic to determine whether this parser can parse the given raw content.
        """
        pass

    @abstractmethod
    def parse(
        self,
        content: str,
        filename: Optional[str] = None,
        max_records: int = 500,
    ) -> ParserResult:
        """
        Parse raw content string into normalized dict representations suitable for SecurityEvent.
        Must preserve raw original record in 'original_event_data' and track unsupported fields.
        """
        pass
