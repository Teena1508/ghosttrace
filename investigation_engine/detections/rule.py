"""
Base detection rule interface for GhostTrace.
Every rule is deterministic, modular, explainable, cites exact supporting event IDs,
and provides alternative benign explanations and missing-evidence limitations.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Optional

from investigation_engine.models import DetectionFinding, EventSeverity, SecurityEvent


class BaseDetectionRule(ABC):
    """
    Abstract Base Class for deterministic detection rules.
    """

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Stable unique identifier (e.g. GT-AUTH-001)."""
        pass

    @property
    @abstractmethod
    def rule_name(self) -> str:
        """Human-readable concise name of the rule."""
        pass

    @property
    @abstractmethod
    def severity(self) -> EventSeverity:
        """Severity assessment."""
        pass

    @property
    @abstractmethod
    def category(self) -> str:
        """Tactic category (e.g. INITIAL_ACCESS, EXECUTION, CREDENTIAL_ACCESS, LATERAL_MOVEMENT, EXFILTRATION, ANOMALY)."""
        pass

    @property
    def mitre_attack_id(self) -> Optional[str]:
        """Optional MITRE ATT&CK technique reference (e.g. T1110.001)."""
        return None

    @abstractmethod
    def evaluate(self, events: List[SecurityEvent]) -> List[DetectionFinding]:
        """
        Evaluate events and return detected findings.
        Must NOT fabricate evidence, must cite exact event IDs.
        """
        pass
