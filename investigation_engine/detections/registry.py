"""
Detection Engine and Rule Registry for GhostTrace.
Runs all registered modular detection rules against an event collection.
"""

from __future__ import annotations

from typing import List, Type

from investigation_engine.models import DetectionFinding, SecurityEvent
from investigation_engine.detections.rule import BaseDetectionRule
from investigation_engine.detections.rules.auth_rules import BruteForceAuthenticationRule
from investigation_engine.detections.rules.execution_rules import SuspiciousCommandExecutionRule
from investigation_engine.detections.rules.file_rules import SensitiveFileAccessRule
from investigation_engine.detections.rules.network_rules import SuspiciousNetworkConnectionRule


DEFAULT_RULES: List[Type[BaseDetectionRule]] = [
    BruteForceAuthenticationRule,
    SuspiciousCommandExecutionRule,
    SensitiveFileAccessRule,
    SuspiciousNetworkConnectionRule,
]


class DetectionEngine:
    """
    Coordinates evaluation of detection rules against imported security events.
    """

    def __init__(self, rule_classes: List[Type[BaseDetectionRule]] = None):
        self.rules: List[BaseDetectionRule] = [
            cls() for cls in (rule_classes or DEFAULT_RULES)
        ]

    def run_detections(self, events: List[SecurityEvent]) -> List[DetectionFinding]:
        """
        Evaluate all detection rules against the event collection.
        Returns all findings deduplicated by finding_id.
        """
        all_findings: List[DetectionFinding] = []
        seen_ids = set()

        for rule in self.rules:
            findings = rule.evaluate(events)
            for f in findings:
                if f.finding_id not in seen_ids:
                    seen_ids.add(f.finding_id)
                    all_findings.append(f)

        return all_findings


def evaluate_detections(events: List[SecurityEvent]) -> List[DetectionFinding]:
    """Convenience helper to run default detection suite."""
    engine = DetectionEngine()
    return engine.run_detections(events)
