"""
GhostTrace Detections Subpackage.
Provides modular, explainable detection rules citing exact event IDs.
"""

from investigation_engine.detections.rule import BaseDetectionRule
from investigation_engine.detections.registry import (
    DEFAULT_RULES,
    DetectionEngine,
    evaluate_detections,
)

__all__ = [
    "BaseDetectionRule",
    "DetectionEngine",
    "DEFAULT_RULES",
    "evaluate_detections",
]
