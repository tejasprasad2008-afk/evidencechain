"""Self-correction engine: contradiction detectors, confidence scoring, re-investigation."""

from .confidence import ConfidenceBreakdown, ConfidenceScorer
from .detectors import (
    ALL_DETECTORS,
    AntiForensicIndicatorDetector,
    AttributionMismatchDetector,
    BaseDetector,
    ExecutionOverclaimDetector,
    GhostProcessDetector,
    PhantomArtifactDetector,
    TimelineGapDetector,
    TimestampParadoxDetector,
    run_all_detectors,
)
from .engine import (
    CorrectionEngine,
    CorrectionReport,
    PassResult,
    ReinvestigationAction,
    ReinvestigationPlan,
)

__all__ = [
    # Detectors
    "ALL_DETECTORS",
    "AntiForensicIndicatorDetector",
    "AttributionMismatchDetector",
    "BaseDetector",
    "ExecutionOverclaimDetector",
    "GhostProcessDetector",
    "PhantomArtifactDetector",
    "TimelineGapDetector",
    "TimestampParadoxDetector",
    "run_all_detectors",
    # Confidence
    "ConfidenceBreakdown",
    "ConfidenceScorer",
    # Engine
    "CorrectionEngine",
    "CorrectionReport",
    "PassResult",
    "ReinvestigationAction",
    "ReinvestigationPlan",
]
