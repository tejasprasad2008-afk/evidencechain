"""Base validator interface for tool output parsing."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from ..models import EvidenceAtom


@dataclass
class ValidationWarning:
    """A non-fatal warning generated during validation."""

    message: str
    field: str = ""
    severity: str = "info"  # "info", "warning", "error"


@dataclass
class OverclaimFlag:
    """Raised when a tool output would be misinterpreted without correction."""

    message: str
    artifact_field: str = ""
    claimed_semantic: str = ""  # What the LLM might wrongly claim
    actual_semantic: str = ""  # What the evidence actually proves


@dataclass
class ValidatorResult:
    """Result of validating and parsing a tool's output."""

    atoms: list[EvidenceAtom] = field(default_factory=list)
    warnings: list[ValidationWarning] = field(default_factory=list)
    overclaim_flags: list[OverclaimFlag] = field(default_factory=list)
    record_count: int = 0


class BaseValidator(ABC):
    """Base class for all tool output validators."""

    @abstractmethod
    def validate(
        self,
        execution_id: str,
        raw_output: str,
        **kwargs,
    ) -> ValidatorResult:
        """Parse raw tool output and produce validated EvidenceAtoms.

        Args:
            execution_id: The execution ID of the tool call that produced this output.
            raw_output: The raw stdout from the tool.
            **kwargs: Additional context (e.g., evidence_id, file paths).

        Returns:
            ValidatorResult with atoms, warnings, and overclaim flags.
        """
        ...
