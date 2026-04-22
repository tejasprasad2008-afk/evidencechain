"""Core data models for EvidenceChain."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .enums import (
    ArtifactType,
    ContradictionPattern,
    ContradictionResolution,
    EvidenceType,
    FindingCategory,
    FindingStatus,
    Severity,
    ThreatIntelSource,
    ThreatIntelVerdict,
    TimestampSemanticType,
    ToolStatus,
)


def _new_id(prefix: str = "") -> str:
    """Generate a short unique ID with optional prefix."""
    short = uuid.uuid4().hex[:8]
    return f"{prefix}{short}" if prefix else short


def _utcnow() -> str:
    """Return current UTC time as ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Timestamp record
# ---------------------------------------------------------------------------

@dataclass
class TimestampRecord:
    """A single timestamp extracted from a forensic artifact with semantic meaning."""

    value: str  # ISO 8601 UTC
    source_field: str  # e.g. "$SI_Modified", "TimeCreated", "LastRunTime"
    semantic_type: TimestampSemanticType
    attribute_source: str | None = None  # e.g. "$STANDARD_INFO" vs "$FILE_NAME"


# ---------------------------------------------------------------------------
# Forensic context attached to every tool result
# ---------------------------------------------------------------------------

@dataclass
class ForensicContext:
    """What a tool's output proves, suggests, and cannot prove."""

    proves: list[str] = field(default_factory=list)
    suggests: list[str] = field(default_factory=list)
    cannot_prove: list[str] = field(default_factory=list)
    caveats: list[str] = field(default_factory=list)
    corroboration_hints: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Tool execution result (returned to agent via MCP)
# ---------------------------------------------------------------------------

@dataclass
class ToolResult:
    """Standardized response envelope for every MCP tool call."""

    tool_name: str
    evidence_id: str
    execution_id: str = field(default_factory=lambda: _new_id("EXE-"))
    timestamp_utc: str = field(default_factory=_utcnow)
    duration_seconds: float = 0.0
    status: ToolStatus = ToolStatus.SUCCESS
    command_executed: list[str] = field(default_factory=list)
    raw_output_path: str = ""
    structured_data: dict | list = field(default_factory=dict)
    record_count: int = 0
    truncated: bool = False
    forensic_context: ForensicContext = field(default_factory=ForensicContext)
    error_message: str = ""


# ---------------------------------------------------------------------------
# Evidence atom (stored in evidence store)
# ---------------------------------------------------------------------------

@dataclass
class EvidenceAtom:
    """The atomic unit of evidence — one parsed artifact from one tool execution."""

    atom_id: str = field(default_factory=lambda: _new_id("ATM-"))
    tool_name: str = ""
    execution_id: str = ""
    artifact_type: ArtifactType = ArtifactType.FILESYSTEM_ENTRY
    raw_data: dict = field(default_factory=dict)
    timestamps: list[TimestampRecord] = field(default_factory=list)
    file_references: list[str] = field(default_factory=list)
    proves: set[str] = field(default_factory=set)
    suggests: set[str] = field(default_factory=set)
    cannot_prove: set[str] = field(default_factory=set)
    created_at: str = field(default_factory=_utcnow)


# ---------------------------------------------------------------------------
# Finding revision history entry
# ---------------------------------------------------------------------------

@dataclass
class FindingRevision:
    """A single change in a finding's lifecycle."""

    timestamp_utc: str = field(default_factory=_utcnow)
    from_status: str = ""
    to_status: str = ""
    reason: str = ""
    contradiction_id: str | None = None


# ---------------------------------------------------------------------------
# Forensic finding
# ---------------------------------------------------------------------------

@dataclass
class ForensicFinding:
    """An investigative conclusion backed by evidence atoms."""

    finding_id: str = field(default_factory=lambda: _new_id("FND-"))
    category: FindingCategory = FindingCategory.BENIGN_ACTIVITY
    title: str = ""
    description: str = ""
    supporting_atoms: list[str] = field(default_factory=list)
    contradicting_atoms: list[str] = field(default_factory=list)
    evidence_type: EvidenceType = EvidenceType.CIRCUMSTANTIAL
    confidence_score: float = 0.0
    status: FindingStatus = FindingStatus.DRAFT
    mitre_attack: list[str] = field(default_factory=list)
    revision_history: list[FindingRevision] = field(default_factory=list)
    missing_expected_evidence: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=_utcnow)


# ---------------------------------------------------------------------------
# Contradiction record
# ---------------------------------------------------------------------------

@dataclass
class ContradictionRecord:
    """A detected conflict between evidence atoms or findings."""

    contradiction_id: str = field(default_factory=lambda: _new_id("CTR-"))
    pattern_type: ContradictionPattern = ContradictionPattern.PHANTOM_ARTIFACT
    severity: Severity = Severity.MEDIUM
    atom_a_id: str = ""
    atom_b_id: str | None = None
    affected_finding_ids: list[str] = field(default_factory=list)
    description: str = ""
    resolution: ContradictionResolution = ContradictionResolution.UNRESOLVED
    resolution_evidence: list[str] = field(default_factory=list)
    reinvestigation_actions: list[dict] = field(default_factory=list)
    created_at: str = field(default_factory=_utcnow)


# ---------------------------------------------------------------------------
# Tool execution record (for audit trail)
# ---------------------------------------------------------------------------

@dataclass
class ToolExecution:
    """Full provenance record for a single tool invocation."""

    execution_id: str = field(default_factory=lambda: _new_id("EXE-"))
    tool_name: str = ""
    evidence_id: str = ""
    command: list[str] = field(default_factory=list)
    input_params: dict = field(default_factory=dict)
    started_at: str = field(default_factory=_utcnow)
    completed_at: str = ""
    duration_seconds: float = 0.0
    status: ToolStatus = ToolStatus.SUCCESS
    exit_code: int = 0
    stdout_hash: str = ""
    stderr_summary: str = ""
    raw_output_path: str = ""
    record_count: int = 0
    atoms_produced: list[str] = field(default_factory=list)
    parse_warnings: list[str] = field(default_factory=list)
    error_message: str = ""


# ---------------------------------------------------------------------------
# Threat intelligence models
# ---------------------------------------------------------------------------

@dataclass
class Indicator:
    """An indicator to look up in threat intelligence sources."""

    indicator_type: str  # "hash_sha256", "hash_sha1", "hash_md5", "ipv4", "domain", "filename"
    value: str


@dataclass
class ThreatIntelResult:
    """Result from a single threat intelligence source for one indicator."""

    indicator_type: str
    indicator_value: str
    source: ThreatIntelSource
    source_url: str = ""
    query_timestamp_utc: str = field(default_factory=_utcnow)
    verdict: ThreatIntelVerdict = ThreatIntelVerdict.UNKNOWN
    confidence: float = 0.0
    details: dict = field(default_factory=dict)
    raw_response_excerpt: str = ""


@dataclass
class AggregatedVerdict:
    """Aggregated threat intel verdict across multiple sources for one indicator."""

    indicator_type: str
    indicator_value: str
    overall_verdict: ThreatIntelVerdict = ThreatIntelVerdict.UNKNOWN
    overall_confidence: float = 0.0
    source_count: int = 0
    source_results: list[ThreatIntelResult] = field(default_factory=list)
    attribution_summary: str = ""
