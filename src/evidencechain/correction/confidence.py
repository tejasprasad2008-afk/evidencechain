"""Evidence-weighted confidence scoring engine.

Computes a 0.0-1.0 confidence score for every forensic finding based on:
  1. Evidence type base weight (DIRECT > CORROBORATED > CIRCUMSTANTIAL > INFERRED)
  2. Corroboration bonus — distinct artifact types that independently support the finding
  3. Contradiction penalty — unresolved contradictions depress confidence
  4. Missing evidence penalty — expected corroboration that wasn't found
  5. Threat intel bonus — malicious verdicts from threat intelligence

Scoring is DETERMINISTIC and CODE-DRIVEN, not LLM-driven. The same evidence
store state always produces the same scores.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from ..enums import (
    ArtifactType,
    ContradictionResolution,
    EvidenceSemantics,
    EvidenceType,
    FindingStatus,
    Severity,
    ThreatIntelVerdict,
)
from ..forensic_semantics import SEMANTICS_MAP
from ..models import ContradictionRecord, EvidenceAtom, ForensicFinding, _utcnow
from ..provenance.audit_logger import AuditLogger
from ..provenance.evidence_store import EvidenceStore

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Base weights for each evidence type
EVIDENCE_TYPE_WEIGHTS: dict[EvidenceType, float] = {
    EvidenceType.DIRECT: 0.90,
    EvidenceType.CORROBORATED: 0.80,
    EvidenceType.CIRCUMSTANTIAL: 0.50,
    EvidenceType.INFERRED: 0.30,
}

# Bonus per distinct artifact type that corroborates (diminishing returns)
_CORROBORATION_BONUS_PER_TYPE = 0.05
_MAX_CORROBORATION_BONUS = 0.15  # Cap at 3 distinct types

# Penalty per unresolved contradiction that affects this finding
_CONTRADICTION_PENALTY = 0.15

# Penalty if the finding lists missing expected evidence
_MISSING_EVIDENCE_PENALTY = 0.10

# Bonus if threat intel confirms maliciousness of a related indicator
_THREAT_INTEL_BONUS = 0.10

# Thresholds for automatic status transitions
CONFIRM_THRESHOLD = 0.75  # >= this: DRAFT -> CONFIRMED
REVIEW_THRESHOLD = 0.40   # < this: DRAFT -> UNDER_REVIEW


# ---------------------------------------------------------------------------
# Score breakdown
# ---------------------------------------------------------------------------

@dataclass
class ConfidenceBreakdown:
    """Detailed breakdown of how a finding's score was computed."""

    finding_id: str = ""
    base_weight: float = 0.0
    evidence_type: str = ""
    distinct_artifact_types: int = 0
    corroboration_bonus: float = 0.0
    contradiction_count: int = 0
    contradiction_penalty: float = 0.0
    missing_evidence_count: int = 0
    missing_evidence_penalty: float = 0.0
    threat_intel_bonus: float = 0.0
    raw_score: float = 0.0
    final_score: float = 0.0  # Clamped to [0.0, 1.0]
    status_action: str = ""  # "confirmed", "under_review", or "no_change"
    computed_at: str = field(default_factory=_utcnow)


# ---------------------------------------------------------------------------
# Confidence Scorer
# ---------------------------------------------------------------------------

class ConfidenceScorer:
    """Computes evidence-weighted confidence scores for forensic findings."""

    def __init__(self, store: EvidenceStore, audit: AuditLogger) -> None:
        self.store = store
        self.audit = audit

    # -------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------

    def score_finding(self, finding: ForensicFinding) -> ConfidenceBreakdown:
        """Compute the confidence score for a single finding."""
        breakdown = ConfidenceBreakdown(finding_id=finding.finding_id)

        # 1) Determine evidence type and base weight
        evidence_type = self._classify_evidence_type(finding)
        finding.evidence_type = evidence_type
        breakdown.evidence_type = evidence_type.value
        breakdown.base_weight = EVIDENCE_TYPE_WEIGHTS[evidence_type]

        # 2) Corroboration bonus: count distinct artifact types
        distinct_types = self._count_distinct_artifact_types(finding)
        breakdown.distinct_artifact_types = distinct_types
        corr_bonus = min(
            (distinct_types - 1) * _CORROBORATION_BONUS_PER_TYPE,
            _MAX_CORROBORATION_BONUS,
        )
        # Don't penalize for single source — bonus starts at 2+ types
        corr_bonus = max(corr_bonus, 0.0)
        breakdown.corroboration_bonus = corr_bonus

        # 3) Contradiction penalty
        contradiction_count = self._count_contradictions(finding)
        breakdown.contradiction_count = contradiction_count
        breakdown.contradiction_penalty = contradiction_count * _CONTRADICTION_PENALTY

        # 4) Missing evidence penalty
        missing_count = len(finding.missing_expected_evidence)
        breakdown.missing_evidence_count = missing_count
        breakdown.missing_evidence_penalty = missing_count * _MISSING_EVIDENCE_PENALTY

        # 5) Threat intel bonus
        ti_bonus = self._compute_threat_intel_bonus(finding)
        breakdown.threat_intel_bonus = ti_bonus

        # 6) Combine
        raw = (
            breakdown.base_weight
            + breakdown.corroboration_bonus
            + breakdown.threat_intel_bonus
            - breakdown.contradiction_penalty
            - breakdown.missing_evidence_penalty
        )
        breakdown.raw_score = raw
        breakdown.final_score = max(0.0, min(1.0, raw))

        # 7) Apply score to finding
        finding.confidence_score = breakdown.final_score

        # 8) Auto-transition status
        breakdown.status_action = self._apply_status_transition(finding)

        return breakdown

    def score_all_findings(self) -> list[ConfidenceBreakdown]:
        """Score every active (non-retracted) finding. Returns all breakdowns."""
        breakdowns: list[ConfidenceBreakdown] = []

        for finding in self.store.get_active_findings():
            bd = self.score_finding(finding)
            breakdowns.append(bd)

            # Audit log the score computation
            self.audit.log_correction({
                "event": "confidence_scored",
                "finding_id": finding.finding_id,
                "title": finding.title,
                "evidence_type": bd.evidence_type,
                "final_score": bd.final_score,
                "status_action": bd.status_action,
                "breakdown": {
                    "base_weight": bd.base_weight,
                    "corroboration_bonus": bd.corroboration_bonus,
                    "contradiction_penalty": bd.contradiction_penalty,
                    "missing_evidence_penalty": bd.missing_evidence_penalty,
                    "threat_intel_bonus": bd.threat_intel_bonus,
                },
            })

        # Summary log
        scored = len(breakdowns)
        confirmed = sum(1 for b in breakdowns if b.status_action == "confirmed")
        reviewed = sum(1 for b in breakdowns if b.status_action == "under_review")
        logger.info(
            "Scored %d findings: %d confirmed, %d under_review, %d unchanged",
            scored,
            confirmed,
            reviewed,
            scored - confirmed - reviewed,
        )

        return breakdowns

    # -------------------------------------------------------------------
    # Internal scoring methods
    # -------------------------------------------------------------------

    # Semantic implication map: proving a stronger semantic also satisfies
    # weaker ones.  E.g., proving EXECUTION implies PRESENCE (if it ran,
    # it must have existed on disk).
    _SEMANTIC_IMPLIES: dict[str, set[str]] = {
        EvidenceSemantics.EXECUTION: {EvidenceSemantics.PRESENCE},
        EvidenceSemantics.NETWORK_CONNECTION: {EvidenceSemantics.PRESENCE},
        EvidenceSemantics.PERSISTENCE: {EvidenceSemantics.PRESENCE},
        EvidenceSemantics.USER_INTERACTION: {EvidenceSemantics.PRESENCE},
        EvidenceSemantics.FILE_MODIFICATION: {EvidenceSemantics.PRESENCE},
        EvidenceSemantics.KNOWN_MALWARE: {EvidenceSemantics.PRESENCE},
        EvidenceSemantics.KNOWN_C2_INFRASTRUCTURE: {
            EvidenceSemantics.NETWORK_CONNECTION,
        },
    }

    def _expand_proves(self, proves: set[str]) -> set[str]:
        """Expand a 'proves' set with implied semantics.

        For example, {EXECUTION} expands to {EXECUTION, PRESENCE} because
        proving execution also proves the file existed.
        """
        expanded = set(proves)
        for sem in proves:
            expanded |= self._SEMANTIC_IMPLIES.get(sem, set())
        return expanded

    def _classify_evidence_type(self, finding: ForensicFinding) -> EvidenceType:
        """Determine the strongest evidence type for a finding's atoms.

        Classification logic:
        - DIRECT: at least one atom directly proves the finding's implied semantic
        - CORROBORATED: multiple atoms from different sources agree
        - CIRCUMSTANTIAL: atoms suggest but don't prove
        - INFERRED: atoms from types that cannot_prove the relevant semantic
        """
        if not finding.supporting_atoms:
            return EvidenceType.INFERRED

        atoms = [
            self.store.get_atom(aid)
            for aid in finding.supporting_atoms
        ]
        atoms = [a for a in atoms if a is not None]

        if not atoms:
            return EvidenceType.INFERRED

        # What semantic does this finding imply?
        implied_semantics = self._get_implied_semantics(finding)

        # Check for direct proof (with semantic implication expansion)
        has_direct_proof = False
        unique_sources: set[ArtifactType] = set()

        for atom in atoms:
            unique_sources.add(atom.artifact_type)

            # Expand the atom's proves set with implied semantics
            expanded_proves = self._expand_proves(atom.proves)
            if expanded_proves & implied_semantics:
                has_direct_proof = True

        if has_direct_proof:
            if len(unique_sources) >= 2:
                return EvidenceType.CORROBORATED
            return EvidenceType.DIRECT

        # No direct proof — check if atoms suggest
        has_suggestion = any(
            atom.suggests & implied_semantics for atom in atoms
        )

        if has_suggestion and len(unique_sources) >= 2:
            return EvidenceType.CIRCUMSTANTIAL

        if has_suggestion:
            return EvidenceType.CIRCUMSTANTIAL

        # Neither proves nor suggests — purely inferred
        return EvidenceType.INFERRED

    def _get_implied_semantics(self, finding: ForensicFinding) -> set[str]:
        """Map a finding's category to the forensic semantics it implies."""
        _CATEGORY_SEMANTICS: dict[str, set[str]] = {
            "malware_execution": {
                EvidenceSemantics.EXECUTION,
                EvidenceSemantics.KNOWN_MALWARE,
            },
            "lateral_movement": {
                EvidenceSemantics.EXECUTION,
                EvidenceSemantics.LATERAL_MOVEMENT,
                EvidenceSemantics.NETWORK_CONNECTION,
            },
            "persistence": {
                EvidenceSemantics.PERSISTENCE,
            },
            "data_exfiltration": {
                EvidenceSemantics.EXECUTION,
                EvidenceSemantics.DATA_EXFILTRATION,
                EvidenceSemantics.NETWORK_CONNECTION,
            },
            "credential_access": {
                EvidenceSemantics.EXECUTION,
                EvidenceSemantics.CREDENTIAL_ACCESS,
            },
            "defense_evasion": {
                EvidenceSemantics.TIMESTOMPING,
                EvidenceSemantics.LOG_CLEARING,
            },
            "anti_forensics": {
                EvidenceSemantics.TIMESTOMPING,
                EvidenceSemantics.LOG_CLEARING,
            },
            "command_and_control": {
                EvidenceSemantics.NETWORK_CONNECTION,
                EvidenceSemantics.KNOWN_C2_INFRASTRUCTURE,
            },
            "initial_access": {
                EvidenceSemantics.EXECUTION,
                EvidenceSemantics.USER_INTERACTION,
            },
            "privilege_escalation": {
                EvidenceSemantics.EXECUTION,
            },
            "reconnaissance": {
                EvidenceSemantics.EXECUTION,
            },
            "benign_activity": {
                EvidenceSemantics.PRESENCE,
            },
        }
        return _CATEGORY_SEMANTICS.get(finding.category.value, {EvidenceSemantics.PRESENCE})

    def _count_distinct_artifact_types(self, finding: ForensicFinding) -> int:
        """Count the number of distinct artifact types across supporting atoms."""
        types: set[ArtifactType] = set()
        for atom_id in finding.supporting_atoms:
            atom = self.store.get_atom(atom_id)
            if atom:
                types.add(atom.artifact_type)
        return len(types)

    def _count_contradictions(self, finding: ForensicFinding) -> int:
        """Count unresolved contradictions that affect this finding."""
        count = 0
        for c in self.store.contradictions.values():
            if c.resolution != ContradictionResolution.UNRESOLVED:
                continue

            # Check if contradiction explicitly references this finding
            if finding.finding_id in c.affected_finding_ids:
                count += 1
                continue

            # Check if contradiction references any of our supporting atoms
            affected_atoms = set()
            if c.atom_a_id:
                affected_atoms.add(c.atom_a_id)
            if c.atom_b_id:
                affected_atoms.add(c.atom_b_id)

            if affected_atoms & set(finding.supporting_atoms):
                count += 1

        return count

    def _compute_threat_intel_bonus(self, finding: ForensicFinding) -> float:
        """Check if threat intel atoms corroborate this finding."""
        bonus = 0.0

        for atom_id in finding.supporting_atoms:
            atom = self.store.get_atom(atom_id)
            if atom is None:
                continue

            if atom.artifact_type != ArtifactType.THREAT_INTEL:
                continue

            verdict = atom.raw_data.get("verdict", "")
            if verdict == ThreatIntelVerdict.MALICIOUS.value:
                bonus = _THREAT_INTEL_BONUS
                break
            elif verdict == ThreatIntelVerdict.SUSPICIOUS.value:
                bonus = max(bonus, _THREAT_INTEL_BONUS / 2)

        return bonus

    # -------------------------------------------------------------------
    # Status transitions
    # -------------------------------------------------------------------

    def _apply_status_transition(self, finding: ForensicFinding) -> str:
        """Apply automatic status transitions based on confidence score.

        Only transitions DRAFT findings. CONFIRMED / UNDER_REVIEW / RETRACTED
        findings are not automatically changed — those require explicit action.
        """
        if finding.status != FindingStatus.DRAFT:
            return "no_change"

        if finding.confidence_score >= CONFIRM_THRESHOLD:
            self.store.update_finding_status(
                finding.finding_id,
                FindingStatus.CONFIRMED,
                reason=(
                    f"Auto-confirmed: confidence {finding.confidence_score:.2f} "
                    f">= threshold {CONFIRM_THRESHOLD}"
                ),
            )
            return "confirmed"

        if finding.confidence_score < REVIEW_THRESHOLD:
            self.store.update_finding_status(
                finding.finding_id,
                FindingStatus.UNDER_REVIEW,
                reason=(
                    f"Sent for review: confidence {finding.confidence_score:.2f} "
                    f"< threshold {REVIEW_THRESHOLD}"
                ),
            )
            return "under_review"

        return "no_change"
