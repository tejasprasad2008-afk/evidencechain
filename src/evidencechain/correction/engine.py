"""Four-pass self-correction engine.

The engine orchestrates all correction phases in a deterministic pipeline
that runs after each batch of tool executions:

    Pass 1 — Inline Validation (already done by validators at tool-execution time)
             This pass SUMMARIZES what the validators flagged: overclaim warnings,
             timestamp anomalies, and semantic constraints.

    Pass 2 — Cross-Source Contradiction Detection
             Runs all 7 detectors from detectors.py to find internal inconsistencies
             across the entire evidence store.

    Pass 3 — Confidence Scoring
             Computes 0.0-1.0 scores for every active finding. Automatically
             promotes DRAFT->CONFIRMED (score >= 0.75) or DRAFT->UNDER_REVIEW
             (score < 0.40).

    Pass 4 — Reinvestigation Planning
             For every UNRESOLVED contradiction, generates a structured list of
             tool calls that could resolve the conflict. The orchestrator (Qoder)
             then executes these in the next investigation cycle.

The full pipeline repeats up to MAX_CORRECTION_ITERATIONS (default 3) times
or until no new contradictions are discovered.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from ..config import MAX_CORRECTION_ITERATIONS, MAX_REINVESTIGATION_TOOL_CALLS
from ..enums import ContradictionResolution, FindingStatus, Severity
from ..models import ContradictionRecord, _utcnow
from ..provenance.audit_logger import AuditLogger
from ..provenance.evidence_store import EvidenceStore
from .confidence import ConfidenceBreakdown, ConfidenceScorer
from .detectors import run_all_detectors

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Reinvestigation plan
# ---------------------------------------------------------------------------

@dataclass
class ReinvestigationAction:
    """A single tool call recommended to resolve a contradiction."""

    tool_name: str
    reason: str
    params: dict = field(default_factory=dict)
    priority: int = 0  # Lower = higher priority
    contradiction_id: str = ""


@dataclass
class ReinvestigationPlan:
    """Ordered list of tool calls needed to resolve unresolved contradictions."""

    actions: list[ReinvestigationAction] = field(default_factory=list)
    total_contradictions: int = 0
    unresolved_count: int = 0
    critical_count: int = 0
    capped: bool = False  # True if actions were capped at MAX_REINVESTIGATION_TOOL_CALLS


# ---------------------------------------------------------------------------
# Correction report (one per pass)
# ---------------------------------------------------------------------------

@dataclass
class PassResult:
    """Result of a single correction pass."""

    pass_number: int
    pass_name: str
    items_processed: int = 0
    issues_found: int = 0
    details: dict = field(default_factory=dict)
    duration_seconds: float = 0.0


@dataclass
class CorrectionReport:
    """Full report from one iteration of the correction engine."""

    iteration: int = 0
    started_at: str = field(default_factory=_utcnow)
    completed_at: str = ""
    pass_results: list[PassResult] = field(default_factory=list)
    new_contradictions: list[ContradictionRecord] = field(default_factory=list)
    confidence_breakdowns: list[ConfidenceBreakdown] = field(default_factory=list)
    reinvestigation_plan: ReinvestigationPlan = field(
        default_factory=ReinvestigationPlan
    )
    converged: bool = False  # True if no new contradictions found

    @property
    def summary(self) -> dict:
        """Human-readable summary for the orchestrator."""
        return {
            "iteration": self.iteration,
            "converged": self.converged,
            "total_contradictions_found": len(self.new_contradictions),
            "findings_scored": len(self.confidence_breakdowns),
            "confirmed": sum(
                1 for b in self.confidence_breakdowns if b.status_action == "confirmed"
            ),
            "under_review": sum(
                1 for b in self.confidence_breakdowns
                if b.status_action == "under_review"
            ),
            "reinvestigation_actions": len(self.reinvestigation_plan.actions),
            "pass_summaries": [
                {
                    "pass": p.pass_name,
                    "processed": p.items_processed,
                    "issues": p.issues_found,
                }
                for p in self.pass_results
            ],
        }


# ---------------------------------------------------------------------------
# Correction Engine
# ---------------------------------------------------------------------------

class CorrectionEngine:
    """Four-pass self-correction engine.

    Usage::

        engine = CorrectionEngine(store, audit)

        # After each batch of tool executions:
        report = engine.run_iteration()

        if not report.converged:
            # Execute report.reinvestigation_plan.actions
            # Then run another iteration
            pass

        # Or run full pipeline with auto-iteration:
        reports = engine.run_full_pipeline()
    """

    def __init__(self, store: EvidenceStore, audit: AuditLogger) -> None:
        self.store = store
        self.audit = audit
        self._scorer = ConfidenceScorer(store, audit)
        self._iteration = 0

    # -------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------

    def run_iteration(self) -> CorrectionReport:
        """Run one full 4-pass correction iteration.

        Returns a CorrectionReport with all findings, contradictions,
        scores, and reinvestigation actions.
        """
        self._iteration += 1
        report = CorrectionReport(iteration=self._iteration)

        logger.info(
            "=== Correction Engine: iteration %d ===",
            self._iteration,
        )

        # Pass 1: Inline validation summary
        p1 = self._pass1_inline_validation_summary()
        report.pass_results.append(p1)

        # Pass 2: Cross-source contradiction detection
        p2, contradictions = self._pass2_contradiction_detection()
        report.pass_results.append(p2)
        report.new_contradictions = contradictions

        # Pass 3: Confidence scoring
        p3, breakdowns = self._pass3_confidence_scoring()
        report.pass_results.append(p3)
        report.confidence_breakdowns = breakdowns

        # Pass 4: Reinvestigation planning
        p4, plan = self._pass4_reinvestigation_planning()
        report.pass_results.append(p4)
        report.reinvestigation_plan = plan

        # Convergence check
        report.converged = len(contradictions) == 0
        report.completed_at = _utcnow()

        # Audit the full iteration
        self.audit.log_correction({
            "event": "correction_iteration_complete",
            "iteration": self._iteration,
            "converged": report.converged,
            "summary": report.summary,
        })

        logger.info(
            "Correction iteration %d complete: converged=%s, "
            "%d contradictions, %d findings scored, %d reinvestigation actions",
            self._iteration,
            report.converged,
            len(contradictions),
            len(breakdowns),
            len(plan.actions),
        )

        return report

    def run_full_pipeline(
        self,
        max_iterations: int | None = None,
    ) -> list[CorrectionReport]:
        """Run the correction pipeline until convergence or iteration limit.

        This does NOT execute reinvestigation tool calls — it only plans them.
        The orchestrator (Qoder) must execute the plan and call run_iteration()
        again.

        For fully autonomous operation, use run_iteration() in a loop where
        the orchestrator executes reinvestigation actions between iterations.

        Args:
            max_iterations: Override MAX_CORRECTION_ITERATIONS if needed.

        Returns:
            List of CorrectionReports, one per iteration.
        """
        limit = max_iterations or MAX_CORRECTION_ITERATIONS
        reports: list[CorrectionReport] = []

        for _ in range(limit):
            report = self.run_iteration()
            reports.append(report)

            if report.converged:
                logger.info(
                    "Correction engine converged after %d iteration(s).",
                    len(reports),
                )
                break
        else:
            logger.warning(
                "Correction engine did NOT converge after %d iterations. "
                "Manual analyst review recommended.",
                limit,
            )

        # Final summary
        self.audit.log_correction({
            "event": "correction_pipeline_complete",
            "iterations": len(reports),
            "converged": reports[-1].converged if reports else False,
            "total_contradictions": sum(
                len(r.new_contradictions) for r in reports
            ),
        })

        return reports

    @property
    def iteration_count(self) -> int:
        """Number of iterations completed so far."""
        return self._iteration

    # -------------------------------------------------------------------
    # Pass 1: Inline Validation Summary
    # -------------------------------------------------------------------

    def _pass1_inline_validation_summary(self) -> PassResult:
        """Summarize inline validation results from tool executions.

        Validators already flagged overclaims and anomalies during tool execution.
        This pass aggregates those flags into a summary for the report.
        """
        result = PassResult(pass_number=1, pass_name="inline_validation_summary")

        # Count atoms with overclaim flags
        overclaim_count = 0
        timestomping_count = 0
        total_atoms = len(self.store.atoms)

        for atom in self.store.atoms.values():
            if atom.raw_data.get("overclaim_flags"):
                overclaim_count += 1
            if atom.raw_data.get("timestomping_detected"):
                timestomping_count += 1

        result.items_processed = total_atoms
        result.issues_found = overclaim_count + timestomping_count
        result.details = {
            "total_atoms": total_atoms,
            "atoms_with_overclaim_flags": overclaim_count,
            "timestomping_detections": timestomping_count,
        }

        logger.info(
            "Pass 1 (inline validation): %d atoms, %d overclaims, %d timestomps",
            total_atoms,
            overclaim_count,
            timestomping_count,
        )

        return result

    # -------------------------------------------------------------------
    # Pass 2: Cross-Source Contradiction Detection
    # -------------------------------------------------------------------

    def _pass2_contradiction_detection(
        self,
    ) -> tuple[PassResult, list[ContradictionRecord]]:
        """Run all 7 contradiction detectors."""
        result = PassResult(pass_number=2, pass_name="contradiction_detection")

        # Track which contradictions are NEW (not already in store)
        existing_ids = set(self.store.contradictions.keys())

        contradictions = run_all_detectors(self.store, self.audit)

        new_contradictions = [
            c for c in contradictions if c.contradiction_id not in existing_ids
        ]

        result.items_processed = len(self.store.atoms) + len(self.store.findings)
        result.issues_found = len(new_contradictions)

        # Breakdown by pattern type
        pattern_counts: dict[str, int] = {}
        for c in new_contradictions:
            key = c.pattern_type.value
            pattern_counts[key] = pattern_counts.get(key, 0) + 1

        result.details = {
            "new_contradictions": len(new_contradictions),
            "total_contradictions_in_store": len(self.store.contradictions),
            "by_pattern": pattern_counts,
        }

        logger.info(
            "Pass 2 (contradiction detection): %d new contradiction(s) found",
            len(new_contradictions),
        )

        return result, new_contradictions

    # -------------------------------------------------------------------
    # Pass 3: Confidence Scoring
    # -------------------------------------------------------------------

    def _pass3_confidence_scoring(
        self,
    ) -> tuple[PassResult, list[ConfidenceBreakdown]]:
        """Score every active finding."""
        result = PassResult(pass_number=3, pass_name="confidence_scoring")

        breakdowns = self._scorer.score_all_findings()

        result.items_processed = len(breakdowns)
        confirmed = sum(1 for b in breakdowns if b.status_action == "confirmed")
        under_review = sum(1 for b in breakdowns if b.status_action == "under_review")
        result.issues_found = under_review  # Low-confidence findings are the "issue"

        # Score distribution
        scores = [b.final_score for b in breakdowns]
        result.details = {
            "findings_scored": len(breakdowns),
            "auto_confirmed": confirmed,
            "auto_under_review": under_review,
            "score_min": min(scores) if scores else 0.0,
            "score_max": max(scores) if scores else 0.0,
            "score_avg": sum(scores) / len(scores) if scores else 0.0,
        }

        logger.info(
            "Pass 3 (confidence scoring): %d scored, %d confirmed, %d under_review",
            len(breakdowns),
            confirmed,
            under_review,
        )

        return result, breakdowns

    # -------------------------------------------------------------------
    # Pass 4: Reinvestigation Planning
    # -------------------------------------------------------------------

    def _pass4_reinvestigation_planning(self) -> tuple[PassResult, ReinvestigationPlan]:
        """Generate a plan of tool calls to resolve unresolved contradictions.

        Actions are prioritized by:
          1. Contradiction severity (CRITICAL > HIGH > MEDIUM > LOW)
          2. Pattern type (PHANTOM_ARTIFACT first since it indicates hallucination)
        """
        result = PassResult(pass_number=4, pass_name="reinvestigation_planning")
        plan = ReinvestigationPlan()

        unresolved = self.store.get_unresolved_contradictions()
        plan.total_contradictions = len(self.store.contradictions)
        plan.unresolved_count = len(unresolved)
        plan.critical_count = sum(
            1 for c in unresolved if c.severity == Severity.CRITICAL
        )

        if not unresolved:
            result.items_processed = 0
            result.issues_found = 0
            result.details = {"message": "No unresolved contradictions — no reinvestigation needed"}
            return result, plan

        # Priority ordering
        severity_priority = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
        }

        # Sort contradictions by severity then by pattern
        sorted_contradictions = sorted(
            unresolved,
            key=lambda c: (
                severity_priority.get(c.severity, 4),
                0 if c.pattern_type.value == "phantom_artifact" else 1,
            ),
        )

        # Deduplicate tool calls (same tool+params = one action)
        seen_actions: set[str] = set()
        actions: list[ReinvestigationAction] = []
        priority = 0

        for contradiction in sorted_contradictions:
            for action_spec in contradiction.reinvestigation_actions:
                tool_name = action_spec.get("tool", "")
                reason = action_spec.get("reason", "")
                params = action_spec.get("params", {})

                # Dedup key: tool + sorted params
                dedup_key = f"{tool_name}:{sorted(params.items()) if params else ''}"
                if dedup_key in seen_actions:
                    continue
                seen_actions.add(dedup_key)

                actions.append(ReinvestigationAction(
                    tool_name=tool_name,
                    reason=reason,
                    params=params,
                    priority=priority,
                    contradiction_id=contradiction.contradiction_id,
                ))
                priority += 1

        # Cap at MAX_REINVESTIGATION_TOOL_CALLS
        if len(actions) > MAX_REINVESTIGATION_TOOL_CALLS:
            actions = actions[:MAX_REINVESTIGATION_TOOL_CALLS]
            plan.capped = True

        plan.actions = actions

        result.items_processed = len(unresolved)
        result.issues_found = len(actions)
        result.details = {
            "unresolved_contradictions": len(unresolved),
            "planned_actions": len(actions),
            "capped": plan.capped,
            "critical_contradictions": plan.critical_count,
        }

        logger.info(
            "Pass 4 (reinvestigation): %d unresolved contradictions -> %d tool actions planned%s",
            len(unresolved),
            len(actions),
            " (CAPPED)" if plan.capped else "",
        )

        return result, plan

    # -------------------------------------------------------------------
    # Utility: Format plan for LLM consumption
    # -------------------------------------------------------------------

    def format_reinvestigation_for_llm(self, plan: ReinvestigationPlan) -> str:
        """Format the reinvestigation plan as structured text for the orchestrator.

        This is what gets returned to Qoder so it knows what tools to run next.
        """
        if not plan.actions:
            return (
                "SELF-CORRECTION COMPLETE: No reinvestigation needed. "
                f"All {plan.total_contradictions} contradiction(s) are resolved."
            )

        lines = [
            f"REINVESTIGATION PLAN ({len(plan.actions)} actions, "
            f"{plan.unresolved_count} unresolved contradictions, "
            f"{plan.critical_count} CRITICAL):",
            "",
        ]

        for i, action in enumerate(plan.actions, 1):
            line = f"  {i}. [{action.tool_name}]"
            if action.params:
                params_str = ", ".join(f"{k}={v}" for k, v in action.params.items())
                line += f" ({params_str})"
            line += f" — {action.reason}"
            if action.contradiction_id:
                line += f"  [resolves: {action.contradiction_id}]"
            lines.append(line)

        if plan.capped:
            lines.append("")
            lines.append(
                f"  NOTE: Action list was capped at {MAX_REINVESTIGATION_TOOL_CALLS}. "
                f"Additional actions may be needed in subsequent iterations."
            )

        return "\n".join(lines)

    # -------------------------------------------------------------------
    # Utility: Get engine status for MCP status tool
    # -------------------------------------------------------------------

    def get_status(self) -> dict:
        """Return the current state of the correction engine."""
        unresolved = self.store.get_unresolved_contradictions()
        active_findings = self.store.get_active_findings()

        confirmed = [
            f for f in active_findings if f.status == FindingStatus.CONFIRMED
        ]
        draft = [
            f for f in active_findings if f.status == FindingStatus.DRAFT
        ]
        under_review = [
            f for f in active_findings if f.status == FindingStatus.UNDER_REVIEW
        ]

        return {
            "iterations_completed": self._iteration,
            "total_atoms": len(self.store.atoms),
            "total_findings": len(self.store.findings),
            "findings_confirmed": len(confirmed),
            "findings_draft": len(draft),
            "findings_under_review": len(under_review),
            "findings_retracted": len(self.store.findings) - len(active_findings),
            "total_contradictions": len(self.store.contradictions),
            "unresolved_contradictions": len(unresolved),
            "critical_unresolved": sum(
                1 for c in unresolved if c.severity == Severity.CRITICAL
            ),
            "converged": len(unresolved) == 0 and self._iteration > 0,
        }
