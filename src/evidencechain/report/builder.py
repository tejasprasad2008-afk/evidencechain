"""Report builder — assembles structured report data from the evidence store.

Collects all findings, contradictions, timeline data, and correction engine
results into a ReportData structure that can be rendered by any template.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime

from ..enums import FindingStatus, Severity
from ..knowledge.forensic_kb import (
    CATEGORY_NARRATIVES,
    get_techniques_for_finding,
)
from ..models import ContradictionRecord, EvidenceAtom, ForensicFinding, _utcnow
from ..provenance.evidence_store import EvidenceStore

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Report data structures
# ---------------------------------------------------------------------------

@dataclass
class FindingReport:
    """One finding, fully resolved with atoms and narrative context."""

    finding_id: str = ""
    title: str = ""
    category: str = ""
    category_label: str = ""
    category_icon: str = ""
    description: str = ""
    status: str = ""
    confidence_score: float = 0.0
    evidence_type: str = ""
    narrative_prefix: str = ""
    investigation_note: str = ""
    mitre_techniques: list[dict] = field(default_factory=list)
    supporting_evidence: list[dict] = field(default_factory=list)
    contradicting_evidence: list[dict] = field(default_factory=list)
    missing_expected: list[str] = field(default_factory=list)
    revision_count: int = 0
    created_at: str = ""


@dataclass
class ContradictionReport:
    """One contradiction, formatted for reporting."""

    contradiction_id: str = ""
    pattern_type: str = ""
    severity: str = ""
    description: str = ""
    resolution: str = ""
    affected_findings: list[str] = field(default_factory=list)


@dataclass
class TimelineEntry:
    """A single event in the investigation timeline."""

    timestamp: str = ""
    source: str = ""
    description: str = ""
    artifact_type: str = ""
    severity: str = "info"


@dataclass
class CorrectionSummary:
    """Summary of self-correction engine activity."""

    iterations_completed: int = 0
    total_contradictions: int = 0
    unresolved_contradictions: int = 0
    critical_contradictions: int = 0
    findings_confirmed: int = 0
    findings_retracted: int = 0
    findings_under_review: int = 0
    converged: bool = False


@dataclass
class ReportData:
    """Complete report data, ready for template rendering."""

    # Metadata
    report_id: str = ""
    generated_at: str = ""
    evidence_sources: list[dict] = field(default_factory=list)

    # Summary statistics
    total_atoms: int = 0
    total_findings: int = 0
    total_executions: int = 0

    # Findings by status
    confirmed_findings: list[FindingReport] = field(default_factory=list)
    draft_findings: list[FindingReport] = field(default_factory=list)
    under_review_findings: list[FindingReport] = field(default_factory=list)
    retracted_findings: list[FindingReport] = field(default_factory=list)

    # Contradictions
    contradictions: list[ContradictionReport] = field(default_factory=list)

    # Timeline
    timeline: list[TimelineEntry] = field(default_factory=list)

    # Self-correction summary
    correction_summary: CorrectionSummary = field(default_factory=CorrectionSummary)

    # MITRE ATT&CK coverage
    mitre_coverage: list[dict] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Report Builder
# ---------------------------------------------------------------------------

class ReportBuilder:
    """Builds structured ReportData from the evidence store."""

    def __init__(self, store: EvidenceStore) -> None:
        self.store = store

    def build(self) -> ReportData:
        """Build the full report data structure."""
        report = ReportData(
            report_id=f"RPT-{_utcnow().replace(':', '').replace('-', '')[:15]}",
            generated_at=_utcnow(),
            total_atoms=len(self.store.atoms),
            total_findings=len(self.store.findings),
            total_executions=len(self.store.executions),
        )

        # Build finding reports by status
        for finding in self.store.findings.values():
            fr = self._build_finding_report(finding)

            if finding.status == FindingStatus.CONFIRMED:
                report.confirmed_findings.append(fr)
            elif finding.status == FindingStatus.DRAFT:
                report.draft_findings.append(fr)
            elif finding.status == FindingStatus.UNDER_REVIEW:
                report.under_review_findings.append(fr)
            elif finding.status == FindingStatus.RETRACTED:
                report.retracted_findings.append(fr)

        # Sort confirmed findings by confidence (highest first)
        report.confirmed_findings.sort(key=lambda f: f.confidence_score, reverse=True)

        # Build contradiction reports
        for contradiction in self.store.contradictions.values():
            report.contradictions.append(self._build_contradiction_report(contradiction))

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        report.contradictions.sort(
            key=lambda c: severity_order.get(c.severity, 4)
        )

        # Build timeline
        report.timeline = self._build_timeline()

        # Build correction summary
        report.correction_summary = self._build_correction_summary()

        # Build MITRE coverage
        report.mitre_coverage = self._build_mitre_coverage()

        return report

    def _build_finding_report(self, finding: ForensicFinding) -> FindingReport:
        """Convert a ForensicFinding into a FindingReport with narrative context."""
        cat_info = CATEGORY_NARRATIVES.get(finding.category.value, {})

        # Resolve supporting atoms
        supporting = []
        for atom_id in finding.supporting_atoms:
            atom = self.store.get_atom(atom_id)
            if atom:
                supporting.append({
                    "atom_id": atom.atom_id,
                    "artifact_type": atom.artifact_type.value,
                    "tool_name": atom.tool_name,
                    "proves": sorted(atom.proves),
                    "suggests": sorted(atom.suggests),
                    "file_references": atom.file_references[:5],
                    "key_data": self._extract_key_data(atom),
                })

        # Resolve contradicting atoms
        contradicting = []
        for atom_id in finding.contradicting_atoms:
            atom = self.store.get_atom(atom_id)
            if atom:
                contradicting.append({
                    "atom_id": atom.atom_id,
                    "artifact_type": atom.artifact_type.value,
                    "reason": "Contradicts finding",
                })

        # MITRE techniques
        mitre = get_techniques_for_finding(finding.mitre_attack)

        return FindingReport(
            finding_id=finding.finding_id,
            title=finding.title,
            category=finding.category.value,
            category_label=cat_info.get("label", finding.category.value),
            category_icon=cat_info.get("icon", ""),
            description=finding.description,
            status=finding.status.value,
            confidence_score=finding.confidence_score,
            evidence_type=finding.evidence_type.value,
            narrative_prefix=cat_info.get("narrative_prefix", ""),
            investigation_note=cat_info.get("investigation_note", ""),
            mitre_techniques=mitre,
            supporting_evidence=supporting,
            contradicting_evidence=contradicting,
            missing_expected=finding.missing_expected_evidence,
            revision_count=len(finding.revision_history),
            created_at=finding.created_at,
        )

    def _build_contradiction_report(self, c: ContradictionRecord) -> ContradictionReport:
        """Convert a ContradictionRecord into a report-friendly format."""
        return ContradictionReport(
            contradiction_id=c.contradiction_id,
            pattern_type=c.pattern_type.value,
            severity=c.severity.value,
            description=c.description,
            resolution=c.resolution.value,
            affected_findings=c.affected_finding_ids,
        )

    def _build_timeline(self) -> list[TimelineEntry]:
        """Build a chronological timeline from all atoms with timestamps."""
        entries: list[TimelineEntry] = []

        for atom in self.store.atoms.values():
            for ts in atom.timestamps:
                entries.append(TimelineEntry(
                    timestamp=ts.value,
                    source=atom.tool_name,
                    description=self._describe_atom(atom),
                    artifact_type=atom.artifact_type.value,
                ))

        # Sort chronologically
        entries.sort(key=lambda e: e.timestamp)
        return entries

    def _build_correction_summary(self) -> CorrectionSummary:
        """Summarize self-correction engine results."""
        unresolved = self.store.get_unresolved_contradictions()
        active = self.store.get_active_findings()

        return CorrectionSummary(
            total_contradictions=len(self.store.contradictions),
            unresolved_contradictions=len(unresolved),
            critical_contradictions=sum(
                1 for c in unresolved if c.severity == Severity.CRITICAL
            ),
            findings_confirmed=sum(
                1 for f in self.store.findings.values()
                if f.status == FindingStatus.CONFIRMED
            ),
            findings_retracted=sum(
                1 for f in self.store.findings.values()
                if f.status == FindingStatus.RETRACTED
            ),
            findings_under_review=sum(
                1 for f in self.store.findings.values()
                if f.status == FindingStatus.UNDER_REVIEW
            ),
            converged=len(unresolved) == 0,
        )

    def _build_mitre_coverage(self) -> list[dict]:
        """Aggregate MITRE ATT&CK techniques across all confirmed findings."""
        techniques: dict[str, dict] = {}

        confirmed = self.store.get_findings_by_status(FindingStatus.CONFIRMED)
        for finding in confirmed:
            for tid in finding.mitre_attack:
                if tid not in techniques:
                    from ..knowledge.forensic_kb import get_technique
                    info = get_technique(tid)
                    techniques[tid] = {
                        "id": tid,
                        "name": info["name"],
                        "tactic": info["tactic"],
                        "finding_count": 0,
                        "findings": [],
                    }
                techniques[tid]["finding_count"] += 1
                techniques[tid]["findings"].append(finding.finding_id)

        # Sort by tactic then technique ID
        return sorted(techniques.values(), key=lambda t: (t["tactic"], t["id"]))

    # -------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------

    def _extract_key_data(self, atom: EvidenceAtom) -> dict:
        """Extract the most relevant fields from an atom's raw_data for display."""
        raw = atom.raw_data
        key_fields = {}

        # Process name
        if "process_name" in raw:
            key_fields["process"] = raw["process_name"]
        if "pid" in raw:
            key_fields["pid"] = raw["pid"]

        # File info
        if "full_path" in raw:
            key_fields["path"] = raw["full_path"]
        if "sha1" in raw:
            key_fields["sha1"] = raw["sha1"][:16] + "..."
        if "sha256" in raw:
            key_fields["sha256"] = raw["sha256"][:16] + "..."

        # Event info
        if "event_id" in raw:
            key_fields["event_id"] = raw["event_id"]

        # Threat intel
        if "verdict" in raw:
            key_fields["verdict"] = raw["verdict"]

        # Flags
        if raw.get("timestomping_detected"):
            key_fields["timestomping"] = True
        if raw.get("potentially_hidden"):
            key_fields["hidden_process"] = True
        if raw.get("suspicious_patterns"):
            key_fields["suspicious_patterns"] = raw["suspicious_patterns"][:3]

        return key_fields

    def _describe_atom(self, atom: EvidenceAtom) -> str:
        """Generate a one-line description for a timeline entry."""
        raw = atom.raw_data
        atype = atom.artifact_type.value

        if "process_name" in raw:
            pid = raw.get("pid", "?")
            return f"[{atype}] Process: {raw['process_name']} (PID {pid})"

        if "event_id" in raw:
            return f"[{atype}] Event ID {raw['event_id']}"

        if "full_path" in raw:
            return f"[{atype}] File: {raw['full_path']}"

        if atom.file_references:
            return f"[{atype}] {atom.file_references[0]}"

        return f"[{atype}] {atom.tool_name}"
