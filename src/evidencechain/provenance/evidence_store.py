"""Central evidence store with indexes and JSONL persistence.

This is the single source of truth for all evidence atoms, findings,
contradictions, and tool executions during an investigation. Every other
module reads from and writes to this store.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from ..config import ANALYSIS_DIR
from ..enums import ArtifactType, FindingStatus
from ..models import (
    ContradictionRecord,
    EvidenceAtom,
    FindingRevision,
    ForensicFinding,
    ToolExecution,
    _utcnow,
)

logger = logging.getLogger(__name__)


class EvidenceStore:
    """In-memory evidence store with JSONL persistence and indexes."""

    def __init__(self, persist_path: Path | None = None) -> None:
        self._persist_path = persist_path or (ANALYSIS_DIR / "evidence_chain.jsonl")

        # Primary storage
        self.atoms: dict[str, EvidenceAtom] = {}
        self.findings: dict[str, ForensicFinding] = {}
        self.contradictions: dict[str, ContradictionRecord] = {}
        self.executions: dict[str, ToolExecution] = {}

        # Indexes for fast cross-referencing
        self._atoms_by_file: dict[str, list[str]] = {}
        self._atoms_by_process: dict[str, list[str]] = {}
        self._atoms_by_artifact_type: dict[ArtifactType, list[str]] = {}
        self._atoms_by_execution: dict[str, list[str]] = {}

    # -------------------------------------------------------------------
    # Atom operations
    # -------------------------------------------------------------------

    def add_atom(self, atom: EvidenceAtom) -> str:
        """Add an evidence atom to the store and update indexes."""
        self.atoms[atom.atom_id] = atom

        # Index by file references
        for fref in atom.file_references:
            self._atoms_by_file.setdefault(fref.lower(), []).append(atom.atom_id)

        # Index by artifact type
        self._atoms_by_artifact_type.setdefault(atom.artifact_type, []).append(
            atom.atom_id
        )

        # Index by execution ID
        if atom.execution_id:
            self._atoms_by_execution.setdefault(atom.execution_id, []).append(
                atom.atom_id
            )

        # Index by process name (extract from raw_data if present)
        process_name = atom.raw_data.get("process_name", "").lower()
        if process_name:
            self._atoms_by_process.setdefault(process_name, []).append(atom.atom_id)

        # Also index by filename from file_references
        for fref in atom.file_references:
            fname = Path(fref).name.lower()
            if fname:
                self._atoms_by_process.setdefault(fname, []).append(atom.atom_id)

        logger.debug("Added atom %s (type=%s)", atom.atom_id, atom.artifact_type)
        return atom.atom_id

    def add_atoms(self, atoms: list[EvidenceAtom]) -> list[str]:
        """Add multiple atoms and return their IDs."""
        return [self.add_atom(a) for a in atoms]

    def get_atom(self, atom_id: str) -> EvidenceAtom | None:
        """Get an atom by ID."""
        return self.atoms.get(atom_id)

    def get_atoms_by_type(self, artifact_type: ArtifactType) -> list[EvidenceAtom]:
        """Get all atoms of a given artifact type."""
        ids = self._atoms_by_artifact_type.get(artifact_type, [])
        return [self.atoms[aid] for aid in ids if aid in self.atoms]

    def get_atoms_by_file(self, file_path: str) -> list[EvidenceAtom]:
        """Get all atoms referencing a file path (case-insensitive)."""
        ids = self._atoms_by_file.get(file_path.lower(), [])
        return [self.atoms[aid] for aid in ids if aid in self.atoms]

    def get_atoms_by_process(self, process_name: str) -> list[EvidenceAtom]:
        """Get all atoms referencing a process name (case-insensitive)."""
        ids = self._atoms_by_process.get(process_name.lower(), [])
        return [self.atoms[aid] for aid in ids if aid in self.atoms]

    def get_atoms_by_execution(self, execution_id: str) -> list[EvidenceAtom]:
        """Get all atoms produced by a specific tool execution."""
        ids = self._atoms_by_execution.get(execution_id, [])
        return [self.atoms[aid] for aid in ids if aid in self.atoms]

    # -------------------------------------------------------------------
    # Finding operations
    # -------------------------------------------------------------------

    def add_finding(self, finding: ForensicFinding) -> str:
        """Register a new finding in the store.

        All supporting_atoms must exist in the store. Returns finding_id.
        Raises ValueError if any supporting atom is missing.
        """
        missing = [
            aid for aid in finding.supporting_atoms if aid not in self.atoms
        ]
        if missing:
            raise ValueError(
                f"Cannot register finding '{finding.title}': "
                f"supporting atoms not in store: {missing}"
            )

        self.findings[finding.finding_id] = finding
        logger.info(
            "Registered finding %s: %s (status=%s, confidence=%.2f)",
            finding.finding_id,
            finding.title,
            finding.status.value,
            finding.confidence_score,
        )
        return finding.finding_id

    def update_finding_status(
        self,
        finding_id: str,
        new_status: FindingStatus,
        reason: str,
        contradiction_id: str | None = None,
    ) -> None:
        """Update a finding's status with an audit trail entry."""
        finding = self.findings.get(finding_id)
        if not finding:
            logger.warning("Finding %s not found for status update.", finding_id)
            return

        old_status = finding.status
        finding.status = new_status
        finding.revision_history.append(
            FindingRevision(
                from_status=old_status.value,
                to_status=new_status.value,
                reason=reason,
                contradiction_id=contradiction_id,
            )
        )
        logger.info(
            "Finding %s: %s -> %s (%s)",
            finding_id,
            old_status.value,
            new_status.value,
            reason,
        )

    def get_findings_by_status(self, status: FindingStatus) -> list[ForensicFinding]:
        """Get all findings with a given status."""
        return [f for f in self.findings.values() if f.status == status]

    def get_active_findings(self) -> list[ForensicFinding]:
        """Get all non-retracted findings."""
        return [
            f
            for f in self.findings.values()
            if f.status != FindingStatus.RETRACTED
        ]

    # -------------------------------------------------------------------
    # Contradiction operations
    # -------------------------------------------------------------------

    def add_contradiction(self, contradiction: ContradictionRecord) -> str:
        """Register a detected contradiction."""
        self.contradictions[contradiction.contradiction_id] = contradiction
        logger.info(
            "Detected contradiction %s: %s (severity=%s)",
            contradiction.contradiction_id,
            contradiction.pattern_type.value,
            contradiction.severity.value,
        )
        return contradiction.contradiction_id

    def get_unresolved_contradictions(self) -> list[ContradictionRecord]:
        """Get all unresolved contradictions."""
        from ..enums import ContradictionResolution

        return [
            c
            for c in self.contradictions.values()
            if c.resolution == ContradictionResolution.UNRESOLVED
        ]

    # -------------------------------------------------------------------
    # Execution operations
    # -------------------------------------------------------------------

    def add_execution(self, execution: ToolExecution) -> str:
        """Record a tool execution."""
        self.executions[execution.execution_id] = execution
        return execution.execution_id

    def get_execution(self, execution_id: str) -> ToolExecution | None:
        """Get a tool execution by ID."""
        return self.executions.get(execution_id)

    # -------------------------------------------------------------------
    # Persistence
    # -------------------------------------------------------------------

    def persist(self) -> None:
        """Save the entire store to a JSONL file for crash recovery and audit."""
        self._persist_path.parent.mkdir(parents=True, exist_ok=True)

        def _serialize(obj: object) -> dict:
            from dataclasses import asdict

            d = asdict(obj)
            for k, v in d.items():
                if isinstance(v, set):
                    d[k] = sorted(v)
            return d

        with open(self._persist_path, "w", encoding="utf-8") as f:
            for atom in self.atoms.values():
                record = {"_type": "atom", **_serialize(atom)}
                f.write(json.dumps(record, default=str) + "\n")

            for finding in self.findings.values():
                record = {"_type": "finding", **_serialize(finding)}
                f.write(json.dumps(record, default=str) + "\n")

            for contradiction in self.contradictions.values():
                record = {"_type": "contradiction", **_serialize(contradiction)}
                f.write(json.dumps(record, default=str) + "\n")

            for execution in self.executions.values():
                record = {"_type": "execution", **_serialize(execution)}
                f.write(json.dumps(record, default=str) + "\n")

        logger.info(
            "Persisted store: %d atoms, %d findings, %d contradictions, %d executions -> %s",
            len(self.atoms),
            len(self.findings),
            len(self.contradictions),
            len(self.executions),
            self._persist_path,
        )

    # -------------------------------------------------------------------
    # Statistics
    # -------------------------------------------------------------------

    def summary(self) -> dict:
        """Return a summary of the store's contents."""
        return {
            "total_atoms": len(self.atoms),
            "total_findings": len(self.findings),
            "total_contradictions": len(self.contradictions),
            "total_executions": len(self.executions),
            "findings_by_status": {
                status.value: len(self.get_findings_by_status(status))
                for status in FindingStatus
            },
            "atoms_by_type": {
                at.value: len(ids)
                for at, ids in self._atoms_by_artifact_type.items()
            },
        }
