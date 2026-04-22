"""Contradiction detectors for the self-correction engine.

Seven detectors that scan the evidence store for internal inconsistencies,
logical impossibilities, and forensic overclaims. Each detector produces
ContradictionRecord objects that trigger finding status changes and
potential reinvestigation.

The 7 Contradiction Patterns:
  1. TIMESTAMP_PARADOX       — Timestamps that are logically impossible
  2. EXECUTION_OVERCLAIM     — Claiming execution from presence-only evidence
  3. GHOST_PROCESS           — Process in memory with no disk execution trace
  4. TIMELINE_GAP            — Suspicious gaps in event log continuity
  5. ATTRIBUTION_MISMATCH    — Conflicting source attributions for same file
  6. ANTI_FORENSIC_INDICATOR — Evidence of tampering (timestomping, log clearing)
  7. PHANTOM_ARTIFACT        — Finding references evidence that doesn't exist

These detectors are ARCHITECTURAL, not prompt-based. They enforce forensic
correctness at the code level regardless of what the LLM believes.
"""

from __future__ import annotations

import hashlib
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone

from ..enums import (
    ArtifactType,
    ContradictionPattern,
    ContradictionResolution,
    EvidenceSemantics,
    FindingStatus,
    Severity,
)
from ..forensic_semantics import SEMANTICS_MAP
from ..models import ContradictionRecord, EvidenceAtom, ForensicFinding
from ..provenance.audit_logger import AuditLogger
from ..provenance.evidence_store import EvidenceStore
from ..validators.timestamps import parse_timestamp

logger = logging.getLogger(__name__)


class BaseDetector(ABC):
    """Base class for contradiction detectors."""

    pattern: ContradictionPattern

    def __init__(self, store: EvidenceStore, audit: AuditLogger) -> None:
        self.store = store
        self.audit = audit

    @abstractmethod
    def detect(self) -> list[ContradictionRecord]:
        """Scan the evidence store and return any contradictions found."""
        ...

    def _register(self, contradiction: ContradictionRecord) -> ContradictionRecord:
        """Register a contradiction in the store and audit log (idempotent).

        Computes a deterministic dedup key from stable fields so repeated
        detector runs don't create duplicate records for the same logical
        contradiction.
        """
        dedup_key = self._dedup_key(contradiction)

        # Check if an equivalent contradiction already exists
        for existing in self.store.contradictions.values():
            if self._dedup_key(existing) == dedup_key:
                return existing

        self.store.add_contradiction(contradiction)
        self.audit.log_contradiction(contradiction)
        return contradiction

    @staticmethod
    def _dedup_key(c: ContradictionRecord) -> str:
        """Derive a stable fingerprint from a contradiction's identifying fields."""
        parts = [
            c.pattern_type.value,
            c.atom_a_id or "",
            c.atom_b_id or "",
            ",".join(sorted(c.affected_finding_ids)),
        ]
        raw = "|".join(parts)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ==========================================================================
# Detector 1: TIMESTAMP_PARADOX
# ==========================================================================

class TimestampParadoxDetector(BaseDetector):
    """Detects logically impossible timestamp relationships.

    Examples:
    - File created AFTER it was last modified
    - Process started AFTER evidence acquisition date
    - Prefetch last-run time BEFORE the file's MFT creation time
    - Event timestamps that violate causal ordering
    """

    pattern = ContradictionPattern.TIMESTAMP_PARADOX

    def detect(self) -> list[ContradictionRecord]:
        contradictions: list[ContradictionRecord] = []

        # --- Check 1: Cross-artifact timestamp conflicts for same file ---
        # For each file referenced in multiple artifact types,
        # check that timestamps don't contradict each other.
        file_atoms = self._group_atoms_by_file()

        for file_path, atoms in file_atoms.items():
            if len(atoms) < 2:
                continue

            # Get earliest creation time from MFT
            mft_created = self._get_earliest_mft_creation(atoms)
            if mft_created is None:
                continue

            for atom in atoms:
                if atom.artifact_type == ArtifactType.MFT_ENTRY:
                    continue

                for ts in atom.timestamps:
                    ts_dt = parse_timestamp(ts.value)
                    if ts_dt is None:
                        continue

                    # Execution time before file creation = paradox
                    if ts_dt < mft_created - timedelta(seconds=5):
                        c = ContradictionRecord(
                            pattern_type=self.pattern,
                            severity=Severity.HIGH,
                            atom_a_id=atom.atom_id,
                            description=(
                                f"TIMESTAMP PARADOX: {atom.artifact_type.value} timestamp "
                                f"({ts.value}) for '{file_path}' is BEFORE the file's "
                                f"MFT creation time ({mft_created.isoformat()}). "
                                f"The file cannot have been used before it was created."
                            ),
                            reinvestigation_actions=[
                                {"tool": "parse_mft", "reason": "Re-check MFT timestamps for this file"},
                                {"tool": f"{atom.tool_name}", "reason": "Re-verify artifact timestamps"},
                            ],
                        )
                        contradictions.append(self._register(c))

        # --- Check 2: MFT $SI created > $SI modified (internal paradox) ---
        mft_atoms = self.store.get_atoms_by_type(ArtifactType.MFT_ENTRY)
        for atom in mft_atoms:
            if atom.raw_data.get("timestomping_detected"):
                # Already caught by the MFT validator; skip to avoid duplication
                continue

            si_created = atom.raw_data.get("si_created", "")
            si_modified = None
            for ts in atom.timestamps:
                if ts.source_field == "LastModified0x10":
                    si_modified = ts.value
                    break

            if si_created and si_modified:
                c_dt = parse_timestamp(si_created)
                m_dt = parse_timestamp(si_modified)
                if c_dt and m_dt and c_dt > m_dt + timedelta(seconds=2):
                    c = ContradictionRecord(
                        pattern_type=self.pattern,
                        severity=Severity.MEDIUM,
                        atom_a_id=atom.atom_id,
                        description=(
                            f"TIMESTAMP PARADOX: File '{atom.raw_data.get('full_path', '?')}' "
                            f"$SI_Created ({si_created}) is AFTER $SI_Modified ({si_modified}). "
                            f"This is physically impossible without timestamp manipulation."
                        ),
                    )
                    contradictions.append(self._register(c))

        return contradictions

    def _group_atoms_by_file(self) -> dict[str, list[EvidenceAtom]]:
        """Group atoms by their file references for cross-artifact comparison."""
        groups: dict[str, list[EvidenceAtom]] = {}
        for atom in self.store.atoms.values():
            for fref in atom.file_references:
                key = fref.lower()
                groups.setdefault(key, []).append(atom)
        return groups

    def _get_earliest_mft_creation(self, atoms: list[EvidenceAtom]) -> datetime | None:
        """Get the earliest MFT $FN_Created timestamp for a group of atoms."""
        earliest = None
        for atom in atoms:
            if atom.artifact_type != ArtifactType.MFT_ENTRY:
                continue
            fn_created = atom.raw_data.get("fn_created", "")
            if fn_created:
                dt = parse_timestamp(fn_created)
                if dt and (earliest is None or dt < earliest):
                    earliest = dt
        return earliest


# ==========================================================================
# Detector 2: EXECUTION_OVERCLAIM
# ==========================================================================

class ExecutionOverclaimDetector(BaseDetector):
    """Detects when a finding claims EXECUTION based only on PRESENCE evidence.

    Core anti-hallucination check: if a finding's category implies execution
    (e.g., MALWARE_EXECUTION) but its supporting atoms only prove PRESENCE
    (e.g., Shimcache on Win8+), this is an overclaim.
    """

    pattern = ContradictionPattern.EXECUTION_OVERCLAIM

    # Finding categories that imply execution occurred
    _EXECUTION_CATEGORIES = frozenset({
        "malware_execution",
        "lateral_movement",
        "credential_access",
        "data_exfiltration",
        "privilege_escalation",
    })

    def detect(self) -> list[ContradictionRecord]:
        contradictions: list[ContradictionRecord] = []

        for finding in self.store.get_active_findings():
            if finding.category.value not in self._EXECUTION_CATEGORIES:
                continue

            # Check if ANY supporting atom actually proves EXECUTION
            has_execution_proof = False
            presence_only_atoms: list[str] = []

            for atom_id in finding.supporting_atoms:
                atom = self.store.get_atom(atom_id)
                if atom is None:
                    continue

                if EvidenceSemantics.EXECUTION in atom.proves:
                    has_execution_proof = True
                    break

                # Check if this atom type explicitly CANNOT prove execution
                semantics = SEMANTICS_MAP.get(atom.artifact_type, {})
                if EvidenceSemantics.EXECUTION in semantics.get("cannot_prove", set()):
                    presence_only_atoms.append(atom_id)

            if not has_execution_proof and presence_only_atoms:
                c = ContradictionRecord(
                    pattern_type=self.pattern,
                    severity=Severity.CRITICAL,
                    atom_a_id=presence_only_atoms[0],
                    affected_finding_ids=[finding.finding_id],
                    description=(
                        f"EXECUTION OVERCLAIM: Finding '{finding.title}' "
                        f"(category={finding.category.value}) claims execution, but ALL "
                        f"{len(presence_only_atoms)} supporting atom(s) come from artifact "
                        f"types that CANNOT prove execution. "
                        f"Need Prefetch, Amcache, Event ID 4688, or memory evidence to confirm."
                    ),
                    reinvestigation_actions=[
                        {"tool": "parse_prefetch", "reason": "Look for execution evidence"},
                        {"tool": "parse_amcache", "reason": "Look for execution + hash"},
                        {"tool": "parse_event_logs", "params": {"event_ids": [4688]},
                         "reason": "Look for process creation events"},
                    ],
                )
                contradictions.append(self._register(c))

        return contradictions


# ==========================================================================
# Detector 3: GHOST_PROCESS
# ==========================================================================

class GhostProcessDetector(BaseDetector):
    """Detects processes found in memory with NO corresponding disk artifacts.

    A process in memory should have at least one of:
    - Prefetch entry (proves historical execution)
    - Amcache entry (proves first execution)
    - MFT entry (proves file presence on disk)
    - Event log entry (process creation 4688)

    If NONE of these exist, the process is a "ghost" — it may have been:
    - Loaded directly into memory (fileless malware)
    - Its disk artifacts were cleaned up
    - A legitimate in-memory-only process (rare)
    """

    pattern = ContradictionPattern.GHOST_PROCESS

    # Processes that legitimately have no disk artifacts
    _WHITELIST = frozenset({
        "system", "idle", "registry", "secure system",
        "memory compression", "smss.exe",
    })

    def detect(self) -> list[ContradictionRecord]:
        contradictions: list[ContradictionRecord] = []

        mem_processes = self.store.get_atoms_by_type(ArtifactType.MEMORY_PROCESS)

        for proc_atom in mem_processes:
            proc_name = proc_atom.raw_data.get("process_name", "").lower()
            if not proc_name or proc_name in self._WHITELIST:
                continue

            # Search for ANY disk artifact referencing this process
            disk_atoms = self.store.get_atoms_by_process(proc_name)

            has_disk_evidence = False
            for da in disk_atoms:
                if da.artifact_type in (
                    ArtifactType.PREFETCH,
                    ArtifactType.AMCACHE,
                    ArtifactType.SHIMCACHE,
                    ArtifactType.MFT_ENTRY,
                    ArtifactType.EVTX_EVENT,
                ):
                    has_disk_evidence = True
                    break

            if not has_disk_evidence:
                severity = Severity.HIGH
                # Hidden processes with no disk evidence are critical
                if proc_atom.raw_data.get("potentially_hidden"):
                    severity = Severity.CRITICAL

                c = ContradictionRecord(
                    pattern_type=self.pattern,
                    severity=severity,
                    atom_a_id=proc_atom.atom_id,
                    description=(
                        f"GHOST PROCESS: '{proc_atom.raw_data.get('process_name')}' "
                        f"(PID {proc_atom.raw_data.get('pid')}) found in memory but has "
                        f"NO corresponding disk artifacts (Prefetch, Amcache, Shimcache, "
                        f"MFT, or Event Logs). This may indicate fileless malware, "
                        f"artifact cleanup, or a memory-only payload."
                    ),
                    reinvestigation_actions=[
                        {"tool": "parse_prefetch", "reason": f"Search for {proc_name} in Prefetch"},
                        {"tool": "parse_amcache", "reason": f"Search for {proc_name} in Amcache"},
                        {"tool": "memory_command_lines",
                         "params": {"pid": proc_atom.raw_data.get("pid")},
                         "reason": "Get command line of ghost process"},
                        {"tool": "memory_injected_code",
                         "params": {"pid": proc_atom.raw_data.get("pid")},
                         "reason": "Check for code injection in ghost process"},
                    ],
                )
                contradictions.append(self._register(c))

        return contradictions


# ==========================================================================
# Detector 4: TIMELINE_GAP
# ==========================================================================

class TimelineGapDetector(BaseDetector):
    """Detects suspicious gaps in event log coverage.

    If there are event log atoms with a gap > 6 hours between consecutive
    events, AND there is no corresponding log-clearing event (1102/104),
    this indicates potential evidence tampering or data loss.

    If a log-clearing event IS found near the gap, the contradiction is
    RESOLVED as anti-forensics and the severity is elevated.
    """

    pattern = ContradictionPattern.TIMELINE_GAP
    _GAP_THRESHOLD = timedelta(hours=6)

    def detect(self) -> list[ContradictionRecord]:
        contradictions: list[ContradictionRecord] = []

        evtx_atoms = self.store.get_atoms_by_type(ArtifactType.EVTX_EVENT)
        if len(evtx_atoms) < 2:
            return contradictions

        # Sort events by timestamp
        timed_atoms: list[tuple[datetime, EvidenceAtom]] = []
        for atom in evtx_atoms:
            for ts in atom.timestamps:
                dt = parse_timestamp(ts.value)
                if dt:
                    timed_atoms.append((dt, atom))
                    break

        timed_atoms.sort(key=lambda x: x[0])

        # Check for log-clearing events
        log_clear_times: list[datetime] = []
        for atom in evtx_atoms:
            eid = atom.raw_data.get("event_id")
            if eid in (1102, 104):
                for ts in atom.timestamps:
                    dt = parse_timestamp(ts.value)
                    if dt:
                        log_clear_times.append(dt)
                        break

        # Detect gaps
        for i in range(1, len(timed_atoms)):
            gap = timed_atoms[i][0] - timed_atoms[i - 1][0]
            if gap <= self._GAP_THRESHOLD:
                continue

            gap_start = timed_atoms[i - 1][0]
            gap_end = timed_atoms[i][0]

            # Check if a log-clearing event is near the gap boundary
            has_clear_event = any(
                abs((ct - gap_start).total_seconds()) < 3600  # Within 1 hour
                for ct in log_clear_times
            )

            if has_clear_event:
                severity = Severity.HIGH
                resolution = ContradictionResolution.RESOLVED_ANTI_FORENSICS
                desc_suffix = (
                    "A log-clearing event (1102/104) was found near this gap. "
                    "This CONFIRMS anti-forensic activity."
                )
            else:
                severity = Severity.MEDIUM
                resolution = ContradictionResolution.UNRESOLVED
                desc_suffix = (
                    "No log-clearing event found. May indicate system "
                    "shutdown, log rotation, or selective event deletion."
                )

            c = ContradictionRecord(
                pattern_type=self.pattern,
                severity=severity,
                atom_a_id=timed_atoms[i - 1][1].atom_id,
                atom_b_id=timed_atoms[i][1].atom_id,
                description=(
                    f"TIMELINE GAP: {gap.total_seconds() / 3600:.1f}-hour gap in event logs "
                    f"from {gap_start.isoformat()} to {gap_end.isoformat()}. {desc_suffix}"
                ),
                resolution=resolution,
            )
            contradictions.append(self._register(c))

        return contradictions


# ==========================================================================
# Detector 5: ATTRIBUTION_MISMATCH
# ==========================================================================

class AttributionMismatchDetector(BaseDetector):
    """Detects conflicting metadata for the same file across sources.

    Examples:
    - SHA1 in Amcache differs from SHA1 computed from current file on disk
      (indicates file replacement after initial execution)
    - File size in MFT differs from size in Amcache
    - Contradicting publisher/version info
    """

    pattern = ContradictionPattern.ATTRIBUTION_MISMATCH

    def detect(self) -> list[ContradictionRecord]:
        contradictions: list[ContradictionRecord] = []

        # --- Check 1: Amcache SHA1 vs extracted file SHA1 ---
        amcache_atoms = self.store.get_atoms_by_type(ArtifactType.AMCACHE)
        hash_atoms = self.store.get_atoms_by_type(ArtifactType.FILE_HASH)

        for am_atom in amcache_atoms:
            am_sha1 = am_atom.raw_data.get("sha1", "").lower()
            if not am_sha1:
                continue

            am_path = am_atom.raw_data.get("full_path", "").lower()
            if not am_path:
                continue

            # Find a file hash atom for the same file
            for h_atom in hash_atoms:
                h_path = ""
                for fref in h_atom.file_references:
                    if am_path in fref.lower() or fref.lower().endswith(
                        am_path.split("\\")[-1] if "\\" in am_path else am_path
                    ):
                        h_path = fref
                        break

                if not h_path:
                    continue

                h_sha1 = h_atom.raw_data.get("sha1", "").lower()
                if h_sha1 and h_sha1 != am_sha1:
                    c = ContradictionRecord(
                        pattern_type=self.pattern,
                        severity=Severity.HIGH,
                        atom_a_id=am_atom.atom_id,
                        atom_b_id=h_atom.atom_id,
                        description=(
                            f"ATTRIBUTION MISMATCH: Amcache SHA1 ({am_sha1[:16]}...) for "
                            f"'{am_path}' differs from current file SHA1 ({h_sha1[:16]}...). "
                            f"The file has been REPLACED since Amcache recorded its first execution."
                        ),
                        reinvestigation_actions=[
                            {"tool": "compute_hashes", "reason": "Re-hash the file for confirmation"},
                            {"tool": "enrich_indicators",
                             "params": {"type": "hash_sha1", "value": am_sha1},
                             "reason": "Look up the ORIGINAL file hash in threat intel"},
                            {"tool": "enrich_indicators",
                             "params": {"type": "hash_sha1", "value": h_sha1},
                             "reason": "Look up the CURRENT file hash in threat intel"},
                        ],
                    )
                    contradictions.append(self._register(c))

        return contradictions


# ==========================================================================
# Detector 6: ANTI_FORENSIC_INDICATOR
# ==========================================================================

class AntiForensicIndicatorDetector(BaseDetector):
    """Detects evidence of active anti-forensic techniques.

    Checks for:
    - Timestomping ($SI vs $FN discrepancies already flagged by MFT validator)
    - Log clearing events (Event ID 1102, 104)
    - Presence of known anti-forensic tools in execution artifacts
    - Absence of expected artifacts (e.g., no Prefetch for a file that was
      in memory — may indicate Prefetch was disabled or cleared)
    """

    pattern = ContradictionPattern.ANTI_FORENSIC_INDICATOR

    # Known anti-forensic tool names
    _ANTI_FORENSIC_TOOLS = frozenset({
        "timestomp.exe", "timestomp", "logcleaner", "ccleaner.exe",
        "ccleaner64.exe", "sdelete.exe", "sdelete64.exe", "eraser.exe",
        "bleachbit.exe", "wevtutil.exe", "cipher.exe",
        "bcwipe.exe", "evidence-eliminator",
    })

    def detect(self) -> list[ContradictionRecord]:
        contradictions: list[ContradictionRecord] = []

        # --- Check 1: Timestomping in MFT entries ---
        mft_atoms = self.store.get_atoms_by_type(ArtifactType.MFT_ENTRY)
        timestomped_files = []
        for atom in mft_atoms:
            if atom.raw_data.get("timestomping_detected"):
                timestomped_files.append(atom)

        if timestomped_files:
            # Group all timestomped files into one contradiction
            c = ContradictionRecord(
                pattern_type=self.pattern,
                severity=Severity.HIGH,
                atom_a_id=timestomped_files[0].atom_id,
                description=(
                    f"ANTI-FORENSICS: Timestomping detected in {len(timestomped_files)} "
                    f"file(s). $STANDARD_INFO timestamps were manipulated. "
                    f"Files: {', '.join(a.raw_data.get('full_path', '?') for a in timestomped_files[:5])}"
                    + (f" (and {len(timestomped_files) - 5} more)" if len(timestomped_files) > 5 else "")
                ),
                reinvestigation_actions=[
                    {"tool": "parse_mft", "reason": "Re-examine MFT for additional timestomping"},
                ],
            )
            contradictions.append(self._register(c))

        # --- Check 2: Log clearing events ---
        evtx_atoms = self.store.get_atoms_by_type(ArtifactType.EVTX_EVENT)
        log_clears = [
            a for a in evtx_atoms if a.raw_data.get("event_id") in (1102, 104)
        ]
        if log_clears:
            c = ContradictionRecord(
                pattern_type=self.pattern,
                severity=Severity.HIGH,
                atom_a_id=log_clears[0].atom_id,
                description=(
                    f"ANTI-FORENSICS: {len(log_clears)} log clearing event(s) detected "
                    f"(Event IDs 1102/104). Security or System logs were intentionally cleared. "
                    f"Evidence from the cleared period may be permanently lost."
                ),
            )
            contradictions.append(self._register(c))

        # --- Check 3: Known anti-forensic tools in execution artifacts ---
        for tool_name in self._ANTI_FORENSIC_TOOLS:
            tool_atoms = self.store.get_atoms_by_process(tool_name)
            exec_atoms = [
                a for a in tool_atoms
                if a.artifact_type in (
                    ArtifactType.PREFETCH, ArtifactType.AMCACHE,
                    ArtifactType.EVTX_EVENT, ArtifactType.MEMORY_PROCESS,
                )
            ]
            if exec_atoms:
                c = ContradictionRecord(
                    pattern_type=self.pattern,
                    severity=Severity.CRITICAL,
                    atom_a_id=exec_atoms[0].atom_id,
                    description=(
                        f"ANTI-FORENSICS: Known anti-forensic tool '{tool_name}' found "
                        f"in execution artifacts ({exec_atoms[0].artifact_type.value}). "
                        f"Other artifacts on this system may have been tampered with."
                    ),
                    reinvestigation_actions=[
                        {"tool": "parse_prefetch",
                         "reason": f"Check execution frequency of {tool_name}"},
                        {"tool": "get_filesystem_timeline",
                         "reason": "Check filesystem activity around the anti-forensic tool's execution"},
                    ],
                )
                contradictions.append(self._register(c))

        return contradictions


# ==========================================================================
# Detector 7: PHANTOM_ARTIFACT (Hallucination Catcher)
# ==========================================================================

class PhantomArtifactDetector(BaseDetector):
    """Detects findings that reference non-existent evidence atoms.

    This is the HALLUCINATION CATCHER. If the LLM creates a finding that
    claims to be supported by atom IDs that don't exist in the store,
    the finding is immediately flagged and put UNDER_REVIEW.

    Also checks for findings with zero supporting atoms.
    """

    pattern = ContradictionPattern.PHANTOM_ARTIFACT

    def detect(self) -> list[ContradictionRecord]:
        contradictions: list[ContradictionRecord] = []

        for finding in self.store.findings.values():
            if finding.status == FindingStatus.RETRACTED:
                continue

            # --- Check 1: References to non-existent atoms ---
            phantom_ids = [
                aid for aid in finding.supporting_atoms
                if aid not in self.store.atoms
            ]

            if phantom_ids:
                c = ContradictionRecord(
                    pattern_type=self.pattern,
                    severity=Severity.CRITICAL,
                    affected_finding_ids=[finding.finding_id],
                    description=(
                        f"PHANTOM ARTIFACT: Finding '{finding.title}' references "
                        f"{len(phantom_ids)} non-existent atom ID(s): "
                        f"{', '.join(phantom_ids[:5])}. "
                        f"These atoms were never produced by any tool execution. "
                        f"This is likely an LLM hallucination."
                    ),
                )
                contradictions.append(self._register(c))

                # Immediately put finding under review
                self.store.update_finding_status(
                    finding.finding_id,
                    FindingStatus.UNDER_REVIEW,
                    reason=f"Phantom artifact detected: {len(phantom_ids)} non-existent atom(s)",
                    contradiction_id=c.contradiction_id,
                )

            # --- Check 2: Findings with zero supporting atoms ---
            if not finding.supporting_atoms:
                c = ContradictionRecord(
                    pattern_type=self.pattern,
                    severity=Severity.HIGH,
                    affected_finding_ids=[finding.finding_id],
                    description=(
                        f"PHANTOM ARTIFACT: Finding '{finding.title}' has ZERO supporting "
                        f"atoms. Every finding must be backed by at least one evidence atom "
                        f"produced by a tool execution."
                    ),
                )
                contradictions.append(self._register(c))

                self.store.update_finding_status(
                    finding.finding_id,
                    FindingStatus.UNDER_REVIEW,
                    reason="Finding has zero supporting atoms",
                    contradiction_id=c.contradiction_id,
                )

        return contradictions


# ==========================================================================
# Detector Registry
# ==========================================================================

ALL_DETECTORS: list[type[BaseDetector]] = [
    TimestampParadoxDetector,
    ExecutionOverclaimDetector,
    GhostProcessDetector,
    TimelineGapDetector,
    AttributionMismatchDetector,
    AntiForensicIndicatorDetector,
    PhantomArtifactDetector,
]


def run_all_detectors(
    store: EvidenceStore,
    audit: AuditLogger,
) -> list[ContradictionRecord]:
    """Instantiate and run all 7 detectors. Return all contradictions found."""
    all_contradictions: list[ContradictionRecord] = []

    for detector_cls in ALL_DETECTORS:
        detector = detector_cls(store, audit)
        try:
            found = detector.detect()
            if found:
                logger.info(
                    "%s: found %d contradiction(s)",
                    detector_cls.__name__,
                    len(found),
                )
            all_contradictions.extend(found)
        except Exception:
            logger.exception("Error in detector %s", detector_cls.__name__)

    logger.info(
        "Self-correction scan complete: %d total contradiction(s) across %d detectors",
        len(all_contradictions),
        len(ALL_DETECTORS),
    )
    return all_contradictions
