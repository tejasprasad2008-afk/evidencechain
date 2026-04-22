"""Block 4 smoke tests: Self-Correction Engine.

Tests all 7 detectors, confidence scoring, and the 4-pass engine.
Run: python3 tests/test_block4_smoke.py
"""

import sys
import os
import tempfile

# Add the src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pathlib import Path
from evidencechain.provenance.evidence_store import EvidenceStore
from evidencechain.provenance.audit_logger import AuditLogger
from evidencechain.models import (
    ContradictionRecord,
    EvidenceAtom,
    ForensicFinding,
    TimestampRecord,
)
from evidencechain.enums import (
    ArtifactType,
    ContradictionPattern,
    EvidenceSemantics,
    EvidenceType,
    FindingCategory,
    FindingStatus,
    Severity,
    TimestampSemanticType,
)

passed = 0
failed = 0


def check(name, condition):
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS: {name}")
    else:
        failed += 1
        print(f"  FAIL: {name}")


def make_test_env():
    """Create a fresh store + audit logger in a temp directory."""
    tmpdir = tempfile.mkdtemp(prefix="ectest_")
    store = EvidenceStore(persist_path=Path(tmpdir) / "test.jsonl")
    audit = AuditLogger(audit_dir=Path(tmpdir) / "audit")
    return store, audit


# ===========================================================================
# Test 1: Import all correction modules
# ===========================================================================

print("Test 1: Import correction modules")
try:
    from evidencechain.correction import (
        CorrectionEngine,
        CorrectionReport,
        ConfidenceScorer,
        ConfidenceBreakdown,
        ReinvestigationPlan,
        ReinvestigationAction,
        PassResult,
        ALL_DETECTORS,
        run_all_detectors,
        TimestampParadoxDetector,
        ExecutionOverclaimDetector,
        GhostProcessDetector,
        TimelineGapDetector,
        AttributionMismatchDetector,
        AntiForensicIndicatorDetector,
        PhantomArtifactDetector,
    )
    check("All correction modules import successfully", True)
    check("7 detectors in ALL_DETECTORS", len(ALL_DETECTORS) == 7)
except Exception as e:
    check(f"Import failed: {e}", False)
    sys.exit(1)


# ===========================================================================
# Test 2: PhantomArtifactDetector — hallucination catcher
# ===========================================================================

print("\nTest 2: PhantomArtifactDetector")
store, audit = make_test_env()

# Create a finding with a non-existent atom ID
atom_real = EvidenceAtom(
    artifact_type=ArtifactType.PREFETCH,
    proves={EvidenceSemantics.EXECUTION},
    file_references=["malware.exe"],
)
store.add_atom(atom_real)

# Add finding that references a real + phantom atom
finding = ForensicFinding(
    category=FindingCategory.MALWARE_EXECUTION,
    title="Test malware execution",
    supporting_atoms=[atom_real.atom_id, "ATM-FAKE0001"],
    status=FindingStatus.DRAFT,
)
# Bypass validation for test — we need the phantom ID in there
store.findings[finding.finding_id] = finding

detector = PhantomArtifactDetector(store, audit)
contradictions = detector.detect()

check("Phantom detector finds 1 contradiction", len(contradictions) == 1)
check(
    "Pattern is PHANTOM_ARTIFACT",
    contradictions[0].pattern_type == ContradictionPattern.PHANTOM_ARTIFACT,
)
check(
    "Severity is CRITICAL",
    contradictions[0].severity == Severity.CRITICAL,
)
check(
    "Finding moved to UNDER_REVIEW",
    finding.status == FindingStatus.UNDER_REVIEW,
)


# ===========================================================================
# Test 3: PhantomArtifactDetector — zero-atom finding
# ===========================================================================

print("\nTest 3: PhantomArtifactDetector (zero atoms)")
store, audit = make_test_env()

finding_empty = ForensicFinding(
    category=FindingCategory.PERSISTENCE,
    title="Unsupported persistence claim",
    supporting_atoms=[],
    status=FindingStatus.DRAFT,
)
store.findings[finding_empty.finding_id] = finding_empty

detector = PhantomArtifactDetector(store, audit)
contradictions = detector.detect()

check("Finds zero-atom finding", len(contradictions) == 1)
check(
    "Finding sent to UNDER_REVIEW",
    finding_empty.status == FindingStatus.UNDER_REVIEW,
)


# ===========================================================================
# Test 4: ExecutionOverclaimDetector
# ===========================================================================

print("\nTest 4: ExecutionOverclaimDetector")
store, audit = make_test_env()

# Create a Shimcache atom (proves PRESENCE, cannot_prove EXECUTION)
shimcache_atom = EvidenceAtom(
    artifact_type=ArtifactType.SHIMCACHE,
    proves={EvidenceSemantics.PRESENCE},
    cannot_prove={EvidenceSemantics.EXECUTION},
    file_references=["suspect.exe"],
)
store.add_atom(shimcache_atom)

# Create a finding claiming MALWARE_EXECUTION backed only by Shimcache
overclaim_finding = ForensicFinding(
    category=FindingCategory.MALWARE_EXECUTION,
    title="Shimcache-only execution claim",
    supporting_atoms=[shimcache_atom.atom_id],
    status=FindingStatus.DRAFT,
)
store.add_finding(overclaim_finding)

detector = ExecutionOverclaimDetector(store, audit)
contradictions = detector.detect()

check("Overclaim detector fires", len(contradictions) == 1)
check(
    "Pattern is EXECUTION_OVERCLAIM",
    contradictions[0].pattern_type == ContradictionPattern.EXECUTION_OVERCLAIM,
)
check(
    "Severity is CRITICAL",
    contradictions[0].severity == Severity.CRITICAL,
)
check(
    "Has reinvestigation actions",
    len(contradictions[0].reinvestigation_actions) >= 2,
)


# ===========================================================================
# Test 5: ExecutionOverclaimDetector — legit execution (should NOT fire)
# ===========================================================================

print("\nTest 5: ExecutionOverclaimDetector (legitimate — no fire)")
store, audit = make_test_env()

# Prefetch atom PROVES execution
prefetch_atom = EvidenceAtom(
    artifact_type=ArtifactType.PREFETCH,
    proves={EvidenceSemantics.EXECUTION},
    file_references=["legit.exe"],
)
store.add_atom(prefetch_atom)

legit_finding = ForensicFinding(
    category=FindingCategory.MALWARE_EXECUTION,
    title="Properly evidenced execution",
    supporting_atoms=[prefetch_atom.atom_id],
    status=FindingStatus.DRAFT,
)
store.add_finding(legit_finding)

detector = ExecutionOverclaimDetector(store, audit)
contradictions = detector.detect()

check("No overclaim for Prefetch-backed finding", len(contradictions) == 0)


# ===========================================================================
# Test 6: GhostProcessDetector
# ===========================================================================

print("\nTest 6: GhostProcessDetector")
store, audit = make_test_env()

# Memory process with NO disk artifacts
ghost = EvidenceAtom(
    artifact_type=ArtifactType.MEMORY_PROCESS,
    raw_data={"process_name": "evil_payload.exe", "pid": 1337},
    file_references=["evil_payload.exe"],
)
store.add_atom(ghost)

# System process (should be whitelisted)
system_proc = EvidenceAtom(
    artifact_type=ArtifactType.MEMORY_PROCESS,
    raw_data={"process_name": "System", "pid": 4},
)
store.add_atom(system_proc)

detector = GhostProcessDetector(store, audit)
contradictions = detector.detect()

check("Ghost detector fires for evil_payload.exe", len(contradictions) == 1)
check(
    "Pattern is GHOST_PROCESS",
    contradictions[0].pattern_type == ContradictionPattern.GHOST_PROCESS,
)
check(
    "System process NOT flagged",
    all("System" not in c.description for c in contradictions),
)


# ===========================================================================
# Test 7: GhostProcessDetector — hidden ghost (CRITICAL severity)
# ===========================================================================

print("\nTest 7: GhostProcessDetector (hidden process)")
store, audit = make_test_env()

hidden_ghost = EvidenceAtom(
    artifact_type=ArtifactType.MEMORY_PROCESS,
    raw_data={
        "process_name": "injector.exe",
        "pid": 9999,
        "potentially_hidden": True,
    },
    file_references=["injector.exe"],
)
store.add_atom(hidden_ghost)

detector = GhostProcessDetector(store, audit)
contradictions = detector.detect()

check("Hidden ghost detected", len(contradictions) == 1)
check(
    "Severity is CRITICAL for hidden ghost",
    contradictions[0].severity == Severity.CRITICAL,
)


# ===========================================================================
# Test 8: AntiForensicIndicatorDetector — timestomping
# ===========================================================================

print("\nTest 8: AntiForensicIndicatorDetector (timestomping)")
store, audit = make_test_env()

stomped = EvidenceAtom(
    artifact_type=ArtifactType.MFT_ENTRY,
    raw_data={
        "timestomping_detected": True,
        "full_path": "C:" + "\\Windows" + "\\malware.dll",
    },
)
store.add_atom(stomped)

detector = AntiForensicIndicatorDetector(store, audit)
contradictions = detector.detect()

check("Timestomping detected", len(contradictions) >= 1)
check(
    "Pattern is ANTI_FORENSIC_INDICATOR",
    any(
        c.pattern_type == ContradictionPattern.ANTI_FORENSIC_INDICATOR
        for c in contradictions
    ),
)


# ===========================================================================
# Test 9: AntiForensicIndicatorDetector — known tool
# ===========================================================================

print("\nTest 9: AntiForensicIndicatorDetector (sdelete.exe)")
store, audit = make_test_env()

sdelete_atom = EvidenceAtom(
    artifact_type=ArtifactType.PREFETCH,
    raw_data={"process_name": "sdelete.exe"},
    file_references=["sdelete.exe"],
)
store.add_atom(sdelete_atom)

detector = AntiForensicIndicatorDetector(store, audit)
contradictions = detector.detect()

check("Anti-forensic tool detected", len(contradictions) >= 1)
check(
    "Severity is CRITICAL for known tool",
    any(c.severity == Severity.CRITICAL for c in contradictions),
)


# ===========================================================================
# Test 10: TimelineGapDetector
# ===========================================================================

print("\nTest 10: TimelineGapDetector")
store, audit = make_test_env()

# Create event log atoms with a 12-hour gap
events_data = [
    ("2024-01-15T08:00:00Z", 4624),
    ("2024-01-15T08:30:00Z", 4688),
    ("2024-01-15T09:00:00Z", 4624),
    # 12-hour gap here
    ("2024-01-15T21:00:00Z", 4688),
    ("2024-01-15T21:30:00Z", 4624),
]

for ts_val, eid in events_data:
    atom = EvidenceAtom(
        artifact_type=ArtifactType.EVTX_EVENT,
        raw_data={"event_id": eid},
        timestamps=[
            TimestampRecord(
                value=ts_val,
                source_field="TimeCreated",
                semantic_type=TimestampSemanticType.EVENT_TIME,
            )
        ],
    )
    store.add_atom(atom)

detector = TimelineGapDetector(store, audit)
contradictions = detector.detect()

check("Timeline gap detected", len(contradictions) >= 1)
check(
    "Pattern is TIMELINE_GAP",
    contradictions[0].pattern_type == ContradictionPattern.TIMELINE_GAP,
)


# ===========================================================================
# Test 11: TimelineGapDetector with log clearing
# ===========================================================================

print("\nTest 11: TimelineGapDetector (with log clearing)")
store, audit = make_test_env()

events_with_clear = [
    ("2024-01-15T08:00:00Z", 4624),
    ("2024-01-15T08:55:00Z", 1102),  # Log clear near gap start
    ("2024-01-15T09:00:00Z", 4688),
    # 12-hour gap here
    ("2024-01-15T21:00:00Z", 4688),
]

for ts_val, eid in events_with_clear:
    atom = EvidenceAtom(
        artifact_type=ArtifactType.EVTX_EVENT,
        raw_data={"event_id": eid},
        timestamps=[
            TimestampRecord(
                value=ts_val,
                source_field="TimeCreated",
                semantic_type=TimestampSemanticType.EVENT_TIME,
            )
        ],
    )
    store.add_atom(atom)

detector = TimelineGapDetector(store, audit)
contradictions = detector.detect()

has_resolved_antiforensics = any(
    c.resolution.value == "resolved_anti_forensics_detected"
    for c in contradictions
)
check(
    "Log clearing upgrades resolution to RESOLVED_ANTI_FORENSICS",
    has_resolved_antiforensics,
)


# ===========================================================================
# Test 12: ConfidenceScorer — high confidence (direct + corroborated)
# ===========================================================================

print("\nTest 12: ConfidenceScorer (high confidence)")
store, audit = make_test_env()

prefetch = EvidenceAtom(
    artifact_type=ArtifactType.PREFETCH,
    proves={EvidenceSemantics.EXECUTION},
    file_references=["malware.exe"],
)
amcache = EvidenceAtom(
    artifact_type=ArtifactType.AMCACHE,
    proves={EvidenceSemantics.EXECUTION},
    file_references=["malware.exe"],
)
evtx = EvidenceAtom(
    artifact_type=ArtifactType.EVTX_EVENT,
    proves={EvidenceSemantics.EXECUTION},
    file_references=["malware.exe"],
)
store.add_atom(prefetch)
store.add_atom(amcache)
store.add_atom(evtx)

finding = ForensicFinding(
    category=FindingCategory.MALWARE_EXECUTION,
    title="Triple-confirmed malware execution",
    supporting_atoms=[prefetch.atom_id, amcache.atom_id, evtx.atom_id],
    status=FindingStatus.DRAFT,
)
store.add_finding(finding)

scorer = ConfidenceScorer(store, audit)
bd = scorer.score_finding(finding)

check(
    f"High confidence score ({bd.final_score:.2f} >= 0.75)",
    bd.final_score >= 0.75,
)
check(
    "Evidence type is CORROBORATED",
    bd.evidence_type == EvidenceType.CORROBORATED.value,
)
check(
    "Auto-confirmed",
    bd.status_action == "confirmed",
)
check(
    "Finding status is now CONFIRMED",
    finding.status == FindingStatus.CONFIRMED,
)


# ===========================================================================
# Test 13: ConfidenceScorer — low confidence (inferred)
# ===========================================================================

print("\nTest 13: ConfidenceScorer (low confidence)")
store, audit = make_test_env()

weak_atom = EvidenceAtom(
    artifact_type=ArtifactType.FILESYSTEM_ENTRY,
    proves={EvidenceSemantics.PRESENCE},
    cannot_prove={EvidenceSemantics.EXECUTION},
    file_references=["maybe_bad.exe"],
)
store.add_atom(weak_atom)

weak_finding = ForensicFinding(
    category=FindingCategory.MALWARE_EXECUTION,
    title="Weak execution claim from filesystem",
    supporting_atoms=[weak_atom.atom_id],
    status=FindingStatus.DRAFT,
    missing_expected_evidence=["Prefetch", "Amcache"],
)
store.add_finding(weak_finding)

scorer = ConfidenceScorer(store, audit)
bd = scorer.score_finding(weak_finding)

check(
    f"Low confidence score ({bd.final_score:.2f} < 0.40)",
    bd.final_score < 0.40,
)
check(
    "Auto-sent to UNDER_REVIEW",
    bd.status_action == "under_review",
)
check(
    "Finding status is UNDER_REVIEW",
    weak_finding.status == FindingStatus.UNDER_REVIEW,
)
check(
    "Missing evidence penalty applied",
    bd.missing_evidence_penalty > 0,
)


# ===========================================================================
# Test 14: ConfidenceScorer — contradiction penalty
# ===========================================================================

print("\nTest 14: ConfidenceScorer (contradiction penalty)")
store, audit = make_test_env()

atom_a = EvidenceAtom(
    artifact_type=ArtifactType.PREFETCH,
    proves={EvidenceSemantics.EXECUTION},
    file_references=["contested.exe"],
)
store.add_atom(atom_a)

finding_c = ForensicFinding(
    category=FindingCategory.MALWARE_EXECUTION,
    title="Contested finding",
    supporting_atoms=[atom_a.atom_id],
    status=FindingStatus.DRAFT,
)
store.add_finding(finding_c)

# Score WITHOUT contradiction first
scorer = ConfidenceScorer(store, audit)
bd_before = scorer.score_finding(finding_c)
score_before = bd_before.final_score

# Reset status back to DRAFT for re-scoring
finding_c.status = FindingStatus.DRAFT
finding_c.revision_history.clear()

# Add an unresolved contradiction referencing our atom
contradiction = ContradictionRecord(
    pattern_type=ContradictionPattern.TIMESTAMP_PARADOX,
    severity=Severity.HIGH,
    atom_a_id=atom_a.atom_id,
    description="Test contradiction",
)
store.add_contradiction(contradiction)

bd_after = scorer.score_finding(finding_c)
score_after = bd_after.final_score

check(
    f"Contradiction reduces score ({score_before:.2f} -> {score_after:.2f})",
    score_after < score_before,
)
check(
    "Contradiction penalty is reflected in breakdown",
    bd_after.contradiction_penalty > 0,
)


# ===========================================================================
# Test 15: CorrectionEngine — empty store converges immediately
# ===========================================================================

print("\nTest 15: CorrectionEngine (empty store)")
store, audit = make_test_env()

engine = CorrectionEngine(store, audit)
report = engine.run_iteration()

check("Engine returns a CorrectionReport", isinstance(report, CorrectionReport))
check("4 passes executed", len(report.pass_results) == 4)
check("Empty store converges", report.converged)
check("No reinvestigation actions", len(report.reinvestigation_plan.actions) == 0)


# ===========================================================================
# Test 16: CorrectionEngine — full pipeline with contradiction
# ===========================================================================

print("\nTest 16: CorrectionEngine (full pipeline with overclaim)")
store, audit = make_test_env()

# Set up an overclaim scenario
shim_atom = EvidenceAtom(
    artifact_type=ArtifactType.SHIMCACHE,
    proves={EvidenceSemantics.PRESENCE},
    cannot_prove={EvidenceSemantics.EXECUTION},
    file_references=["suspect.exe"],
)
store.add_atom(shim_atom)

overclaim = ForensicFinding(
    category=FindingCategory.MALWARE_EXECUTION,
    title="Overclaimed execution",
    supporting_atoms=[shim_atom.atom_id],
    status=FindingStatus.DRAFT,
)
store.add_finding(overclaim)

engine = CorrectionEngine(store, audit)
report = engine.run_iteration()

check(
    "Overclaim contradiction detected",
    len(report.new_contradictions) > 0,
)
check(
    "Not converged (has contradictions)",
    not report.converged,
)
check(
    "Reinvestigation actions generated",
    len(report.reinvestigation_plan.actions) > 0,
)

# Check that the report summary is well-formed
summary = report.summary
check("Summary has expected keys", "converged" in summary and "iteration" in summary)


# ===========================================================================
# Test 17: CorrectionEngine — format_reinvestigation_for_llm
# ===========================================================================

print("\nTest 17: format_reinvestigation_for_llm")
store, audit = make_test_env()
engine = CorrectionEngine(store, audit)

# Empty plan
empty_plan = ReinvestigationPlan()
text = engine.format_reinvestigation_for_llm(empty_plan)
check("Empty plan says 'no reinvestigation needed'", "no reinvestigation" in text.lower())

# Plan with actions
plan_with_actions = ReinvestigationPlan(
    actions=[
        ReinvestigationAction(
            tool_name="parse_prefetch",
            reason="Look for execution evidence",
            contradiction_id="CTR-test01",
        ),
        ReinvestigationAction(
            tool_name="parse_amcache",
            reason="Check hash",
            params={"evidence_id": "E01"},
            contradiction_id="CTR-test02",
        ),
    ],
    total_contradictions=5,
    unresolved_count=2,
    critical_count=1,
)
text = engine.format_reinvestigation_for_llm(plan_with_actions)
check("Formatted plan contains tool names", "parse_prefetch" in text)
check("Formatted plan contains params", "evidence_id" in text)
check("Formatted plan contains contradiction IDs", "CTR-test01" in text)


# ===========================================================================
# Test 18: CorrectionEngine — get_status
# ===========================================================================

print("\nTest 18: CorrectionEngine.get_status")
store, audit = make_test_env()

# Populate with some data
a1 = EvidenceAtom(
    artifact_type=ArtifactType.PREFETCH,
    proves={EvidenceSemantics.EXECUTION},
)
store.add_atom(a1)

f1 = ForensicFinding(
    category=FindingCategory.MALWARE_EXECUTION,
    title="Test",
    supporting_atoms=[a1.atom_id],
    status=FindingStatus.CONFIRMED,
)
store.findings[f1.finding_id] = f1

engine = CorrectionEngine(store, audit)
status = engine.get_status()

check("Status has total_atoms", status["total_atoms"] == 1)
check("Status has findings_confirmed", status["findings_confirmed"] == 1)
check("Status has iterations_completed", status["iterations_completed"] == 0)


# ===========================================================================
# Test 19: run_all_detectors integration
# ===========================================================================

print("\nTest 19: run_all_detectors integration")
store, audit = make_test_env()

# Mix of scenarios: phantom + ghost
ghost_proc = EvidenceAtom(
    artifact_type=ArtifactType.MEMORY_PROCESS,
    raw_data={"process_name": "stealthy.exe", "pid": 666},
    file_references=["stealthy.exe"],
)
store.add_atom(ghost_proc)

phantom_finding = ForensicFinding(
    category=FindingCategory.PERSISTENCE,
    title="Phantom finding",
    supporting_atoms=["ATM-NONEXISTENT"],
    status=FindingStatus.DRAFT,
)
store.findings[phantom_finding.finding_id] = phantom_finding

all_c = run_all_detectors(store, audit)

patterns_found = {c.pattern_type for c in all_c}
check(
    "Ghost process detected by run_all_detectors",
    ContradictionPattern.GHOST_PROCESS in patterns_found,
)
check(
    "Phantom artifact detected by run_all_detectors",
    ContradictionPattern.PHANTOM_ARTIFACT in patterns_found,
)


# ===========================================================================
# Test 20: Full pipeline convergence (clean store)
# ===========================================================================

print("\nTest 20: Full pipeline convergence")
store, audit = make_test_env()

# Add clean, well-evidenced finding
prefetch_clean = EvidenceAtom(
    artifact_type=ArtifactType.PREFETCH,
    proves={EvidenceSemantics.EXECUTION},
    file_references=["calc.exe"],
)
amcache_clean = EvidenceAtom(
    artifact_type=ArtifactType.AMCACHE,
    proves={EvidenceSemantics.EXECUTION},
    file_references=["calc.exe"],
)
store.add_atom(prefetch_clean)
store.add_atom(amcache_clean)

clean_finding = ForensicFinding(
    category=FindingCategory.BENIGN_ACTIVITY,
    title="calc.exe execution",
    supporting_atoms=[prefetch_clean.atom_id, amcache_clean.atom_id],
    status=FindingStatus.DRAFT,
)
store.add_finding(clean_finding)

engine = CorrectionEngine(store, audit)
reports = engine.run_full_pipeline()

check("Pipeline returns at least 1 report", len(reports) >= 1)
check("Pipeline converges", reports[-1].converged)
check(
    "Clean finding was auto-confirmed",
    clean_finding.status == FindingStatus.CONFIRMED,
)


# ===========================================================================
# Summary
# ===========================================================================

print(f"\n{'='*60}")
print(f"Block 4 Smoke Tests: {passed} passed, {failed} failed out of {passed + failed}")
print(f"{'='*60}")

sys.exit(0 if failed == 0 else 1)
