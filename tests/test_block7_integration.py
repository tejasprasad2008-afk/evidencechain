#!/usr/bin/env python3
"""Block 7 Integration Tests — Full pipeline end-to-end.

Tests the complete EvidenceChain workflow:
  1. Create evidence atoms from multiple artifact types
  2. Create findings backed by those atoms
  3. Introduce contradictions (overclaim, ghost process, timestomping)
  4. Run the self-correction engine
  5. Verify confidence scoring and status transitions
  6. Generate reports (Markdown + JSON)
  7. Verify audit trail
  8. Verify server dispatch table (21 tools)
  9. Verify handler wiring for new tools
"""

import json
import os
import sys
import tempfile

# Ensure we can import from src/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

passed = 0
failed = 0


def check(label: str, condition: bool):
    global passed, failed
    if condition:
        print(f"  PASS: {label}")
        passed += 1
    else:
        print(f"  FAIL: {label}")
        failed += 1


# ===================================================================
# Test 1: Full pipeline — atoms through to report
# ===================================================================
print("\nTest 1: Full pipeline — atoms through to report")

from evidencechain.enums import (
    ArtifactType,
    ContradictionPattern,
    ContradictionResolution,
    EvidenceType,
    FindingCategory,
    FindingStatus,
    EvidenceSemantics,
    Severity,
)
from evidencechain.models import (
    ContradictionRecord,
    EvidenceAtom,
    ForensicFinding,
    TimestampRecord,
    TimestampSemanticType,
)
from evidencechain.provenance.evidence_store import EvidenceStore
from evidencechain.provenance.audit_logger import AuditLogger
from evidencechain.correction.engine import CorrectionEngine
from evidencechain.report.generator import ReportGenerator

store = EvidenceStore()
audit = AuditLogger()

# Create atoms simulating a real investigation
# Atom 1: Prefetch — proves execution of malware.exe
atom_prefetch = EvidenceAtom(
    atom_id="ATM-pf001",
    tool_name="parse_prefetch",
    execution_id="EXE-001",
    artifact_type=ArtifactType.PREFETCH,
    raw_data={"process_name": "malware.exe", "full_path": "C:\\Windows\\Temp\\malware.exe", "run_count": 3},
    timestamps=[TimestampRecord(value="2026-01-15T10:30:00Z", source_field="LastRunTime", semantic_type=TimestampSemanticType.LAST_RUN)],
    file_references=["C:\\Windows\\Temp\\malware.exe"],
    proves={"execution", "presence"},
    suggests=set(),
    cannot_prove={"user_interaction"},
)
store.add_atom(atom_prefetch)

# Atom 2: Amcache — proves execution + hash
atom_amcache = EvidenceAtom(
    atom_id="ATM-am001",
    tool_name="parse_amcache",
    execution_id="EXE-002",
    artifact_type=ArtifactType.AMCACHE,
    raw_data={"process_name": "malware.exe", "sha1": "abc123def456", "full_path": "C:\\Windows\\Temp\\malware.exe"},
    timestamps=[TimestampRecord(value="2026-01-15T10:28:00Z", source_field="FirstRunTime", semantic_type=TimestampSemanticType.FIRST_RUN)],
    file_references=["C:\\Windows\\Temp\\malware.exe"],
    proves={"execution", "presence"},
    suggests=set(),
    cannot_prove=set(),
)
store.add_atom(atom_amcache)

# Atom 3: ShimCache — proves PRESENCE only (for overclaim test)
atom_shimcache = EvidenceAtom(
    atom_id="ATM-sc001",
    tool_name="parse_shimcache",
    execution_id="EXE-003",
    artifact_type=ArtifactType.SHIMCACHE,
    raw_data={"process_name": "suspicious.exe", "full_path": "C:\\Users\\Admin\\suspicious.exe"},
    timestamps=[TimestampRecord(value="2026-01-14T08:00:00Z", source_field="LastModifiedTime", semantic_type=TimestampSemanticType.MODIFIED)],
    file_references=["C:\\Users\\Admin\\suspicious.exe"],
    proves={"presence"},
    suggests=set(),
    cannot_prove={"execution"},
)
store.add_atom(atom_shimcache)

# Atom 4: Memory process list — process found in memory
atom_memproc = EvidenceAtom(
    atom_id="ATM-mp001",
    tool_name="memory_process_list",
    execution_id="EXE-004",
    artifact_type=ArtifactType.MEMORY_PROCESS,
    raw_data={"process_name": "malware.exe", "pid": 1234, "ppid": 4567, "psscan_only": False},
    timestamps=[],
    file_references=[],
    proves={"execution", "presence"},
    suggests=set(),
    cannot_prove=set(),
)
store.add_atom(atom_memproc)

# Atom 5: Memory process — ghost process (psscan only, no disk trace)
atom_ghost = EvidenceAtom(
    atom_id="ATM-gp001",
    tool_name="memory_process_list",
    execution_id="EXE-004",
    artifact_type=ArtifactType.MEMORY_PROCESS,
    raw_data={"process_name": "stealthy.exe", "pid": 9999, "ppid": 4, "psscan_only": True, "potentially_hidden": True},
    timestamps=[],
    file_references=[],
    proves={"execution"},
    suggests={"defense_evasion"},
    cannot_prove=set(),
)
store.add_atom(atom_ghost)

# Atom 6: Network connection
atom_net = EvidenceAtom(
    atom_id="ATM-nc001",
    tool_name="memory_network_connections",
    execution_id="EXE-005",
    artifact_type=ArtifactType.MEMORY_NETWORK,
    raw_data={"pid": 1234, "remote_ip": "192.168.1.100", "remote_port": 443, "protocol": "TCP"},
    timestamps=[],
    file_references=[],
    proves={"network_connection"},
    suggests={"command_and_control"},
    cannot_prove=set(),
)
store.add_atom(atom_net)

# Atom 7: MFT with timestomping
atom_mft = EvidenceAtom(
    atom_id="ATM-mf001",
    tool_name="parse_mft",
    execution_id="EXE-006",
    artifact_type=ArtifactType.MFT_ENTRY,
    raw_data={
        "full_path": "C:\\Windows\\Temp\\malware.exe",
        "timestomping_detected": True,
        "si_modified": "2020-01-01T00:00:00Z",
        "fn_modified": "2026-01-15T10:25:00Z",
    },
    timestamps=[
        TimestampRecord(value="2020-01-01T00:00:00Z", source_field="$SI_Modified", semantic_type=TimestampSemanticType.MODIFIED, attribute_source="$STANDARD_INFO"),
        TimestampRecord(value="2026-01-15T10:25:00Z", source_field="$FN_Modified", semantic_type=TimestampSemanticType.MODIFIED, attribute_source="$FILE_NAME"),
    ],
    file_references=["C:\\Windows\\Temp\\malware.exe"],
    proves={"presence"},
    suggests={"timestomping"},
    cannot_prove=set(),
)
store.add_atom(atom_mft)

check("7 atoms created", len(store.atoms) == 7)

# ===================================================================
# Test 2: Create findings
# ===================================================================
print("\nTest 2: Create findings backed by atoms")

# Finding 1: Malware execution (CONFIRMED-level evidence)
finding_malware = ForensicFinding(
    finding_id="FND-mal001",
    category=FindingCategory.MALWARE_EXECUTION,
    title="Malware execution: malware.exe",
    description="malware.exe was executed from C:\\Windows\\Temp\\",
    supporting_atoms=["ATM-pf001", "ATM-am001", "ATM-mp001"],
    evidence_type=EvidenceType.CORROBORATED,
    mitre_attack=["T1059.001", "T1204.002"],
    status=FindingStatus.DRAFT,
)
store.add_finding(finding_malware)

# Finding 2: Suspicious file (only ShimCache — should trigger overclaim if we claim execution)
finding_suspicious = ForensicFinding(
    finding_id="FND-sus001",
    category=FindingCategory.MALWARE_EXECUTION,
    title="Suspicious file: suspicious.exe",
    description="suspicious.exe found in ShimCache only — presence on disk, not execution",
    supporting_atoms=["ATM-sc001"],
    evidence_type=EvidenceType.CIRCUMSTANTIAL,
    mitre_attack=["T1059.001"],
    status=FindingStatus.DRAFT,
)
store.add_finding(finding_suspicious)

# Finding 3: C2 Communication
finding_c2 = ForensicFinding(
    finding_id="FND-c2001",
    category=FindingCategory.COMMAND_AND_CONTROL,
    title="C2 connection to 192.168.1.100:443",
    description="Malware.exe (PID 1234) connected to 192.168.1.100 on port 443",
    supporting_atoms=["ATM-nc001", "ATM-mp001"],
    evidence_type=EvidenceType.CORROBORATED,
    mitre_attack=["T1071.001"],
    status=FindingStatus.DRAFT,
)
store.add_finding(finding_c2)

# Finding 4: Anti-forensics
finding_antifor = ForensicFinding(
    finding_id="FND-af001",
    category=FindingCategory.ANTI_FORENSICS,
    title="Timestomping detected on malware.exe",
    description="$SI and $FN timestamps differ by 6+ years — clear timestomping",
    supporting_atoms=["ATM-mf001"],
    evidence_type=EvidenceType.DIRECT,
    mitre_attack=["T1070.006"],
    status=FindingStatus.DRAFT,
)
store.add_finding(finding_antifor)

check("4 findings created", len(store.findings) == 4)
check("All findings are DRAFT", all(f.status == FindingStatus.DRAFT for f in store.findings.values()))

# ===================================================================
# Test 3: Run self-correction engine
# ===================================================================
print("\nTest 3: Run self-correction engine")

engine = CorrectionEngine(store, audit)
reports = engine.run_full_pipeline()

check("Engine ran at least 1 iteration", len(reports) >= 1)
check("Engine produced CorrectionReport", hasattr(reports[0], 'summary'))
check("Report has 4 pass results", len(reports[0].pass_results) == 4)

# Check pass names
pass_names = [p.pass_name for p in reports[0].pass_results]
check("Pass 1 is inline_validation_summary", pass_names[0] == "inline_validation_summary")
check("Pass 2 is contradiction_detection", pass_names[1] == "contradiction_detection")
check("Pass 3 is confidence_scoring", pass_names[2] == "confidence_scoring")
check("Pass 4 is reinvestigation_planning", pass_names[3] == "reinvestigation_planning")

# ===================================================================
# Test 4: Verify confidence scoring worked
# ===================================================================
print("\nTest 4: Verify confidence scoring and status transitions")

malware_finding = store.findings["FND-mal001"]
check("Malware finding scored > 0", malware_finding.confidence_score > 0.0)
check("Malware finding CONFIRMED (3 corroborating atoms)", malware_finding.status == FindingStatus.CONFIRMED)

suspicious_finding = store.findings["FND-sus001"]
check("Suspicious finding scored >= 0 (ShimCache lacks execution proof)", suspicious_finding.confidence_score >= 0.0)
# ShimCache-only finding should have lower confidence
check("Suspicious finding confidence < malware finding", suspicious_finding.confidence_score < malware_finding.confidence_score)

c2_finding = store.findings["FND-c2001"]
check("C2 finding scored > 0", c2_finding.confidence_score > 0.0)

af_finding = store.findings["FND-af001"]
check("Anti-forensics finding scored > 0", af_finding.confidence_score > 0.0)

# ===================================================================
# Test 5: Verify engine status
# ===================================================================
print("\nTest 5: Verify engine status")

status = engine.get_status()
check("Status has iterations_completed", status["iterations_completed"] >= 1)
check("Status has total_atoms = 7", status["total_atoms"] == 7)
check("Status has total_findings = 4", status["total_findings"] == 4)
check("Status has findings_confirmed >= 1", status["findings_confirmed"] >= 1)

# ===================================================================
# Test 6: Generate reports
# ===================================================================
print("\nTest 6: Generate reports")

with tempfile.TemporaryDirectory() as tmpdir:
    gen = ReportGenerator(store, audit, output_dir=__import__("pathlib").Path(tmpdir))
    paths = gen.generate(formats=["markdown", "json"])

    check("Markdown output generated", "markdown" in paths)
    check("JSON output generated", "json" in paths)
    check("Markdown file exists", os.path.isfile(paths["markdown"]))
    check("JSON file exists", os.path.isfile(paths["json"]))

    # Read and validate Markdown
    with open(paths["markdown"], "r") as f:
        md = f.read()
    check("Markdown has title", "EvidenceChain" in md)
    check("Markdown has confirmed findings section", "Confirmed" in md)
    check("Markdown has malware finding", "malware.exe" in md)
    check("Markdown has MITRE technique", "T1059" in md)

    # Read and validate JSON
    with open(paths["json"], "r") as f:
        data = json.load(f)
    check("JSON has report_id", "report_id" in data)
    check("JSON has summary", "summary" in data)
    check("JSON has confirmed_findings", "confirmed_findings" in data)
    check("JSON confirmed_findings count >= 1", len(data.get("confirmed_findings", [])) >= 1)

    # Test generate_to_string
    md_str = gen.generate_to_string("markdown")
    check("generate_to_string works", len(md_str) > 0)

# ===================================================================
# Test 7: Server dispatch table has 21 tools
# ===================================================================
print("\nTest 7: Server dispatch table has 21 tools")

from evidencechain.server import _TOOL_DISPATCH

check("Dispatch table has 21 entries", len(_TOOL_DISPATCH) == 21)
check("run_self_correction in dispatch", "run_self_correction" in _TOOL_DISPATCH)
check("generate_report in dispatch", "generate_report" in _TOOL_DISPATCH)

# Verify all expected tools exist
expected_tools = [
    "mount_evidence", "get_filesystem_timeline", "parse_mft",
    "parse_event_logs", "parse_prefetch", "parse_amcache",
    "parse_registry", "extract_file", "unmount_evidence",
    "memory_process_list", "memory_network_connections",
    "memory_injected_code", "memory_services",
    "memory_command_lines", "memory_dump_process",
    "enrich_indicators", "compute_hashes", "yara_scan",
    "generate_super_timeline",
    "run_self_correction", "generate_report",
]
for tool in expected_tools:
    check(f"  {tool}", tool in _TOOL_DISPATCH)

# ===================================================================
# Test 8: Handler wiring — run_self_correction
# ===================================================================
print("\nTest 8: Handler wiring — run_self_correction")

from evidencechain.server import _handle_run_self_correction, _handle_generate_report
from evidencechain.server import correction_engine as server_engine
from evidencechain.server import report_generator as server_gen

check("correction_engine is CorrectionEngine", type(server_engine).__name__ == "CorrectionEngine")
check("report_generator is ReportGenerator", type(server_gen).__name__ == "ReportGenerator")

# Test handler with empty store (fresh server globals)
result = _handle_run_self_correction({"full_pipeline": False})
check("run_self_correction returns status ok", result["status"] == "ok")
check("run_self_correction returns iteration number", "iteration" in result)

result_full = _handle_run_self_correction({"full_pipeline": True})
check("run_self_correction full_pipeline returns status ok", result_full["status"] == "ok")
check("run_self_correction full_pipeline returns iterations", "iterations" in result_full)

# ===================================================================
# Test 9: Handler wiring — generate_report
# ===================================================================
print("\nTest 9: Handler wiring — generate_report")

result = _handle_generate_report({})
check("generate_report returns status ok", result["status"] == "ok")
check("generate_report returns output_paths", "output_paths" in result)
check("generate_report returns report_preview", "report_preview" in result)

# ===================================================================
# Test 10: Evidence provenance chain
# ===================================================================
print("\nTest 10: Evidence provenance chain")

# Verify we can trace from finding -> atoms -> tool execution
finding = store.findings["FND-mal001"]
check("Finding has supporting atoms", len(finding.supporting_atoms) >= 1)

for atom_id in finding.supporting_atoms:
    atom = store.get_atom(atom_id)
    check(f"  Atom {atom_id} exists", atom is not None)
    if atom:
        check(f"  Atom {atom_id} has tool_name", atom.tool_name != "")
        check(f"  Atom {atom_id} has execution_id", atom.execution_id != "")
        check(f"  Atom {atom_id} has proves set", len(atom.proves) > 0)

# ===================================================================
# Test 11: Correction report summary format
# ===================================================================
print("\nTest 11: Correction report summary format")

summary = reports[0].summary
check("Summary has iteration", "iteration" in summary)
check("Summary has converged", "converged" in summary)
check("Summary has total_contradictions_found", "total_contradictions_found" in summary)
check("Summary has findings_scored", "findings_scored" in summary)
check("Summary has pass_summaries", "pass_summaries" in summary)
check("Summary has 4 pass summaries", len(summary["pass_summaries"]) == 4)

# ===================================================================
# Test 12: Reinvestigation plan format
# ===================================================================
print("\nTest 12: Reinvestigation plan format")

plan = reports[0].reinvestigation_plan
check("Plan has actions list", hasattr(plan, "actions"))
check("Plan has total_contradictions", hasattr(plan, "total_contradictions"))
check("Plan has unresolved_count", hasattr(plan, "unresolved_count"))
check("Plan has capped flag", hasattr(plan, "capped"))

# Format for LLM
llm_text = engine.format_reinvestigation_for_llm(plan)
check("LLM text is non-empty string", len(llm_text) > 0)

# ===================================================================
# Test 13: Knowledge base coverage
# ===================================================================
print("\nTest 13: Knowledge base coverage")

from evidencechain.knowledge.forensic_kb import (
    MITRE_TECHNIQUES,
    CATEGORY_NARRATIVES,
    WINDOWS_PROCESS_BASELINES,
    get_technique,
    get_techniques_for_finding,
)

check("MITRE_TECHNIQUES >= 30", len(MITRE_TECHNIQUES) >= 30)
check("All 12 categories have narratives", len(CATEGORY_NARRATIVES) == 12)
check("Windows baselines >= 10", len(WINDOWS_PROCESS_BASELINES) >= 10)

# Check finding's MITRE mapping
techniques = get_techniques_for_finding(["T1059.001", "T1204.002"])
check("Resolved 2 techniques", len(techniques) == 2)
check("T1059.001 is PowerShell", techniques[0]["name"] == "PowerShell")

# ===================================================================
# Test 14: Forensic semantics map
# ===================================================================
print("\nTest 14: Forensic semantics map")

from evidencechain.forensic_semantics import SEMANTICS_MAP

check("Semantics map has entries", len(SEMANTICS_MAP) > 0)
check("SHIMCACHE proves PRESENCE", EvidenceSemantics.PRESENCE in SEMANTICS_MAP.get(ArtifactType.SHIMCACHE, {}).get("proves", set()))
check("SHIMCACHE cannot_prove EXECUTION", EvidenceSemantics.EXECUTION in SEMANTICS_MAP.get(ArtifactType.SHIMCACHE, {}).get("cannot_prove", set()))
check("PREFETCH proves EXECUTION", EvidenceSemantics.EXECUTION in SEMANTICS_MAP.get(ArtifactType.PREFETCH, {}).get("proves", set()))
check("AMCACHE proves EXECUTION", EvidenceSemantics.EXECUTION in SEMANTICS_MAP.get(ArtifactType.AMCACHE, {}).get("proves", set()))

# ===================================================================
# Test 15: Security guardrails
# ===================================================================
print("\nTest 15: Security guardrails")

from evidencechain.security.path_validator import validate_read_path, PathValidationError
from evidencechain.security.command_guard import execute, CommandDeniedError
from evidencechain.security.output_cap import cap_output
from evidencechain.config import DENIED_BINARIES

# Path validator — /cases is in READ_ALLOWLIST
try:
    validate_read_path("/cases/evidence.E01")
    check("Path validator allows /cases/evidence.E01", True)
except PathValidationError:
    check("Path validator allows /cases/evidence.E01", False)

try:
    validate_read_path("/etc/passwd")
    check("Path validator blocks /etc/passwd", False)
except PathValidationError:
    check("Path validator blocks /etc/passwd", True)

# Command guard — binary denylist
check("Command guard denies rm", "rm" in DENIED_BINARIES)
check("Command guard denies curl", "curl" in DENIED_BINARIES)
check("Command guard denies python3", "python3" in DENIED_BINARIES)

try:
    execute(["rm", "--version"])
    check("Command guard blocks rm execution", False)
except CommandDeniedError:
    check("Command guard blocks rm execution", True)

# Output cap
big_output = "x" * 200_000
capped_output, was_truncated, _ = cap_output(big_output)
check("Output cap truncates large output", was_truncated)
check("Capped output is smaller", len(capped_output) < 200_000)

# ===================================================================
# Results
# ===================================================================

print(f"\n{'=' * 60}")
print(f"Block 7 Integration Tests: {passed} passed, {failed} failed out of {passed + failed}")
print(f"{'=' * 60}")

sys.exit(0 if failed == 0 else 1)
