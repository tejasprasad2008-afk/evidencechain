"""Block 6 smoke tests: Report Generator.

Tests knowledge base, report builder, Jinja2 rendering, and generator.
Run: python3 tests/test_block6_smoke.py
"""

import sys
import os
import tempfile

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
    tmpdir = tempfile.mkdtemp(prefix="ectest_")
    store = EvidenceStore(persist_path=Path(tmpdir) / "test.jsonl")
    audit = AuditLogger(audit_dir=Path(tmpdir) / "audit")
    return store, audit, tmpdir


def populate_store(store):
    """Create a realistic evidence store for report testing."""
    # Prefetch atom proving execution
    prefetch = EvidenceAtom(
        tool_name="parse_prefetch",
        execution_id="EXE-test001",
        artifact_type=ArtifactType.PREFETCH,
        proves={EvidenceSemantics.EXECUTION},
        file_references=["evil.exe"],
        timestamps=[TimestampRecord(
            value="2024-01-15T10:30:00Z",
            source_field="LastRunTime",
            semantic_type=TimestampSemanticType.LAST_RUN,
        )],
        raw_data={"process_name": "evil.exe", "run_count": 3},
    )
    store.add_atom(prefetch)

    # Amcache atom corroborating
    amcache = EvidenceAtom(
        tool_name="parse_amcache",
        execution_id="EXE-test002",
        artifact_type=ArtifactType.AMCACHE,
        proves={EvidenceSemantics.EXECUTION},
        file_references=["evil.exe"],
        raw_data={"full_path": "C:\\Users\\admin\\evil.exe", "sha1": "abc123def456"},
    )
    store.add_atom(amcache)

    # Network connection
    net_atom = EvidenceAtom(
        tool_name="memory_network_connections",
        execution_id="EXE-test003",
        artifact_type=ArtifactType.MEMORY_NETWORK,
        proves={EvidenceSemantics.NETWORK_CONNECTION},
        raw_data={"remote_ip": "185.100.87.42", "remote_port": 443, "pid": 1234},
    )
    store.add_atom(net_atom)

    # MFT with timestomping
    mft_atom = EvidenceAtom(
        tool_name="parse_mft",
        execution_id="EXE-test004",
        artifact_type=ArtifactType.MFT_ENTRY,
        raw_data={
            "full_path": "C:\\Windows\\Temp\\backdoor.dll",
            "timestomping_detected": True,
        },
        timestamps=[TimestampRecord(
            value="2024-01-15T08:00:00Z",
            source_field="Created0x10",
            semantic_type=TimestampSemanticType.CREATED,
        )],
    )
    store.add_atom(mft_atom)

    # EVTX log clearing
    evtx_clear = EvidenceAtom(
        tool_name="parse_event_logs",
        execution_id="EXE-test005",
        artifact_type=ArtifactType.EVTX_EVENT,
        raw_data={"event_id": 1102},
        timestamps=[TimestampRecord(
            value="2024-01-15T11:00:00Z",
            source_field="TimeCreated",
            semantic_type=TimestampSemanticType.EVENT_TIME,
        )],
    )
    store.add_atom(evtx_clear)

    # Confirmed finding: malware execution
    f1 = ForensicFinding(
        category=FindingCategory.MALWARE_EXECUTION,
        title="evil.exe executed on victim host",
        description="The file evil.exe was executed at least 3 times.",
        supporting_atoms=[prefetch.atom_id, amcache.atom_id],
        evidence_type=EvidenceType.CORROBORATED,
        confidence_score=0.90,
        status=FindingStatus.CONFIRMED,
        mitre_attack=["T1059.001", "T1105"],
    )
    store.add_finding(f1)

    # Confirmed finding: C2 communication
    f2 = ForensicFinding(
        category=FindingCategory.COMMAND_AND_CONTROL,
        title="C2 communication to 185.100.87.42",
        description="Network connection from PID 1234 to external IP.",
        supporting_atoms=[net_atom.atom_id],
        evidence_type=EvidenceType.DIRECT,
        confidence_score=0.80,
        status=FindingStatus.CONFIRMED,
        mitre_attack=["T1071.001"],
    )
    store.add_finding(f2)

    # Under-review finding
    f3 = ForensicFinding(
        category=FindingCategory.ANTI_FORENSICS,
        title="Anti-forensic activity detected",
        description="Timestomping and log clearing detected.",
        supporting_atoms=[mft_atom.atom_id, evtx_clear.atom_id],
        evidence_type=EvidenceType.CIRCUMSTANTIAL,
        confidence_score=0.55,
        status=FindingStatus.UNDER_REVIEW,
    )
    store.add_finding(f3)

    # Retracted finding
    f4 = ForensicFinding(
        category=FindingCategory.LATERAL_MOVEMENT,
        title="Retracted lateral movement claim",
        description="Initially suspected but disproved.",
        supporting_atoms=[prefetch.atom_id],
        status=FindingStatus.RETRACTED,
    )
    store.findings[f4.finding_id] = f4

    # Contradiction
    c1 = ContradictionRecord(
        pattern_type=ContradictionPattern.ANTI_FORENSIC_INDICATOR,
        severity=Severity.HIGH,
        atom_a_id=mft_atom.atom_id,
        description="Timestomping detected in backdoor.dll",
        affected_finding_ids=[f3.finding_id],
    )
    store.add_contradiction(c1)

    return {
        "atoms": [prefetch, amcache, net_atom, mft_atom, evtx_clear],
        "findings": [f1, f2, f3, f4],
        "contradictions": [c1],
    }


# ===========================================================================
# Test 1: Import all modules
# ===========================================================================

print("Test 1: Import report and knowledge modules")
try:
    from evidencechain.report import (
        ReportBuilder,
        ReportGenerator,
        ReportData,
        FindingReport,
        ContradictionReport,
        CorrectionSummary,
    )
    from evidencechain.knowledge import (
        MITRE_TECHNIQUES,
        CATEGORY_NARRATIVES,
        WINDOWS_PROCESS_BASELINES,
        get_technique,
        get_techniques_for_finding,
    )
    check("All modules import successfully", True)
except Exception as e:
    check(f"Import failed: {e}", False)
    sys.exit(1)


# ===========================================================================
# Test 2: MITRE ATT&CK knowledge base
# ===========================================================================

print("\nTest 2: MITRE ATT&CK knowledge base")
check("Has 30+ techniques", len(MITRE_TECHNIQUES) >= 30)
check("T1059.001 is PowerShell", get_technique("T1059.001")["name"] == "PowerShell")
check("Unknown technique handled", get_technique("T9999")["tactic"] == "Unknown")

techniques = get_techniques_for_finding(["T1059.001", "T1105"])
check("Resolves 2 techniques", len(techniques) == 2)
check("Each has id/name/tactic", all("id" in t and "name" in t and "tactic" in t for t in techniques))


# ===========================================================================
# Test 3: Category narratives
# ===========================================================================

print("\nTest 3: Category narratives")
check("All 12 categories have narratives", len(CATEGORY_NARRATIVES) == 12)
for cat in FindingCategory:
    check(
        f"  {cat.value} has narrative",
        cat.value in CATEGORY_NARRATIVES,
    )


# ===========================================================================
# Test 4: Windows process baselines
# ===========================================================================

print("\nTest 4: Windows process baselines")
check("Has baseline processes", len(WINDOWS_PROCESS_BASELINES) >= 10)
check("svchost parent is services.exe", WINDOWS_PROCESS_BASELINES["svchost.exe"]["expected_parent"] == "services.exe")
check("lsass parent is wininit.exe", WINDOWS_PROCESS_BASELINES["lsass.exe"]["expected_parent"] == "wininit.exe")


# ===========================================================================
# Test 5: ReportBuilder — basic structure
# ===========================================================================

print("\nTest 5: ReportBuilder — basic structure")
store, audit, tmpdir = make_test_env()
populate_store(store)

builder = ReportBuilder(store)
report = builder.build()

check("Report is ReportData", isinstance(report, ReportData))
check("Has report_id", report.report_id.startswith("RPT-"))
check("Has generated_at", len(report.generated_at) > 0)
check("total_atoms = 5", report.total_atoms == 5)
check("total_findings = 4", report.total_findings == 4)


# ===========================================================================
# Test 6: ReportBuilder — finding categorization
# ===========================================================================

print("\nTest 6: ReportBuilder — finding categorization")
check("2 confirmed findings", len(report.confirmed_findings) == 2)
check("1 under_review finding", len(report.under_review_findings) == 1)
check("1 retracted finding", len(report.retracted_findings) == 1)
check("0 draft findings", len(report.draft_findings) == 0)

# Confirmed findings sorted by confidence
check(
    "Highest confidence first",
    report.confirmed_findings[0].confidence_score >= report.confirmed_findings[1].confidence_score,
)


# ===========================================================================
# Test 7: FindingReport content
# ===========================================================================

print("\nTest 7: FindingReport content")
f1_report = report.confirmed_findings[0]
check("Has title", len(f1_report.title) > 0)
check("Has category_label", f1_report.category_label == "Malware Execution")
check("Has category_icon", f1_report.category_icon == "[!]")
check("Has narrative_prefix", "malicious" in f1_report.narrative_prefix.lower())
check("Has investigation_note", len(f1_report.investigation_note) > 0)
check("Has supporting_evidence", len(f1_report.supporting_evidence) >= 2)
check("Has MITRE techniques", len(f1_report.mitre_techniques) == 2)
check("Evidence has atom_id", "atom_id" in f1_report.supporting_evidence[0])
check("Evidence has artifact_type", "artifact_type" in f1_report.supporting_evidence[0])


# ===========================================================================
# Test 8: Contradictions in report
# ===========================================================================

print("\nTest 8: Contradictions in report")
check("1 contradiction", len(report.contradictions) == 1)
c_report = report.contradictions[0]
check("Has pattern_type", c_report.pattern_type == "anti_forensic_indicator")
check("Has severity", c_report.severity == "high")
check("Has description", len(c_report.description) > 0)


# ===========================================================================
# Test 9: Timeline
# ===========================================================================

print("\nTest 9: Timeline")
check("Timeline has entries", len(report.timeline) >= 3)
check(
    "Timeline is chronologically sorted",
    all(report.timeline[i].timestamp <= report.timeline[i+1].timestamp
        for i in range(len(report.timeline) - 1)),
)


# ===========================================================================
# Test 10: Correction summary
# ===========================================================================

print("\nTest 10: Correction summary")
cs = report.correction_summary
check("Has total_contradictions", cs.total_contradictions == 1)
check("Has findings_confirmed", cs.findings_confirmed == 2)
check("Has findings_retracted", cs.findings_retracted == 1)


# ===========================================================================
# Test 11: MITRE coverage
# ===========================================================================

print("\nTest 11: MITRE coverage")
check("Has MITRE coverage entries", len(report.mitre_coverage) >= 2)
check("Each entry has id/name/tactic", all(
    "id" in t and "name" in t and "tactic" in t
    for t in report.mitre_coverage
))


# ===========================================================================
# Test 12: ReportGenerator — Markdown rendering
# ===========================================================================

print("\nTest 12: ReportGenerator — Markdown rendering")
store, audit, tmpdir = make_test_env()
populate_store(store)

generator = ReportGenerator(store, audit, output_dir=Path(tmpdir) / "reports")
md_content = generator.generate_to_string("markdown")

check("Markdown is non-empty", len(md_content) > 100)
check("Contains report title", "Forensic Investigation Report" in md_content)
check("Contains confirmed finding", "evil.exe" in md_content)
check("Contains MITRE technique", "T1059.001" in md_content)
check("Contains contradiction", "anti_forensic_indicator" in md_content.lower() or "ANTI_FORENSIC" in md_content)
check("Contains timeline section", "Timeline" in md_content)
check("Contains provenance section", "Provenance" in md_content)


# ===========================================================================
# Test 13: ReportGenerator — JSON rendering
# ===========================================================================

print("\nTest 13: ReportGenerator — JSON rendering")
import json

json_content = generator.generate_to_string("json")
check("JSON is non-empty", len(json_content) > 50)

try:
    parsed = json.loads(json_content)
    check("JSON is valid", True)
    check("Has report_id", "report_id" in parsed)
    check("Has summary", "summary" in parsed)
    check("Has confirmed_findings", "confirmed_findings" in parsed)
    check("Has contradictions", "contradictions" in parsed)
    check("confirmed_findings count = 2", parsed["summary"]["confirmed_count"] == 2)
except json.JSONDecodeError as e:
    check(f"JSON is valid: {e}", False)
    # Print first 500 chars for debugging
    print(f"  JSON content (first 500): {json_content[:500]}")


# ===========================================================================
# Test 14: ReportGenerator — file output
# ===========================================================================

print("\nTest 14: ReportGenerator — file output")
outputs = generator.generate(formats=["markdown", "json"])

check("Markdown file created", "markdown" in outputs)
check("JSON file created", "json" in outputs)
check("Markdown file exists", Path(outputs["markdown"]).exists())
check("JSON file exists", Path(outputs["json"]).exists())

# Verify file content
with open(outputs["markdown"], "r") as f:
    md_file_content = f.read()
check("Markdown file has content", len(md_file_content) > 100)

with open(outputs["json"], "r") as f:
    json_file_content = f.read()
check("JSON file has valid JSON", json.loads(json_file_content) is not None)


# ===========================================================================
# Test 15: Empty store report
# ===========================================================================

print("\nTest 15: Empty store report")
empty_store, empty_audit, tmpdir2 = make_test_env()
empty_gen = ReportGenerator(empty_store, empty_audit, output_dir=Path(tmpdir2) / "reports")
empty_md = empty_gen.generate_to_string("markdown")

check("Empty report renders", len(empty_md) > 50)
check("Shows zero findings", "0" in empty_md)


# ===========================================================================
# Summary
# ===========================================================================

print(f"\n{'='*60}")
print(f"Block 6 Smoke Tests: {passed} passed, {failed} failed out of {passed + failed}")
print(f"{'='*60}")

sys.exit(0 if failed == 0 else 1)
