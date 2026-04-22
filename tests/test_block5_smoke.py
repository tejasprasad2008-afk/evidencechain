"""Block 5 smoke tests: Threat Intel Enrichment.

Tests rate limiter, LOLBAS local DB, aggregator logic, enrichment tools,
and server dispatch wiring.
Run: python3 tests/test_block5_smoke.py
"""

import sys
import os
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pathlib import Path
from evidencechain.provenance.evidence_store import EvidenceStore
from evidencechain.provenance.audit_logger import AuditLogger
from evidencechain.provenance.evidence_registry import EvidenceRegistry
from evidencechain.models import Indicator, ThreatIntelResult, AggregatedVerdict
from evidencechain.enums import (
    ArtifactType,
    ThreatIntelSource,
    ThreatIntelVerdict,
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
    registry = EvidenceRegistry()
    return store, audit, registry


# ===========================================================================
# Test 1: Import all threat intel modules
# ===========================================================================

print("Test 1: Import threat intel modules")
try:
    from evidencechain.threat_intel import (
        ThreatIntelAggregator,
        RateLimiter,
        VirusTotalSource,
        AbuseIPDBSource,
        MalwareBazaarSource,
        LOLBASSource,
        AlienVaultOTXSource,
    )
    check("All threat intel modules import successfully", True)
except Exception as e:
    check(f"Import failed: {e}", False)
    sys.exit(1)


# ===========================================================================
# Test 2: Import enrichment tools
# ===========================================================================

print("\nTest 2: Import enrichment tools")
try:
    from evidencechain.tools.enrichment import EnrichmentToolExecutor
    check("EnrichmentToolExecutor imports", True)
except Exception as e:
    check(f"Import failed: {e}", False)
    sys.exit(1)


# ===========================================================================
# Test 3: Rate limiter
# ===========================================================================

print("\nTest 3: Rate limiter")
rl = RateLimiter(max_per_minute=3)

check("First acquire succeeds", rl.acquire("test_source", timeout=1))
check("Second acquire succeeds", rl.acquire("test_source", timeout=1))
check("Third acquire succeeds", rl.acquire("test_source", timeout=1))
check("Remaining is 0", rl.remaining("test_source") == 0)
# Fourth should fail (timeout quickly)
check("Fourth acquire fails (rate limited)", not rl.acquire("test_source", timeout=0.5))

# Reset
rl.reset("test_source")
check("After reset, remaining is 3", rl.remaining("test_source") == 3)
check("After reset, acquire succeeds", rl.acquire("test_source", timeout=1))


# ===========================================================================
# Test 4: LOLBAS local knowledge base
# ===========================================================================

print("\nTest 4: LOLBAS local knowledge base")
rl2 = RateLimiter()
lolbas = LOLBASSource(rl2)

check("LOLBAS is configured (no API key needed)", lolbas.is_configured)
check("LOLBAS handles filenames", lolbas.can_handle(Indicator("filename", "certutil.exe")))
check("LOLBAS doesn't handle hashes", not lolbas.can_handle(Indicator("hash_sha256", "abc")))

# Known LOLBin
result = lolbas.lookup(Indicator("filename", "certutil.exe"))
check("certutil.exe is SUSPICIOUS", result.verdict == ThreatIntelVerdict.SUSPICIOUS)
check("Has MITRE techniques", len(result.details.get("mitre_techniques", [])) > 0)
check("Has description", "download" in result.details.get("description", "").lower())

# Unknown file
result2 = lolbas.lookup(Indicator("filename", "myapp.exe"))
check("Unknown file is CLEAN", result2.verdict == ThreatIntelVerdict.CLEAN)

# Full path handling
result3 = lolbas.lookup(Indicator("filename", "C:\\Windows\\System32\\mshta.exe"))
check("Full path resolved to filename", result3.verdict == ThreatIntelVerdict.SUSPICIOUS)

# PowerShell
result4 = lolbas.lookup(Indicator("filename", "powershell.exe"))
check("powershell.exe is SUSPICIOUS", result4.verdict == ThreatIntelVerdict.SUSPICIOUS)


# ===========================================================================
# Test 5: Source adapter base — unconfigured source
# ===========================================================================

print("\nTest 5: Unconfigured source handling")
rl3 = RateLimiter()
vt = VirusTotalSource(rl3)

# VT requires an API key; without it, lookups should return UNKNOWN gracefully
if not vt.is_configured:
    result = vt.lookup(Indicator("hash_sha256", "abc123"))
    check("Unconfigured VT returns UNKNOWN", result.verdict == ThreatIntelVerdict.UNKNOWN)
    check("Error explains missing key", "API key" in result.details.get("error", ""))
else:
    check("VT is configured (API key found)", True)
    check("Skipping unconfigured test", True)


# ===========================================================================
# Test 6: Aggregator — LOLBAS only (no API keys needed)
# ===========================================================================

print("\nTest 6: Aggregator with LOLBAS")
store, audit, registry = make_test_env()
agg = ThreatIntelAggregator(store)

# Look up certutil.exe with only LOLBAS source
verdict = agg.lookup_indicator(
    Indicator("filename", "certutil.exe"),
    source_filter=["lolbas"],
    execution_id="EXE-test001",
)

check("Aggregated verdict returned", isinstance(verdict, AggregatedVerdict))
check("Source count >= 1", verdict.source_count >= 1)
check(
    "certutil.exe is SUSPICIOUS via aggregator",
    verdict.overall_verdict in (ThreatIntelVerdict.SUSPICIOUS, ThreatIntelVerdict.MALICIOUS),
)
check("Attribution summary not empty", len(verdict.attribution_summary) > 0)

# Check that an atom was created
ti_atoms = store.get_atoms_by_type(ArtifactType.THREAT_INTEL)
check("THREAT_INTEL atom created", len(ti_atoms) >= 1)
check("Atom has verdict in raw_data", ti_atoms[0].raw_data.get("verdict") == "suspicious")


# ===========================================================================
# Test 7: Aggregator — unknown file (all CLEAN)
# ===========================================================================

print("\nTest 7: Aggregator with unknown file")
store, audit, registry = make_test_env()
agg = ThreatIntelAggregator(store)

verdict2 = agg.lookup_indicator(
    Indicator("filename", "totally_legit_app.exe"),
    source_filter=["lolbas"],
)

check("Unknown file verdict is CLEAN", verdict2.overall_verdict == ThreatIntelVerdict.CLEAN)


# ===========================================================================
# Test 8: Aggregator — batch lookup
# ===========================================================================

print("\nTest 8: Aggregator batch lookup")
store, audit, registry = make_test_env()
agg = ThreatIntelAggregator(store)

indicators = [
    Indicator("filename", "certutil.exe"),
    Indicator("filename", "normal.exe"),
    Indicator("filename", "mshta.exe"),
]

verdicts = agg.lookup_batch(indicators, source_filter=["lolbas"])
check("3 verdicts returned", len(verdicts) == 3)
check("certutil.exe is suspicious", verdicts[0].overall_verdict == ThreatIntelVerdict.SUSPICIOUS)
check("normal.exe is clean", verdicts[1].overall_verdict == ThreatIntelVerdict.CLEAN)
check("mshta.exe is suspicious", verdicts[2].overall_verdict == ThreatIntelVerdict.SUSPICIOUS)


# ===========================================================================
# Test 9: Aggregator configured_sources property
# ===========================================================================

print("\nTest 9: Configured sources")
store, audit, registry = make_test_env()
agg = ThreatIntelAggregator(store)

sources = agg.configured_sources
check("LOLBAS is always configured", "lolbas" in sources)
check("MalwareBazaar is always configured (no key needed)", "malwarebazaar" in sources)


# ===========================================================================
# Test 10: EnrichmentToolExecutor — enrich_indicators
# ===========================================================================

print("\nTest 10: EnrichmentToolExecutor.enrich_indicators")
store, audit, registry = make_test_env()
executor = EnrichmentToolExecutor(store, audit, registry)

result = executor.enrich_indicators(
    indicators=[
        {"type": "filename", "value": "certutil.exe"},
        {"type": "filename", "value": "normal.exe"},
    ],
    sources=["lolbas"],
)

check("ToolResult status is SUCCESS", result.status.value == "success")
check("2 results returned", result.record_count == 2)
check("Has configured_sources in data", "configured_sources" in result.structured_data)
check("Has forensic_context", result.forensic_context is not None)
check(
    "Cannot prove execution",
    "execution" in result.forensic_context.cannot_prove,
)


# ===========================================================================
# Test 11: EnrichmentToolExecutor — compute_hashes
# ===========================================================================

print("\nTest 11: EnrichmentToolExecutor.compute_hashes")
store, audit, registry = make_test_env()
executor = EnrichmentToolExecutor(store, audit, registry)

# Create a temp file to hash
tmpdir = tempfile.mkdtemp(prefix="ectest_hash_")
test_file = os.path.join(tmpdir, "test.bin")
with open(test_file, "wb") as f:
    f.write(b"EvidenceChain test data for hashing")

# Temporarily add tmpdir to read allowlist
import evidencechain.config as cfg
original_read = cfg.READ_ALLOWLIST[:]
cfg.READ_ALLOWLIST.append(tmpdir)

try:
    result = executor.compute_hashes(
        file_path=test_file,
        evidence_id="EVD-test-001",
    )

    check("Hash result is SUCCESS", result.status.value == "success")
    check("Has md5", "md5" in result.structured_data)
    check("Has sha1", "sha1" in result.structured_data)
    check("Has sha256", "sha256" in result.structured_data)
    check("MD5 is 32 chars", len(result.structured_data["md5"]) == 32)
    check("SHA256 is 64 chars", len(result.structured_data["sha256"]) == 64)

    # Check atom was created
    hash_atoms = store.get_atoms_by_type(ArtifactType.FILE_HASH)
    check("FILE_HASH atom created", len(hash_atoms) == 1)
finally:
    cfg.READ_ALLOWLIST[:] = original_read


# ===========================================================================
# Test 12: Server dispatch table includes enrichment tools
# ===========================================================================

print("\nTest 12: Server dispatch table")
import importlib
mod = importlib.import_module("evidencechain.server")
dispatch = mod._TOOL_DISPATCH

check(f"Dispatch table has >= 19 entries (got {len(dispatch)})", len(dispatch) >= 19)
for tool_name in ["enrich_indicators", "compute_hashes", "yara_scan", "generate_super_timeline"]:
    check(f"'{tool_name}' in dispatch", tool_name in dispatch)


# ===========================================================================
# Test 13: Verdict score mapping
# ===========================================================================

print("\nTest 13: Verdict aggregation math")
from evidencechain.threat_intel.aggregator import _VERDICT_SCORES, _SOURCE_WEIGHTS

check("MALICIOUS score is 1.0", _VERDICT_SCORES[ThreatIntelVerdict.MALICIOUS] == 1.0)
check("CLEAN score is 0.0", _VERDICT_SCORES[ThreatIntelVerdict.CLEAN] == 0.0)
check("UNKNOWN is excluded (negative)", _VERDICT_SCORES[ThreatIntelVerdict.UNKNOWN] < 0)
check("VT has highest weight", _SOURCE_WEIGHTS[ThreatIntelSource.VIRUSTOTAL] == 1.0)
check("LOLBAS has lowest weight", _SOURCE_WEIGHTS[ThreatIntelSource.LOLBAS] == 0.5)


# ===========================================================================
# Test 14: Source type support matrix
# ===========================================================================

print("\nTest 14: Source type support matrix")
rl_test = RateLimiter()

vt = VirusTotalSource(rl_test)
check("VT supports hash_sha256", vt.can_handle(Indicator("hash_sha256", "x")))
check("VT supports ipv4", vt.can_handle(Indicator("ipv4", "x")))
check("VT supports domain", vt.can_handle(Indicator("domain", "x")))
check("VT doesn't support filename", not vt.can_handle(Indicator("filename", "x")))

abuse = AbuseIPDBSource(rl_test)
check("AbuseIPDB supports ipv4", abuse.can_handle(Indicator("ipv4", "x")))
check("AbuseIPDB doesn't support hash", not abuse.can_handle(Indicator("hash_sha256", "x")))

mb = MalwareBazaarSource(rl_test)
check("MB supports hash_sha256", mb.can_handle(Indicator("hash_sha256", "x")))
check("MB supports hash_md5", mb.can_handle(Indicator("hash_md5", "x")))
check("MB doesn't support ipv4", not mb.can_handle(Indicator("ipv4", "x")))

lol = LOLBASSource(rl_test)
check("LOLBAS supports filename only", lol.can_handle(Indicator("filename", "x")))

otx = AlienVaultOTXSource(rl_test)
check("OTX supports hash + ip + domain", otx.can_handle(Indicator("hash_sha1", "x")) and otx.can_handle(Indicator("ipv4", "x")))


# ===========================================================================
# Summary
# ===========================================================================

print(f"\n{'='*60}")
print(f"Block 5 Smoke Tests: {passed} passed, {failed} failed out of {passed + failed}")
print(f"{'='*60}")

sys.exit(0 if failed == 0 else 1)
