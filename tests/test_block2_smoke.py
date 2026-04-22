# ===== Block 2 Smoke Tests =====
import sys
print("=== Test 1: Import all validators ===")
from evidencechain.validators import (
    AmcacheValidator, EvtxValidator, MftValidator,
    PrefetchValidator, RegistryValidator, ShimcacheValidator,
)
print("  All 6 validators imported OK")

print()
print("=== Test 2: Import disk tools ===")
from evidencechain.tools.disk import DiskToolExecutor
print("  DiskToolExecutor imported OK")

print()
print("=== Test 3: Shimcache validator with sample CSV ===")
sv = ShimcacheValidator()
sample_csv = "Path,LastModifiedTimeUTC,CacheEntryPosition\n"
sample_csv += "C:\\Windows\\System32\\cmd.exe,2024-03-15T10:30:00Z,1\n"
sample_csv += "C:\\Users\\admin\\Desktop\\evil.exe,2024-03-16T14:22:00Z,2\n"
result = sv.validate("EXE-test001", sample_csv)
print(f"  Records: {result.record_count}")
print(f"  Atoms: {len(result.atoms)}")
print(f"  Overclaim flags: {len(result.overclaim_flags)}")
assert result.record_count == 2, "Expected 2 records"
assert len(result.atoms) == 2
assert any("execution" in f.message.lower() for f in result.overclaim_flags)
print(f"  Shimcache semantics: proves={result.atoms[0].proves}, cannot_prove={result.atoms[0].cannot_prove}")
assert "execution" in result.atoms[0].cannot_prove
assert "presence" in result.atoms[0].proves
print("  PASS")

print()
print("=== Test 4: Prefetch validator with sample CSV ===")
pv = PrefetchValidator()
sample_pf = "ExecutableName,LastRun,RunCount,PreviousRun0,Hash,SourceFilename\n"
sample_pf += "CMD.EXE,2024-03-15T10:30:00Z,5,2024-03-14T09:00:00Z,ABCD1234,CMD.EXE-12345678.pf\n"
sample_pf += "POWERSHELL.EXE,2024-03-16T14:22:00Z,12,,EFGH5678,POWERSHELL.EXE-AABBCCDD.pf\n"
result = pv.validate("EXE-test002", sample_pf)
print(f"  Records: {result.record_count}")
assert result.record_count == 2
# First entry should have 2 timestamps (LastRun + PreviousRun0)
assert len(result.atoms[0].timestamps) == 2, f"Expected 2 timestamps, got {len(result.atoms[0].timestamps)}"
assert "execution" in result.atoms[0].proves
print("  PASS")

print()
print("=== Test 5: MFT validator with timestomping detection ===")
mv = MftValidator()
sample_mft = "FileName,ParentPath,EntryNumber,SequenceNumber,InUse,Created0x10,LastModified0x10,Created0x30,LastModified0x30,FileSize\n"
sample_mft += "evil.exe,.\\Users\\admin\\Desktop,12345,1,True,2020-01-01T00:00:00Z,2024-03-16T14:22:00Z,2024-03-16T14:20:00Z,2024-03-16T14:22:00Z,65536\n"
sample_mft += "normal.txt,.\\Users\\admin\\Documents,12346,1,True,2024-03-10T08:00:00Z,2024-03-10T09:00:00Z,2024-03-10T08:00:00Z,2024-03-10T09:00:00Z,1024\n"
result = mv.validate("EXE-test003", sample_mft)
print(f"  Records: {result.record_count}")
assert result.record_count == 2
# evil.exe should have timestomping detected ($SI_Created=2020 vs $FN_Created=2024)
evil_atom = result.atoms[0]
print(f"  evil.exe timestomping detected: {evil_atom.raw_data.get('timestomping_detected')}")
assert evil_atom.raw_data["timestomping_detected"] == True, "Timestomping should be detected!"
# normal.txt should NOT have timestomping
normal_atom = result.atoms[1]
assert normal_atom.raw_data["timestomping_detected"] == False
print(f"  normal.txt timestomping detected: {normal_atom.raw_data.get('timestomping_detected')}")
# Should have overclaim flag about timestomping
assert len(result.overclaim_flags) > 0
print(f"  Overclaim flags: {result.overclaim_flags[0].message[:80]}...")
print("  PASS")

print()
print("=== Test 6: EVTX validator with timeline gap detection ===")
ev = EvtxValidator()
sample_evtx = "TimeCreated,EventId,Channel,Computer,Provider,PayloadData1\n"
sample_evtx += "2024-03-10T08:00:00Z,4624,Security,WORKSTATION1,Microsoft-Windows-Security-Auditing,Logon\n"
sample_evtx += "2024-03-10T08:05:00Z,4688,Security,WORKSTATION1,Microsoft-Windows-Security-Auditing,cmd.exe\n"
sample_evtx += "2024-03-10T20:00:00Z,1102,Security,WORKSTATION1,Microsoft-Windows-Eventlog,LogCleared\n"
sample_evtx += "2024-03-12T10:00:00Z,4624,Security,WORKSTATION1,Microsoft-Windows-Security-Auditing,Logon\n"
result = ev.validate("EXE-test004", sample_evtx)
print(f"  Records: {result.record_count}")
assert result.record_count == 4
# Should detect gap between March 10 20:00 and March 12 10:00 (38 hours)
gaps = [w for w in result.warnings if "TIMELINE GAP" in w.message]
print(f"  Timeline gaps detected: {len(gaps)}")
assert len(gaps) >= 1, "Should detect the 38-hour gap"
# Should detect log clearing (Event 1102)
assert len(result.overclaim_flags) > 0
print(f"  Log clearing flagged: {any('LOG CLEARING' in f.message for f in result.overclaim_flags)}")
# Event 4688 should prove EXECUTION
exec_atoms = [a for a in result.atoms if a.raw_data.get("event_id") == 4688]
assert len(exec_atoms) == 1
assert "execution" in exec_atoms[0].proves
print("  PASS")

print()
print("=== Test 7: Registry validator with persistence detection ===")
rv = RegistryValidator()
sample_reg = "KeyPath,ValueName,ValueData,LastWriteTimestamp,ValueType\n"
sample_reg += "Software\\Microsoft\\Windows\\CurrentVersion\\Run,MalwareStartup,C:\\Users\\admin\\Desktop\\evil.exe,2024-03-16T14:22:00Z,REG_SZ\n"
sample_reg += "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs,MRUListEx,binary_data,2024-03-15T10:00:00Z,REG_BINARY\n"
sample_reg += "ControlSet001\\Services\\FakeService,ImagePath,C:\\Windows\\Temp\\svc.exe,2024-03-14T12:00:00Z,REG_EXPAND_SZ\n"
result = rv.validate("EXE-test005", sample_reg)
print(f"  Records: {result.record_count}")
assert result.record_count == 3
# Run key and Service should be flagged as persistence
persistence_atoms = [a for a in result.atoms if a.raw_data.get("is_persistence_key")]
print(f"  Persistence keys: {len(persistence_atoms)}")
assert len(persistence_atoms) == 2, f"Expected 2 persistence keys, got {len(persistence_atoms)}"
# RecentDocs should be flagged as user activity
user_atoms = [a for a in result.atoms if a.raw_data.get("is_user_activity_key")]
print(f"  User activity keys: {len(user_atoms)}")
assert len(user_atoms) == 1
# Run key should extract file reference
run_atom = [a for a in result.atoms if "Run" in a.raw_data["key_path"]][0]
assert len(run_atom.file_references) > 0
print(f"  File reference extracted: {run_atom.file_references[0]}")
# Should have persistence overclaim flag
assert any("persistence" in f.message.lower() for f in result.overclaim_flags)
print("  PASS")

print()
print("=== Test 8: Amcache validator ===")
av = AmcacheValidator()
sample_am = "FullPath,ProgramName,SHA1,KeyLastWriteTimestamp,LinkDate,Publisher,Version,Size\n"
sample_am += "C:\\Users\\admin\\evil.exe,evil.exe,0000abcdef1234567890abcdef1234567890abcd,2024-03-16T14:22:00Z,2024-03-16T14:20:00Z,Unknown,,65536\n"
result = av.validate("EXE-test006", sample_am)
print(f"  Records: {result.record_count}")
assert result.record_count == 1
# SHA1 should have 0000 prefix stripped
print(f"  SHA1 (cleaned): {result.atoms[0].raw_data['sha1']}")
assert result.atoms[0].raw_data["sha1"] == "abcdef1234567890abcdef1234567890abcd"
assert "execution" in result.atoms[0].proves
print("  PASS")

print()
print("=== Test 9: DiskToolExecutor initialization ===")
from evidencechain.provenance.evidence_store import EvidenceStore
from evidencechain.provenance.audit_logger import AuditLogger
from evidencechain.provenance.evidence_registry import EvidenceRegistry
store = EvidenceStore()
audit_log = AuditLogger()
reg = EvidenceRegistry()
dt = DiskToolExecutor(store, audit_log, reg)
# Verify all methods exist
for method in ["mount_evidence", "get_filesystem_timeline", "parse_mft",
               "parse_event_logs", "parse_prefetch", "parse_amcache",
               "parse_registry", "extract_file", "unmount_evidence"]:
    assert hasattr(dt, method), f"Missing method: {method}"
print(f"  All 9 disk tool methods present")
print("  PASS")

print()
print("=== Test 10: Server dispatch table ===")
# Can't import the async server directly, but check the module loads
import importlib
mod = importlib.import_module("evidencechain.server")
assert hasattr(mod, "_TOOL_DISPATCH")
dispatch = mod._TOOL_DISPATCH
print(f"  Dispatch table has {len(dispatch)} entries")
assert len(dispatch) >= 9, f"Expected >= 9, got {len(dispatch)}"
for tool_name in ["mount_evidence", "get_filesystem_timeline", "parse_mft",
                   "parse_event_logs", "parse_prefetch", "parse_amcache",
                   "parse_registry", "extract_file", "unmount_evidence"]:
    assert tool_name in dispatch, f"Missing from dispatch: {tool_name}"
print("  All 9 disk tools in dispatch table")
print("  PASS")

print()
print("=" * 50)
print("ALL 10 BLOCK 2 SMOKE TESTS PASSED")
print("=" * 50)
