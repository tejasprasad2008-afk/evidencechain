"""Forensic knowledge bases: MITRE ATT&CK mapping, Windows process baselines, investigation playbooks.

These are static, hardcoded knowledge modules that provide context to
the report generator and help the agent reason about findings.
"""

from __future__ import annotations

from ..enums import FindingCategory


# ---------------------------------------------------------------------------
# MITRE ATT&CK technique reference
# ---------------------------------------------------------------------------

MITRE_TECHNIQUES: dict[str, dict[str, str]] = {
    "T1059.001": {"name": "PowerShell", "tactic": "Execution"},
    "T1059.003": {"name": "Windows Command Shell", "tactic": "Execution"},
    "T1059.005": {"name": "Visual Basic", "tactic": "Execution"},
    "T1047": {"name": "WMI", "tactic": "Execution"},
    "T1053.005": {"name": "Scheduled Task", "tactic": "Persistence"},
    "T1053.002": {"name": "At", "tactic": "Persistence"},
    "T1543.003": {"name": "Windows Service", "tactic": "Persistence"},
    "T1547.001": {"name": "Registry Run Keys", "tactic": "Persistence"},
    "T1546.007": {"name": "Netsh Helper DLL", "tactic": "Persistence"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "T1197": {"name": "BITS Jobs", "tactic": "Defense Evasion"},
    "T1140": {"name": "Deobfuscate/Decode Files", "tactic": "Defense Evasion"},
    "T1070.001": {"name": "Clear Windows Event Logs", "tactic": "Defense Evasion"},
    "T1070.006": {"name": "Timestomp", "tactic": "Defense Evasion"},
    "T1112": {"name": "Modify Registry", "tactic": "Defense Evasion"},
    "T1218.003": {"name": "CMSTP", "tactic": "Defense Evasion"},
    "T1218.004": {"name": "InstallUtil", "tactic": "Defense Evasion"},
    "T1218.005": {"name": "Mshta", "tactic": "Defense Evasion"},
    "T1218.007": {"name": "Msiexec", "tactic": "Defense Evasion"},
    "T1218.010": {"name": "Regsvr32", "tactic": "Defense Evasion"},
    "T1218.011": {"name": "Rundll32", "tactic": "Defense Evasion"},
    "T1127.001": {"name": "MSBuild", "tactic": "Defense Evasion"},
    "T1202": {"name": "Indirect Command Execution", "tactic": "Defense Evasion"},
    "T1564.004": {"name": "NTFS File Attributes", "tactic": "Defense Evasion"},
    "T1562.004": {"name": "Disable or Modify System Firewall", "tactic": "Defense Evasion"},
    "T1003.002": {"name": "Security Account Manager", "tactic": "Credential Access"},
    "T1003.003": {"name": "NTDS", "tactic": "Credential Access"},
    "T1482": {"name": "Domain Trust Discovery", "tactic": "Discovery"},
    "T1021.002": {"name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement"},
    "T1021.001": {"name": "Remote Desktop Protocol", "tactic": "Lateral Movement"},
    "T1071.001": {"name": "Web Protocols", "tactic": "Command and Control"},
}


def get_technique(technique_id: str) -> dict[str, str]:
    """Get MITRE ATT&CK technique name and tactic."""
    return MITRE_TECHNIQUES.get(technique_id, {"name": technique_id, "tactic": "Unknown"})


def get_techniques_for_finding(mitre_ids: list[str]) -> list[dict[str, str]]:
    """Resolve a list of technique IDs to full references."""
    return [
        {"id": tid, **get_technique(tid)}
        for tid in mitre_ids
    ]


# ---------------------------------------------------------------------------
# Finding category → human-readable narrative context
# ---------------------------------------------------------------------------

CATEGORY_NARRATIVES: dict[str, dict[str, str]] = {
    FindingCategory.MALWARE_EXECUTION.value: {
        "label": "Malware Execution",
        "icon": "[!]",
        "narrative_prefix": "Evidence indicates malicious code was executed",
        "investigation_note": "Verify execution with Prefetch + Amcache + Event 4688. Check memory for running instance.",
    },
    FindingCategory.LATERAL_MOVEMENT.value: {
        "label": "Lateral Movement",
        "icon": "[->]",
        "narrative_prefix": "Evidence suggests the attacker moved laterally",
        "investigation_note": "Check logon events (4624 type 3/10), SMB access, PsExec artifacts.",
    },
    FindingCategory.PERSISTENCE.value: {
        "label": "Persistence",
        "icon": "[P]",
        "narrative_prefix": "A persistence mechanism was established",
        "investigation_note": "Registry Run keys, Services (7045), Scheduled Tasks. Verify the target binary exists and has been executed.",
    },
    FindingCategory.DATA_EXFILTRATION.value: {
        "label": "Data Exfiltration",
        "icon": "[<-]",
        "narrative_prefix": "Evidence suggests data was exfiltrated",
        "investigation_note": "Check network connections, large file transfers, archive creation timestamps.",
    },
    FindingCategory.CREDENTIAL_ACCESS.value: {
        "label": "Credential Access",
        "icon": "[K]",
        "narrative_prefix": "Credential theft or access was detected",
        "investigation_note": "Check for LSASS access, SAM dumps, Mimikatz artifacts, Event 4648/4672.",
    },
    FindingCategory.DEFENSE_EVASION.value: {
        "label": "Defense Evasion",
        "icon": "[~]",
        "narrative_prefix": "Anti-forensic or evasion techniques were used",
        "investigation_note": "Check for timestomping, log clearing, process injection, packed binaries.",
    },
    FindingCategory.ANTI_FORENSICS.value: {
        "label": "Anti-Forensics",
        "icon": "[X]",
        "narrative_prefix": "Active anti-forensic techniques were detected",
        "investigation_note": "Timestomping, log clearing, secure deletion tools. Evidence may be permanently lost.",
    },
    FindingCategory.COMMAND_AND_CONTROL.value: {
        "label": "Command & Control",
        "icon": "[C2]",
        "narrative_prefix": "Command and control communication was identified",
        "investigation_note": "Check external IPs/domains in threat intel. Look for beaconing patterns.",
    },
    FindingCategory.INITIAL_ACCESS.value: {
        "label": "Initial Access",
        "icon": "[>>]",
        "narrative_prefix": "The initial compromise vector was identified",
        "investigation_note": "Check phishing artifacts, exploit indicators, external-facing service logs.",
    },
    FindingCategory.PRIVILEGE_ESCALATION.value: {
        "label": "Privilege Escalation",
        "icon": "[^]",
        "narrative_prefix": "Privilege escalation was detected",
        "investigation_note": "Check for UAC bypass, token manipulation, service exploitation.",
    },
    FindingCategory.RECONNAISSANCE.value: {
        "label": "Reconnaissance",
        "icon": "[?]",
        "narrative_prefix": "System/network reconnaissance was performed",
        "investigation_note": "Check for enumeration commands (net, nltest, systeminfo), discovery tools.",
    },
    FindingCategory.BENIGN_ACTIVITY.value: {
        "label": "Benign Activity",
        "icon": "[OK]",
        "narrative_prefix": "This activity appears to be benign",
        "investigation_note": "Verified as normal system or user activity.",
    },
}


# ---------------------------------------------------------------------------
# Windows process baselines (for identifying suspicious parent-child)
# ---------------------------------------------------------------------------

WINDOWS_PROCESS_BASELINES: dict[str, dict] = {
    "system": {"expected_parent": "none", "expected_path": "N/A", "expected_user": "NT AUTHORITY\\SYSTEM"},
    "smss.exe": {"expected_parent": "system", "expected_path": "\\SystemRoot\\System32\\smss.exe", "expected_user": "NT AUTHORITY\\SYSTEM"},
    "csrss.exe": {"expected_parent": "smss.exe", "expected_path": "\\SystemRoot\\System32\\csrss.exe", "expected_user": "NT AUTHORITY\\SYSTEM"},
    "wininit.exe": {"expected_parent": "smss.exe", "expected_path": "\\SystemRoot\\System32\\wininit.exe", "expected_user": "NT AUTHORITY\\SYSTEM"},
    "winlogon.exe": {"expected_parent": "smss.exe", "expected_path": "\\SystemRoot\\System32\\winlogon.exe", "expected_user": "NT AUTHORITY\\SYSTEM"},
    "services.exe": {"expected_parent": "wininit.exe", "expected_path": "\\SystemRoot\\System32\\services.exe", "expected_user": "NT AUTHORITY\\SYSTEM"},
    "lsass.exe": {"expected_parent": "wininit.exe", "expected_path": "\\SystemRoot\\System32\\lsass.exe", "expected_user": "NT AUTHORITY\\SYSTEM"},
    "svchost.exe": {"expected_parent": "services.exe", "expected_path": "\\SystemRoot\\System32\\svchost.exe", "expected_user": "NT AUTHORITY\\SYSTEM or NETWORK SERVICE or LOCAL SERVICE"},
    "explorer.exe": {"expected_parent": "userinit.exe", "expected_path": "\\SystemRoot\\explorer.exe", "expected_user": "User account"},
    "taskhostw.exe": {"expected_parent": "svchost.exe", "expected_path": "\\SystemRoot\\System32\\taskhostw.exe", "expected_user": "Varies"},
    "runtimebroker.exe": {"expected_parent": "svchost.exe", "expected_path": "\\SystemRoot\\System32\\RuntimeBroker.exe", "expected_user": "User account"},
}
