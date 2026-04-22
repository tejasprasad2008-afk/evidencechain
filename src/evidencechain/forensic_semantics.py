"""Forensic semantics map: what each artifact type can and cannot prove.

This is the core anti-hallucination knowledge base. It is hardcoded in Python,
NOT derived from LLM reasoning. Every tool validator uses this to annotate
EvidenceAtoms with correct proves/suggests/cannot_prove sets.
"""

from __future__ import annotations

from .enums import ArtifactType, EvidenceSemantics

# Each entry maps an ArtifactType to its semantic capabilities.
# "proves": the artifact DEFINITIVELY proves these facts.
# "suggests": the artifact SUGGESTS these facts but cannot prove them.
# "cannot_prove": the artifact is commonly MISINTERPRETED as proving these.

SEMANTICS_MAP: dict[ArtifactType, dict[str, set[str]]] = {
    # -----------------------------------------------------------------------
    # Disk artifacts
    # -----------------------------------------------------------------------
    ArtifactType.SHIMCACHE: {
        "proves": {EvidenceSemantics.PRESENCE},
        "suggests": set(),
        "cannot_prove": {EvidenceSemantics.EXECUTION},
        "caveats": [
            "Shimcache on Windows 8+ proves file PRESENCE on disk only, NOT execution.",
            "On Windows 7, execution order can be inferred from Shimcache entry order.",
            "Entries persist across reboots; presence may reflect historical state.",
        ],
        "corroboration_hints": [
            "Cross-reference with Prefetch for execution evidence.",
            "Cross-reference with Amcache for SHA1 hash and execution timestamp.",
            "Check Event ID 4688 for process creation events matching this file.",
        ],
    },
    ArtifactType.PREFETCH: {
        "proves": {EvidenceSemantics.EXECUTION},
        "suggests": {EvidenceSemantics.USER_INTERACTION},
        "cannot_prove": set(),
        "caveats": [
            "Prefetch records up to 8 most recent run times.",
            "Run count may not reflect total executions (counter resets possible).",
            "Prefetch must be enabled (disabled by default on SSDs in some Windows versions).",
            "Prefetch file creation time is the FIRST execution time.",
        ],
        "corroboration_hints": [
            "Cross-reference run times with Event Log timestamps.",
            "Check Amcache for SHA1 hash of the executed binary.",
            "Look for the process in memory if memory capture is available.",
        ],
    },
    ArtifactType.AMCACHE: {
        "proves": {EvidenceSemantics.EXECUTION},
        "suggests": set(),
        "cannot_prove": set(),
        "caveats": [
            "Amcache records SHA1 hash at time of first execution.",
            "The file may have been modified after Amcache recorded the hash.",
            "Amcache does not track repeated execution count.",
        ],
        "corroboration_hints": [
            "Use SHA1 hash for threat intelligence lookups (VirusTotal, MalwareBazaar).",
            "Cross-reference with Prefetch for execution frequency.",
            "Compare hash with the current file on disk to detect replacement.",
        ],
    },
    ArtifactType.MFT_ENTRY: {
        "proves": {EvidenceSemantics.FILE_MODIFICATION},
        "suggests": {EvidenceSemantics.TIMESTOMPING},
        "cannot_prove": {EvidenceSemantics.USER_INTERACTION},
        "caveats": [
            "$STANDARD_INFO timestamps can be modified by user-mode tools (timestomping).",
            "$FILE_NAME timestamps are harder to forge (require raw NTFS editing).",
            "Compare $SI vs $FN timestamps to detect timestomping.",
            "$SI_Created > $FN_Created by more than 2 seconds is a strong timestomping indicator.",
        ],
        "corroboration_hints": [
            "If timestomping suspected, check USN Journal for original timestamps.",
            "Compare with Prefetch/Amcache timestamps for the same file.",
            "Look for anti-forensic tools (timestomp.exe) in execution artifacts.",
        ],
    },
    ArtifactType.EVTX_EVENT: {
        "proves": set(),  # Depends on specific Event ID — set per-event in validator
        "suggests": set(),
        "cannot_prove": set(),
        "caveats": [
            "Event log entries can be cleared (Event ID 1102 for Security, 104 for System).",
            "Absence of events does NOT prove absence of activity.",
            "Event timestamps use system clock, which can be manipulated.",
        ],
        "corroboration_hints": [
            "Cross-reference logon events (4624) with filesystem timeline activity.",
            "Check for log clearing events (1102, 104) near suspicious gaps.",
            "Correlate process creation (4688) with Prefetch and memory process list.",
        ],
    },
    ArtifactType.REGISTRY_KEY: {
        "proves": {EvidenceSemantics.PERSISTENCE},
        "suggests": set(),
        "cannot_prove": {EvidenceSemantics.EXECUTION},
        "caveats": [
            "Registry persistence keys prove the mechanism was CONFIGURED, not that it executed.",
            "Registry timestamps reflect last modification of the KEY, not individual values.",
            "Deleted keys may still be recoverable from registry hive slack space.",
        ],
        "corroboration_hints": [
            "Check if the persistence target file exists on disk.",
            "Cross-reference with services in memory (vol3 windows.svcscan).",
            "Look for corresponding execution artifacts (Prefetch, Amcache).",
        ],
    },
    ArtifactType.FILESYSTEM_ENTRY: {
        "proves": {EvidenceSemantics.PRESENCE},
        "suggests": set(),
        "cannot_prove": {EvidenceSemantics.EXECUTION},
        "caveats": [
            "File presence on disk does not prove execution.",
            "MAC timestamps from fls/mactime reflect filesystem metadata.",
        ],
        "corroboration_hints": [
            "Compute hash and look up in threat intelligence.",
            "Check Prefetch/Amcache for execution evidence.",
            "Run YARA scan on the file for malware signatures.",
        ],
    },
    ArtifactType.TIMELINE_EVENT: {
        "proves": set(),
        "suggests": set(),
        "cannot_prove": set(),
        "caveats": [
            "Super timeline entries aggregate multiple sources; check the original source.",
            "Timeline density varies by artifact type and system activity.",
        ],
        "corroboration_hints": [
            "Filter timeline to specific time windows around suspicious events.",
            "Look for clusters of activity that suggest attacker sessions.",
        ],
    },

    # -----------------------------------------------------------------------
    # Memory artifacts
    # -----------------------------------------------------------------------
    ArtifactType.MEMORY_PROCESS: {
        "proves": set(),  # Depends on pslist vs psscan — set per-result in validator
        "suggests": {EvidenceSemantics.EXECUTION},
        "cannot_prove": {EvidenceSemantics.PROCESS_CURRENTLY_RUNNING},
        "caveats": [
            "psscan finds processes via pool tag scanning (finds hidden/exited processes).",
            "pslist walks the active process list (only finds linked processes).",
            "A process in psscan but NOT in pslist may be hidden or already exited.",
            "Memory analysis reflects state at capture time only.",
        ],
        "corroboration_hints": [
            "Cross-reference with disk execution artifacts (Prefetch, Amcache).",
            "Check memory_command_lines for this process's arguments.",
            "Check memory_injected_code for code injection indicators.",
            "Verify process parent-child relationship against Windows baselines.",
        ],
    },
    ArtifactType.MEMORY_NETWORK: {
        "proves": {EvidenceSemantics.NETWORK_CONNECTION},
        "suggests": set(),
        "cannot_prove": {EvidenceSemantics.CONNECTION_ACTIVE_NOW},
        "caveats": [
            "netscan uses pool tag scanning and may find historical (closed) connections.",
            "netstat walks active connection structures (current connections only).",
            "Connection found by netscan but not netstat may be historical.",
        ],
        "corroboration_hints": [
            "Look up remote IP in threat intelligence (AbuseIPDB, VirusTotal).",
            "Cross-reference the owning PID with process list findings.",
            "Check disk for related network artifacts (browser history, DNS cache).",
        ],
    },
    ArtifactType.MEMORY_MALFIND: {
        "proves": set(),
        "suggests": {EvidenceSemantics.CODE_INJECTION},
        "cannot_prove": {EvidenceSemantics.MALICIOUS_INTENT},
        "caveats": [
            "malfind reports memory regions with RWX permissions and no file backing.",
            ".NET and JIT-compiled processes commonly have RWX regions (false positives).",
            "Packed executables may trigger malfind on their unpacking stubs.",
            "Must correlate with process context to determine if truly malicious.",
        ],
        "corroboration_hints": [
            "Check if the process is a known .NET application (filter FPs).",
            "Dump the process memory and run YARA scan.",
            "Check the process parent and command line for suspicious indicators.",
        ],
    },
    ArtifactType.MEMORY_SERVICE: {
        "proves": set(),
        "suggests": {EvidenceSemantics.PERSISTENCE},
        "cannot_prove": set(),
        "caveats": [
            "svcscan shows services registered in memory's service control manager.",
            "Services present in memory were registered at some point; may or may not be running.",
        ],
        "corroboration_hints": [
            "Cross-reference with registry persistence keys for this service.",
            "Check if the service binary exists on disk.",
            "Look for service installation events (Event ID 7045).",
        ],
    },
    ArtifactType.MEMORY_CMDLINE: {
        "proves": set(),
        "suggests": set(),
        "cannot_prove": set(),
        "caveats": [
            "Command line arguments reflect what was passed at process creation.",
            "Arguments can be spoofed by the process after creation (argument cloaking).",
        ],
        "corroboration_hints": [
            "Cross-reference encoded commands with Event ID 4688 command line logging.",
            "Decode any Base64 or obfuscated arguments.",
        ],
    },

    # -----------------------------------------------------------------------
    # Enrichment artifacts
    # -----------------------------------------------------------------------
    ArtifactType.YARA_HIT: {
        "proves": set(),
        "suggests": {EvidenceSemantics.KNOWN_MALWARE},
        "cannot_prove": {EvidenceSemantics.MALICIOUS_INTENT},
        "caveats": [
            "YARA rules match byte patterns; a match suggests but does not prove malware.",
            "False positives are common with broad rules.",
            "Rule quality varies by source.",
        ],
        "corroboration_hints": [
            "Compute hash and look up in threat intelligence for confirmation.",
            "Correlate with execution artifacts to determine if the file ran.",
        ],
    },
    ArtifactType.FILE_HASH: {
        "proves": set(),
        "suggests": set(),
        "cannot_prove": set(),
        "caveats": [
            "Hash identifies the file content at time of hashing.",
            "File may have been modified since the hash was recorded elsewhere (e.g., Amcache).",
        ],
        "corroboration_hints": [
            "Look up hash in VirusTotal, MalwareBazaar, and AlienVault OTX.",
            "Compare with Amcache SHA1 to detect file replacement.",
        ],
    },
    ArtifactType.THREAT_INTEL: {
        "proves": set(),  # Set dynamically: KNOWN_MALWARE if VT detections > threshold
        "suggests": set(),
        "cannot_prove": {EvidenceSemantics.EXECUTION},
        "caveats": [
            "Threat intel verdicts reflect current database state; may change over time.",
            "Absence from threat intel databases does NOT mean the file is clean.",
            "Different sources may disagree; aggregate verdicts carefully.",
        ],
        "corroboration_hints": [
            "A MALICIOUS verdict from threat intel corroborates malware execution findings.",
            "A CLEAN verdict from all sources may weaken a malware hypothesis.",
            "NOT_FOUND from all sources may indicate novel/targeted malware.",
        ],
    },
}


def get_semantics(artifact_type: ArtifactType) -> dict[str, set[str] | list[str]]:
    """Get the forensic semantics for a given artifact type.

    Returns a dict with keys: proves, suggests, cannot_prove, caveats, corroboration_hints.
    If the artifact type is not in the map, returns empty sets/lists.
    """
    default = {
        "proves": set(),
        "suggests": set(),
        "cannot_prove": set(),
        "caveats": [],
        "corroboration_hints": [],
    }
    return SEMANTICS_MAP.get(artifact_type, default)
