"""LOLBAS (Living Off The Land Binaries and Scripts) knowledge base.

This is a LOCAL knowledge base — no API calls needed. It checks whether
a filename matches known LOLBins/LOLLibs that attackers commonly abuse.

Project: https://lolbas-project.github.io/

Supports: filename
"""

from __future__ import annotations

import logging

from ...enums import ThreatIntelSource, ThreatIntelVerdict
from ...models import Indicator, ThreatIntelResult
from .base import BaseSource

logger = logging.getLogger(__name__)


# Curated subset of the most commonly abused LOLBins in real-world attacks.
# Full list: https://lolbas-project.github.io/
# Format: filename -> (description, MITRE ATT&CK techniques)
_LOLBAS_DB: dict[str, dict] = {
    "certutil.exe": {
        "description": "Certificate utility that can download files and decode Base64",
        "mitre": ["T1140", "T1105"],
        "abuse_functions": ["Download", "Decode", "Encode", "ADS"],
    },
    "bitsadmin.exe": {
        "description": "BITS admin tool that can download files",
        "mitre": ["T1105", "T1197"],
        "abuse_functions": ["Download", "Execute", "Copy"],
    },
    "mshta.exe": {
        "description": "Execute HTA files or inline scripts",
        "mitre": ["T1218.005"],
        "abuse_functions": ["Execute"],
    },
    "msiexec.exe": {
        "description": "Install MSI packages (can download and execute remote packages)",
        "mitre": ["T1218.007"],
        "abuse_functions": ["Execute"],
    },
    "regsvr32.exe": {
        "description": "Register COM DLLs (Squiblydoo attack vector)",
        "mitre": ["T1218.010"],
        "abuse_functions": ["Execute", "AWL Bypass"],
    },
    "rundll32.exe": {
        "description": "Execute DLL exports (commonly abused for proxy execution)",
        "mitre": ["T1218.011"],
        "abuse_functions": ["Execute", "AWL Bypass"],
    },
    "wmic.exe": {
        "description": "WMI command-line interface for system queries and execution",
        "mitre": ["T1047"],
        "abuse_functions": ["Execute", "Reconnaissance"],
    },
    "cmstp.exe": {
        "description": "Connection Manager installer (UAC bypass, AppLocker bypass)",
        "mitre": ["T1218.003"],
        "abuse_functions": ["Execute", "AWL Bypass"],
    },
    "msbuild.exe": {
        "description": "Build tool that can compile and execute inline C# tasks",
        "mitre": ["T1127.001"],
        "abuse_functions": ["Execute", "AWL Bypass", "Compile"],
    },
    "installutil.exe": {
        "description": ".NET installation utility (AppLocker bypass)",
        "mitre": ["T1218.004"],
        "abuse_functions": ["Execute", "AWL Bypass"],
    },
    "powershell.exe": {
        "description": "PowerShell scripting engine",
        "mitre": ["T1059.001"],
        "abuse_functions": ["Execute", "Download", "Encode"],
    },
    "cmd.exe": {
        "description": "Windows command interpreter",
        "mitre": ["T1059.003"],
        "abuse_functions": ["Execute"],
    },
    "wscript.exe": {
        "description": "Windows Script Host (VBScript, JScript execution)",
        "mitre": ["T1059.005"],
        "abuse_functions": ["Execute"],
    },
    "cscript.exe": {
        "description": "Console-based Windows Script Host",
        "mitre": ["T1059.005"],
        "abuse_functions": ["Execute"],
    },
    "forfiles.exe": {
        "description": "Batch utility that can execute commands",
        "mitre": ["T1202"],
        "abuse_functions": ["Execute"],
    },
    "pcalua.exe": {
        "description": "Program Compatibility Assistant (AppLocker bypass)",
        "mitre": ["T1202"],
        "abuse_functions": ["Execute", "AWL Bypass"],
    },
    "sc.exe": {
        "description": "Service Control Manager CLI (create/modify services)",
        "mitre": ["T1543.003"],
        "abuse_functions": ["Execute"],
    },
    "schtasks.exe": {
        "description": "Task scheduler CLI (persistence, execution)",
        "mitre": ["T1053.005"],
        "abuse_functions": ["Execute"],
    },
    "reg.exe": {
        "description": "Registry editor CLI (persistence, credential access)",
        "mitre": ["T1112", "T1003.002"],
        "abuse_functions": ["Execute", "Credential Dump"],
    },
    "at.exe": {
        "description": "Legacy task scheduler (deprecated but still abused)",
        "mitre": ["T1053.002"],
        "abuse_functions": ["Execute"],
    },
    "expand.exe": {
        "description": "Expands CAB files (ADS writing capability)",
        "mitre": ["T1564.004"],
        "abuse_functions": ["ADS", "Copy"],
    },
    "esentutl.exe": {
        "description": "ESE database utility (file copy via ADS, credential access)",
        "mitre": ["T1003.003", "T1564.004"],
        "abuse_functions": ["Copy", "ADS", "Credential Dump"],
    },
    "nltest.exe": {
        "description": "Domain trust enumeration tool",
        "mitre": ["T1482"],
        "abuse_functions": ["Reconnaissance"],
    },
    "netsh.exe": {
        "description": "Network shell (helper DLL loading, firewall manipulation)",
        "mitre": ["T1546.007", "T1562.004"],
        "abuse_functions": ["Execute", "Persistence"],
    },
    "desktopimgdownldr.dll": {
        "description": "Zoom DLL that can download files",
        "mitre": ["T1105"],
        "abuse_functions": ["Download"],
    },
}


class LOLBASSource(BaseSource):
    """Local LOLBAS knowledge base (no API calls needed)."""

    source = ThreatIntelSource.LOLBAS
    api_key_env = None
    supported_types = frozenset({"filename"})

    def _do_lookup(self, indicator: Indicator) -> ThreatIntelResult:
        filename = indicator.value.lower().strip()

        # Also check just the basename if a full path was given
        if "/" in filename or "\\" in filename:
            import ntpath
            filename = ntpath.basename(filename).lower()

        entry = _LOLBAS_DB.get(filename)

        if entry is None:
            return ThreatIntelResult(
                indicator_type=indicator.indicator_type,
                indicator_value=indicator.value,
                source=self.source,
                source_url="https://lolbas-project.github.io/",
                verdict=ThreatIntelVerdict.CLEAN,
                confidence=0.3,  # Low confidence — absence from LOLBAS doesn't mean clean
                details={"message": "Not a known LOLBin/LOLLib"},
            )

        return ThreatIntelResult(
            indicator_type=indicator.indicator_type,
            indicator_value=indicator.value,
            source=self.source,
            source_url=f"https://lolbas-project.github.io/lolbas/Binaries/{filename.replace('.exe', '').replace('.dll', '').title()}/",
            verdict=ThreatIntelVerdict.SUSPICIOUS,
            confidence=0.6,  # Suspicious by default — LOLBins are dual-use
            details={
                "description": entry["description"],
                "mitre_techniques": entry["mitre"],
                "abuse_functions": entry["abuse_functions"],
                "note": (
                    "LOLBins are legitimate system binaries that can be abused. "
                    "Presence alone is NOT malicious — check the command line "
                    "arguments and execution context."
                ),
            },
        )
