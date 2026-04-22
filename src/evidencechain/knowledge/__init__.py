"""Forensic knowledge bases: Windows baselines, tool caveats, MITRE ATT&CK mapping."""

from .forensic_kb import (
    CATEGORY_NARRATIVES,
    MITRE_TECHNIQUES,
    WINDOWS_PROCESS_BASELINES,
    get_technique,
    get_techniques_for_finding,
)

__all__ = [
    "CATEGORY_NARRATIVES",
    "MITRE_TECHNIQUES",
    "WINDOWS_PROCESS_BASELINES",
    "get_technique",
    "get_techniques_for_finding",
]
