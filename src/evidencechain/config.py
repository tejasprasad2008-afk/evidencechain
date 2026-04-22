"""Configuration constants for EvidenceChain."""

from __future__ import annotations

import os
from pathlib import Path

# ---------------------------------------------------------------------------
# Directory paths (configurable via environment variables)
# ---------------------------------------------------------------------------

EVIDENCE_BASE_DIR = Path(os.environ.get("EVIDENCE_BASE_DIR", "/cases"))
ANALYSIS_DIR = Path(os.environ.get("ANALYSIS_DIR", "./analysis"))
EXPORTS_DIR = ANALYSIS_DIR / "exports"
REPORTS_DIR = Path(os.environ.get("REPORTS_DIR", "./reports"))
AUDIT_DIR = ANALYSIS_DIR / "audit"

# ---------------------------------------------------------------------------
# Security: Path allowlists
# ---------------------------------------------------------------------------

# Directories the agent is allowed to READ from
READ_ALLOWLIST: list[str] = [
    "/cases",
    "/mnt",
    "/tmp/evidencechain",
    str(EVIDENCE_BASE_DIR),
    str(ANALYSIS_DIR),
    str(EXPORTS_DIR),
]

# Directories the agent is allowed to WRITE to
WRITE_ALLOWLIST: list[str] = [
    str(ANALYSIS_DIR),
    str(EXPORTS_DIR),
    str(REPORTS_DIR),
    str(AUDIT_DIR),
    "/tmp/evidencechain",
]

# ---------------------------------------------------------------------------
# Security: Command denylist
# ---------------------------------------------------------------------------

# Binaries that must NEVER be executed, regardless of arguments
DENIED_BINARIES: set[str] = {
    "rm",
    "rmdir",
    "dd",
    "shred",
    "wget",
    "curl",
    "ssh",
    "scp",
    "nc",
    "ncat",
    "netcat",
    "python",
    "python3",
    "perl",
    "ruby",
    "bash",
    "sh",
    "zsh",
    "mkfs",
    "fdisk",
    "parted",
    "chmod",
    "chown",
}

# ---------------------------------------------------------------------------
# Output limits
# ---------------------------------------------------------------------------

# Maximum bytes of tool output returned to the LLM
MAX_OUTPUT_SIZE: int = int(os.environ.get("MAX_OUTPUT_SIZE", str(100 * 1024)))  # 100KB

# ---------------------------------------------------------------------------
# Self-correction engine
# ---------------------------------------------------------------------------

# Maximum verification/re-investigation iterations
MAX_CORRECTION_ITERATIONS: int = 3

# Maximum tool executions during a single re-investigation phase
MAX_REINVESTIGATION_TOOL_CALLS: int = 20

# ---------------------------------------------------------------------------
# Threat intel
# ---------------------------------------------------------------------------

# Max lookups per minute per source
THREAT_INTEL_RATE_LIMIT: int = int(os.environ.get("THREAT_INTEL_RATE_LIMIT", "10"))

# Timeout for a single WebFetch call (seconds)
THREAT_INTEL_TIMEOUT: int = 15

# ---------------------------------------------------------------------------
# Mount options
# ---------------------------------------------------------------------------

# Always mount evidence read-only
MOUNT_OPTIONS: str = "ro,loop,noatime"
