"""Path validation with allowlist/denylist enforcement.

All file paths passed to forensic tools are validated here before any
subprocess call. This is an ARCHITECTURAL security boundary — not prompt-based.
"""

from __future__ import annotations

import os
from pathlib import Path

from ..config import READ_ALLOWLIST, WRITE_ALLOWLIST


class PathValidationError(Exception):
    """Raised when a path fails validation."""


def _resolve_real(path: str) -> Path:
    """Resolve a path to its real absolute form, following symlinks."""
    return Path(path).resolve()


def validate_read_path(path: str) -> Path:
    """Validate that a path is allowed for reading.

    Resolves symlinks, rejects path traversal, and checks against the read
    allowlist.

    Returns the resolved Path if valid.
    Raises PathValidationError if invalid.
    """
    resolved = _resolve_real(path)

    # Reject path traversal patterns in the raw input
    if ".." in Path(path).parts:
        raise PathValidationError(
            f"Path traversal detected in '{path}'. Resolved to '{resolved}'."
        )

    # Check against allowlist (exact match or proper child via os.sep)
    resolved_str = str(resolved)
    for allowed in READ_ALLOWLIST:
        allowed_resolved = str(Path(allowed).resolve())
        if resolved_str == allowed_resolved or resolved_str.startswith(allowed_resolved + os.sep):
            return resolved

    raise PathValidationError(
        f"Path '{path}' (resolved: '{resolved}') is not in the read allowlist. "
        f"Allowed prefixes: {READ_ALLOWLIST}"
    )


def validate_write_path(path: str) -> Path:
    """Validate that a path is allowed for writing.

    Resolves symlinks, rejects path traversal, and checks against the write
    allowlist.

    Returns the resolved Path if valid.
    Raises PathValidationError if invalid.
    """
    resolved = _resolve_real(path)

    if ".." in Path(path).parts:
        raise PathValidationError(
            f"Path traversal detected in '{path}'. Resolved to '{resolved}'."
        )

    resolved_str = str(resolved)
    for allowed in WRITE_ALLOWLIST:
        allowed_resolved = str(Path(allowed).resolve())
        if resolved_str == allowed_resolved or resolved_str.startswith(allowed_resolved + os.sep):
            return resolved

    raise PathValidationError(
        f"Path '{path}' (resolved: '{resolved}') is not in the write allowlist. "
        f"Allowed prefixes: {WRITE_ALLOWLIST}"
    )


def ensure_directory(path: str) -> Path:
    """Create a directory (and parents) if it doesn't exist, after validating write access."""
    validated = validate_write_path(path)
    validated.mkdir(parents=True, exist_ok=True)
    return validated
