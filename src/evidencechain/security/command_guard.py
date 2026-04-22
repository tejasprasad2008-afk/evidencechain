"""Command execution guard with binary denylist.

Every subprocess call in EvidenceChain goes through this module.
This is an ARCHITECTURAL security boundary:
  - shell=True is NEVER used
  - Denied binaries are blocked before execution
  - All executions are logged
"""

from __future__ import annotations

import hashlib
import logging
import subprocess
import time
from dataclasses import dataclass

from ..config import DENIED_BINARIES

logger = logging.getLogger(__name__)


class CommandDeniedError(Exception):
    """Raised when a command is blocked by the denylist."""


@dataclass
class ExecutionResult:
    """Result of a guarded subprocess execution."""

    command: list[str]
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    stdout_hash: str  # SHA-256 of raw stdout


def execute(
    command: list[str],
    timeout: int = 300,
    cwd: str | None = None,
) -> ExecutionResult:
    """Execute a command with security guards.

    Args:
        command: Command as a list of strings (NO shell interpretation).
        timeout: Maximum execution time in seconds.
        cwd: Working directory for the command.

    Returns:
        ExecutionResult with stdout, stderr, exit code, timing, and hash.

    Raises:
        CommandDeniedError: If the binary is on the denylist.
        subprocess.TimeoutExpired: If execution exceeds timeout.
    """
    if not command:
        raise CommandDeniedError("Empty command.")

    binary = command[0].split("/")[-1]  # Handle full paths like /usr/bin/rm

    if binary in DENIED_BINARIES:
        raise CommandDeniedError(
            f"Binary '{binary}' is on the denylist and cannot be executed. "
            f"Denied binaries: {sorted(DENIED_BINARIES)}"
        )

    # Additional check: reject if any argument looks like shell metacharacters
    # being used to chain commands
    dangerous_patterns = ["|", "&&", "||", ";", "`", "$(", ">>", ">"]
    for arg in command[1:]:
        for pattern in dangerous_patterns:
            if pattern in arg and not arg.startswith("-"):
                raise CommandDeniedError(
                    f"Suspicious shell metacharacter '{pattern}' found in argument '{arg}'. "
                    "All commands are executed without shell interpretation."
                )

    logger.info("Executing: %s", " ".join(command))
    start_time = time.monotonic()

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,  # NEVER use shell=True
            cwd=cwd,
        )
    except FileNotFoundError:
        elapsed = time.monotonic() - start_time
        return ExecutionResult(
            command=command,
            exit_code=-1,
            stdout="",
            stderr=f"Binary not found: {command[0]}",
            duration_seconds=elapsed,
            stdout_hash="",
        )

    elapsed = time.monotonic() - start_time
    stdout_hash = hashlib.sha256(result.stdout.encode()).hexdigest()

    logger.info(
        "Completed: %s (exit=%d, %.1fs, %d bytes stdout)",
        binary,
        result.returncode,
        elapsed,
        len(result.stdout),
    )

    return ExecutionResult(
        command=command,
        exit_code=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
        duration_seconds=elapsed,
        stdout_hash=stdout_hash,
    )
