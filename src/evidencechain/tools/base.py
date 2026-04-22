"""Base tool execution wrapper.

Every forensic tool in EvidenceChain uses this base module to:
1. Validate input paths
2. Execute commands through the security guard
3. Cap output size
4. Log to the audit trail
5. Return standardized ToolResult objects
"""

from __future__ import annotations

import logging
import time

from ..config import EXPORTS_DIR
from ..models import ForensicContext, ToolExecution, ToolResult, _new_id, _utcnow
from ..enums import ToolStatus
from ..provenance.audit_logger import AuditLogger
from ..provenance.evidence_store import EvidenceStore
from ..security.command_guard import CommandDeniedError, execute
from ..security.output_cap import cap_output

logger = logging.getLogger(__name__)


class BaseToolExecutor:
    """Base class for forensic tool execution with full audit trail."""

    def __init__(
        self,
        store: EvidenceStore,
        audit: AuditLogger,
    ) -> None:
        self.store = store
        self.audit = audit

    def run_tool(
        self,
        tool_name: str,
        evidence_id: str,
        command: list[str],
        input_params: dict | None = None,
        timeout: int = 300,
        cwd: str | None = None,
    ) -> tuple[ToolResult, str]:
        """Execute a forensic tool with full audit trail.

        Args:
            tool_name: Name of the MCP tool (e.g., "parse_prefetch").
            evidence_id: Evidence source ID (e.g., "EVD-disk-001").
            command: Command to execute as a list of strings.
            input_params: Parameters passed to the tool (for logging).
            timeout: Max execution time in seconds.
            cwd: Working directory.

        Returns:
            Tuple of (ToolResult, raw_stdout).
            The ToolResult has structured_data=None — the caller is
            responsible for parsing the raw output and populating it.
        """
        execution_id = _new_id("EXE-")
        start_time = _utcnow()

        # Create execution record
        execution = ToolExecution(
            execution_id=execution_id,
            tool_name=tool_name,
            evidence_id=evidence_id,
            command=command,
            input_params=input_params or {},
            started_at=start_time,
        )

        try:
            exec_result = execute(command, timeout=timeout, cwd=cwd)
        except CommandDeniedError as e:
            execution.status = ToolStatus.ERROR
            execution.error_message = str(e)
            execution.completed_at = _utcnow()
            self.store.add_execution(execution)
            self.audit.log_execution(execution)

            return ToolResult(
                tool_name=tool_name,
                evidence_id=evidence_id,
                execution_id=execution_id,
                status=ToolStatus.ERROR,
                error_message=str(e),
            ), ""

        # Save and cap output
        save_path = str(EXPORTS_DIR / tool_name / f"{execution_id}.raw")
        capped_output, truncated, output_hash = cap_output(
            exec_result.stdout, save_path=save_path
        )

        # Complete execution record
        execution.completed_at = _utcnow()
        execution.duration_seconds = exec_result.duration_seconds
        execution.exit_code = exec_result.exit_code
        execution.stdout_hash = output_hash
        execution.stderr_summary = exec_result.stderr[:500] if exec_result.stderr else ""
        execution.raw_output_path = save_path
        execution.status = (
            ToolStatus.SUCCESS if exec_result.exit_code == 0 else ToolStatus.ERROR
        )

        if exec_result.exit_code != 0:
            execution.error_message = (
                f"Exit code {exec_result.exit_code}: {exec_result.stderr[:200]}"
            )

        self.store.add_execution(execution)
        self.audit.log_execution(execution)

        tool_result = ToolResult(
            tool_name=tool_name,
            evidence_id=evidence_id,
            execution_id=execution_id,
            timestamp_utc=start_time,
            duration_seconds=exec_result.duration_seconds,
            status=execution.status,
            command_executed=command,
            raw_output_path=save_path,
            truncated=truncated,
            error_message=execution.error_message,
        )

        return tool_result, exec_result.stdout

    @staticmethod
    def build_forensic_context(
        proves: list[str] | None = None,
        suggests: list[str] | None = None,
        cannot_prove: list[str] | None = None,
        caveats: list[str] | None = None,
        corroboration_hints: list[str] | None = None,
    ) -> ForensicContext:
        """Build a ForensicContext with provided values."""
        return ForensicContext(
            proves=proves or [],
            suggests=suggests or [],
            cannot_prove=cannot_prove or [],
            caveats=caveats or [],
            corroboration_hints=corroboration_hints or [],
        )
