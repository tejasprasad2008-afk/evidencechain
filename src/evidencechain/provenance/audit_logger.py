"""Append-only JSONL audit logger.

Every tool execution, finding registration, and contradiction detection
is logged here. The audit trail is the backbone of evidence tracing —
judges must be able to follow any finding back to the exact tool call.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict
from pathlib import Path

from ..config import AUDIT_DIR

logger = logging.getLogger(__name__)


class AuditLogger:
    """Append-only JSONL logger for forensic audit trails."""

    def __init__(self, audit_dir: Path | None = None) -> None:
        self._audit_dir = audit_dir or AUDIT_DIR
        self._audit_dir.mkdir(parents=True, exist_ok=True)
        self._files: dict[str, Path] = {}

    def _get_file(self, log_name: str) -> Path:
        """Get or create a log file path."""
        if log_name not in self._files:
            path = self._audit_dir / f"{log_name}.jsonl"
            self._files[log_name] = path
        return self._files[log_name]

    def _serialize(self, obj: object) -> dict:
        """Convert an object to a JSON-serializable dict."""
        if hasattr(obj, "__dataclass_fields__"):
            data = asdict(obj)
            # Convert sets to sorted lists for JSON
            for key, value in data.items():
                if isinstance(value, set):
                    data[key] = sorted(value)
            return data
        if isinstance(obj, dict):
            return obj
        return {"value": str(obj)}

    def log(self, log_name: str, record: object) -> None:
        """Append a record to the named JSONL log file.

        Args:
            log_name: Name of the log (e.g., "execution_log", "findings_log").
            record: A dataclass instance or dict to log.
        """
        path = self._get_file(log_name)
        data = self._serialize(record)
        line = json.dumps(data, default=str, ensure_ascii=False)
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
        logger.debug("Audit[%s]: %s", log_name, line[:200])

    def log_execution(self, execution: object) -> None:
        """Log a tool execution record."""
        self.log("execution_log", execution)

    def log_finding(self, finding: object) -> None:
        """Log a finding registration or update."""
        self.log("findings_log", finding)

    def log_contradiction(self, contradiction: object) -> None:
        """Log a detected contradiction."""
        self.log("contradiction_log", contradiction)

    def log_correction(self, correction: object) -> None:
        """Log a correction iteration."""
        self.log("correction_log", correction)

    def read_log(self, log_name: str) -> list[dict]:
        """Read all records from a JSONL log file."""
        path = self._get_file(log_name)
        if not path.exists():
            return []
        records = []
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        return records
