"""Evidence ID management.

Generates and tracks deterministic evidence IDs:
  - EVD-disk-001, EVD-disk-002, ...
  - EVD-mem-001, EVD-mem-002, ...
"""

from __future__ import annotations

import threading


class EvidenceRegistry:
    """Manages evidence source registration and ID assignment."""

    def __init__(self) -> None:
        self._counters: dict[str, int] = {}
        self._evidence: dict[str, dict] = {}  # evidence_id -> metadata
        self._lock = threading.Lock()

    def register(
        self,
        source_type: str,
        path: str,
        sha256: str = "",
        metadata: dict | None = None,
    ) -> str:
        """Register a new evidence source and return its ID.

        Args:
            source_type: Type of evidence ("disk", "mem", "network", "logs").
            path: Path to the evidence file.
            sha256: SHA-256 hash of the evidence file.
            metadata: Additional metadata about the evidence.

        Returns:
            Evidence ID string like "EVD-disk-001".
        """
        with self._lock:
            self._counters.setdefault(source_type, 0)
            self._counters[source_type] += 1
            seq = self._counters[source_type]

            evidence_id = f"EVD-{source_type}-{seq:03d}"

            self._evidence[evidence_id] = {
                "evidence_id": evidence_id,
                "source_type": source_type,
                "path": path,
                "sha256": sha256,
                **(metadata or {}),
            }

            return evidence_id

    def get(self, evidence_id: str) -> dict | None:
        """Get metadata for a registered evidence source."""
        with self._lock:
            item = self._evidence.get(evidence_id)
            return dict(item) if item is not None else None

    def list_all(self) -> list[dict]:
        """List all registered evidence sources."""
        with self._lock:
            return [dict(item) for item in self._evidence.values()]

    def exists(self, evidence_id: str) -> bool:
        """Check if an evidence ID is registered."""
        with self._lock:
            return evidence_id in self._evidence
