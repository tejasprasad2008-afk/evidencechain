"""Event log (EvtxECmd) output validator.

Parses CSV output from EvtxECmd and produces EvidenceAtoms with
per-Event-ID forensic context. Different Event IDs prove different things:
- 4624/4625: Authentication (proves logon attempt)
- 4688: Process creation (proves execution when command line enabled)
- 7045: Service install (proves persistence)
- 1102/104: Log clearing (proves anti-forensics)
- 1116: Defender detection (suggests malware)

Also detects timeline gaps: periods where expected log continuity is broken,
which may indicate log clearing or system downtime.
"""

from __future__ import annotations

import csv
import io
import logging
from datetime import datetime, timedelta, timezone

from ..enums import ArtifactType, EvidenceSemantics, TimestampSemanticType
from ..forensic_semantics import get_semantics
from ..models import EvidenceAtom, TimestampRecord
from .base import BaseValidator, OverclaimFlag, ValidatorResult, ValidationWarning
from .timestamps import validate_timestamps

logger = logging.getLogger(__name__)

# Forensic significance of key Event IDs
EVENT_ID_CONTEXT: dict[int, dict] = {
    # Security log — authentication
    4624: {
        "description": "Successful logon",
        "proves": {EvidenceSemantics.USER_INTERACTION},
        "suggests": set(),
    },
    4625: {
        "description": "Failed logon attempt",
        "proves": set(),
        "suggests": {EvidenceSemantics.CREDENTIAL_ACCESS},
    },
    4648: {
        "description": "Explicit credential logon (runas/pass-the-hash)",
        "proves": set(),
        "suggests": {EvidenceSemantics.LATERAL_MOVEMENT, EvidenceSemantics.CREDENTIAL_ACCESS},
    },
    # Security log — process
    4688: {
        "description": "Process creation",
        "proves": {EvidenceSemantics.EXECUTION},
        "suggests": set(),
    },
    # System log — services
    7045: {
        "description": "Service installed",
        "proves": {EvidenceSemantics.PERSISTENCE},
        "suggests": set(),
    },
    7036: {
        "description": "Service started/stopped",
        "proves": set(),
        "suggests": {EvidenceSemantics.PERSISTENCE},
    },
    # Security log — anti-forensics
    1102: {
        "description": "Security log cleared",
        "proves": set(),
        "suggests": {EvidenceSemantics.LOG_CLEARING},
    },
    104: {
        "description": "System log cleared",
        "proves": set(),
        "suggests": {EvidenceSemantics.LOG_CLEARING},
    },
    # Defender / Sysmon
    1116: {
        "description": "Windows Defender detection",
        "proves": set(),
        "suggests": {EvidenceSemantics.KNOWN_MALWARE},
    },
    1: {
        "description": "Sysmon process creation",
        "proves": {EvidenceSemantics.EXECUTION},
        "suggests": set(),
    },
    3: {
        "description": "Sysmon network connection",
        "proves": {EvidenceSemantics.NETWORK_CONNECTION},
        "suggests": set(),
    },
    # PowerShell
    4104: {
        "description": "PowerShell script block logging",
        "proves": {EvidenceSemantics.EXECUTION},
        "suggests": set(),
    },
}

# Gap threshold — if no events for this long in a log, flag it
_GAP_THRESHOLD = timedelta(hours=6)


class EvtxValidator(BaseValidator):
    """Validator for EvtxECmd CSV output with timeline gap detection."""

    def validate(
        self,
        execution_id: str,
        raw_output: str,
        **kwargs,
    ) -> ValidatorResult:
        result = ValidatorResult()
        base_semantics = get_semantics(ArtifactType.EVTX_EVENT)

        if not raw_output.strip():
            result.warnings.append(
                ValidationWarning(message="Empty EVTX output", severity="warning")
            )
            return result

        reader = csv.DictReader(io.StringIO(raw_output))

        # Track event timestamps for gap detection
        event_datetimes: list[datetime] = []
        log_clear_count = 0

        for row in reader:
            try:
                atom = self._parse_row(row, execution_id, base_semantics)
                if atom:
                    ts_warnings = validate_timestamps(atom)
                    result.warnings.extend(ts_warnings)
                    result.atoms.append(atom)
                    result.record_count += 1

                    # Track for gap detection
                    event_dt = self._extract_event_datetime(row)
                    if event_dt:
                        event_datetimes.append(event_dt)

                    # Count log clearing events
                    event_id = self._get_event_id(row)
                    if event_id in (1102, 104):
                        log_clear_count += 1

            except Exception as e:
                result.warnings.append(
                    ValidationWarning(
                        message=f"Failed to parse EVTX row: {e}",
                        severity="warning",
                    )
                )

        # Timeline gap detection
        gaps = self._detect_gaps(event_datetimes)
        for gap_start, gap_end, gap_duration in gaps:
            result.warnings.append(
                ValidationWarning(
                    message=(
                        f"TIMELINE GAP: No events from {gap_start.isoformat()} to "
                        f"{gap_end.isoformat()} ({gap_duration.total_seconds() / 3600:.1f} hours). "
                        "This may indicate log clearing, system shutdown, or data loss."
                    ),
                    field="TimeCreated",
                    severity="error",
                )
            )

        if log_clear_count > 0:
            result.overclaim_flags.append(
                OverclaimFlag(
                    message=(
                        f"LOG CLEARING DETECTED: {log_clear_count} log clearing event(s) found "
                        "(Event IDs 1102/104). Absence of events after these points "
                        "does NOT prove absence of activity."
                    ),
                    claimed_semantic="absence_of_evidence",
                    actual_semantic=EvidenceSemantics.LOG_CLEARING,
                )
            )

        logger.info(
            "EVTX validator: %d atoms, %d gaps, %d log clears",
            len(result.atoms),
            len(gaps),
            log_clear_count,
        )
        return result

    def _get_event_id(self, row: dict) -> int | None:
        """Extract Event ID from a row, handling column name variants."""
        for col in ("EventId", "EventID", "Event Id", "Id"):
            val = row.get(col, "").strip()
            if val:
                try:
                    return int(val)
                except ValueError:
                    continue
        return None

    def _parse_row(
        self,
        row: dict,
        execution_id: str,
        base_semantics: dict,
    ) -> EvidenceAtom | None:
        event_id = self._get_event_id(row)
        if event_id is None:
            return None

        # Resolve timestamp
        time_created = (
            row.get("TimeCreated", "")
            or row.get("Timestamp", "")
            or row.get("DateUtc", "")
        ).strip()

        timestamps = []
        if time_created:
            timestamps.append(
                TimestampRecord(
                    value=time_created,
                    source_field="TimeCreated",
                    semantic_type=TimestampSemanticType.EVENT_TIME,
                )
            )

        # Event-specific context
        evt_context = EVENT_ID_CONTEXT.get(event_id, {})
        proves = set(evt_context.get("proves", set()))
        suggests = set(evt_context.get("suggests", set()))
        cannot_prove = set(base_semantics.get("cannot_prove", set()))

        # Source / channel
        channel = (
            row.get("Channel", "")
            or row.get("LogName", "")
        ).strip()
        computer = row.get("Computer", row.get("ComputerName", "")).strip()
        provider = row.get("Provider", row.get("SourceName", "")).strip()

        # Payload fields (EvtxECmd puts XML payload in "Payload" or maps common fields)
        payload_data = {}
        for key in ("Payload", "PayloadData1", "PayloadData2", "PayloadData3",
                     "PayloadData4", "PayloadData5", "PayloadData6",
                     "MapDescription", "UserName", "RemoteHost",
                     "ExecutableInfo", "ServiceName", "CommandLine"):
            val = row.get(key, "").strip()
            if val:
                payload_data[key] = val[:500]  # Cap large payloads

        # Extract process info if available (Event 4688, Sysmon 1)
        file_refs = []
        if event_id in (4688, 1):
            new_process = (
                payload_data.get("ExecutableInfo", "")
                or payload_data.get("PayloadData1", "")
            )
            if new_process:
                file_refs.append(new_process)

        return EvidenceAtom(
            tool_name="EvtxECmd",
            execution_id=execution_id,
            artifact_type=ArtifactType.EVTX_EVENT,
            raw_data={
                "event_id": event_id,
                "channel": channel,
                "computer": computer,
                "provider": provider,
                "description": evt_context.get("description", ""),
                **payload_data,
            },
            timestamps=timestamps,
            file_references=file_refs,
            proves=proves,
            suggests=suggests,
            cannot_prove=cannot_prove,
        )

    def _extract_event_datetime(self, row: dict) -> datetime | None:
        """Parse the event timestamp into a datetime for gap detection."""
        from .timestamps import parse_timestamp

        time_str = (
            row.get("TimeCreated", "")
            or row.get("Timestamp", "")
            or row.get("DateUtc", "")
        ).strip()
        return parse_timestamp(time_str) if time_str else None

    def _detect_gaps(
        self,
        event_datetimes: list[datetime],
    ) -> list[tuple[datetime, datetime, timedelta]]:
        """Detect gaps in event timeline exceeding the threshold.

        Returns list of (gap_start, gap_end, duration) tuples.
        """
        if len(event_datetimes) < 2:
            return []

        sorted_dts = sorted(event_datetimes)
        gaps = []

        for i in range(1, len(sorted_dts)):
            diff = sorted_dts[i] - sorted_dts[i - 1]
            if diff > _GAP_THRESHOLD:
                gaps.append((sorted_dts[i - 1], sorted_dts[i], diff))

        return gaps
