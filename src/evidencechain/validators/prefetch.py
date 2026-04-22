"""Prefetch (PECmd) output validator.

Parses CSV output from PECmd and produces EvidenceAtoms.
Prefetch PROVES execution with up to 8 most recent run timestamps.
"""

from __future__ import annotations

import csv
import io
import logging
import re

from ..enums import ArtifactType, EvidenceSemantics, TimestampSemanticType
from ..forensic_semantics import get_semantics
from ..models import EvidenceAtom, TimestampRecord
from .base import BaseValidator, ValidatorResult, ValidationWarning
from .timestamps import validate_timestamps

logger = logging.getLogger(__name__)


class PrefetchValidator(BaseValidator):
    """Validator for PECmd CSV output."""

    def validate(
        self,
        execution_id: str,
        raw_output: str,
        **kwargs,
    ) -> ValidatorResult:
        result = ValidatorResult()
        semantics = get_semantics(ArtifactType.PREFETCH)

        if not raw_output.strip():
            result.warnings.append(
                ValidationWarning(message="Empty Prefetch output", severity="warning")
            )
            return result

        reader = csv.DictReader(io.StringIO(raw_output))

        for row in reader:
            try:
                atom = self._parse_row(row, execution_id, semantics)
                if atom:
                    ts_warnings = validate_timestamps(atom)
                    result.warnings.extend(ts_warnings)
                    result.atoms.append(atom)
                    result.record_count += 1
            except Exception as e:
                result.warnings.append(
                    ValidationWarning(
                        message=f"Failed to parse Prefetch row: {e}",
                        severity="warning",
                    )
                )

        logger.info("Prefetch validator: %d atoms from %d records", len(result.atoms), result.record_count)
        return result

    def _parse_row(
        self,
        row: dict,
        execution_id: str,
        semantics: dict,
    ) -> EvidenceAtom | None:
        executable = (
            row.get("ExecutableName", "")
            or row.get("SourceFilename", "")
            or row.get("Executable", "")
        ).strip()

        if not executable:
            return None

        # Extract run timestamps (PECmd outputs up to 8 in various column formats)
        timestamps = []

        # Last run time
        last_run = (
            row.get("LastRun", "")
            or row.get("SourceCreated", "")
        ).strip()
        if last_run:
            timestamps.append(
                TimestampRecord(
                    value=last_run,
                    source_field="LastRun",
                    semantic_type=TimestampSemanticType.LAST_RUN,
                )
            )

        # Previous run times (PECmd uses PreviousRun0 through PreviousRun6)
        for i in range(7):
            key = f"PreviousRun{i}"
            val = row.get(key, "").strip()
            if val:
                timestamps.append(
                    TimestampRecord(
                        value=val,
                        source_field=key,
                        semantic_type=TimestampSemanticType.LAST_RUN,
                    )
                )

        run_count_str = row.get("RunCount", "0").strip()
        try:
            run_count = int(run_count_str)
        except ValueError:
            run_count = 0

        # Source file path (the .pf file)
        source_path = row.get("SourceFilename", row.get("SourceFile", "")).strip()

        # Directories referenced by the prefetch file
        dirs_raw = row.get("Directories", "").strip()
        volume_info = row.get("Volume0Name", "").strip()

        return EvidenceAtom(
            tool_name="PECmd",
            execution_id=execution_id,
            artifact_type=ArtifactType.PREFETCH,
            raw_data={
                "executable_name": executable,
                "run_count": run_count,
                "last_run": last_run,
                "source_file": source_path,
                "volume": volume_info,
                "directories": dirs_raw[:500],  # Cap large directory lists
                "hash": row.get("Hash", "").strip(),
            },
            timestamps=timestamps,
            file_references=[executable, source_path] if source_path else [executable],
            proves=set(semantics.get("proves", set())),
            suggests=set(semantics.get("suggests", set())),
            cannot_prove=set(semantics.get("cannot_prove", set())),
        )
