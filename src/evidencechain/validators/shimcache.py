"""Shimcache (AppCompatCacheParser) output validator.

Parses CSV output from AppCompatCacheParser and produces EvidenceAtoms
with the correct forensic semantics: Shimcache proves PRESENCE on
Windows 8+, NOT execution.
"""

from __future__ import annotations

import csv
import io
import logging

from ..enums import ArtifactType, EvidenceSemantics, TimestampSemanticType
from ..forensic_semantics import get_semantics
from ..models import EvidenceAtom, TimestampRecord
from .base import BaseValidator, OverclaimFlag, ValidatorResult, ValidationWarning
from .timestamps import validate_timestamps

logger = logging.getLogger(__name__)


class ShimcacheValidator(BaseValidator):
    """Validator for AppCompatCacheParser CSV output."""

    def validate(
        self,
        execution_id: str,
        raw_output: str,
        **kwargs,
    ) -> ValidatorResult:
        result = ValidatorResult()
        semantics = get_semantics(ArtifactType.SHIMCACHE)

        if not raw_output.strip():
            result.warnings.append(
                ValidationWarning(message="Empty Shimcache output", severity="warning")
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
                        message=f"Failed to parse Shimcache row: {e}",
                        severity="warning",
                    )
                )

        # Add overclaim flag for the entire result set
        result.overclaim_flags.append(
            OverclaimFlag(
                message=(
                    "Shimcache on Windows 8+ proves file PRESENCE only, NOT execution. "
                    "Do NOT claim a file was 'executed' based solely on Shimcache evidence."
                ),
                claimed_semantic=EvidenceSemantics.EXECUTION,
                actual_semantic=EvidenceSemantics.PRESENCE,
            )
        )

        logger.info("Shimcache validator: %d atoms from %d records", len(result.atoms), result.record_count)
        return result

    def _parse_row(
        self,
        row: dict,
        execution_id: str,
        semantics: dict,
    ) -> EvidenceAtom | None:
        # AppCompatCacheParser CSV columns vary; handle common column names
        path = (
            row.get("Path", "")
            or row.get("path", "")
            or row.get("FileName", "")
            or row.get("CachePath", "")
        ).strip()

        if not path:
            return None

        last_modified = (
            row.get("LastModifiedTimeUTC", "")
            or row.get("LastModified", "")
            or row.get("LastModifiedTime", "")
            or row.get("Modified", "")
        ).strip()

        timestamps = []
        if last_modified:
            timestamps.append(
                TimestampRecord(
                    value=last_modified,
                    source_field="LastModifiedTimeUTC",
                    semantic_type=TimestampSemanticType.MODIFIED,
                )
            )

        return EvidenceAtom(
            tool_name="AppCompatCacheParser",
            execution_id=execution_id,
            artifact_type=ArtifactType.SHIMCACHE,
            raw_data={
                "path": path,
                "last_modified": last_modified,
                "cache_entry_position": row.get("CacheEntryPosition", row.get("ControlSet", "")),
            },
            timestamps=timestamps,
            file_references=[path],
            proves=set(semantics.get("proves", set())),
            suggests=set(semantics.get("suggests", set())),
            cannot_prove=set(semantics.get("cannot_prove", set())),
        )
