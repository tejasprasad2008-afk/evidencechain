"""Amcache (AmcacheParser) output validator.

Parses CSV output from AmcacheParser and produces EvidenceAtoms.
Amcache PROVES execution and provides SHA1 hashes for threat intel pivoting.
"""

from __future__ import annotations

import csv
import io
import logging

from ..enums import ArtifactType, EvidenceSemantics, TimestampSemanticType
from ..forensic_semantics import get_semantics
from ..models import EvidenceAtom, TimestampRecord
from .base import BaseValidator, ValidatorResult, ValidationWarning
from .timestamps import validate_timestamps

logger = logging.getLogger(__name__)


class AmcacheValidator(BaseValidator):
    """Validator for AmcacheParser CSV output."""

    def validate(
        self,
        execution_id: str,
        raw_output: str,
        **kwargs,
    ) -> ValidatorResult:
        result = ValidatorResult()
        semantics = get_semantics(ArtifactType.AMCACHE)

        if not raw_output.strip():
            result.warnings.append(
                ValidationWarning(message="Empty Amcache output", severity="warning")
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
                        message=f"Failed to parse Amcache row: {e}",
                        severity="warning",
                    )
                )

        logger.info("Amcache validator: %d atoms from %d records", len(result.atoms), result.record_count)
        return result

    def _parse_row(
        self,
        row: dict,
        execution_id: str,
        semantics: dict,
    ) -> EvidenceAtom | None:
        # AmcacheParser outputs vary between versions
        full_path = (
            row.get("FullPath", "")
            or row.get("ApplicationPath", "")
            or row.get("Path", "")
            or row.get("ProgramName", "")
        ).strip()

        name = (
            row.get("ProgramName", "")
            or row.get("Name", "")
            or row.get("FileName", "")
        ).strip()

        if not full_path and not name:
            return None

        sha1 = (
            row.get("SHA1", "")
            or row.get("Sha1", "")
            or row.get("FileHash", "")
        ).strip()

        # Clean up SHA1 - AmcacheParser sometimes prefixes with "0000"
        if sha1 and sha1.startswith("0000"):
            sha1 = sha1[4:]

        timestamps = []

        # Key timestamp for Amcache
        key_last_write = (
            row.get("KeyLastWriteTimestamp", "")
            or row.get("FileKeyLastWriteTimestamp", "")
            or row.get("LastWriteTime", "")
        ).strip()
        if key_last_write:
            timestamps.append(
                TimestampRecord(
                    value=key_last_write,
                    source_field="KeyLastWriteTimestamp",
                    semantic_type=TimestampSemanticType.FIRST_RUN,
                )
            )

        # File creation / link date
        link_date = row.get("LinkDate", row.get("InstallDate", "")).strip()
        if link_date:
            timestamps.append(
                TimestampRecord(
                    value=link_date,
                    source_field="LinkDate",
                    semantic_type=TimestampSemanticType.CREATED,
                )
            )

        return EvidenceAtom(
            tool_name="AmcacheParser",
            execution_id=execution_id,
            artifact_type=ArtifactType.AMCACHE,
            raw_data={
                "full_path": full_path,
                "program_name": name,
                "sha1": sha1,
                "publisher": row.get("Publisher", row.get("CompanyName", "")).strip(),
                "version": row.get("Version", row.get("FileVersion", "")).strip(),
                "file_size": row.get("Size", row.get("FileSize", "")).strip(),
                "language": row.get("Language", "").strip(),
            },
            timestamps=timestamps,
            file_references=[full_path] if full_path else [],
            proves=set(semantics.get("proves", set())),
            suggests=set(semantics.get("suggests", set())),
            cannot_prove=set(semantics.get("cannot_prove", set())),
        )
