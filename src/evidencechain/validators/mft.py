"""MFT (MFTECmd) output validator.

Parses CSV output from MFTECmd and produces EvidenceAtoms.
Built-in timestomping detection: compares $STANDARD_INFO vs $FILE_NAME
timestamps for each entry. A discrepancy > 2 seconds is a strong indicator.

MFT entries PROVE: file modification metadata.
MFT entries SUGGEST: timestomping (when $SI vs $FN differ).
MFT entries CANNOT PROVE: user interaction, who created the file.
"""

from __future__ import annotations

import csv
import io
import logging

from ..enums import ArtifactType, EvidenceSemantics, TimestampSemanticType
from ..forensic_semantics import get_semantics
from ..models import EvidenceAtom, TimestampRecord
from .base import BaseValidator, OverclaimFlag, ValidatorResult, ValidationWarning
from .timestamps import (
    check_creation_after_modification,
    check_si_fn_discrepancy,
    validate_timestamps,
)

logger = logging.getLogger(__name__)

# Column name variants across MFTECmd versions
_PATH_COLS = ("FileName", "FilePath", "FullPath", "ParentPath")
_ENTRY_COLS = ("EntryNumber", "SequenceNumber")


class MftValidator(BaseValidator):
    """Validator for MFTECmd CSV output with timestomping detection."""

    def validate(
        self,
        execution_id: str,
        raw_output: str,
        **kwargs,
    ) -> ValidatorResult:
        result = ValidatorResult()
        semantics = get_semantics(ArtifactType.MFT_ENTRY)

        if not raw_output.strip():
            result.warnings.append(
                ValidationWarning(message="Empty MFT output", severity="warning")
            )
            return result

        reader = csv.DictReader(io.StringIO(raw_output))

        timestomping_count = 0

        for row in reader:
            try:
                atom, stomped = self._parse_row(row, execution_id, semantics)
                if atom:
                    ts_warnings = validate_timestamps(atom)
                    result.warnings.extend(ts_warnings)
                    result.atoms.append(atom)
                    result.record_count += 1
                    if stomped:
                        timestomping_count += 1
            except Exception as e:
                result.warnings.append(
                    ValidationWarning(
                        message=f"Failed to parse MFT row: {e}",
                        severity="warning",
                    )
                )

        if timestomping_count > 0:
            result.overclaim_flags.append(
                OverclaimFlag(
                    message=(
                        f"TIMESTOMPING DETECTED in {timestomping_count} MFT entries. "
                        "$STANDARD_INFO timestamps differ significantly from $FILE_NAME timestamps. "
                        "$FILE_NAME timestamps are harder to forge and should be treated as more reliable."
                    ),
                    claimed_semantic=EvidenceSemantics.FILE_MODIFICATION,
                    actual_semantic=EvidenceSemantics.TIMESTOMPING,
                )
            )

        logger.info(
            "MFT validator: %d atoms, %d timestomping indicators",
            len(result.atoms),
            timestomping_count,
        )
        return result

    def _parse_row(
        self,
        row: dict,
        execution_id: str,
        semantics: dict,
    ) -> tuple[EvidenceAtom | None, bool]:
        """Parse a single MFT CSV row.

        Returns:
            Tuple of (EvidenceAtom or None, timestomping_detected: bool).
        """
        # Resolve filename / path
        filename = ""
        for col in _PATH_COLS:
            val = row.get(col, "").strip()
            if val:
                filename = val
                break

        parent_path = row.get("ParentPath", "").strip()
        if parent_path and filename and not filename.startswith(parent_path):
            full_path = f"{parent_path}\\{filename}"
        else:
            full_path = filename

        if not full_path:
            return None, False

        # --- Extract all 8 MFT timestamps (4 $SI + 4 $FN) ---
        timestamps: list[TimestampRecord] = []
        raw_ts: dict[str, str] = {}

        # $STANDARD_INFO timestamps
        si_fields = {
            "Created0x10": (TimestampSemanticType.CREATED, "$STANDARD_INFO"),
            "LastModified0x10": (TimestampSemanticType.MODIFIED, "$STANDARD_INFO"),
            "LastRecordChange0x10": (TimestampSemanticType.MFT_MODIFIED, "$STANDARD_INFO"),
            "LastAccess0x10": (TimestampSemanticType.ACCESSED, "$STANDARD_INFO"),
        }
        for col, (sem_type, attr_src) in si_fields.items():
            val = row.get(col, "").strip()
            if val:
                timestamps.append(
                    TimestampRecord(
                        value=val,
                        source_field=col,
                        semantic_type=sem_type,
                        attribute_source=attr_src,
                    )
                )
                raw_ts[col] = val

        # $FILE_NAME timestamps
        fn_fields = {
            "Created0x30": (TimestampSemanticType.CREATED, "$FILE_NAME"),
            "LastModified0x30": (TimestampSemanticType.MODIFIED, "$FILE_NAME"),
            "LastRecordChange0x30": (TimestampSemanticType.MFT_MODIFIED, "$FILE_NAME"),
            "LastAccess0x30": (TimestampSemanticType.ACCESSED, "$FILE_NAME"),
        }
        for col, (sem_type, attr_src) in fn_fields.items():
            val = row.get(col, "").strip()
            if val:
                timestamps.append(
                    TimestampRecord(
                        value=val,
                        source_field=col,
                        semantic_type=sem_type,
                        attribute_source=attr_src,
                    )
                )
                raw_ts[col] = val

        # --- Timestomping detection ---
        timestomping_detected = False
        ts_warnings: list[ValidationWarning] = []

        # Compare $SI_Created vs $FN_Created
        si_created = raw_ts.get("Created0x10")
        fn_created = raw_ts.get("Created0x30")
        stomp_warn = check_si_fn_discrepancy(si_created, fn_created)
        if stomp_warn:
            ts_warnings.append(stomp_warn)
            timestomping_detected = True

        # Compare $SI_Modified vs $FN_Modified
        si_modified = raw_ts.get("LastModified0x10")
        fn_modified = raw_ts.get("LastModified0x30")
        stomp_mod_warn = check_si_fn_discrepancy(si_modified, fn_modified)
        if stomp_mod_warn:
            ts_warnings.append(stomp_mod_warn)
            timestomping_detected = True

        # Check for creation > modification paradox
        paradox_warn = check_creation_after_modification(si_created, si_modified)
        if paradox_warn:
            ts_warnings.append(paradox_warn)
            timestomping_detected = True

        # Build proves/suggests sets — add TIMESTOMPING if detected
        proves = set(semantics.get("proves", set()))
        suggests = set(semantics.get("suggests", set()))
        if timestomping_detected:
            suggests.add(EvidenceSemantics.TIMESTOMPING)

        entry_number = row.get("EntryNumber", "").strip()
        sequence_number = row.get("SequenceNumber", "").strip()
        in_use = row.get("InUse", "").strip()
        is_directory = row.get("IsDirectory", row.get("Directory", "")).strip()

        atom = EvidenceAtom(
            tool_name="MFTECmd",
            execution_id=execution_id,
            artifact_type=ArtifactType.MFT_ENTRY,
            raw_data={
                "full_path": full_path,
                "entry_number": entry_number,
                "sequence_number": sequence_number,
                "in_use": in_use,
                "is_directory": is_directory,
                "file_size": row.get("FileSize", row.get("LogicalSize", "")).strip(),
                "timestomping_detected": timestomping_detected,
                "si_created": si_created or "",
                "fn_created": fn_created or "",
            },
            timestamps=timestamps,
            file_references=[full_path],
            proves=proves,
            suggests=suggests,
            cannot_prove=set(semantics.get("cannot_prove", set())),
        )

        # Attach timestomping warnings to the atom's raw_data for downstream use
        if ts_warnings:
            atom.raw_data["timestomping_warnings"] = [w.message for w in ts_warnings]

        return atom, timestomping_detected
