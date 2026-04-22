"""Universal timestamp sanity checks applied to all EvidenceAtoms.

Catches impossible or suspicious timestamps before they enter the evidence store:
- Timestamps in the future relative to evidence acquisition
- Timestamps before OS installation (if known)
- Sentinel/null dates (1601-01-01, 0000-00-00)
- Timestamps where creation > modification (possible timestomping)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from ..models import EvidenceAtom, TimestampRecord
from .base import ValidationWarning

logger = logging.getLogger(__name__)

# Windows NTFS epoch sentinel — often appears as "null" timestamp
NTFS_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

# Reasonable earliest date for Windows artifacts (Windows XP era)
EARLIEST_REASONABLE = datetime(2000, 1, 1, tzinfo=timezone.utc)


def parse_timestamp(ts_str: str) -> datetime | None:
    """Try to parse a timestamp string into a UTC datetime."""
    if not ts_str or ts_str.strip() == "":
        return None

    # Common formats from forensic tools
    formats = [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
    ]

    for fmt in formats:
        try:
            dt = datetime.strptime(ts_str.strip(), fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue

    logger.warning("Could not parse timestamp: %s", ts_str)
    return None


def validate_timestamps(
    atom: EvidenceAtom,
    acquisition_date: datetime | None = None,
) -> list[ValidationWarning]:
    """Validate all timestamps in an EvidenceAtom.

    Args:
        atom: The atom whose timestamps to validate.
        acquisition_date: When the evidence was acquired (if known).

    Returns:
        List of warnings for any suspicious timestamps.
    """
    warnings: list[ValidationWarning] = []

    for ts_record in atom.timestamps:
        dt = parse_timestamp(ts_record.value)
        if dt is None:
            warnings.append(
                ValidationWarning(
                    message=f"Unparseable timestamp in {ts_record.source_field}: '{ts_record.value}'",
                    field=ts_record.source_field,
                    severity="warning",
                )
            )
            continue

        # Check for NTFS epoch sentinel (1601-01-01)
        if dt.year == 1601:
            warnings.append(
                ValidationWarning(
                    message=(
                        f"NTFS epoch sentinel (1601-01-01) in {ts_record.source_field}. "
                        "This likely means the timestamp was never set, not a real date."
                    ),
                    field=ts_record.source_field,
                    severity="info",
                )
            )
            continue

        # Check for dates before reasonable earliest
        if dt < EARLIEST_REASONABLE:
            warnings.append(
                ValidationWarning(
                    message=(
                        f"Timestamp {ts_record.value} in {ts_record.source_field} "
                        f"is before {EARLIEST_REASONABLE.year}. Possibly invalid or sentinel."
                    ),
                    field=ts_record.source_field,
                    severity="warning",
                )
            )

        # Check for future timestamps
        now = datetime.now(timezone.utc)
        if dt > now:
            warnings.append(
                ValidationWarning(
                    message=(
                        f"Future timestamp {ts_record.value} in {ts_record.source_field}. "
                        "This may indicate clock skew or manipulation."
                    ),
                    field=ts_record.source_field,
                    severity="warning",
                )
            )

        # Check against acquisition date
        if acquisition_date and dt > acquisition_date:
            warnings.append(
                ValidationWarning(
                    message=(
                        f"Timestamp {ts_record.value} in {ts_record.source_field} "
                        f"is AFTER evidence acquisition date ({acquisition_date.isoformat()}). "
                        "This should be impossible unless the clock was wrong."
                    ),
                    field=ts_record.source_field,
                    severity="error",
                )
            )

    return warnings


def check_si_fn_discrepancy(
    si_created: str | None,
    fn_created: str | None,
    threshold_seconds: float = 2.0,
) -> ValidationWarning | None:
    """Check for timestomping by comparing $STANDARD_INFO vs $FILE_NAME creation times.

    A discrepancy > threshold_seconds between $SI_Created and $FN_Created is a
    strong indicator of timestomping, because $FILE_NAME timestamps are much
    harder to forge.

    Returns a warning if discrepancy detected, None otherwise.
    """
    if not si_created or not fn_created:
        return None

    si_dt = parse_timestamp(si_created)
    fn_dt = parse_timestamp(fn_created)

    if si_dt is None or fn_dt is None:
        return None

    diff_seconds = abs((si_dt - fn_dt).total_seconds())

    if diff_seconds > threshold_seconds:
        return ValidationWarning(
            message=(
                f"TIMESTOMPING INDICATOR: $SI_Created ({si_created}) differs from "
                f"$FN_Created ({fn_created}) by {diff_seconds:.1f} seconds. "
                "$FILE_NAME timestamps are harder to forge than $STANDARD_INFO. "
                "This discrepancy strongly suggests timestamp manipulation."
            ),
            field="$SI_Created vs $FN_Created",
            severity="error",
        )

    return None


def check_creation_after_modification(
    created: str | None,
    modified: str | None,
) -> ValidationWarning | None:
    """Check if a file's creation time is AFTER its modification time.

    This is a temporal paradox that suggests timestomping or file copy.

    Returns a warning if paradox detected, None otherwise.
    """
    if not created or not modified:
        return None

    created_dt = parse_timestamp(created)
    modified_dt = parse_timestamp(modified)

    if created_dt is None or modified_dt is None:
        return None

    if created_dt > modified_dt:
        diff = (created_dt - modified_dt).total_seconds()
        return ValidationWarning(
            message=(
                f"TEMPORAL PARADOX: File created ({created}) AFTER it was modified ({modified}). "
                f"Difference: {diff:.1f} seconds. "
                "This may indicate timestomping, file copy, or system clock issue."
            ),
            field="Created vs Modified",
            severity="error",
        )

    return None
