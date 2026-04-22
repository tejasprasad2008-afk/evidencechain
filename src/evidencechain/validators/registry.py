"""Registry (RECmd) output validator.

Parses CSV output from RECmd batch processing and produces EvidenceAtoms.
Focuses on persistence keys and indicators of compromise in the registry.

Registry keys PROVE: persistence mechanism was configured.
Registry keys CANNOT PROVE: that the persistence mechanism actually executed.
"""

from __future__ import annotations

import csv
import io
import logging
import re

from ..enums import ArtifactType, EvidenceSemantics, TimestampSemanticType
from ..forensic_semantics import get_semantics
from ..models import EvidenceAtom, TimestampRecord
from .base import BaseValidator, OverclaimFlag, ValidatorResult, ValidationWarning
from .timestamps import validate_timestamps

logger = logging.getLogger(__name__)

# Registry key patterns that indicate persistence
PERSISTENCE_KEY_PATTERNS: list[re.Pattern] = [
    re.compile(r"Run$", re.IGNORECASE),
    re.compile(r"RunOnce$", re.IGNORECASE),
    re.compile(r"RunOnceEx", re.IGNORECASE),
    re.compile(r"CurrentVersion\\Explorer\\Shell Folders", re.IGNORECASE),
    re.compile(r"CurrentVersion\\Explorer\\User Shell Folders", re.IGNORECASE),
    re.compile(r"Winlogon\\", re.IGNORECASE),
    re.compile(r"CurrentVersion\\Policies\\Explorer\\Run", re.IGNORECASE),
    re.compile(r"Services\\", re.IGNORECASE),
    re.compile(r"ControlSet\d+\\Services\\", re.IGNORECASE),
    re.compile(r"Wow6432Node\\.*\\Run", re.IGNORECASE),
    re.compile(r"AppInit_DLLs", re.IGNORECASE),
    re.compile(r"Image File Execution Options\\", re.IGNORECASE),
    re.compile(r"BootExecute", re.IGNORECASE),
    re.compile(r"Session Manager\\KnownDLLs", re.IGNORECASE),
    re.compile(r"Browser Helper Objects", re.IGNORECASE),
    re.compile(r"ShellServiceObjectDelayLoad", re.IGNORECASE),
    re.compile(r"SharedTaskScheduler", re.IGNORECASE),
    re.compile(r"Startup\\", re.IGNORECASE),
    re.compile(r"Classes\\CLSID\\.*\\InprocServer32", re.IGNORECASE),
    re.compile(r"Classes\\CLSID\\.*\\LocalServer32", re.IGNORECASE),
    re.compile(r"Environment\\.*\\UserInitMprLogonScript", re.IGNORECASE),
    re.compile(r"Active Setup\\Installed Components", re.IGNORECASE),
]

# Keys indicating user activity / MRU
USER_ACTIVITY_PATTERNS: list[re.Pattern] = [
    re.compile(r"RecentDocs", re.IGNORECASE),
    re.compile(r"ComDlg32\\OpenSavePidlMRU", re.IGNORECASE),
    re.compile(r"ComDlg32\\LastVisitedPidlMRU", re.IGNORECASE),
    re.compile(r"TypedPaths", re.IGNORECASE),
    re.compile(r"TypedURLs", re.IGNORECASE),
    re.compile(r"RunMRU", re.IGNORECASE),
    re.compile(r"UserAssist", re.IGNORECASE),
    re.compile(r"MountPoints2", re.IGNORECASE),
    re.compile(r"BAM\\.*\\UserSettings", re.IGNORECASE),
]


def _is_persistence_key(key_path: str) -> bool:
    """Check if a registry key path matches known persistence locations."""
    return any(p.search(key_path) for p in PERSISTENCE_KEY_PATTERNS)


def _is_user_activity_key(key_path: str) -> bool:
    """Check if a registry key path relates to user activity tracking."""
    return any(p.search(key_path) for p in USER_ACTIVITY_PATTERNS)


class RegistryValidator(BaseValidator):
    """Validator for RECmd CSV output."""

    def validate(
        self,
        execution_id: str,
        raw_output: str,
        **kwargs,
    ) -> ValidatorResult:
        result = ValidatorResult()
        semantics = get_semantics(ArtifactType.REGISTRY_KEY)

        if not raw_output.strip():
            result.warnings.append(
                ValidationWarning(message="Empty registry output", severity="warning")
            )
            return result

        reader = csv.DictReader(io.StringIO(raw_output))

        persistence_count = 0

        for row in reader:
            try:
                atom = self._parse_row(row, execution_id, semantics)
                if atom:
                    ts_warnings = validate_timestamps(atom)
                    result.warnings.extend(ts_warnings)
                    result.atoms.append(atom)
                    result.record_count += 1

                    if atom.raw_data.get("is_persistence_key"):
                        persistence_count += 1
            except Exception as e:
                result.warnings.append(
                    ValidationWarning(
                        message=f"Failed to parse registry row: {e}",
                        severity="warning",
                    )
                )

        # Overclaim warning: persistence != execution
        if persistence_count > 0:
            result.overclaim_flags.append(
                OverclaimFlag(
                    message=(
                        f"{persistence_count} persistence key(s) found. "
                        "These prove persistence was CONFIGURED, NOT that the mechanism executed. "
                        "Cross-reference with Prefetch/Amcache/memory to confirm execution."
                    ),
                    claimed_semantic=EvidenceSemantics.EXECUTION,
                    actual_semantic=EvidenceSemantics.PERSISTENCE,
                )
            )

        logger.info(
            "Registry validator: %d atoms, %d persistence keys",
            len(result.atoms),
            persistence_count,
        )
        return result

    def _parse_row(
        self,
        row: dict,
        execution_id: str,
        semantics: dict,
    ) -> EvidenceAtom | None:
        # RECmd CSV columns
        key_path = (
            row.get("KeyPath", "")
            or row.get("HivePath", "")
            or row.get("Key", "")
        ).strip()

        value_name = (
            row.get("ValueName", "")
            or row.get("Name", "")
        ).strip()

        value_data = (
            row.get("ValueData", "")
            or row.get("Data", "")
            or row.get("ValueData1", "")
        ).strip()

        if not key_path:
            return None

        # Timestamp: RECmd outputs LastWriteTimestamp for the key
        last_write = (
            row.get("LastWriteTimestamp", "")
            or row.get("LastWriteTime", "")
            or row.get("Timestamp", "")
        ).strip()

        timestamps = []
        if last_write:
            timestamps.append(
                TimestampRecord(
                    value=last_write,
                    source_field="LastWriteTimestamp",
                    semantic_type=TimestampSemanticType.MODIFIED,
                )
            )

        # Classify the key
        is_persistence = _is_persistence_key(key_path)
        is_user_activity = _is_user_activity_key(key_path)

        # Set semantics based on key type
        proves = set(semantics.get("proves", set()))
        suggests = set(semantics.get("suggests", set()))

        if is_user_activity:
            suggests.add(EvidenceSemantics.USER_INTERACTION)

        # Extract file references from value data (paths to executables)
        file_refs = []
        if value_data:
            # Look for paths in value data (common in Run keys)
            path_match = re.search(
                r'([A-Za-z]:\\[^\s"\'<>|*?]+\.\w{2,4})',
                value_data,
            )
            if path_match:
                file_refs.append(path_match.group(1))

        hive_type = row.get("HiveType", row.get("Description", "")).strip()
        batch_name = row.get("BatchKeyPath", row.get("Plugin", "")).strip()
        value_type = row.get("ValueType", row.get("Type", "")).strip()

        return EvidenceAtom(
            tool_name="RECmd",
            execution_id=execution_id,
            artifact_type=ArtifactType.REGISTRY_KEY,
            raw_data={
                "key_path": key_path,
                "value_name": value_name,
                "value_data": value_data[:1000],  # Cap large values
                "value_type": value_type,
                "hive_type": hive_type,
                "batch_name": batch_name,
                "is_persistence_key": is_persistence,
                "is_user_activity_key": is_user_activity,
            },
            timestamps=timestamps,
            file_references=file_refs,
            proves=proves,
            suggests=suggests,
            cannot_prove=set(semantics.get("cannot_prove", set())),
        )
