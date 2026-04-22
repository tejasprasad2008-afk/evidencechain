"""Disk forensic tool implementations.

This module implements all 8 disk analysis tools exposed via MCP:
  1. mount_evidence     — Mount disk images read-only
  2. get_filesystem_timeline — Generate MAC timeline (fls + mactime)
  3. parse_mft          — Parse $MFT with MFTECmd
  4. parse_event_logs   — Parse EVTX with EvtxECmd
  5. parse_prefetch     — Parse Prefetch with PECmd
  6. parse_amcache      — Parse Amcache with AmcacheParser
  7. parse_registry     — Parse registry with RECmd
  8. extract_file       — Extract file + compute hash

Each tool:
  - Uses BaseToolExecutor for secure execution + audit trail
  - Pipes raw output through the appropriate validator
  - Returns a standardized ToolResult with forensic context
  - Adds EvidenceAtoms to the evidence store
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import asdict
from pathlib import Path

from ..config import ANALYSIS_DIR, EVIDENCE_BASE_DIR, EXPORTS_DIR, MOUNT_OPTIONS
from ..enums import ArtifactType, ToolStatus
from ..forensic_semantics import get_semantics
from ..models import EvidenceAtom, ToolResult, _new_id
from ..provenance.audit_logger import AuditLogger
from ..provenance.evidence_registry import EvidenceRegistry
from ..provenance.evidence_store import EvidenceStore
from ..security.path_validator import validate_read_path, validate_write_path
from .base import BaseToolExecutor

logger = logging.getLogger(__name__)


class DiskToolExecutor(BaseToolExecutor):
    """Implements all 8 disk forensic tools."""

    def __init__(
        self,
        store: EvidenceStore,
        audit: AuditLogger,
        registry: EvidenceRegistry,
    ) -> None:
        super().__init__(store, audit)
        self.registry = registry

        # Lazy-loaded validators
        self._shimcache_validator = None
        self._prefetch_validator = None
        self._amcache_validator = None
        self._mft_validator = None
        self._evtx_validator = None
        self._registry_validator = None

    # --- Lazy validator accessors ---

    @property
    def shimcache_validator(self):
        if self._shimcache_validator is None:
            from ..validators.shimcache import ShimcacheValidator
            self._shimcache_validator = ShimcacheValidator()
        return self._shimcache_validator

    @property
    def prefetch_validator(self):
        if self._prefetch_validator is None:
            from ..validators.prefetch import PrefetchValidator
            self._prefetch_validator = PrefetchValidator()
        return self._prefetch_validator

    @property
    def amcache_validator(self):
        if self._amcache_validator is None:
            from ..validators.amcache import AmcacheValidator
            self._amcache_validator = AmcacheValidator()
        return self._amcache_validator

    @property
    def mft_validator(self):
        if self._mft_validator is None:
            from ..validators.mft import MftValidator
            self._mft_validator = MftValidator()
        return self._mft_validator

    @property
    def evtx_validator(self):
        if self._evtx_validator is None:
            from ..validators.evtx import EvtxValidator
            self._evtx_validator = EvtxValidator()
        return self._evtx_validator

    @property
    def registry_validator(self):
        if self._registry_validator is None:
            from ..validators.registry import RegistryValidator
            self._registry_validator = RegistryValidator()
        return self._registry_validator

    # =======================================================================
    # Tool 1: mount_evidence
    # =======================================================================

    def mount_evidence(self, image_path: str, image_type: str) -> ToolResult:
        """Mount a disk image read-only.

        Uses ewfmount for E01 images, then mount for raw/dd.
        All mounts use -o ro,loop,noatime to ensure read-only access.
        """
        validate_read_path(image_path)

        evidence_id = self.registry.register("disk", image_path)
        mount_base = Path("/mnt/evidencechain")
        mount_point = mount_base / evidence_id
        mount_base.mkdir(parents=True, exist_ok=True)
        mount_point.mkdir(parents=True, exist_ok=True)

        if image_type.upper() == "E01":
            # Step 1: Use ewfmount to expose E01 as raw device
            ewf_mount = mount_base / f"{evidence_id}_ewf"
            ewf_command = ["ewfmount", image_path, str(ewf_mount)]

            tool_result, _ = self.run_tool(
                tool_name="mount_evidence",
                evidence_id=evidence_id,
                command=ewf_command,
                input_params={"image_path": image_path, "image_type": image_type},
            )

            if tool_result.status == ToolStatus.ERROR:
                return tool_result

            # Step 2: Mount the raw image exposed by ewfmount
            raw_image = ewf_mount / "ewf1"
            mount_command = [
                "mount",
                "-o", MOUNT_OPTIONS,
                str(raw_image),
                str(mount_point),
            ]
        else:
            # Direct mount for dd/raw images
            mount_command = [
                "mount",
                "-o", MOUNT_OPTIONS,
                image_path,
                str(mount_point),
            ]

        tool_result, raw_output = self.run_tool(
            tool_name="mount_evidence",
            evidence_id=evidence_id,
            command=mount_command,
            input_params={"image_path": image_path, "image_type": image_type},
        )

        tool_result.structured_data = {
            "mount_point": str(mount_point),
            "evidence_id": evidence_id,
            "image_type": image_type,
            "mount_options": MOUNT_OPTIONS,
        }
        tool_result.forensic_context = self.build_forensic_context(
            caveats=["Evidence mounted read-only. All analysis is non-destructive."],
        )

        return tool_result

    # =======================================================================
    # Tool 2: get_filesystem_timeline
    # =======================================================================

    def get_filesystem_timeline(
        self,
        mount_point: str,
        evidence_id: str,
        date_start: str | None = None,
        date_end: str | None = None,
    ) -> ToolResult:
        """Generate a MAC timeline using fls and mactime.

        Two-step process:
        1. fls -r -m / <image> > bodyfile
        2. mactime -b bodyfile [-d date_range] > timeline.csv
        """
        validate_read_path(mount_point)

        bodyfile_path = EXPORTS_DIR / "timelines" / f"{evidence_id}_body.txt"
        timeline_path = EXPORTS_DIR / "timelines" / f"{evidence_id}_timeline.csv"

        # Ensure output directory exists
        bodyfile_path.parent.mkdir(parents=True, exist_ok=True)

        # Step 1: Generate bodyfile with fls
        fls_command = [
            "fls", "-r", "-m", "/",
            mount_point,
        ]

        tool_result, bodyfile_output = self.run_tool(
            tool_name="get_filesystem_timeline",
            evidence_id=evidence_id,
            command=fls_command,
            input_params={
                "mount_point": mount_point,
                "date_start": date_start,
                "date_end": date_end,
            },
        )

        if tool_result.status == ToolStatus.ERROR:
            return tool_result

        # Write bodyfile for mactime
        validate_write_path(str(bodyfile_path))
        bodyfile_path.write_text(bodyfile_output)

        # Step 2: Generate timeline with mactime
        mactime_command = ["mactime", "-b", str(bodyfile_path), "-d"]
        if date_start:
            mactime_command.extend([date_start])
            if date_end:
                mactime_command[-1] = f"{date_start}..{date_end}"

        tool_result, timeline_output = self.run_tool(
            tool_name="get_filesystem_timeline",
            evidence_id=evidence_id,
            command=mactime_command,
            input_params={
                "mount_point": mount_point,
                "date_start": date_start,
                "date_end": date_end,
            },
        )

        # Save timeline CSV
        validate_write_path(str(timeline_path))
        timeline_path.write_text(timeline_output)

        # Count lines for record count
        line_count = timeline_output.count("\n")

        semantics = get_semantics(ArtifactType.FILESYSTEM_ENTRY)
        tool_result.structured_data = {
            "bodyfile_path": str(bodyfile_path),
            "timeline_path": str(timeline_path),
            "record_count": line_count,
            "date_filter": {"start": date_start, "end": date_end},
        }
        tool_result.record_count = line_count
        tool_result.forensic_context = self.build_forensic_context(
            proves=list(semantics.get("proves", set())),
            cannot_prove=list(semantics.get("cannot_prove", set())),
            caveats=list(semantics.get("caveats", [])),
            corroboration_hints=list(semantics.get("corroboration_hints", [])),
        )

        return tool_result

    # =======================================================================
    # Tool 3: parse_mft
    # =======================================================================

    def parse_mft(self, mft_path: str, evidence_id: str) -> ToolResult:
        """Parse $MFT using MFTECmd with timestomping detection."""
        validate_read_path(mft_path)

        csv_output_dir = str(EXPORTS_DIR / "mft")
        Path(csv_output_dir).mkdir(parents=True, exist_ok=True)

        command = [
            "MFTECmd",
            "-f", mft_path,
            "--csv", csv_output_dir,
            "--at",  # Include all timestamps
        ]

        tool_result, raw_output = self.run_tool(
            tool_name="parse_mft",
            evidence_id=evidence_id,
            command=command,
            input_params={"mft_path": mft_path},
        )

        if tool_result.status == ToolStatus.ERROR:
            return tool_result

        # MFTECmd outputs to a CSV file — read it back
        csv_content = self._read_latest_csv(csv_output_dir, "MFTECmd")
        if csv_content is None:
            # Fall back to stdout if CSV file not found
            csv_content = raw_output

        # Validate and produce atoms
        vr = self.mft_validator.validate(
            execution_id=tool_result.execution_id,
            raw_output=csv_content,
        )

        self._apply_validation_result(tool_result, vr, evidence_id)

        return tool_result

    # =======================================================================
    # Tool 4: parse_event_logs
    # =======================================================================

    def parse_event_logs(
        self,
        evtx_path: str,
        evidence_id: str,
        event_ids: list[int] | None = None,
        date_start: str | None = None,
        date_end: str | None = None,
    ) -> ToolResult:
        """Parse Windows Event Logs using EvtxECmd."""
        validate_read_path(evtx_path)

        csv_output_dir = str(EXPORTS_DIR / "evtx")
        Path(csv_output_dir).mkdir(parents=True, exist_ok=True)

        command = ["EvtxECmd"]

        # EvtxECmd uses -f for single file, -d for directory
        if os.path.isdir(evtx_path):
            command.extend(["-d", evtx_path])
        else:
            command.extend(["-f", evtx_path])

        command.extend(["--csv", csv_output_dir])

        # Apply event ID filter if specified
        if event_ids:
            id_str = ",".join(str(eid) for eid in event_ids)
            command.extend(["--inc", id_str])

        tool_result, raw_output = self.run_tool(
            tool_name="parse_event_logs",
            evidence_id=evidence_id,
            command=command,
            input_params={
                "evtx_path": evtx_path,
                "event_ids": event_ids,
                "date_start": date_start,
                "date_end": date_end,
            },
        )

        if tool_result.status == ToolStatus.ERROR:
            return tool_result

        # EvtxECmd outputs to CSV — read it back
        csv_content = self._read_latest_csv(csv_output_dir, "EvtxECmd")
        if csv_content is None:
            csv_content = raw_output

        # Validate and produce atoms
        vr = self.evtx_validator.validate(
            execution_id=tool_result.execution_id,
            raw_output=csv_content,
        )

        self._apply_validation_result(tool_result, vr, evidence_id)

        return tool_result

    # =======================================================================
    # Tool 5: parse_prefetch
    # =======================================================================

    def parse_prefetch(self, prefetch_dir: str, evidence_id: str) -> ToolResult:
        """Parse Windows Prefetch files using PECmd."""
        validate_read_path(prefetch_dir)

        csv_output_dir = str(EXPORTS_DIR / "prefetch")
        Path(csv_output_dir).mkdir(parents=True, exist_ok=True)

        command = [
            "PECmd",
            "-d", prefetch_dir,
            "--csv", csv_output_dir,
        ]

        tool_result, raw_output = self.run_tool(
            tool_name="parse_prefetch",
            evidence_id=evidence_id,
            command=command,
            input_params={"prefetch_dir": prefetch_dir},
        )

        if tool_result.status == ToolStatus.ERROR:
            return tool_result

        # PECmd outputs to CSV — read it back
        csv_content = self._read_latest_csv(csv_output_dir, "PECmd")
        if csv_content is None:
            csv_content = raw_output

        # Validate and produce atoms
        vr = self.prefetch_validator.validate(
            execution_id=tool_result.execution_id,
            raw_output=csv_content,
        )

        self._apply_validation_result(tool_result, vr, evidence_id)

        return tool_result

    # =======================================================================
    # Tool 6: parse_amcache
    # =======================================================================

    def parse_amcache(self, amcache_path: str, evidence_id: str) -> ToolResult:
        """Parse Amcache hive using AmcacheParser."""
        validate_read_path(amcache_path)

        csv_output_dir = str(EXPORTS_DIR / "amcache")
        Path(csv_output_dir).mkdir(parents=True, exist_ok=True)

        command = [
            "AmcacheParser",
            "-f", amcache_path,
            "--csv", csv_output_dir,
        ]

        tool_result, raw_output = self.run_tool(
            tool_name="parse_amcache",
            evidence_id=evidence_id,
            command=command,
            input_params={"amcache_path": amcache_path},
        )

        if tool_result.status == ToolStatus.ERROR:
            return tool_result

        # AmcacheParser outputs to CSV — read it back
        csv_content = self._read_latest_csv(csv_output_dir, "Amcache")
        if csv_content is None:
            csv_content = raw_output

        # Validate and produce atoms
        vr = self.amcache_validator.validate(
            execution_id=tool_result.execution_id,
            raw_output=csv_content,
        )

        self._apply_validation_result(tool_result, vr, evidence_id)

        return tool_result

    # =======================================================================
    # Tool 7: parse_registry
    # =======================================================================

    def parse_registry(self, hive_path: str, evidence_id: str) -> ToolResult:
        """Parse registry hive using RECmd with batch processing."""
        validate_read_path(hive_path)

        csv_output_dir = str(EXPORTS_DIR / "registry")
        Path(csv_output_dir).mkdir(parents=True, exist_ok=True)

        # Use RECmd with the standard batch file for comprehensive parsing
        command = [
            "RECmd",
            "-f", hive_path,
            "--csv", csv_output_dir,
            "--bn", "BatchExamples/RECmd_Batch_MC.reb",
        ]

        tool_result, raw_output = self.run_tool(
            tool_name="parse_registry",
            evidence_id=evidence_id,
            command=command,
            input_params={"hive_path": hive_path},
        )

        if tool_result.status == ToolStatus.ERROR:
            return tool_result

        # RECmd outputs to CSV — read it back
        csv_content = self._read_latest_csv(csv_output_dir, "RECmd")
        if csv_content is None:
            csv_content = raw_output

        # Validate and produce atoms
        vr = self.registry_validator.validate(
            execution_id=tool_result.execution_id,
            raw_output=csv_content,
        )

        self._apply_validation_result(tool_result, vr, evidence_id)

        return tool_result

    # =======================================================================
    # Tool 8: extract_file
    # =======================================================================

    def extract_file(
        self,
        file_path: str,
        evidence_id: str,
        output_name: str | None = None,
    ) -> ToolResult:
        """Extract a file from mounted evidence and compute hashes.

        Does NOT execute commands — uses Python's hashlib for hashing.
        The file is copied to the exports directory.
        """
        validate_read_path(file_path)

        source_path = Path(file_path)
        if not source_path.exists():
            return ToolResult(
                tool_name="extract_file",
                evidence_id=evidence_id,
                status=ToolStatus.ERROR,
                error_message=f"File not found: {file_path}",
            )

        # Determine output name
        if not output_name:
            output_name = source_path.name

        dest_dir = EXPORTS_DIR / "extracted" / evidence_id
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_path = dest_dir / output_name

        validate_write_path(str(dest_path))

        # Copy the file using 'cp' (allowed binary)
        command = ["cp", "-p", file_path, str(dest_path)]

        tool_result, _ = self.run_tool(
            tool_name="extract_file",
            evidence_id=evidence_id,
            command=command,
            input_params={"file_path": file_path, "output_name": output_name},
        )

        if tool_result.status == ToolStatus.ERROR:
            return tool_result

        # Compute hashes (done in Python, not via subprocess)
        hashes = self._compute_file_hashes(dest_path)

        # Create an evidence atom for the extracted file
        atom = EvidenceAtom(
            tool_name="extract_file",
            execution_id=tool_result.execution_id,
            artifact_type=ArtifactType.FILE_HASH,
            raw_data={
                "source_path": file_path,
                "extracted_to": str(dest_path),
                "file_size": dest_path.stat().st_size,
                **hashes,
            },
            file_references=[file_path, str(dest_path)],
        )

        self.store.add_atom(atom)

        semantics = get_semantics(ArtifactType.FILE_HASH)
        tool_result.structured_data = {
            "source_path": file_path,
            "extracted_to": str(dest_path),
            "file_size": dest_path.stat().st_size,
            "atom_id": atom.atom_id,
            **hashes,
        }
        tool_result.record_count = 1
        tool_result.forensic_context = self.build_forensic_context(
            caveats=list(semantics.get("caveats", [])),
            corroboration_hints=[
                "Look up hashes in threat intelligence (VirusTotal, MalwareBazaar).",
                "Run YARA scan on the extracted file.",
                "Compare SHA1 with Amcache hash to detect file replacement.",
            ],
        )

        return tool_result

    # =======================================================================
    # Unmount helper (not a separate class — simple operation)
    # =======================================================================

    def unmount_evidence(self, mount_point: str) -> ToolResult:
        """Unmount a previously mounted disk image."""
        validate_read_path(mount_point)
        command = ["umount", mount_point]

        tool_result, _ = self.run_tool(
            tool_name="unmount_evidence",
            evidence_id="system",
            command=command,
            input_params={"mount_point": mount_point},
        )

        tool_result.structured_data = {
            "mount_point": mount_point,
            "unmounted": tool_result.status == ToolStatus.SUCCESS,
        }

        return tool_result

    # =======================================================================
    # Internal helpers
    # =======================================================================

    def _apply_validation_result(
        self,
        tool_result: ToolResult,
        vr,
        evidence_id: str,
    ) -> None:
        """Apply a ValidatorResult to a ToolResult and store atoms."""
        from ..validators.base import ValidatorResult

        # Add atoms to evidence store
        atom_ids = []
        for atom in vr.atoms:
            self.store.add_atom(atom)
            atom_ids.append(atom.atom_id)

        # Build structured data summary
        tool_result.record_count = vr.record_count
        tool_result.structured_data = {
            "atom_count": len(vr.atoms),
            "atom_ids": atom_ids[:50],  # Cap for large result sets
            "record_count": vr.record_count,
            "warnings": [w.message for w in vr.warnings[:20]],
            "overclaim_flags": [f.message for f in vr.overclaim_flags],
        }

        # Build forensic context from the first atom's semantics (they share the same type)
        if vr.atoms:
            first = vr.atoms[0]
            tool_result.forensic_context = self.build_forensic_context(
                proves=sorted(first.proves),
                suggests=sorted(first.suggests),
                cannot_prove=sorted(first.cannot_prove),
                caveats=[w.message for w in vr.warnings if w.severity == "error"][:5],
                corroboration_hints=[f.message for f in vr.overclaim_flags],
            )

        # Log warnings to audit
        for warning in vr.warnings:
            if warning.severity in ("error", "warning"):
                self.audit.log("validation_warnings", {
                    "execution_id": tool_result.execution_id,
                    "tool": tool_result.tool_name,
                    "warning": warning.message,
                    "severity": warning.severity,
                })

    def _read_latest_csv(self, directory: str, tool_prefix: str) -> str | None:
        """Read the most recently created CSV file from a tool's output directory.

        EZ Tools (MFTECmd, EvtxECmd, PECmd, etc.) write CSV files to the
        specified --csv directory. This finds and reads the latest one.
        """
        dir_path = Path(directory)
        if not dir_path.exists():
            return None

        csv_files = sorted(
            dir_path.glob("*.csv"),
            key=lambda f: f.stat().st_mtime,
            reverse=True,
        )

        if not csv_files:
            return None

        # Read the most recent CSV (could be large — read up to MAX_OUTPUT_SIZE)
        from ..config import MAX_OUTPUT_SIZE

        target = csv_files[0]
        try:
            content = target.read_text(errors="replace")
            original_size = len(content)
            if original_size > MAX_OUTPUT_SIZE:
                # Truncate at last newline before limit
                truncated = content[:MAX_OUTPUT_SIZE]
                last_nl = truncated.rfind("\n")
                if last_nl > 0:
                    content = truncated[:last_nl]
                else:
                    content = truncated
                logger.warning(
                    "CSV output truncated from %d to %d bytes: %s",
                    original_size,
                    MAX_OUTPUT_SIZE,
                    target.name,
                )
            return content
        except Exception as e:
            logger.error("Failed to read CSV %s: %s", target, e)
            return None

    @staticmethod
    def _compute_file_hashes(file_path: Path) -> dict[str, str]:
        """Compute MD5, SHA1, and SHA256 hashes for a file."""
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()

        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)

        return {
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest(),
        }
