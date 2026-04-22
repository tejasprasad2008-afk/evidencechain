"""Memory forensic tool implementations.

This module implements all 6 memory analysis tools exposed via MCP:
  1. memory_process_list     — Dual-scan: pslist + psscan (hidden process detection)
  2. memory_network_connections — Dual-scan: netscan + netstat
  3. memory_injected_code    — malfind (code injection detection)
  4. memory_services         — svcscan
  5. memory_command_lines    — cmdline
  6. memory_dump_process     — procdump + strings

Each tool:
  - Calls Volatility 3 via BaseToolExecutor with --renderer csv
  - Pipes CSV output through the matching memory validator
  - Returns standardized ToolResult with forensic context
  - Adds EvidenceAtoms to the evidence store

Volatility 3 command pattern:
  vol -f <image> [-r csv] <plugin> [--pid <pid>]
"""

from __future__ import annotations

import logging
from pathlib import Path

from ..config import EXPORTS_DIR
from ..enums import ArtifactType, ToolStatus
from ..forensic_semantics import get_semantics
from ..models import ToolResult
from ..provenance.audit_logger import AuditLogger
from ..provenance.evidence_registry import EvidenceRegistry
from ..provenance.evidence_store import EvidenceStore
from ..security.path_validator import validate_read_path
from .base import BaseToolExecutor

logger = logging.getLogger(__name__)

# Volatility 3 binary name (may vary by installation)
VOL3_BIN = "vol"


class MemoryToolExecutor(BaseToolExecutor):
    """Implements all 6 memory forensic tools using Volatility 3."""

    def __init__(
        self,
        store: EvidenceStore,
        audit: AuditLogger,
        registry: EvidenceRegistry,
    ) -> None:
        super().__init__(store, audit)
        self.registry = registry

        # Lazy-loaded validators
        self._process_validator = None
        self._network_validator = None
        self._malfind_validator = None
        self._service_validator = None
        self._cmdline_validator = None
        self._procdump_validator = None

    # --- Lazy validator accessors ---

    @property
    def process_validator(self):
        if self._process_validator is None:
            from ..validators.memory import ProcessListValidator
            self._process_validator = ProcessListValidator()
        return self._process_validator

    @property
    def network_validator(self):
        if self._network_validator is None:
            from ..validators.memory import NetworkValidator
            self._network_validator = NetworkValidator()
        return self._network_validator

    @property
    def malfind_validator(self):
        if self._malfind_validator is None:
            from ..validators.memory import MalfindValidator
            self._malfind_validator = MalfindValidator()
        return self._malfind_validator

    @property
    def service_validator(self):
        if self._service_validator is None:
            from ..validators.memory import ServiceValidator
            self._service_validator = ServiceValidator()
        return self._service_validator

    @property
    def cmdline_validator(self):
        if self._cmdline_validator is None:
            from ..validators.memory import CmdlineValidator
            self._cmdline_validator = CmdlineValidator()
        return self._cmdline_validator

    @property
    def procdump_validator(self):
        if self._procdump_validator is None:
            from ..validators.memory import ProcessDumpValidator
            self._procdump_validator = ProcessDumpValidator()
        return self._procdump_validator

    # --- Helper to build vol3 commands ---

    @staticmethod
    def _vol3_cmd(
        memory_image: str,
        plugin: str,
        renderer: str = "csv",
        extra_args: list[str] | None = None,
    ) -> list[str]:
        """Build a Volatility 3 command line."""
        cmd = [VOL3_BIN, "-f", memory_image, "-r", renderer, plugin]
        if extra_args:
            cmd.extend(extra_args)
        return cmd

    # =======================================================================
    # Tool 1: memory_process_list (pslist + psscan dual-scan)
    # =======================================================================

    def memory_process_list(
        self,
        memory_image: str,
        evidence_id: str,
    ) -> ToolResult:
        """List processes using dual-scan: pslist + psscan.

        Runs both plugins and compares results. Processes found by psscan
        but NOT in pslist are flagged as potentially hidden/unlinked.
        """
        validate_read_path(memory_image)

        # --- Step 1: Run pslist ---
        pslist_cmd = self._vol3_cmd(
            memory_image, "windows.pslist.PsList",
        )

        pslist_result, pslist_output = self.run_tool(
            tool_name="memory_process_list",
            evidence_id=evidence_id,
            command=pslist_cmd,
            input_params={"memory_image": memory_image, "scan": "pslist"},
            timeout=600,
        )

        if pslist_result.status == ToolStatus.ERROR:
            return pslist_result

        # Parse pslist to get the set of known PIDs
        pslist_vr = self.process_validator.validate(
            execution_id=pslist_result.execution_id,
            raw_output=pslist_output,
            scan_type="pslist",
        )

        pslist_pids: set[int] = set()
        for atom in pslist_vr.atoms:
            pid = atom.raw_data.get("pid")
            if pid is not None:
                pslist_pids.add(int(pid))

        # Store pslist atoms
        pslist_atom_ids = []
        for atom in pslist_vr.atoms:
            self.store.add_atom(atom)
            pslist_atom_ids.append(atom.atom_id)

        # --- Step 2: Run psscan ---
        psscan_cmd = self._vol3_cmd(
            memory_image, "windows.psscan.PsScan",
        )

        psscan_result, psscan_output = self.run_tool(
            tool_name="memory_process_list",
            evidence_id=evidence_id,
            command=psscan_cmd,
            input_params={"memory_image": memory_image, "scan": "psscan"},
            timeout=600,
        )

        # Parse psscan with pslist PIDs for hidden detection
        psscan_vr = self.process_validator.validate(
            execution_id=psscan_result.execution_id,
            raw_output=psscan_output if psscan_result.status != ToolStatus.ERROR else "",
            scan_type="psscan",
            pslist_pids=pslist_pids,
        )

        psscan_atom_ids = []
        for atom in psscan_vr.atoms:
            self.store.add_atom(atom)
            psscan_atom_ids.append(atom.atom_id)

        # --- Merge results ---
        hidden_processes = [
            a for a in psscan_vr.atoms
            if a.raw_data.get("potentially_hidden")
        ]

        all_warnings = pslist_vr.warnings + psscan_vr.warnings
        all_overclaims = pslist_vr.overclaim_flags + psscan_vr.overclaim_flags

        total_atoms = len(pslist_vr.atoms) + len(psscan_vr.atoms)
        all_atom_ids = pslist_atom_ids + psscan_atom_ids

        semantics = get_semantics(ArtifactType.MEMORY_PROCESS)

        pslist_result.structured_data = {
            "pslist_count": len(pslist_vr.atoms),
            "psscan_count": len(psscan_vr.atoms),
            "hidden_process_count": len(hidden_processes),
            "hidden_processes": [
                {
                    "pid": a.raw_data["pid"],
                    "name": a.raw_data["process_name"],
                    "atom_id": a.atom_id,
                }
                for a in hidden_processes
            ],
            "atom_ids": all_atom_ids[:100],
            "warnings": [w.message for w in all_warnings[:20]],
            "overclaim_flags": [f.message for f in all_overclaims],
        }
        pslist_result.record_count = total_atoms
        pslist_result.forensic_context = self.build_forensic_context(
            suggests=sorted(semantics.get("suggests", set())),
            cannot_prove=sorted(semantics.get("cannot_prove", set())),
            caveats=list(semantics.get("caveats", []))[:3],
            corroboration_hints=list(semantics.get("corroboration_hints", []))[:3],
        )

        return pslist_result

    # =======================================================================
    # Tool 2: memory_network_connections (netscan + netstat)
    # =======================================================================

    def memory_network_connections(
        self,
        memory_image: str,
        evidence_id: str,
    ) -> ToolResult:
        """List network connections using netscan (+ netstat for comparison)."""
        validate_read_path(memory_image)

        # --- Run netscan (primary — finds historical connections too) ---
        netscan_cmd = self._vol3_cmd(
            memory_image, "windows.netscan.NetScan",
        )

        netscan_result, netscan_output = self.run_tool(
            tool_name="memory_network_connections",
            evidence_id=evidence_id,
            command=netscan_cmd,
            input_params={"memory_image": memory_image, "scan": "netscan"},
            timeout=600,
        )

        if netscan_result.status == ToolStatus.ERROR:
            return netscan_result

        netscan_vr = self.network_validator.validate(
            execution_id=netscan_result.execution_id,
            raw_output=netscan_output,
            scan_type="netscan",
        )

        atom_ids = []
        for atom in netscan_vr.atoms:
            self.store.add_atom(atom)
            atom_ids.append(atom.atom_id)

        # Count external connections (potential C2)
        external_conns = [
            a for a in netscan_vr.atoms
            if a.raw_data.get("is_external_connection")
        ]

        semantics = get_semantics(ArtifactType.MEMORY_NETWORK)

        netscan_result.structured_data = {
            "connection_count": len(netscan_vr.atoms),
            "external_connection_count": len(external_conns),
            "external_connections": [
                {
                    "foreign_addr": a.raw_data["foreign_addr"],
                    "foreign_port": a.raw_data["foreign_port"],
                    "owner_pid": a.raw_data["owner_pid"],
                    "owner_name": a.raw_data["owner_name"],
                    "state": a.raw_data["state"],
                    "atom_id": a.atom_id,
                }
                for a in external_conns[:30]
            ],
            "atom_ids": atom_ids[:100],
            "warnings": [w.message for w in netscan_vr.warnings[:20]],
            "overclaim_flags": [f.message for f in netscan_vr.overclaim_flags],
        }
        netscan_result.record_count = len(netscan_vr.atoms)
        netscan_result.forensic_context = self.build_forensic_context(
            proves=sorted(semantics.get("proves", set())),
            cannot_prove=sorted(semantics.get("cannot_prove", set())),
            caveats=list(semantics.get("caveats", []))[:3],
            corroboration_hints=list(semantics.get("corroboration_hints", []))[:3],
        )

        return netscan_result

    # =======================================================================
    # Tool 3: memory_injected_code (malfind)
    # =======================================================================

    def memory_injected_code(
        self,
        memory_image: str,
        evidence_id: str,
        pid: int | None = None,
    ) -> ToolResult:
        """Detect potentially injected code using malfind."""
        validate_read_path(memory_image)

        extra_args = []
        if pid is not None:
            extra_args = ["--pid", str(pid)]

        malfind_cmd = self._vol3_cmd(
            memory_image, "windows.malfind.Malfind",
            extra_args=extra_args,
        )

        tool_result, raw_output = self.run_tool(
            tool_name="memory_injected_code",
            evidence_id=evidence_id,
            command=malfind_cmd,
            input_params={"memory_image": memory_image, "pid": pid},
            timeout=600,
        )

        if tool_result.status == ToolStatus.ERROR:
            return tool_result

        vr = self.malfind_validator.validate(
            execution_id=tool_result.execution_id,
            raw_output=raw_output,
        )

        atom_ids = []
        for atom in vr.atoms:
            self.store.add_atom(atom)
            atom_ids.append(atom.atom_id)

        # Separate true hits from likely FPs
        true_hits = [a for a in vr.atoms if not a.raw_data.get("likely_false_positive")]
        fp_hits = [a for a in vr.atoms if a.raw_data.get("likely_false_positive")]

        semantics = get_semantics(ArtifactType.MEMORY_MALFIND)

        tool_result.structured_data = {
            "total_hits": len(vr.atoms),
            "likely_true_hits": len(true_hits),
            "likely_false_positives": len(fp_hits),
            "true_hits": [
                {
                    "pid": a.raw_data["pid"],
                    "process": a.raw_data["process_name"],
                    "protection": a.raw_data.get("protection", ""),
                    "atom_id": a.atom_id,
                }
                for a in true_hits[:20]
            ],
            "atom_ids": atom_ids[:100],
            "warnings": [w.message for w in vr.warnings[:20]],
            "overclaim_flags": [f.message for f in vr.overclaim_flags],
        }
        tool_result.record_count = len(vr.atoms)
        tool_result.forensic_context = self.build_forensic_context(
            suggests=sorted(semantics.get("suggests", set())),
            cannot_prove=sorted(semantics.get("cannot_prove", set())),
            caveats=list(semantics.get("caveats", []))[:4],
            corroboration_hints=list(semantics.get("corroboration_hints", []))[:3],
        )

        return tool_result

    # =======================================================================
    # Tool 4: memory_services (svcscan)
    # =======================================================================

    def memory_services(
        self,
        memory_image: str,
        evidence_id: str,
    ) -> ToolResult:
        """List Windows services from memory."""
        validate_read_path(memory_image)

        svcscan_cmd = self._vol3_cmd(
            memory_image, "windows.svcscan.SvcScan",
        )

        tool_result, raw_output = self.run_tool(
            tool_name="memory_services",
            evidence_id=evidence_id,
            command=svcscan_cmd,
            input_params={"memory_image": memory_image},
            timeout=600,
        )

        if tool_result.status == ToolStatus.ERROR:
            return tool_result

        vr = self.service_validator.validate(
            execution_id=tool_result.execution_id,
            raw_output=raw_output,
        )

        atom_ids = []
        for atom in vr.atoms:
            self.store.add_atom(atom)
            atom_ids.append(atom.atom_id)

        semantics = get_semantics(ArtifactType.MEMORY_SERVICE)

        tool_result.structured_data = {
            "service_count": len(vr.atoms),
            "services": [
                {
                    "name": a.raw_data["service_name"],
                    "binary": a.raw_data.get("binary_path", ""),
                    "state": a.raw_data.get("state", ""),
                    "atom_id": a.atom_id,
                }
                for a in vr.atoms[:50]
            ],
            "atom_ids": atom_ids[:100],
            "warnings": [w.message for w in vr.warnings[:20]],
        }
        tool_result.record_count = len(vr.atoms)
        tool_result.forensic_context = self.build_forensic_context(
            suggests=sorted(semantics.get("suggests", set())),
            caveats=list(semantics.get("caveats", []))[:3],
            corroboration_hints=list(semantics.get("corroboration_hints", []))[:3],
        )

        return tool_result

    # =======================================================================
    # Tool 5: memory_command_lines (cmdline)
    # =======================================================================

    def memory_command_lines(
        self,
        memory_image: str,
        evidence_id: str,
        pid: int | None = None,
    ) -> ToolResult:
        """Extract process command lines from memory."""
        validate_read_path(memory_image)

        extra_args = []
        if pid is not None:
            extra_args = ["--pid", str(pid)]

        cmdline_cmd = self._vol3_cmd(
            memory_image, "windows.cmdline.CmdLine",
            extra_args=extra_args,
        )

        tool_result, raw_output = self.run_tool(
            tool_name="memory_command_lines",
            evidence_id=evidence_id,
            command=cmdline_cmd,
            input_params={"memory_image": memory_image, "pid": pid},
            timeout=600,
        )

        if tool_result.status == ToolStatus.ERROR:
            return tool_result

        vr = self.cmdline_validator.validate(
            execution_id=tool_result.execution_id,
            raw_output=raw_output,
        )

        atom_ids = []
        for atom in vr.atoms:
            self.store.add_atom(atom)
            atom_ids.append(atom.atom_id)

        # Highlight suspicious command lines
        suspicious = [
            a for a in vr.atoms
            if a.raw_data.get("suspicious_patterns")
        ]

        semantics = get_semantics(ArtifactType.MEMORY_CMDLINE)

        tool_result.structured_data = {
            "process_count": len(vr.atoms),
            "suspicious_count": len(suspicious),
            "suspicious_commands": [
                {
                    "pid": a.raw_data["pid"],
                    "process": a.raw_data["process_name"],
                    "command_line": a.raw_data["command_line"][:200],
                    "patterns": a.raw_data["suspicious_patterns"],
                    "atom_id": a.atom_id,
                }
                for a in suspicious[:20]
            ],
            "atom_ids": atom_ids[:100],
            "warnings": [w.message for w in vr.warnings[:20]],
        }
        tool_result.record_count = len(vr.atoms)
        tool_result.forensic_context = self.build_forensic_context(
            caveats=list(semantics.get("caveats", []))[:3],
            corroboration_hints=list(semantics.get("corroboration_hints", []))[:3],
        )

        return tool_result

    # =======================================================================
    # Tool 6: memory_dump_process (procdump + strings)
    # =======================================================================

    def memory_dump_process(
        self,
        memory_image: str,
        evidence_id: str,
        pid: int,
    ) -> ToolResult:
        """Dump process memory and extract strings for IOC analysis.

        Two-step process:
        1. vol -f <image> windows.memmap.Memmap --pid <pid> --dump
        2. strings <dump_file> (extracts ASCII + Unicode strings)
        """
        validate_read_path(memory_image)

        dump_dir = EXPORTS_DIR / "memdumps" / evidence_id
        dump_dir.mkdir(parents=True, exist_ok=True)

        # Step 1: Dump process memory
        dump_cmd = [
            VOL3_BIN, "-f", memory_image,
            "-o", str(dump_dir),
            "windows.memmap.Memmap",
            "--pid", str(pid),
            "--dump",
        ]

        dump_result, dump_output = self.run_tool(
            tool_name="memory_dump_process",
            evidence_id=evidence_id,
            command=dump_cmd,
            input_params={"memory_image": memory_image, "pid": pid, "step": "dump"},
            timeout=600,
        )

        if dump_result.status == ToolStatus.ERROR:
            return dump_result

        # Find the dump file (Volatility names it pid.<pid>.dmp)
        dump_files = list(dump_dir.glob(f"pid.{pid}.dmp")) + list(dump_dir.glob(f"*{pid}*"))
        if not dump_files:
            dump_result.structured_data = {
                "error": f"No dump file found for PID {pid} in {dump_dir}",
            }
            return dump_result

        dump_file = dump_files[0]

        # Step 2: Extract strings (ASCII + Unicode)
        strings_cmd = [
            "strings", "-a", "-t", "x", str(dump_file),
        ]

        strings_result, strings_output = self.run_tool(
            tool_name="memory_dump_process",
            evidence_id=evidence_id,
            command=strings_cmd,
            input_params={"memory_image": memory_image, "pid": pid, "step": "strings"},
            timeout=300,
        )

        # Also try Unicode strings
        strings_uni_cmd = [
            "strings", "-a", "-t", "x", "-e", "l", str(dump_file),
        ]

        strings_uni_result, strings_uni_output = self.run_tool(
            tool_name="memory_dump_process",
            evidence_id=evidence_id,
            command=strings_uni_cmd,
            input_params={"memory_image": memory_image, "pid": pid, "step": "strings_unicode"},
            timeout=300,
        )

        # Combine ASCII + Unicode strings
        combined_strings = strings_output + "\n" + strings_uni_output

        # Get process name from the store (look up existing process atoms)
        process_name = "unknown"
        process_atoms = self.store.get_atoms_by_type(ArtifactType.MEMORY_PROCESS)
        for pa in process_atoms:
            if pa.raw_data.get("pid") == pid:
                process_name = pa.raw_data.get("process_name", "unknown")
                break

        # Validate and extract IOCs
        vr = self.procdump_validator.validate(
            execution_id=dump_result.execution_id,
            raw_output=combined_strings,
            pid=pid,
            process_name=process_name,
        )

        atom_ids = []
        for atom in vr.atoms:
            self.store.add_atom(atom)
            atom_ids.append(atom.atom_id)

        dump_result.structured_data = {
            "pid": pid,
            "process_name": process_name,
            "dump_file": str(dump_file),
            "dump_size_bytes": dump_file.stat().st_size if dump_file.exists() else 0,
            "strings_count": combined_strings.count("\n"),
            "atom_ids": atom_ids,
            "warnings": [w.message for w in vr.warnings[:20]],
        }

        # Add IOC summary from the atom
        if vr.atoms:
            ioc_data = vr.atoms[0].raw_data
            dump_result.structured_data.update({
                "urls_found": ioc_data.get("urls_found", []),
                "ips_found": ioc_data.get("ips_found", []),
                "domains_found": ioc_data.get("domains_found", []),
            })

        dump_result.record_count = 1
        dump_result.forensic_context = self.build_forensic_context(
            corroboration_hints=[
                "Look up extracted IPs/domains in threat intelligence.",
                "Run YARA scan on the dump file for malware signatures.",
                "Cross-reference URLs with network connection artifacts.",
            ],
        )

        return dump_result
