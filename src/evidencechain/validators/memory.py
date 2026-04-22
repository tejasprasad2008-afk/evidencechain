"""Memory analysis (Volatility 3) output validators.

Parses CSV output from Volatility 3 plugins and produces EvidenceAtoms:
  - ProcessListValidator: pslist + psscan (hidden process detection)
  - NetworkValidator: netscan + netstat
  - MalfindValidator: malfind (code injection detection)
  - ServiceValidator: svcscan
  - CmdlineValidator: cmdline
  - ProcessDumpValidator: procdump strings extraction

Volatility 3 with --renderer csv produces structured CSV output.
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

# Known .NET / JIT processes that commonly trigger malfind false positives
_DOTNET_JIT_PROCESSES = frozenset({
    "w3wp.exe", "mscorsvw.exe", "ngen.exe", "clr.exe",
    "powershell.exe", "pwsh.exe", "devenv.exe", "msbuild.exe",
    "iisexpress.exe", "dotnet.exe", "sqlservr.exe",
    "javaw.exe", "java.exe",  # JVM also uses RWX
})

# Suspicious process names that should be flagged for closer analysis
_SUSPICIOUS_PROCESS_NAMES = frozenset({
    "cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe",
    "wscript.exe", "cscript.exe", "regsvr32.exe", "rundll32.exe",
    "msiexec.exe", "certutil.exe", "bitsadmin.exe", "schtasks.exe",
    "at.exe", "net.exe", "net1.exe", "psexec.exe", "psexesvc.exe",
    "wmiprvse.exe", "wmic.exe",
})


class ProcessListValidator(BaseValidator):
    """Validator for Volatility 3 pslist/psscan CSV output.

    When run with dual-scan, processes found by psscan but NOT in the
    pslist set are flagged as potentially hidden/unlinked.
    """

    def validate(
        self,
        execution_id: str,
        raw_output: str,
        **kwargs,
    ) -> ValidatorResult:
        """Validate process list output.

        kwargs:
            scan_type: "pslist" or "psscan" (for context)
            pslist_pids: set[int] — PIDs from pslist (for hidden detection in psscan)
        """
        result = ValidatorResult()
        semantics = get_semantics(ArtifactType.MEMORY_PROCESS)
        scan_type = kwargs.get("scan_type", "pslist")
        pslist_pids: set[int] = kwargs.get("pslist_pids", set())

        if not raw_output.strip():
            result.warnings.append(
                ValidationWarning(
                    message=f"Empty {scan_type} output",
                    severity="warning",
                )
            )
            return result

        reader = csv.DictReader(io.StringIO(raw_output))
        hidden_count = 0

        for row in reader:
            try:
                atom = self._parse_process_row(
                    row, execution_id, semantics, scan_type, pslist_pids,
                )
                if atom:
                    ts_warnings = validate_timestamps(atom)
                    result.warnings.extend(ts_warnings)
                    result.atoms.append(atom)
                    result.record_count += 1

                    if atom.raw_data.get("potentially_hidden"):
                        hidden_count += 1
            except Exception as e:
                result.warnings.append(
                    ValidationWarning(
                        message=f"Failed to parse {scan_type} row: {e}",
                        severity="warning",
                    )
                )

        if hidden_count > 0:
            result.overclaim_flags.append(
                OverclaimFlag(
                    message=(
                        f"HIDDEN PROCESS ALERT: {hidden_count} process(es) found by psscan "
                        "but NOT in pslist. These may be hidden by rootkits, "
                        "or simply exited processes whose EPROCESS is still in memory."
                    ),
                    claimed_semantic=EvidenceSemantics.PROCESS_CURRENTLY_RUNNING,
                    actual_semantic=EvidenceSemantics.EXECUTION,
                )
            )

        logger.info(
            "ProcessList validator (%s): %d atoms, %d hidden",
            scan_type, len(result.atoms), hidden_count,
        )
        return result

    def _parse_process_row(
        self,
        row: dict,
        execution_id: str,
        semantics: dict,
        scan_type: str,
        pslist_pids: set[int],
    ) -> EvidenceAtom | None:
        # Volatility 3 CSV column names
        pid_str = (
            row.get("PID", "")
            or row.get("pid", "")
        ).strip()
        if not pid_str:
            return None

        try:
            pid = int(pid_str)
        except ValueError:
            return None

        ppid_str = (
            row.get("PPID", "")
            or row.get("ppid", "")
            or row.get("InheritedFromUniqueProcessId", "")
        ).strip()
        try:
            ppid = int(ppid_str) if ppid_str else 0
        except ValueError:
            ppid = 0

        process_name = (
            row.get("ImageFileName", "")
            or row.get("Name", "")
            or row.get("image_file_name", "")
        ).strip()

        if not process_name:
            return None

        # Timestamps
        timestamps = []
        create_time = (
            row.get("CreateTime", "")
            or row.get("create_time", "")
        ).strip()
        if create_time:
            timestamps.append(
                TimestampRecord(
                    value=create_time,
                    source_field="CreateTime",
                    semantic_type=TimestampSemanticType.PROCESS_START,
                )
            )

        exit_time = (
            row.get("ExitTime", "")
            or row.get("exit_time", "")
        ).strip()
        if exit_time:
            timestamps.append(
                TimestampRecord(
                    value=exit_time,
                    source_field="ExitTime",
                    semantic_type=TimestampSemanticType.PROCESS_EXIT,
                )
            )

        # Hidden process detection (psscan result not in pslist)
        potentially_hidden = False
        if scan_type == "psscan" and pslist_pids and pid not in pslist_pids:
            potentially_hidden = True

        # Flag suspicious LOLBins
        is_suspicious = process_name.lower() in _SUSPICIOUS_PROCESS_NAMES

        offset = (
            row.get("Offset(V)", "")
            or row.get("offset", "")
            or row.get("OFFSET (V)", "")
        ).strip()

        threads = row.get("Threads", row.get("threads", "")).strip()
        handles = row.get("Handles", row.get("handles", "")).strip()
        session_id = row.get("SessionId", row.get("session_id", "")).strip()
        wow64 = row.get("Wow64", row.get("wow64", "")).strip()

        proves = set(semantics.get("proves", set()))
        suggests = set(semantics.get("suggests", set()))

        return EvidenceAtom(
            tool_name=f"vol3.{scan_type}",
            execution_id=execution_id,
            artifact_type=ArtifactType.MEMORY_PROCESS,
            raw_data={
                "process_name": process_name,
                "pid": pid,
                "ppid": ppid,
                "offset": offset,
                "threads": threads,
                "handles": handles,
                "session_id": session_id,
                "wow64": wow64,
                "scan_type": scan_type,
                "potentially_hidden": potentially_hidden,
                "is_suspicious_lolbin": is_suspicious,
            },
            timestamps=timestamps,
            file_references=[process_name],
            proves=proves,
            suggests=suggests,
            cannot_prove=set(semantics.get("cannot_prove", set())),
        )


class NetworkValidator(BaseValidator):
    """Validator for Volatility 3 netscan/netstat CSV output."""

    def validate(
        self,
        execution_id: str,
        raw_output: str,
        **kwargs,
    ) -> ValidatorResult:
        result = ValidatorResult()
        semantics = get_semantics(ArtifactType.MEMORY_NETWORK)
        scan_type = kwargs.get("scan_type", "netscan")

        if not raw_output.strip():
            result.warnings.append(
                ValidationWarning(
                    message=f"Empty {scan_type} output",
                    severity="warning",
                )
            )
            return result

        reader = csv.DictReader(io.StringIO(raw_output))

        for row in reader:
            try:
                atom = self._parse_network_row(
                    row, execution_id, semantics, scan_type,
                )
                if atom:
                    ts_warnings = validate_timestamps(atom)
                    result.warnings.extend(ts_warnings)
                    result.atoms.append(atom)
                    result.record_count += 1
            except Exception as e:
                result.warnings.append(
                    ValidationWarning(
                        message=f"Failed to parse {scan_type} row: {e}",
                        severity="warning",
                    )
                )

        # Add caveat about netscan finding historical connections
        if scan_type == "netscan":
            result.overclaim_flags.append(
                OverclaimFlag(
                    message=(
                        "netscan uses pool tag scanning and may find HISTORICAL (closed) "
                        "connections. Do NOT claim connections were active at capture time."
                    ),
                    claimed_semantic=EvidenceSemantics.CONNECTION_ACTIVE_NOW,
                    actual_semantic=EvidenceSemantics.NETWORK_CONNECTION,
                )
            )

        logger.info(
            "Network validator (%s): %d connections",
            scan_type, len(result.atoms),
        )
        return result

    def _parse_network_row(
        self,
        row: dict,
        execution_id: str,
        semantics: dict,
        scan_type: str,
    ) -> EvidenceAtom | None:
        # Volatility 3 netscan columns
        local_addr = (
            row.get("LocalAddr", "")
            or row.get("local_addr", "")
        ).strip()
        local_port = (
            row.get("LocalPort", "")
            or row.get("local_port", "")
        ).strip()
        foreign_addr = (
            row.get("ForeignAddr", "")
            or row.get("foreign_addr", "")
        ).strip()
        foreign_port = (
            row.get("ForeignPort", "")
            or row.get("foreign_port", "")
        ).strip()

        if not local_addr and not foreign_addr:
            return None

        state = (
            row.get("State", "")
            or row.get("state", "")
        ).strip()
        protocol = (
            row.get("Proto", "")
            or row.get("proto", "")
            or row.get("Protocol", "")
        ).strip()
        owner_pid = (
            row.get("PID", "")
            or row.get("Owner", "")
            or row.get("pid", "")
        ).strip()
        owner_name = (
            row.get("Owner", "")
            or row.get("ImageFileName", "")
        ).strip()
        offset = row.get("Offset(V)", row.get("offset", "")).strip()

        timestamps = []
        created = row.get("Created", row.get("CreateTime", "")).strip()
        if created:
            timestamps.append(
                TimestampRecord(
                    value=created,
                    source_field="Created",
                    semantic_type=TimestampSemanticType.CONNECTION_TIME,
                )
            )

        # Check for non-RFC1918 foreign addresses (potential C2)
        is_external = False
        if foreign_addr and foreign_addr not in ("0.0.0.0", "*", "::", ""):
            is_external = not self._is_rfc1918(foreign_addr)

        return EvidenceAtom(
            tool_name=f"vol3.{scan_type}",
            execution_id=execution_id,
            artifact_type=ArtifactType.MEMORY_NETWORK,
            raw_data={
                "local_addr": local_addr,
                "local_port": local_port,
                "foreign_addr": foreign_addr,
                "foreign_port": foreign_port,
                "state": state,
                "protocol": protocol,
                "owner_pid": owner_pid,
                "owner_name": owner_name,
                "offset": offset,
                "scan_type": scan_type,
                "is_external_connection": is_external,
            },
            timestamps=timestamps,
            file_references=[],
            proves=set(semantics.get("proves", set())),
            suggests=set(semantics.get("suggests", set())),
            cannot_prove=set(semantics.get("cannot_prove", set())),
        )

    @staticmethod
    def _is_rfc1918(ip: str) -> bool:
        """Check if an IP is a private RFC 1918 address."""
        try:
            parts = ip.split(".")
            if len(parts) != 4:
                return False
            a, b = int(parts[0]), int(parts[1])
            if a == 10:
                return True
            if a == 172 and 16 <= b <= 31:
                return True
            if a == 192 and b == 168:
                return True
            if a == 127:
                return True
            return False
        except (ValueError, IndexError):
            return False


class MalfindValidator(BaseValidator):
    """Validator for Volatility 3 malfind output.

    Detects potentially injected code (RWX memory regions without file backing).
    Filters known .NET/JIT false positives.
    """

    def validate(
        self,
        execution_id: str,
        raw_output: str,
        **kwargs,
    ) -> ValidatorResult:
        result = ValidatorResult()
        semantics = get_semantics(ArtifactType.MEMORY_MALFIND)

        if not raw_output.strip():
            result.warnings.append(
                ValidationWarning(
                    message="Empty malfind output (no suspicious regions found)",
                    severity="info",
                )
            )
            return result

        reader = csv.DictReader(io.StringIO(raw_output))
        fp_count = 0

        for row in reader:
            try:
                atom, is_fp = self._parse_malfind_row(
                    row, execution_id, semantics,
                )
                if atom:
                    result.atoms.append(atom)
                    result.record_count += 1
                    if is_fp:
                        fp_count += 1
            except Exception as e:
                result.warnings.append(
                    ValidationWarning(
                        message=f"Failed to parse malfind row: {e}",
                        severity="warning",
                    )
                )

        if fp_count > 0:
            result.warnings.append(
                ValidationWarning(
                    message=(
                        f"{fp_count} malfind hit(s) are from known .NET/JIT processes "
                        "and are likely false positives. These are still reported but "
                        "flagged with likely_false_positive=True."
                    ),
                    severity="info",
                )
            )

        result.overclaim_flags.append(
            OverclaimFlag(
                message=(
                    "malfind reports RWX memory regions without file backing. "
                    "This SUGGESTS code injection but does NOT prove malicious intent. "
                    ".NET, JIT, and packed applications commonly trigger malfind."
                ),
                claimed_semantic=EvidenceSemantics.MALICIOUS_INTENT,
                actual_semantic=EvidenceSemantics.CODE_INJECTION,
            )
        )

        logger.info(
            "Malfind validator: %d hits, %d likely FPs",
            len(result.atoms), fp_count,
        )
        return result

    def _parse_malfind_row(
        self,
        row: dict,
        execution_id: str,
        semantics: dict,
    ) -> tuple[EvidenceAtom | None, bool]:
        pid_str = (
            row.get("PID", "")
            or row.get("pid", "")
        ).strip()
        if not pid_str:
            return None, False

        try:
            pid = int(pid_str)
        except ValueError:
            return None, False

        process_name = (
            row.get("Process", "")
            or row.get("ImageFileName", "")
            or row.get("process", "")
        ).strip()

        start_vpn = row.get("Start VPN", row.get("start_vpn", "")).strip()
        end_vpn = row.get("End VPN", row.get("end_vpn", "")).strip()
        tag = row.get("Tag", row.get("tag", "")).strip()
        protection = row.get("Protection", row.get("protection", "")).strip()
        committed = row.get("CommitCharge", row.get("commit_charge", "")).strip()
        hexdump = row.get("Hexdump", row.get("hexdump", "")).strip()
        disasm = row.get("Disasm", row.get("disasm", "")).strip()

        # Check for .NET/JIT false positive
        is_likely_fp = process_name.lower() in _DOTNET_JIT_PROCESSES

        suggests = set(semantics.get("suggests", set()))

        atom = EvidenceAtom(
            tool_name="vol3.malfind",
            execution_id=execution_id,
            artifact_type=ArtifactType.MEMORY_MALFIND,
            raw_data={
                "process_name": process_name,
                "pid": pid,
                "start_vpn": start_vpn,
                "end_vpn": end_vpn,
                "tag": tag,
                "protection": protection,
                "commit_charge": committed,
                "hexdump_preview": hexdump[:200] if hexdump else "",
                "disasm_preview": disasm[:200] if disasm else "",
                "likely_false_positive": is_likely_fp,
            },
            timestamps=[],
            file_references=[process_name] if process_name else [],
            proves=set(semantics.get("proves", set())),
            suggests=suggests,
            cannot_prove=set(semantics.get("cannot_prove", set())),
        )

        return atom, is_likely_fp


class ServiceValidator(BaseValidator):
    """Validator for Volatility 3 svcscan CSV output."""

    def validate(
        self,
        execution_id: str,
        raw_output: str,
        **kwargs,
    ) -> ValidatorResult:
        result = ValidatorResult()
        semantics = get_semantics(ArtifactType.MEMORY_SERVICE)

        if not raw_output.strip():
            result.warnings.append(
                ValidationWarning(message="Empty svcscan output", severity="warning")
            )
            return result

        reader = csv.DictReader(io.StringIO(raw_output))

        for row in reader:
            try:
                atom = self._parse_service_row(row, execution_id, semantics)
                if atom:
                    result.atoms.append(atom)
                    result.record_count += 1
            except Exception as e:
                result.warnings.append(
                    ValidationWarning(
                        message=f"Failed to parse svcscan row: {e}",
                        severity="warning",
                    )
                )

        logger.info("Service validator: %d services", len(result.atoms))
        return result

    def _parse_service_row(
        self,
        row: dict,
        execution_id: str,
        semantics: dict,
    ) -> EvidenceAtom | None:
        service_name = (
            row.get("Name", "")
            or row.get("service_name", "")
        ).strip()

        if not service_name:
            return None

        display_name = row.get("Display", row.get("display_name", "")).strip()
        binary_path = (
            row.get("Binary", "")
            or row.get("binary_path", "")
            or row.get("ImagePath", "")
        ).strip()
        state = row.get("State", row.get("state", "")).strip()
        start_type = row.get("Start", row.get("start_type", "")).strip()
        svc_type = row.get("Type", row.get("service_type", "")).strip()
        pid = row.get("PID", row.get("pid", "")).strip()

        file_refs = []
        if binary_path:
            # Extract actual executable path from service binary path
            # (strip quotes and arguments)
            clean_path = binary_path.strip('"').split(" -")[0].split(" /")[0].strip()
            file_refs.append(clean_path)

        return EvidenceAtom(
            tool_name="vol3.svcscan",
            execution_id=execution_id,
            artifact_type=ArtifactType.MEMORY_SERVICE,
            raw_data={
                "service_name": service_name,
                "display_name": display_name,
                "binary_path": binary_path,
                "state": state,
                "start_type": start_type,
                "service_type": svc_type,
                "pid": pid,
            },
            timestamps=[],
            file_references=file_refs,
            proves=set(semantics.get("proves", set())),
            suggests=set(semantics.get("suggests", set())),
            cannot_prove=set(semantics.get("cannot_prove", set())),
        )


class CmdlineValidator(BaseValidator):
    """Validator for Volatility 3 cmdline CSV output."""

    def validate(
        self,
        execution_id: str,
        raw_output: str,
        **kwargs,
    ) -> ValidatorResult:
        result = ValidatorResult()
        semantics = get_semantics(ArtifactType.MEMORY_CMDLINE)

        if not raw_output.strip():
            result.warnings.append(
                ValidationWarning(message="Empty cmdline output", severity="warning")
            )
            return result

        reader = csv.DictReader(io.StringIO(raw_output))

        for row in reader:
            try:
                atom = self._parse_cmdline_row(row, execution_id, semantics)
                if atom:
                    result.atoms.append(atom)
                    result.record_count += 1
            except Exception as e:
                result.warnings.append(
                    ValidationWarning(
                        message=f"Failed to parse cmdline row: {e}",
                        severity="warning",
                    )
                )

        logger.info("Cmdline validator: %d processes", len(result.atoms))
        return result

    def _parse_cmdline_row(
        self,
        row: dict,
        execution_id: str,
        semantics: dict,
    ) -> EvidenceAtom | None:
        pid_str = (
            row.get("PID", "")
            or row.get("pid", "")
        ).strip()
        if not pid_str:
            return None

        try:
            pid = int(pid_str)
        except ValueError:
            return None

        process_name = (
            row.get("Process", "")
            or row.get("ImageFileName", "")
        ).strip()
        args = (
            row.get("Args", "")
            or row.get("CommandLine", "")
            or row.get("args", "")
        ).strip()

        if not process_name:
            return None

        # Detect encoded PowerShell commands
        has_encoded_command = bool(
            re.search(r"-[eE](?:nc|ncodedcommand)\s+", args)
        )

        # Detect suspicious command patterns
        suspicious_patterns = []
        if has_encoded_command:
            suspicious_patterns.append("encoded_powershell")
        if re.search(r"(?:Invoke-|IEX|iex|DownloadString|DownloadFile)", args):
            suspicious_patterns.append("powershell_download")
        if re.search(r"(?:\\\\[\d.]+\\|\\\\[\w]+\\)", args):
            suspicious_patterns.append("unc_path")
        if re.search(r"(?:certutil.*-urlcache|bitsadmin.*\/transfer)", args, re.IGNORECASE):
            suspicious_patterns.append("lolbin_download")

        return EvidenceAtom(
            tool_name="vol3.cmdline",
            execution_id=execution_id,
            artifact_type=ArtifactType.MEMORY_CMDLINE,
            raw_data={
                "process_name": process_name,
                "pid": pid,
                "command_line": args[:2000],  # Cap very long command lines
                "has_encoded_command": has_encoded_command,
                "suspicious_patterns": suspicious_patterns,
            },
            timestamps=[],
            file_references=[process_name],
            proves=set(semantics.get("proves", set())),
            suggests=set(semantics.get("suggests", set())),
            cannot_prove=set(semantics.get("cannot_prove", set())),
        )


class ProcessDumpValidator(BaseValidator):
    """Validator for process memory dump strings output.

    Parses the strings extracted from a dumped process to identify
    IOCs (URLs, IPs, suspicious strings).
    """

    # Regex patterns for IOC extraction from strings output
    _URL_PATTERN = re.compile(r"https?://[^\s\"'<>]{5,200}")
    _IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    _DOMAIN_PATTERN = re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"
        r"+(?:com|net|org|io|xyz|top|ru|cn|tk|info|biz|cc)\b"
    )

    def validate(
        self,
        execution_id: str,
        raw_output: str,
        **kwargs,
    ) -> ValidatorResult:
        """Validate strings output from a process dump.

        kwargs:
            pid: int — PID of the dumped process
            process_name: str — Name of the dumped process
        """
        result = ValidatorResult()
        semantics = get_semantics(ArtifactType.MEMORY_DUMP)

        pid = kwargs.get("pid", 0)
        process_name = kwargs.get("process_name", "unknown")

        if not raw_output.strip():
            result.warnings.append(
                ValidationWarning(
                    message=f"Empty strings output for PID {pid}",
                    severity="warning",
                )
            )
            return result

        # Extract IOCs from strings
        urls = list(set(self._URL_PATTERN.findall(raw_output)))[:50]
        ips = list(set(self._IP_PATTERN.findall(raw_output)))
        domains = list(set(self._DOMAIN_PATTERN.findall(raw_output)))[:50]

        # Filter out common non-suspicious IPs
        ips = [
            ip for ip in ips
            if ip not in ("0.0.0.0", "127.0.0.1", "255.255.255.255")
            and not ip.startswith("0.")
        ][:50]

        atom = EvidenceAtom(
            tool_name="vol3.procdump+strings",
            execution_id=execution_id,
            artifact_type=ArtifactType.MEMORY_DUMP,
            raw_data={
                "process_name": process_name,
                "pid": pid,
                "strings_count": raw_output.count("\n"),
                "urls_found": urls[:20],
                "ips_found": ips[:20],
                "domains_found": domains[:20],
                "total_urls": len(urls),
                "total_ips": len(ips),
                "total_domains": len(domains),
            },
            timestamps=[],
            file_references=[process_name],
            proves=set(semantics.get("proves", set()) if semantics else set()),
            suggests=set(semantics.get("suggests", set()) if semantics else set()),
            cannot_prove=set(semantics.get("cannot_prove", set()) if semantics else set()),
        )

        result.atoms.append(atom)
        result.record_count = 1

        if urls or ips or domains:
            result.warnings.append(
                ValidationWarning(
                    message=(
                        f"IOCs extracted from PID {pid} ({process_name}): "
                        f"{len(urls)} URLs, {len(ips)} IPs, {len(domains)} domains. "
                        "Use enrich_indicators to look these up in threat intelligence."
                    ),
                    severity="info",
                )
            )

        logger.info(
            "ProcessDump validator: PID %d, %d URLs, %d IPs, %d domains",
            pid, len(urls), len(ips), len(domains),
        )
        return result
