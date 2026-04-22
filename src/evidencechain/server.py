"""EvidenceChain MCP Server — entry point.

This is the main MCP server that exposes all 21 forensic tools and
7 contradiction detectors as typed functions. It runs via stdio transport
and is connected to by the Qoder agent.

Usage:
    python -m evidencechain.server
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import asdict
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from .config import ANALYSIS_DIR, AUDIT_DIR, EXPORTS_DIR, REPORTS_DIR
from .correction.engine import CorrectionEngine
from .provenance.audit_logger import AuditLogger
from .provenance.evidence_registry import EvidenceRegistry
from .provenance.evidence_store import EvidenceStore
from .report.generator import ReportGenerator
from .tools.disk import DiskToolExecutor
from .tools.enrichment import EnrichmentToolExecutor
from .tools.memory import MemoryToolExecutor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("evidencechain")

# ---------------------------------------------------------------------------
# Global state (initialized once per server lifetime)
# ---------------------------------------------------------------------------

store = EvidenceStore()
audit = AuditLogger()
registry = EvidenceRegistry()

# Tool executors (initialized with shared state)
disk_tools = DiskToolExecutor(store, audit, registry)
memory_tools = MemoryToolExecutor(store, audit, registry)
enrichment_tools = EnrichmentToolExecutor(store, audit, registry)

# Correction engine and report generator
correction_engine = CorrectionEngine(store, audit)
report_generator = ReportGenerator(store, audit)

# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------

app = Server("evidencechain")


def _serialize(obj: object) -> str:
    """Serialize a dataclass or dict to a JSON string for MCP responses."""
    if hasattr(obj, "__dataclass_fields__"):
        d = asdict(obj)
        for k, v in d.items():
            if isinstance(v, set):
                d[k] = sorted(v)
        return json.dumps(d, default=str, indent=2)
    if isinstance(obj, dict):
        return json.dumps(obj, default=str, indent=2)
    return str(obj)


# ---------------------------------------------------------------------------
# Tool definitions — these are the 21 MCP tools the agent can call
# ---------------------------------------------------------------------------

@app.list_tools()
async def list_tools() -> list[Tool]:
    """Return all available tools."""
    return [
        # Group A: Disk Image Analysis
        Tool(
            name="mount_evidence",
            description=(
                "Mount a disk image (E01, dd, raw) read-only. "
                "Returns the mount point path and partition info. "
                "All evidence is mounted with -o ro,loop,noatime."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "image_path": {
                        "type": "string",
                        "description": "Path to the disk image file (.E01, .dd, .raw)",
                    },
                    "image_type": {
                        "type": "string",
                        "enum": ["E01", "dd", "raw"],
                        "description": "Type of disk image",
                    },
                },
                "required": ["image_path", "image_type"],
            },
        ),
        Tool(
            name="get_filesystem_timeline",
            description=(
                "Generate a MAC timeline from the filesystem using fls and mactime. "
                "Optionally filter by date range. Returns structured timeline entries."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "mount_point": {"type": "string", "description": "Path to mounted evidence"},
                    "evidence_id": {"type": "string", "description": "Evidence ID (e.g., EVD-disk-001)"},
                    "date_start": {"type": "string", "description": "Start date filter (YYYY-MM-DD), optional"},
                    "date_end": {"type": "string", "description": "End date filter (YYYY-MM-DD), optional"},
                },
                "required": ["mount_point", "evidence_id"],
            },
        ),
        Tool(
            name="parse_mft",
            description=(
                "Parse the MFT using MFTECmd with --at flag for all timestamps. "
                "Compares $STANDARD_INFO vs $FILE_NAME timestamps to detect timestomping. "
                "CANNOT PROVE: user vs system distinction."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "mft_path": {"type": "string", "description": "Path to $MFT file"},
                    "evidence_id": {"type": "string", "description": "Evidence ID"},
                },
                "required": ["mft_path", "evidence_id"],
            },
        ),
        Tool(
            name="parse_event_logs",
            description=(
                "Parse Windows Event Logs using EvtxECmd. Filterable by Event ID list "
                "and date range. Returns structured events with forensic context."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "evtx_path": {"type": "string", "description": "Path to .evtx file or directory of .evtx files"},
                    "evidence_id": {"type": "string", "description": "Evidence ID"},
                    "event_ids": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "Filter to specific Event IDs (optional). Key IDs: 4624 (logon), 4688 (process), 7045 (service), 1116 (Defender)",
                    },
                    "date_start": {"type": "string", "description": "Start date filter (YYYY-MM-DD), optional"},
                    "date_end": {"type": "string", "description": "End date filter (YYYY-MM-DD), optional"},
                },
                "required": ["evtx_path", "evidence_id"],
            },
        ),
        Tool(
            name="parse_prefetch",
            description=(
                "Parse Windows Prefetch files using PECmd. "
                "PROVES: execution (up to 8 most recent run timestamps per executable). "
                "SUGGESTS: which user may have run it."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "prefetch_dir": {"type": "string", "description": "Path to the Prefetch directory"},
                    "evidence_id": {"type": "string", "description": "Evidence ID"},
                },
                "required": ["prefetch_dir", "evidence_id"],
            },
        ),
        Tool(
            name="parse_amcache",
            description=(
                "Parse the Amcache hive using AmcacheParser. "
                "PROVES: execution + SHA1 hash at time of first run. "
                "Use SHA1 for threat intelligence lookups."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "amcache_path": {"type": "string", "description": "Path to Amcache.hve file"},
                    "evidence_id": {"type": "string", "description": "Evidence ID"},
                },
                "required": ["amcache_path", "evidence_id"],
            },
        ),
        Tool(
            name="parse_registry",
            description=(
                "Parse Windows registry hives using RECmd for persistence, "
                "user activity, and system configuration. "
                "PROVES: persistence mechanism was configured. "
                "CANNOT PROVE: that the persistence mechanism executed."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "hive_path": {"type": "string", "description": "Path to registry hive file (SYSTEM, SOFTWARE, NTUSER.DAT, etc.)"},
                    "evidence_id": {"type": "string", "description": "Evidence ID"},
                },
                "required": ["hive_path", "evidence_id"],
            },
        ),
        Tool(
            name="extract_file",
            description=(
                "Extract a specific file from a mounted disk image and compute its SHA-256 hash. "
                "Use this to pull suspicious files for YARA scanning or threat intel lookup."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to the file within the mounted image"},
                    "evidence_id": {"type": "string", "description": "Evidence ID"},
                    "output_name": {"type": "string", "description": "Name for the extracted file (optional)"},
                },
                "required": ["file_path", "evidence_id"],
            },
        ),

        # Group B: Memory Analysis
        Tool(
            name="memory_process_list",
            description=(
                "List all processes from a memory image using Volatility 3 (pslist + psscan). "
                "Dual-scan: pslist walks the active linked list, psscan finds processes via "
                "pool tag scanning (reveals hidden/exited processes). "
                "Flags processes found by psscan but NOT pslist as potentially hidden."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "memory_image": {"type": "string", "description": "Path to memory image (.raw, .mem)"},
                    "evidence_id": {"type": "string", "description": "Evidence ID (e.g., EVD-mem-001)"},
                },
                "required": ["memory_image", "evidence_id"],
            },
        ),
        Tool(
            name="memory_network_connections",
            description=(
                "List network connections from a memory image using Volatility 3 (netscan + netstat). "
                "PROVES: network connection existed. "
                "CANNOT PROVE: connection was active at capture time (netscan finds historical)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "memory_image": {"type": "string", "description": "Path to memory image"},
                    "evidence_id": {"type": "string", "description": "Evidence ID"},
                },
                "required": ["memory_image", "evidence_id"],
            },
        ),
        Tool(
            name="memory_injected_code",
            description=(
                "Detect potentially injected code using Volatility 3 malfind. "
                "Finds memory regions with RWX permissions and no file backing. "
                "SUGGESTS: code injection. "
                "CAVEAT: .NET and JIT processes commonly have RWX regions (false positives)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "memory_image": {"type": "string", "description": "Path to memory image"},
                    "evidence_id": {"type": "string", "description": "Evidence ID"},
                    "pid": {"type": "integer", "description": "Filter to specific PID (optional)"},
                },
                "required": ["memory_image", "evidence_id"],
            },
        ),
        Tool(
            name="memory_services",
            description=(
                "List Windows services from memory using Volatility 3 svcscan. "
                "Cross-reference with registry persistence keys to validate running services."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "memory_image": {"type": "string", "description": "Path to memory image"},
                    "evidence_id": {"type": "string", "description": "Evidence ID"},
                },
                "required": ["memory_image", "evidence_id"],
            },
        ),
        Tool(
            name="memory_command_lines",
            description=(
                "Extract process command lines from memory using Volatility 3 cmdline. "
                "Reveals attacker commands, encoded PowerShell, and tool arguments."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "memory_image": {"type": "string", "description": "Path to memory image"},
                    "evidence_id": {"type": "string", "description": "Evidence ID"},
                    "pid": {"type": "integer", "description": "Filter to specific PID (optional)"},
                },
                "required": ["memory_image", "evidence_id"],
            },
        ),
        Tool(
            name="memory_dump_process",
            description=(
                "Dump a process's memory and run strings extraction. "
                "Use for deep analysis of suspicious processes — look for URLs, IPs, credentials."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "memory_image": {"type": "string", "description": "Path to memory image"},
                    "evidence_id": {"type": "string", "description": "Evidence ID"},
                    "pid": {"type": "integer", "description": "PID of process to dump"},
                },
                "required": ["memory_image", "evidence_id", "pid"],
            },
        ),

        # Group C: Enrichment & Cross-Cutting
        Tool(
            name="yara_scan",
            description=(
                "Scan files or directories with YARA rules. "
                "SUGGESTS: known malware pattern match. "
                "CANNOT PROVE: malicious intent (false positives possible)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "rules_path": {"type": "string", "description": "Path to YARA rules file or directory"},
                    "target_path": {"type": "string", "description": "Path to scan (file or directory)"},
                    "evidence_id": {"type": "string", "description": "Evidence ID"},
                    "recursive": {"type": "boolean", "description": "Scan recursively (default: true)"},
                },
                "required": ["rules_path", "target_path", "evidence_id"],
            },
        ),
        Tool(
            name="compute_hashes",
            description=(
                "Compute MD5, SHA1, and SHA256 hashes for a file. "
                "Use for evidence provenance and threat intelligence lookups."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to the file to hash"},
                    "evidence_id": {"type": "string", "description": "Evidence ID"},
                },
                "required": ["file_path", "evidence_id"],
            },
        ),
        Tool(
            name="enrich_indicators",
            description=(
                "Look up indicators (hashes, IPs, domains, filenames) in threat intelligence "
                "sources: VirusTotal, AbuseIPDB, MalwareBazaar, LOLBAS, AlienVault OTX. "
                "Returns structured verdicts (MALICIOUS/SUSPICIOUS/CLEAN/UNKNOWN) with "
                "source attribution. Results are stored as THREAT_INTEL evidence atoms."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "indicators": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "type": {
                                    "type": "string",
                                    "enum": ["hash_sha256", "hash_sha1", "hash_md5", "ipv4", "domain", "filename"],
                                },
                                "value": {"type": "string"},
                            },
                            "required": ["type", "value"],
                        },
                        "description": "List of indicators to look up",
                    },
                    "sources": {
                        "type": "array",
                        "items": {"type": "string", "enum": ["virustotal", "abuseipdb", "malwarebazaar", "lolbas", "alienvault_otx"]},
                        "description": "Optional: limit to specific sources. Default: all applicable sources.",
                    },
                },
                "required": ["indicators"],
            },
        ),
        Tool(
            name="generate_super_timeline",
            description=(
                "Generate a unified super timeline using log2timeline/plaso. "
                "Aggregates timestamps from all evidence sources into a single chronological view."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "image_path": {"type": "string", "description": "Path to disk image or mount point"},
                    "evidence_id": {"type": "string", "description": "Evidence ID"},
                    "date_start": {"type": "string", "description": "Start date filter (YYYY-MM-DD), optional"},
                    "date_end": {"type": "string", "description": "End date filter (YYYY-MM-DD), optional"},
                },
                "required": ["image_path", "evidence_id"],
            },
        ),
        Tool(
            name="unmount_evidence",
            description="Unmount a previously mounted disk image. Clean teardown.",
            inputSchema={
                "type": "object",
                "properties": {
                    "mount_point": {"type": "string", "description": "Mount point to unmount"},
                },
                "required": ["mount_point"],
            },
        ),

        # Group D: Self-Correction & Reporting
        Tool(
            name="run_self_correction",
            description=(
                "Run the 4-pass self-correction engine on all current findings. "
                "Pass 1: Inline validation summary. "
                "Pass 2: Cross-source contradiction detection (7 detectors). "
                "Pass 3: Evidence-weighted confidence scoring (auto-confirms >= 0.75, flags < 0.40). "
                "Pass 4: Reinvestigation planning (prioritized tool calls to resolve contradictions). "
                "Returns the correction report with reinvestigation actions for the agent to execute."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "full_pipeline": {
                        "type": "boolean",
                        "description": (
                            "If true, run up to 3 iterations until convergence. "
                            "If false (default), run a single iteration."
                        ),
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="generate_report",
            description=(
                "Generate the final investigation report. Assembles all confirmed findings, "
                "contradictions, timeline, MITRE ATT&CK coverage, and self-correction summary "
                "into Markdown and/or JSON. Reports are saved to the reports/ directory."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "formats": {
                        "type": "array",
                        "items": {"type": "string", "enum": ["markdown", "json"]},
                        "description": "Output formats (default: both markdown and json)",
                    },
                },
                "required": [],
            },
        ),
    ]


# ---------------------------------------------------------------------------
# Tool dispatch table — maps tool names to handler functions
# ---------------------------------------------------------------------------

def _handle_mount_evidence(args: dict):
    return disk_tools.mount_evidence(
        image_path=args["image_path"],
        image_type=args["image_type"],
    )

def _handle_get_filesystem_timeline(args: dict):
    return disk_tools.get_filesystem_timeline(
        mount_point=args["mount_point"],
        evidence_id=args["evidence_id"],
        date_start=args.get("date_start"),
        date_end=args.get("date_end"),
    )

def _handle_parse_mft(args: dict):
    return disk_tools.parse_mft(
        mft_path=args["mft_path"],
        evidence_id=args["evidence_id"],
    )

def _handle_parse_event_logs(args: dict):
    return disk_tools.parse_event_logs(
        evtx_path=args["evtx_path"],
        evidence_id=args["evidence_id"],
        event_ids=args.get("event_ids"),
        date_start=args.get("date_start"),
        date_end=args.get("date_end"),
    )

def _handle_parse_prefetch(args: dict):
    return disk_tools.parse_prefetch(
        prefetch_dir=args["prefetch_dir"],
        evidence_id=args["evidence_id"],
    )

def _handle_parse_amcache(args: dict):
    return disk_tools.parse_amcache(
        amcache_path=args["amcache_path"],
        evidence_id=args["evidence_id"],
    )

def _handle_parse_registry(args: dict):
    return disk_tools.parse_registry(
        hive_path=args["hive_path"],
        evidence_id=args["evidence_id"],
    )

def _handle_extract_file(args: dict):
    return disk_tools.extract_file(
        file_path=args["file_path"],
        evidence_id=args["evidence_id"],
        output_name=args.get("output_name"),
    )

def _handle_unmount_evidence(args: dict):
    return disk_tools.unmount_evidence(
        mount_point=args["mount_point"],
    )


# Group B: Memory tool handlers

def _handle_memory_process_list(args: dict):
    return memory_tools.memory_process_list(
        memory_image=args["memory_image"],
        evidence_id=args["evidence_id"],
    )

def _handle_memory_network_connections(args: dict):
    return memory_tools.memory_network_connections(
        memory_image=args["memory_image"],
        evidence_id=args["evidence_id"],
    )

def _handle_memory_injected_code(args: dict):
    return memory_tools.memory_injected_code(
        memory_image=args["memory_image"],
        evidence_id=args["evidence_id"],
        pid=args.get("pid"),
    )

def _handle_memory_services(args: dict):
    return memory_tools.memory_services(
        memory_image=args["memory_image"],
        evidence_id=args["evidence_id"],
    )

def _handle_memory_command_lines(args: dict):
    return memory_tools.memory_command_lines(
        memory_image=args["memory_image"],
        evidence_id=args["evidence_id"],
        pid=args.get("pid"),
    )

def _handle_memory_dump_process(args: dict):
    return memory_tools.memory_dump_process(
        memory_image=args["memory_image"],
        evidence_id=args["evidence_id"],
        pid=args["pid"],
    )


# Group C: Enrichment tool handlers

def _handle_enrich_indicators(args: dict):
    return enrichment_tools.enrich_indicators(
        indicators=args["indicators"],
        sources=args.get("sources"),
    )

def _handle_compute_hashes(args: dict):
    return enrichment_tools.compute_hashes(
        file_path=args["file_path"],
        evidence_id=args["evidence_id"],
    )

def _handle_yara_scan(args: dict):
    return enrichment_tools.yara_scan(
        rules_path=args["rules_path"],
        target_path=args["target_path"],
        evidence_id=args["evidence_id"],
        recursive=args.get("recursive", True),
    )

def _handle_generate_super_timeline(args: dict):
    return enrichment_tools.generate_super_timeline(
        image_path=args["image_path"],
        evidence_id=args["evidence_id"],
        date_start=args.get("date_start"),
        date_end=args.get("date_end"),
    )


# Group D: Self-Correction & Reporting handlers

def _handle_run_self_correction(args: dict):
    if args.get("full_pipeline"):
        reports = correction_engine.run_full_pipeline()
        last = reports[-1] if reports else None
        result = {
            "status": "ok",
            "iterations": len(reports),
            "converged": last.converged if last else False,
            "summaries": [r.summary for r in reports],
        }
        if last and not last.converged:
            result["reinvestigation_plan"] = (
                correction_engine.format_reinvestigation_for_llm(
                    last.reinvestigation_plan
                )
            )
        return result
    else:
        report = correction_engine.run_iteration()
        result = {
            "status": "ok",
            "iteration": report.iteration,
            "converged": report.converged,
            "summary": report.summary,
        }
        if not report.converged:
            result["reinvestigation_plan"] = (
                correction_engine.format_reinvestigation_for_llm(
                    report.reinvestigation_plan
                )
            )
        return result

def _handle_generate_report(args: dict):
    formats = args.get("formats")
    output_paths = report_generator.generate(formats=formats)
    report_string = report_generator.generate_to_string(fmt="markdown")
    return {
        "status": "ok",
        "output_paths": output_paths,
        "report_preview": report_string[:8000],
    }


_TOOL_DISPATCH: dict[str, callable] = {
    # Group A: Disk tools
    "mount_evidence": _handle_mount_evidence,
    "get_filesystem_timeline": _handle_get_filesystem_timeline,
    "parse_mft": _handle_parse_mft,
    "parse_event_logs": _handle_parse_event_logs,
    "parse_prefetch": _handle_parse_prefetch,
    "parse_amcache": _handle_parse_amcache,
    "parse_registry": _handle_parse_registry,
    "extract_file": _handle_extract_file,
    "unmount_evidence": _handle_unmount_evidence,
    # Group B: Memory tools
    "memory_process_list": _handle_memory_process_list,
    "memory_network_connections": _handle_memory_network_connections,
    "memory_injected_code": _handle_memory_injected_code,
    "memory_services": _handle_memory_services,
    "memory_command_lines": _handle_memory_command_lines,
    "memory_dump_process": _handle_memory_dump_process,
    # Group C: Enrichment tools
    "enrich_indicators": _handle_enrich_indicators,
    "compute_hashes": _handle_compute_hashes,
    "yara_scan": _handle_yara_scan,
    "generate_super_timeline": _handle_generate_super_timeline,
    # Group D: Self-Correction & Reporting
    "run_self_correction": _handle_run_self_correction,
    "generate_report": _handle_generate_report,
}


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Dispatch tool calls to the appropriate handler."""
    logger.info("Tool call: %s(%s)", name, json.dumps(arguments, default=str)[:200])

    # Ensure output directories exist
    ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)
    EXPORTS_DIR.mkdir(parents=True, exist_ok=True)
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    try:
        # Route to the appropriate tool handler
        handler = _TOOL_DISPATCH.get(name)
        if handler is None:
            result = {
                "status": "not_implemented",
                "tool": name,
                "message": f"Tool '{name}' is registered but not yet implemented.",
            }
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        tool_result = handler(arguments)
        return [TextContent(type="text", text=_serialize(tool_result))]
    except Exception as e:
        logger.exception("Error in tool %s", name)
        error_result = {
            "status": "error",
            "tool": name,
            "error": str(e),
        }
        return [TextContent(type="text", text=json.dumps(error_result, indent=2))]


# ---------------------------------------------------------------------------
# Server entry point
# ---------------------------------------------------------------------------

async def main() -> None:
    """Run the EvidenceChain MCP server via stdio."""
    logger.info("Starting EvidenceChain MCP server (21 tools registered)")
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


def run() -> None:
    """Synchronous entry point."""
    asyncio.run(main())


if __name__ == "__main__":
    run()
