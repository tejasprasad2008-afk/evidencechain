"""Enrichment tool executor — YARA scanning, hashing, threat intel, and super timeline.

Implements the 4 enrichment/cross-cutting MCP tools:
  1. enrich_indicators  — Multi-source threat intelligence lookups
  2. compute_hashes     — MD5/SHA1/SHA256 file hashing
  3. yara_scan          — YARA rule scanning
  4. generate_super_timeline — log2timeline/plaso super timeline
"""

from __future__ import annotations

import csv
import hashlib
import io
import logging
from dataclasses import asdict
from pathlib import Path

from ..config import ANALYSIS_DIR, EXPORTS_DIR
from ..enums import (
    ArtifactType,
    EvidenceSemantics,
    ToolStatus,
)
from ..forensic_semantics import get_semantics
from ..models import (
    EvidenceAtom,
    ForensicContext,
    Indicator,
    ToolResult,
    _new_id,
    _utcnow,
)
from ..provenance.audit_logger import AuditLogger
from ..provenance.evidence_registry import EvidenceRegistry
from ..provenance.evidence_store import EvidenceStore
from ..security.path_validator import validate_read_path, validate_write_path
from ..threat_intel.aggregator import ThreatIntelAggregator
from ..threat_intel.rate_limiter import RateLimiter
from ..tools.base import BaseToolExecutor

logger = logging.getLogger(__name__)


class EnrichmentToolExecutor(BaseToolExecutor):
    """Executor for enrichment and cross-cutting tools."""

    def __init__(
        self,
        store: EvidenceStore,
        audit: AuditLogger,
        registry: EvidenceRegistry,
    ) -> None:
        super().__init__(store, audit)
        self.registry = registry

        # Lazy-init threat intel aggregator (shares rate limiter)
        self._rate_limiter = RateLimiter()
        self._aggregator: ThreatIntelAggregator | None = None

    @property
    def aggregator(self) -> ThreatIntelAggregator:
        if self._aggregator is None:
            self._aggregator = ThreatIntelAggregator(self.store, self._rate_limiter)
        return self._aggregator

    # -------------------------------------------------------------------
    # Tool 1: enrich_indicators
    # -------------------------------------------------------------------

    def enrich_indicators(
        self,
        indicators: list[dict],
        sources: list[str] | None = None,
    ) -> ToolResult:
        """Look up indicators in threat intelligence sources.

        Args:
            indicators: List of {"type": "hash_sha256|...", "value": "..."}.
            sources: Optional source filter (e.g., ["virustotal", "malwarebazaar"]).

        Returns:
            ToolResult with aggregated verdicts per indicator.
        """
        execution_id = _new_id("EXE-")
        start = _utcnow()

        parsed_indicators = [
            Indicator(indicator_type=ind["type"], value=ind["value"])
            for ind in indicators
        ]

        verdicts = self.aggregator.lookup_batch(
            parsed_indicators,
            source_filter=sources,
            execution_id=execution_id,
        )

        # Serialize verdicts
        results = []
        for v in verdicts:
            results.append({
                "indicator_type": v.indicator_type,
                "indicator_value": v.indicator_value,
                "overall_verdict": v.overall_verdict.value,
                "overall_confidence": v.overall_confidence,
                "source_count": v.source_count,
                "attribution_summary": v.attribution_summary,
                "source_results": [
                    {
                        "source": r.source.value,
                        "verdict": r.verdict.value,
                        "confidence": r.confidence,
                        "source_url": r.source_url,
                        "details": r.details,
                    }
                    for r in v.source_results
                ],
            })

        # Build forensic context
        any_malicious = any(
            v.overall_verdict.value == "malicious" for v in verdicts
        )
        any_suspicious = any(
            v.overall_verdict.value == "suspicious" for v in verdicts
        )

        context = ForensicContext(
            proves=["known_malware"] if any_malicious else [],
            suggests=["known_malware"] if any_suspicious and not any_malicious else [],
            cannot_prove=["execution"],
            caveats=[
                "Threat intel verdicts reflect current database state; may change over time.",
                "Absence from databases does NOT mean the file is clean.",
                "Different sources may disagree; aggregated verdict uses weighted consensus.",
            ],
            corroboration_hints=[
                "A MALICIOUS verdict corroborates malware execution findings.",
                "A CLEAN verdict from all sources may weaken a malware hypothesis.",
                "NOT_FOUND from all sources may indicate novel/targeted malware.",
            ],
        )

        return ToolResult(
            tool_name="enrich_indicators",
            evidence_id="enrichment",
            execution_id=execution_id,
            timestamp_utc=start,
            status=ToolStatus.SUCCESS,
            structured_data={
                "indicators_queried": len(indicators),
                "configured_sources": self.aggregator.configured_sources,
                "results": results,
            },
            record_count=len(results),
            forensic_context=context,
        )

    # -------------------------------------------------------------------
    # Tool 2: compute_hashes
    # -------------------------------------------------------------------

    def compute_hashes(
        self,
        file_path: str,
        evidence_id: str,
    ) -> ToolResult:
        """Compute MD5, SHA1, and SHA256 hashes for a file.

        Returns a ToolResult with hashes and creates a FILE_HASH atom.
        """
        execution_id = _new_id("EXE-")
        start = _utcnow()

        validate_read_path(file_path)

        fpath = Path(file_path)
        if not fpath.exists():
            return ToolResult(
                tool_name="compute_hashes",
                evidence_id=evidence_id,
                execution_id=execution_id,
                status=ToolStatus.ERROR,
                error_message=f"File not found: {file_path}",
            )

        # Compute hashes in one pass
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        file_size = 0

        with open(fpath, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
                file_size += len(chunk)

        hashes = {
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest(),
            "file_size": file_size,
            "file_path": file_path,
        }

        # Create FILE_HASH atom
        semantics = get_semantics(ArtifactType.FILE_HASH)
        atom = EvidenceAtom(
            tool_name="compute_hashes",
            execution_id=execution_id,
            artifact_type=ArtifactType.FILE_HASH,
            raw_data=hashes,
            file_references=[file_path],
            proves=set(semantics.get("proves", set())),
            suggests=set(semantics.get("suggests", set())),
            cannot_prove=set(semantics.get("cannot_prove", set())),
        )
        self.store.add_atom(atom)

        context = ForensicContext(
            proves=[],
            suggests=[],
            cannot_prove=[],
            caveats=list(semantics.get("caveats", [])),
            corroboration_hints=list(semantics.get("corroboration_hints", [])),
        )

        return ToolResult(
            tool_name="compute_hashes",
            evidence_id=evidence_id,
            execution_id=execution_id,
            timestamp_utc=start,
            status=ToolStatus.SUCCESS,
            structured_data=hashes,
            record_count=1,
            forensic_context=context,
        )

    # -------------------------------------------------------------------
    # Tool 3: yara_scan
    # -------------------------------------------------------------------

    def yara_scan(
        self,
        rules_path: str,
        target_path: str,
        evidence_id: str,
        recursive: bool = True,
    ) -> ToolResult:
        """Scan files with YARA rules.

        Uses the `yara` CLI tool (available on SIFT).
        """
        validate_read_path(rules_path)
        validate_read_path(target_path)

        cmd = ["yara"]
        if recursive:
            cmd.append("-r")
        cmd.extend(["-s", rules_path, target_path])

        tool_result, raw_output = self.run_tool(
            tool_name="yara_scan",
            evidence_id=evidence_id,
            command=cmd,
            input_params={
                "rules_path": rules_path,
                "target_path": target_path,
                "recursive": recursive,
            },
        )

        if tool_result.status == ToolStatus.ERROR:
            return tool_result

        # Parse YARA output: "rule_name file_path"
        hits: list[dict] = []
        for line in raw_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            # Match lines start with "0x..." (string match detail)
            if line.startswith("0x"):
                # This is a string match line from -s flag, append to last hit
                if hits:
                    hits[-1].setdefault("string_matches", []).append(line)
                continue

            # Rule match line: "rule_name file_path"
            parts = line.split(None, 1)
            if len(parts) == 2:
                rule_name, matched_file = parts
                hits.append({
                    "rule_name": rule_name,
                    "matched_file": matched_file,
                    "string_matches": [],
                })

        # Create atoms for each YARA hit
        semantics = get_semantics(ArtifactType.YARA_HIT)
        for hit in hits:
            atom = EvidenceAtom(
                tool_name="yara_scan",
                execution_id=tool_result.execution_id,
                artifact_type=ArtifactType.YARA_HIT,
                raw_data=hit,
                file_references=[hit["matched_file"]],
                proves=set(semantics.get("proves", set())),
                suggests=set(semantics.get("suggests", set())),
                cannot_prove=set(semantics.get("cannot_prove", set())),
            )
            self.store.add_atom(atom)

        tool_result.structured_data = {
            "total_hits": len(hits),
            "rules_path": rules_path,
            "target_path": target_path,
            "hits": hits,
        }
        tool_result.record_count = len(hits)
        tool_result.forensic_context = ForensicContext(
            proves=[],
            suggests=["known_malware"] if hits else [],
            cannot_prove=["malicious_intent"],
            caveats=list(semantics.get("caveats", [])),
            corroboration_hints=list(semantics.get("corroboration_hints", [])),
        )

        return tool_result

    # -------------------------------------------------------------------
    # Tool 4: generate_super_timeline
    # -------------------------------------------------------------------

    def generate_super_timeline(
        self,
        image_path: str,
        evidence_id: str,
        date_start: str | None = None,
        date_end: str | None = None,
    ) -> ToolResult:
        """Generate a super timeline using log2timeline (plaso).

        Runs: log2timeline.py --storage-file <output.plaso> <image>
        Then: psort.py -o l2tcsv <output.plaso> > timeline.csv
        """
        validate_read_path(image_path)

        output_dir = EXPORTS_DIR / "timelines"
        output_dir.mkdir(parents=True, exist_ok=True)

        plaso_file = str(output_dir / f"{evidence_id}_timeline.plaso")
        csv_file = str(output_dir / f"{evidence_id}_timeline.csv")

        # Step 1: Run log2timeline
        l2t_cmd = [
            "log2timeline.py",
            "--storage-file", plaso_file,
            image_path,
        ]

        tool_result, _ = self.run_tool(
            tool_name="generate_super_timeline",
            evidence_id=evidence_id,
            command=l2t_cmd,
            input_params={
                "image_path": image_path,
                "date_start": date_start,
                "date_end": date_end,
            },
            timeout=600,  # Plaso can take a while
        )

        if tool_result.status == ToolStatus.ERROR:
            return tool_result

        # Step 2: Export to CSV with psort
        psort_cmd = ["psort.py", "-o", "l2tcsv", "-w", csv_file, plaso_file]

        if date_start:
            psort_cmd.extend(["--slice", date_start])

        psort_result, raw_csv = self.run_tool(
            tool_name="generate_super_timeline",
            evidence_id=evidence_id,
            command=psort_cmd,
            timeout=300,
        )

        # Count lines in CSV
        line_count = 0
        csv_path = Path(csv_file)
        if csv_path.exists():
            with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
                line_count = sum(1 for _ in f) - 1  # Subtract header

        tool_result.structured_data = {
            "plaso_file": plaso_file,
            "csv_file": csv_file,
            "total_events": max(0, line_count),
            "date_start": date_start,
            "date_end": date_end,
        }
        tool_result.record_count = max(0, line_count)
        tool_result.forensic_context = ForensicContext(
            proves=[],
            suggests=[],
            cannot_prove=[],
            caveats=[
                "Super timeline aggregates multiple sources; check the original source.",
                "Timeline density varies by artifact type and system activity.",
            ],
            corroboration_hints=[
                "Filter timeline to specific time windows around suspicious events.",
                "Look for clusters of activity that suggest attacker sessions.",
            ],
        )

        return tool_result
