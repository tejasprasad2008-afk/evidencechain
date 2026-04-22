"""Report generator — renders investigation reports from templates.

Supports multiple output formats:
  - Markdown (for human analysts and judges)
  - JSON (for machine consumption and downstream tools)

Uses Jinja2 templates for rendering. The ReportBuilder assembles
the data; the ReportGenerator renders it.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..config import REPORTS_DIR
from ..models import _utcnow
from ..provenance.audit_logger import AuditLogger
from ..provenance.evidence_store import EvidenceStore
from .builder import ReportBuilder, ReportData

logger = logging.getLogger(__name__)

# Template directory
_TEMPLATE_DIR = Path(__file__).parent / "templates"


class ReportGenerator:
    """Renders forensic investigation reports in multiple formats."""

    def __init__(
        self,
        store: EvidenceStore,
        audit: AuditLogger,
        output_dir: Path | None = None,
    ) -> None:
        self.store = store
        self.audit = audit
        self._output_dir = output_dir or REPORTS_DIR
        self._builder = ReportBuilder(store)

        # Initialize Jinja2 environment
        self._env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=select_autoescape([]),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def generate(
        self,
        formats: list[str] | None = None,
    ) -> dict[str, str]:
        """Generate reports in the specified formats.

        Args:
            formats: List of formats to generate. Options: "markdown", "json".
                     Default: both.

        Returns:
            Dict mapping format name to output file path.
        """
        if formats is None:
            formats = ["markdown", "json"]

        # Build report data
        report_data = self._builder.build()

        # Ensure output directory exists
        self._output_dir.mkdir(parents=True, exist_ok=True)

        outputs: dict[str, str] = {}

        for fmt in formats:
            if fmt == "markdown":
                path = self._render_markdown(report_data)
                outputs["markdown"] = str(path)
            elif fmt == "json":
                path = self._render_json(report_data)
                outputs["json"] = str(path)
            else:
                logger.warning("Unknown report format: %s", fmt)

        # Audit log
        self.audit.log("report_log", {
            "event": "report_generated",
            "report_id": report_data.report_id,
            "formats": list(outputs.keys()),
            "output_paths": outputs,
            "summary": {
                "confirmed_findings": len(report_data.confirmed_findings),
                "total_contradictions": len(report_data.contradictions),
                "converged": report_data.correction_summary.converged,
            },
        })

        logger.info(
            "Report %s generated: %s",
            report_data.report_id,
            ", ".join(f"{k}={v}" for k, v in outputs.items()),
        )

        return outputs

    def generate_to_string(self, fmt: str = "markdown") -> str:
        """Generate a report and return it as a string (no file write).

        Useful for returning directly via MCP tool response.
        """
        report_data = self._builder.build()

        if fmt == "markdown":
            return self._render_template("report.md.j2", report_data)
        elif fmt == "json":
            return self._render_template("report.json.j2", report_data)
        else:
            raise ValueError(f"Unknown format: {fmt}")

    # -------------------------------------------------------------------
    # Internal rendering
    # -------------------------------------------------------------------

    def _render_markdown(self, report: ReportData) -> Path:
        """Render the Markdown report to a file."""
        content = self._render_template("report.md.j2", report)
        filename = f"{report.report_id}.md"
        path = self._output_dir / filename

        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

        logger.info("Markdown report written to %s", path)
        return path

    def _render_json(self, report: ReportData) -> Path:
        """Render the JSON report to a file."""
        content = self._render_template("report.json.j2", report)

        # Validate JSON
        try:
            parsed = json.loads(content)
            # Re-serialize with pretty formatting
            content = json.dumps(parsed, indent=2, ensure_ascii=False)
        except json.JSONDecodeError:
            logger.warning("JSON template produced invalid JSON; writing raw output")

        filename = f"{report.report_id}.json"
        path = self._output_dir / filename

        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

        logger.info("JSON report written to %s", path)
        return path

    def _render_template(self, template_name: str, report: ReportData) -> str:
        """Render a Jinja2 template with the report data."""
        template = self._env.get_template(template_name)
        return template.render(report=report)
