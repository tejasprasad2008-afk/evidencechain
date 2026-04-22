"""Threat intelligence verdict aggregator.

Takes results from multiple sources for a single indicator and produces
a weighted consensus verdict. The aggregation logic:

  1. Collect results from all applicable sources
  2. Weight each source's verdict by its confidence score
  3. Apply source-specific reliability weights
  4. Determine overall verdict via weighted majority
  5. Generate an attribution summary

The aggregator also creates EvidenceAtoms for each indicator with
appropriate proves/suggests/cannot_prove annotations.
"""

from __future__ import annotations

import logging

from ..enums import (
    ArtifactType,
    EvidenceSemantics,
    ThreatIntelSource,
    ThreatIntelVerdict,
)
from ..models import (
    AggregatedVerdict,
    EvidenceAtom,
    Indicator,
    ThreatIntelResult,
)
from ..provenance.evidence_store import EvidenceStore
from .rate_limiter import RateLimiter
from .sources.abuseipdb import AbuseIPDBSource
from .sources.alienvault_otx import AlienVaultOTXSource
from .sources.base import BaseSource
from .sources.lolbas import LOLBASSource
from .sources.malwarebazaar import MalwareBazaarSource
from .sources.virustotal import VirusTotalSource

logger = logging.getLogger(__name__)

# Source reliability weights (used in consensus calculation)
_SOURCE_WEIGHTS: dict[ThreatIntelSource, float] = {
    ThreatIntelSource.VIRUSTOTAL: 1.0,      # Gold standard for hashes
    ThreatIntelSource.MALWAREBAZAAR: 0.9,    # High quality malware DB
    ThreatIntelSource.ABUSEIPDB: 0.8,        # Community-driven, good for IPs
    ThreatIntelSource.ALIENVAULT_OTX: 0.7,   # Pulse-based, variable quality
    ThreatIntelSource.LOLBAS: 0.5,           # Local DB, dual-use binaries
}

# Verdict numeric mapping for weighted scoring
_VERDICT_SCORES: dict[ThreatIntelVerdict, float] = {
    ThreatIntelVerdict.MALICIOUS: 1.0,
    ThreatIntelVerdict.SUSPICIOUS: 0.5,
    ThreatIntelVerdict.CLEAN: 0.0,
    ThreatIntelVerdict.UNKNOWN: -1.0,  # Excluded from scoring
    ThreatIntelVerdict.NOT_FOUND: -1.0,  # Excluded from scoring
}


class ThreatIntelAggregator:
    """Orchestrates lookups across all configured sources and aggregates verdicts."""

    def __init__(
        self,
        store: EvidenceStore,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        self.store = store
        self._rate_limiter = rate_limiter or RateLimiter()

        # Initialize all source adapters
        self._sources: list[BaseSource] = [
            VirusTotalSource(self._rate_limiter),
            AbuseIPDBSource(self._rate_limiter),
            MalwareBazaarSource(self._rate_limiter),
            LOLBASSource(self._rate_limiter),
            AlienVaultOTXSource(self._rate_limiter),
        ]

    @property
    def configured_sources(self) -> list[str]:
        """List source names that have valid API keys."""
        return [s.source.value for s in self._sources if s.is_configured]

    def lookup_indicator(
        self,
        indicator: Indicator,
        source_filter: list[str] | None = None,
        execution_id: str = "",
    ) -> AggregatedVerdict:
        """Look up a single indicator across all applicable sources.

        Args:
            indicator: The indicator to look up.
            source_filter: Optional list of source names to restrict to.
            execution_id: Execution ID for provenance.

        Returns:
            AggregatedVerdict with results from all sources.
        """
        results: list[ThreatIntelResult] = []

        for source in self._sources:
            # Apply source filter if provided
            if source_filter and source.source.value not in source_filter:
                continue

            if not source.can_handle(indicator):
                continue

            if not source.is_configured:
                logger.debug(
                    "Skipping %s (not configured) for %s",
                    source.source.value,
                    indicator.value,
                )
                continue

            result = source.lookup(indicator)
            results.append(result)

            logger.info(
                "TI lookup: %s -> %s = %s (confidence=%.2f)",
                indicator.value,
                source.source.value,
                result.verdict.value,
                result.confidence,
            )

        # Aggregate
        verdict = self._aggregate_verdicts(indicator, results)

        # Create EvidenceAtom for this indicator
        self._create_atom(indicator, verdict, execution_id)

        return verdict

    def lookup_batch(
        self,
        indicators: list[Indicator],
        source_filter: list[str] | None = None,
        execution_id: str = "",
    ) -> list[AggregatedVerdict]:
        """Look up multiple indicators. Returns one AggregatedVerdict per indicator."""
        return [
            self.lookup_indicator(ind, source_filter, execution_id)
            for ind in indicators
        ]

    # -------------------------------------------------------------------
    # Verdict aggregation
    # -------------------------------------------------------------------

    def _aggregate_verdicts(
        self,
        indicator: Indicator,
        results: list[ThreatIntelResult],
    ) -> AggregatedVerdict:
        """Compute weighted consensus verdict from multiple source results."""
        if not results:
            return AggregatedVerdict(
                indicator_type=indicator.indicator_type,
                indicator_value=indicator.value,
                overall_verdict=ThreatIntelVerdict.UNKNOWN,
                overall_confidence=0.0,
                source_count=0,
                source_results=results,
                attribution_summary="No threat intelligence sources returned results.",
            )

        # Filter out UNKNOWN and NOT_FOUND for scoring
        scorable = [
            r for r in results
            if _VERDICT_SCORES.get(r.verdict, -1.0) >= 0.0
        ]

        if not scorable:
            # All sources returned UNKNOWN or NOT_FOUND
            not_found_count = sum(
                1 for r in results if r.verdict == ThreatIntelVerdict.NOT_FOUND
            )
            return AggregatedVerdict(
                indicator_type=indicator.indicator_type,
                indicator_value=indicator.value,
                overall_verdict=ThreatIntelVerdict.NOT_FOUND if not_found_count > 0 else ThreatIntelVerdict.UNKNOWN,
                overall_confidence=0.0,
                source_count=len(results),
                source_results=results,
                attribution_summary=self._build_attribution(results),
            )

        # Weighted score: sum(verdict_score * source_weight * result_confidence) / sum(weights)
        weighted_sum = 0.0
        weight_sum = 0.0

        for r in scorable:
            v_score = _VERDICT_SCORES[r.verdict]
            s_weight = _SOURCE_WEIGHTS.get(r.source, 0.5)
            weighted_sum += v_score * s_weight * r.confidence
            weight_sum += s_weight

        if weight_sum == 0:
            consensus_score = 0.0
        else:
            consensus_score = weighted_sum / weight_sum

        # Map consensus score to verdict
        if consensus_score >= 0.7:
            overall_verdict = ThreatIntelVerdict.MALICIOUS
        elif consensus_score >= 0.3:
            overall_verdict = ThreatIntelVerdict.SUSPICIOUS
        else:
            overall_verdict = ThreatIntelVerdict.CLEAN

        return AggregatedVerdict(
            indicator_type=indicator.indicator_type,
            indicator_value=indicator.value,
            overall_verdict=overall_verdict,
            overall_confidence=round(min(1.0, consensus_score), 3),
            source_count=len(results),
            source_results=results,
            attribution_summary=self._build_attribution(results),
        )

    def _build_attribution(self, results: list[ThreatIntelResult]) -> str:
        """Build a human-readable attribution summary."""
        if not results:
            return "No sources queried."

        parts: list[str] = []
        for r in results:
            detail = ""
            if r.verdict == ThreatIntelVerdict.MALICIOUS:
                sig = r.details.get("signature") or r.details.get("popular_threat_name", "")
                if sig:
                    detail = f" ({sig})"
            parts.append(f"{r.source.value}={r.verdict.value}{detail}")

        return " | ".join(parts)

    # -------------------------------------------------------------------
    # Atom creation
    # -------------------------------------------------------------------

    def _create_atom(
        self,
        indicator: Indicator,
        verdict: AggregatedVerdict,
        execution_id: str,
    ) -> EvidenceAtom:
        """Create an EvidenceAtom from the aggregated threat intel verdict."""
        proves: set[str] = set()
        suggests: set[str] = set()
        cannot_prove: set[str] = set()

        if verdict.overall_verdict == ThreatIntelVerdict.MALICIOUS:
            proves.add(EvidenceSemantics.KNOWN_MALWARE)
            if indicator.indicator_type == "ipv4":
                suggests.add(EvidenceSemantics.KNOWN_C2_INFRASTRUCTURE)
        elif verdict.overall_verdict == ThreatIntelVerdict.SUSPICIOUS:
            suggests.add(EvidenceSemantics.KNOWN_MALWARE)

        # Threat intel can never prove execution
        cannot_prove.add(EvidenceSemantics.EXECUTION)

        atom = EvidenceAtom(
            tool_name="enrich_indicators",
            execution_id=execution_id,
            artifact_type=ArtifactType.THREAT_INTEL,
            raw_data={
                "indicator_type": indicator.indicator_type,
                "indicator_value": indicator.value,
                "verdict": verdict.overall_verdict.value,
                "confidence": verdict.overall_confidence,
                "source_count": verdict.source_count,
                "attribution": verdict.attribution_summary,
                "source_verdicts": {
                    r.source.value: r.verdict.value
                    for r in verdict.source_results
                },
            },
            file_references=[indicator.value] if indicator.indicator_type.startswith("hash_") else [],
            proves=proves,
            suggests=suggests,
            cannot_prove=cannot_prove,
        )

        self.store.add_atom(atom)
        return atom
