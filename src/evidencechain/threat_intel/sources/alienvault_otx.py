"""AlienVault OTX (Open Threat Exchange) intelligence source.

API docs: https://otx.alienvault.com/api
Env var: OTX_API_KEY

Supports: hash_sha256, hash_sha1, hash_md5, ipv4, domain
"""

from __future__ import annotations

import logging
import urllib.error

from ...enums import ThreatIntelSource, ThreatIntelVerdict
from ...models import Indicator, ThreatIntelResult
from .base import BaseSource

logger = logging.getLogger(__name__)

_OTX_BASE = "https://otx.alienvault.com/api/v1"


class AlienVaultOTXSource(BaseSource):
    """AlienVault OTX API v1 adapter."""

    source = ThreatIntelSource.ALIENVAULT_OTX
    api_key_env = "OTX_API_KEY"
    supported_types = frozenset({
        "hash_sha256", "hash_sha1", "hash_md5",
        "ipv4", "domain",
    })

    def _do_lookup(self, indicator: Indicator) -> ThreatIntelResult:
        headers = {"X-OTX-API-KEY": self._api_key}

        if indicator.indicator_type.startswith("hash_"):
            return self._lookup_hash(indicator, headers)
        elif indicator.indicator_type == "ipv4":
            return self._lookup_ip(indicator, headers)
        elif indicator.indicator_type == "domain":
            return self._lookup_domain(indicator, headers)

        return ThreatIntelResult(
            indicator_type=indicator.indicator_type,
            indicator_value=indicator.value,
            source=self.source,
            verdict=ThreatIntelVerdict.UNKNOWN,
        )

    def _lookup_hash(self, indicator: Indicator, headers: dict) -> ThreatIntelResult:
        # OTX uses /indicators/file/{hash}/general
        url = f"{_OTX_BASE}/indicators/file/{indicator.value}/general"

        try:
            data = self._http_get(url, headers)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return ThreatIntelResult(
                    indicator_type=indicator.indicator_type,
                    indicator_value=indicator.value,
                    source=self.source,
                    verdict=ThreatIntelVerdict.NOT_FOUND,
                )
            raise

        pulse_count = data.get("pulse_info", {}).get("count", 0)
        pulses = data.get("pulse_info", {}).get("pulses", [])

        verdict, confidence = self._assess_pulses(pulse_count)

        # Extract tags and adversary info from pulses
        tags: set[str] = set()
        adversaries: set[str] = set()
        for pulse in pulses[:10]:
            tags.update(pulse.get("tags", []))
            adversary = pulse.get("adversary", "")
            if adversary:
                adversaries.add(adversary)

        return ThreatIntelResult(
            indicator_type=indicator.indicator_type,
            indicator_value=indicator.value,
            source=self.source,
            source_url=f"https://otx.alienvault.com/indicator/file/{indicator.value}",
            verdict=verdict,
            confidence=confidence,
            details={
                "pulse_count": pulse_count,
                "tags": sorted(tags)[:20],
                "adversaries": sorted(adversaries),
                "type_title": data.get("type_title", ""),
            },
            raw_response_excerpt=f"pulses={pulse_count}",
        )

    def _lookup_ip(self, indicator: Indicator, headers: dict) -> ThreatIntelResult:
        url = f"{_OTX_BASE}/indicators/IPv4/{indicator.value}/general"

        try:
            data = self._http_get(url, headers)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return ThreatIntelResult(
                    indicator_type=indicator.indicator_type,
                    indicator_value=indicator.value,
                    source=self.source,
                    verdict=ThreatIntelVerdict.NOT_FOUND,
                )
            raise

        pulse_count = data.get("pulse_info", {}).get("count", 0)
        verdict, confidence = self._assess_pulses(pulse_count)

        return ThreatIntelResult(
            indicator_type=indicator.indicator_type,
            indicator_value=indicator.value,
            source=self.source,
            source_url=f"https://otx.alienvault.com/indicator/ip/{indicator.value}",
            verdict=verdict,
            confidence=confidence,
            details={
                "pulse_count": pulse_count,
                "country": data.get("country_name", ""),
                "asn": data.get("asn", ""),
            },
        )

    def _lookup_domain(self, indicator: Indicator, headers: dict) -> ThreatIntelResult:
        url = f"{_OTX_BASE}/indicators/domain/{indicator.value}/general"

        try:
            data = self._http_get(url, headers)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return ThreatIntelResult(
                    indicator_type=indicator.indicator_type,
                    indicator_value=indicator.value,
                    source=self.source,
                    verdict=ThreatIntelVerdict.NOT_FOUND,
                )
            raise

        pulse_count = data.get("pulse_info", {}).get("count", 0)
        verdict, confidence = self._assess_pulses(pulse_count)

        return ThreatIntelResult(
            indicator_type=indicator.indicator_type,
            indicator_value=indicator.value,
            source=self.source,
            source_url=f"https://otx.alienvault.com/indicator/domain/{indicator.value}",
            verdict=verdict,
            confidence=confidence,
            details={
                "pulse_count": pulse_count,
                "alexa": data.get("alexa", ""),
                "whois": data.get("whois", "")[:200] if data.get("whois") else "",
            },
        )

    @staticmethod
    def _assess_pulses(pulse_count: int) -> tuple[ThreatIntelVerdict, float]:
        """Determine verdict from OTX pulse count."""
        if pulse_count >= 5:
            return ThreatIntelVerdict.MALICIOUS, min(0.9, 0.5 + pulse_count * 0.05)
        elif pulse_count >= 1:
            return ThreatIntelVerdict.SUSPICIOUS, 0.4 + pulse_count * 0.1
        else:
            return ThreatIntelVerdict.CLEAN, 0.3
