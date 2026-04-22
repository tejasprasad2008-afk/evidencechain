"""VirusTotal threat intelligence source.

API docs: https://developers.virustotal.com/reference
Env var: VT_API_KEY

Supports: hash_sha256, hash_sha1, hash_md5, ipv4, domain
"""

from __future__ import annotations

import logging
import urllib.error

from ...enums import ThreatIntelSource, ThreatIntelVerdict
from ...models import Indicator, ThreatIntelResult
from .base import BaseSource

logger = logging.getLogger(__name__)

_VT_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalSource(BaseSource):
    """VirusTotal API v3 adapter."""

    source = ThreatIntelSource.VIRUSTOTAL
    api_key_env = "VT_API_KEY"
    supported_types = frozenset({
        "hash_sha256", "hash_sha1", "hash_md5",
        "ipv4", "domain",
    })

    def _do_lookup(self, indicator: Indicator) -> ThreatIntelResult:
        headers = {"x-apikey": self._api_key}

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
        url = f"{_VT_BASE}/files/{indicator.value}"

        try:
            data = self._http_get(url, headers)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return ThreatIntelResult(
                    indicator_type=indicator.indicator_type,
                    indicator_value=indicator.value,
                    source=self.source,
                    source_url=f"https://www.virustotal.com/gui/file/{indicator.value}",
                    verdict=ThreatIntelVerdict.NOT_FOUND,
                    details={"message": "Hash not found in VirusTotal"},
                )
            raise

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0

        # Verdict logic
        if malicious >= 5:
            verdict = ThreatIntelVerdict.MALICIOUS
            confidence = min(1.0, malicious / max(total, 1))
        elif malicious >= 1 or suspicious >= 3:
            verdict = ThreatIntelVerdict.SUSPICIOUS
            confidence = min(0.7, (malicious + suspicious) / max(total, 1))
        elif total > 0:
            verdict = ThreatIntelVerdict.CLEAN
            confidence = 1.0 - (malicious + suspicious) / max(total, 1)
        else:
            verdict = ThreatIntelVerdict.UNKNOWN
            confidence = 0.0

        return ThreatIntelResult(
            indicator_type=indicator.indicator_type,
            indicator_value=indicator.value,
            source=self.source,
            source_url=f"https://www.virustotal.com/gui/file/{indicator.value}",
            verdict=verdict,
            confidence=round(confidence, 3),
            details={
                "malicious": malicious,
                "suspicious": suspicious,
                "undetected": stats.get("undetected", 0),
                "total_engines": total,
                "popular_threat_name": attrs.get("popular_threat_classification", {}).get(
                    "suggested_threat_label", ""
                ),
                "file_type": attrs.get("type_description", ""),
                "file_size": attrs.get("size", 0),
                "first_submission": attrs.get("first_submission_date", ""),
                "last_analysis_date": attrs.get("last_analysis_date", ""),
            },
            raw_response_excerpt=str(stats),
        )

    def _lookup_ip(self, indicator: Indicator, headers: dict) -> ThreatIntelResult:
        url = f"{_VT_BASE}/ip_addresses/{indicator.value}"

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

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)

        if malicious >= 3:
            verdict = ThreatIntelVerdict.MALICIOUS
        elif malicious >= 1:
            verdict = ThreatIntelVerdict.SUSPICIOUS
        else:
            verdict = ThreatIntelVerdict.CLEAN

        return ThreatIntelResult(
            indicator_type=indicator.indicator_type,
            indicator_value=indicator.value,
            source=self.source,
            source_url=f"https://www.virustotal.com/gui/ip-address/{indicator.value}",
            verdict=verdict,
            confidence=round(malicious / max(sum(stats.values()), 1), 3),
            details={
                "malicious": malicious,
                "as_owner": attrs.get("as_owner", ""),
                "country": attrs.get("country", ""),
            },
        )

    def _lookup_domain(self, indicator: Indicator, headers: dict) -> ThreatIntelResult:
        url = f"{_VT_BASE}/domains/{indicator.value}"

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

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)

        if malicious >= 3:
            verdict = ThreatIntelVerdict.MALICIOUS
        elif malicious >= 1:
            verdict = ThreatIntelVerdict.SUSPICIOUS
        else:
            verdict = ThreatIntelVerdict.CLEAN

        return ThreatIntelResult(
            indicator_type=indicator.indicator_type,
            indicator_value=indicator.value,
            source=self.source,
            source_url=f"https://www.virustotal.com/gui/domain/{indicator.value}",
            verdict=verdict,
            confidence=round(malicious / max(sum(stats.values()), 1), 3),
            details={
                "malicious": malicious,
                "registrar": attrs.get("registrar", ""),
                "creation_date": attrs.get("creation_date", ""),
            },
        )
