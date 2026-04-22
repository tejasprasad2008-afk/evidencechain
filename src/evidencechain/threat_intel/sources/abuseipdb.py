"""AbuseIPDB threat intelligence source.

API docs: https://docs.abuseipdb.com/
Env var: ABUSEIPDB_API_KEY

Supports: ipv4
"""

from __future__ import annotations

import logging
import urllib.error

from ...enums import ThreatIntelSource, ThreatIntelVerdict
from ...models import Indicator, ThreatIntelResult
from .base import BaseSource

logger = logging.getLogger(__name__)

_ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"


class AbuseIPDBSource(BaseSource):
    """AbuseIPDB API v2 adapter."""

    source = ThreatIntelSource.ABUSEIPDB
    api_key_env = "ABUSEIPDB_API_KEY"
    supported_types = frozenset({"ipv4"})

    def _do_lookup(self, indicator: Indicator) -> ThreatIntelResult:
        url = (
            f"{_ABUSEIPDB_BASE}/check"
            f"?ipAddress={indicator.value}"
            f"&maxAgeInDays=90"
            f"&verbose"
        )
        headers = {
            "Key": self._api_key,
            "Accept": "application/json",
        }

        try:
            data = self._http_get(url, headers)
        except urllib.error.HTTPError as e:
            if e.code == 404 or e.code == 422:
                return ThreatIntelResult(
                    indicator_type=indicator.indicator_type,
                    indicator_value=indicator.value,
                    source=self.source,
                    verdict=ThreatIntelVerdict.NOT_FOUND,
                )
            raise

        report = data.get("data", {})
        abuse_score = report.get("abuseConfidenceScore", 0)
        total_reports = report.get("totalReports", 0)
        is_public = report.get("isPublic", True)

        # Verdict logic
        if abuse_score >= 75:
            verdict = ThreatIntelVerdict.MALICIOUS
        elif abuse_score >= 25 or total_reports >= 5:
            verdict = ThreatIntelVerdict.SUSPICIOUS
        elif total_reports == 0:
            verdict = ThreatIntelVerdict.CLEAN
        else:
            verdict = ThreatIntelVerdict.CLEAN

        return ThreatIntelResult(
            indicator_type=indicator.indicator_type,
            indicator_value=indicator.value,
            source=self.source,
            source_url=f"https://www.abuseipdb.com/check/{indicator.value}",
            verdict=verdict,
            confidence=round(abuse_score / 100, 3),
            details={
                "abuse_confidence_score": abuse_score,
                "total_reports": total_reports,
                "country_code": report.get("countryCode", ""),
                "isp": report.get("isp", ""),
                "domain": report.get("domain", ""),
                "is_tor": report.get("isTor", False),
                "is_public": is_public,
                "usage_type": report.get("usageType", ""),
                "last_reported_at": report.get("lastReportedAt", ""),
            },
            raw_response_excerpt=f"score={abuse_score}, reports={total_reports}",
        )
