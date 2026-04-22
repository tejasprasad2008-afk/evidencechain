"""Base class for threat intelligence source adapters.

Each source adapter:
  1. Accepts an Indicator (hash, IP, domain, filename)
  2. Makes an HTTP request to the external API
  3. Parses the response into a ThreatIntelResult
  4. Respects rate limits via the shared RateLimiter

HTTP is done via urllib.request (no external dependencies).
API keys are read from environment variables.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from abc import ABC, abstractmethod

from ...config import THREAT_INTEL_TIMEOUT
from ...enums import ThreatIntelSource, ThreatIntelVerdict
from ...models import Indicator, ThreatIntelResult
from ..rate_limiter import RateLimiter

logger = logging.getLogger(__name__)


class BaseSource(ABC):
    """Base class for all threat intelligence source adapters."""

    source: ThreatIntelSource
    # Environment variable name for the API key (None if no key needed)
    api_key_env: str | None = None
    # Indicator types this source can handle
    supported_types: frozenset[str] = frozenset()

    def __init__(self, rate_limiter: RateLimiter) -> None:
        self._rate_limiter = rate_limiter
        self._api_key: str | None = None
        if self.api_key_env:
            self._api_key = os.environ.get(self.api_key_env, "")

    @property
    def is_configured(self) -> bool:
        """True if this source has a valid API key (or doesn't need one)."""
        if self.api_key_env is None:
            return True  # No key required
        return bool(self._api_key)

    def can_handle(self, indicator: Indicator) -> bool:
        """True if this source supports the given indicator type."""
        return indicator.indicator_type in self.supported_types

    def lookup(self, indicator: Indicator) -> ThreatIntelResult:
        """Look up an indicator, respecting rate limits.

        Returns a ThreatIntelResult. On error, returns a result with
        verdict=UNKNOWN and error details.
        """
        if not self.can_handle(indicator):
            return ThreatIntelResult(
                indicator_type=indicator.indicator_type,
                indicator_value=indicator.value,
                source=self.source,
                verdict=ThreatIntelVerdict.UNKNOWN,
                details={"error": f"Unsupported indicator type: {indicator.indicator_type}"},
            )

        if not self.is_configured:
            return ThreatIntelResult(
                indicator_type=indicator.indicator_type,
                indicator_value=indicator.value,
                source=self.source,
                verdict=ThreatIntelVerdict.UNKNOWN,
                details={"error": f"API key not configured ({self.api_key_env})"},
            )

        # Rate limit
        if not self._rate_limiter.acquire(self.source.value, timeout=30.0):
            return ThreatIntelResult(
                indicator_type=indicator.indicator_type,
                indicator_value=indicator.value,
                source=self.source,
                verdict=ThreatIntelVerdict.UNKNOWN,
                details={"error": "Rate limit exceeded"},
            )

        try:
            return self._do_lookup(indicator)
        except Exception as e:
            logger.exception("Error in %s lookup for %s", self.source.value, indicator.value)
            return ThreatIntelResult(
                indicator_type=indicator.indicator_type,
                indicator_value=indicator.value,
                source=self.source,
                verdict=ThreatIntelVerdict.UNKNOWN,
                details={"error": str(e)},
            )

    @abstractmethod
    def _do_lookup(self, indicator: Indicator) -> ThreatIntelResult:
        """Perform the actual lookup. Implemented by each source adapter."""
        ...

    # -------------------------------------------------------------------
    # HTTP helpers
    # -------------------------------------------------------------------

    def _http_get(
        self,
        url: str,
        headers: dict[str, str] | None = None,
    ) -> dict:
        """Make an HTTP GET request and return parsed JSON."""
        req = urllib.request.Request(url, method="GET")
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)

        with urllib.request.urlopen(req, timeout=THREAT_INTEL_TIMEOUT) as resp:
            body = resp.read().decode("utf-8")
            return json.loads(body)

    def _http_post(
        self,
        url: str,
        data: dict | bytes | None = None,
        headers: dict[str, str] | None = None,
        content_type: str = "application/json",
    ) -> dict:
        """Make an HTTP POST request and return parsed JSON."""
        if isinstance(data, dict):
            body = json.dumps(data).encode("utf-8")
        elif isinstance(data, bytes):
            body = data
        else:
            body = b""

        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", content_type)
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)

        with urllib.request.urlopen(req, timeout=THREAT_INTEL_TIMEOUT) as resp:
            resp_body = resp.read().decode("utf-8")
            return json.loads(resp_body)
