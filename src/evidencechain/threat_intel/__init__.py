"""Threat intelligence enrichment via QoderWork.

Provides:
  - 5 source adapters (VirusTotal, AbuseIPDB, MalwareBazaar, LOLBAS, OTX)
  - Token-bucket rate limiter
  - Weighted consensus verdict aggregator
"""

from .aggregator import ThreatIntelAggregator
from .rate_limiter import RateLimiter
from .sources import (
    AbuseIPDBSource,
    AlienVaultOTXSource,
    BaseSource,
    LOLBASSource,
    MalwareBazaarSource,
    VirusTotalSource,
)

__all__ = [
    "ThreatIntelAggregator",
    "RateLimiter",
    "BaseSource",
    "VirusTotalSource",
    "AbuseIPDBSource",
    "MalwareBazaarSource",
    "LOLBASSource",
    "AlienVaultOTXSource",
]
