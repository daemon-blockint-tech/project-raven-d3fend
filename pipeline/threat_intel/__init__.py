"""
On-Chain Threat Intel Layer

Integrates on-chain threat intelligence to prioritize findings based on
real-world exposure scores rather than just CVSS.
"""

from .onchain_threat_intel import (
    OnChainThreatIntelLayer,
    ThreatIntel,
    PrioritizedFinding,
    ThreatSource,
    ExposureMetric
)
from .shodan_client import ShodanClient, ShodanExposureResult, ShodanAPIError

__all__ = [
    'OnChainThreatIntelLayer',
    'ThreatIntel',
    'PrioritizedFinding',
    'ThreatSource',
    'ExposureMetric',
    'ShodanClient',
    'ShodanExposureResult',
    'ShodanAPIError',
]
