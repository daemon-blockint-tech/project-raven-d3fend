"""
On-Chain Threat Intel Layer for Exposure Scoring

Integrates on-chain threat intelligence to prioritize findings based on
real-world exposure scores rather than just CVSS. Incorporates blockchain data,
transaction patterns, and threat feeds to assess actual risk.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime, timedelta


class ThreatSource(Enum):
    """Sources of threat intelligence"""
    BLOCKCHAIN_ANALYSIS = "blockchain_analysis"
    TRANSACTION_MONITORING = "transaction_monitoring"
    THREAT_FEED = "threat_feed"
    EXPLOIT_DATABASE = "exploit_database"
    SANCTIONS_LIST = "sanctions_list"
    CRYPTO_THREAT_INTEL = "crypto_threat_intel"
    DEFI_MONITORING = "defi_monitoring"


class ExposureMetric(Enum):
    """Types of exposure metrics"""
    TVL = "tvl"  # Total Value Locked
    TRANSACTION_VOLUME = "transaction_volume"
    ACTIVE_ADDRESSES = "active_addresses"
    DEPENDENTS = "dependents"
    PRICE_IMPACT = "price_impact"
    LIQUIDITY_DEPTH = "liquidity_depth"
    TIME_AT_RISK = "time_at_risk"


@dataclass
class ThreatIntel:
    """Represents a threat intelligence finding"""
    intel_id: str
    source: ThreatSource
    address: str
    chain: str  # e.g., "ethereum", "bitcoin", "solana"
    threat_type: str
    severity: str  # "critical", "high", "medium", "low"
    exposure_score: float  # 0-100
    metrics: Dict[ExposureMetric, float]
    first_seen: datetime
    last_seen: datetime
    related_incidents: List[str]
    confidence: float
    description: str


@dataclass
class PrioritizedFinding:
    """A security finding with on-chain exposure and D3FEND/ATT&CK context"""
    finding_id: str
    original_severity: str  # CVSS-based
    exposure_score: float
    adjusted_severity: str
    on_chain_context: List[ThreatIntel]
    real_world_impact: str
    priority_score: float  # Combined score
    recommendation: str
    # Enrichment fields (populated by D3FENDEnrichmentEngine)
    d3fend_techniques: List = None
    attack_techniques: List = None
    cwe_ids: List[str] = None
    threat_narrative: str = ""
    threat_actor_likelihood: str = "UNKNOWN"

    def __post_init__(self):
        if self.d3fend_techniques is None:
            self.d3fend_techniques = []
        if self.attack_techniques is None:
            self.attack_techniques = []
        if self.cwe_ids is None:
            self.cwe_ids = []


class OnChainThreatIntelLayer:
    """
    Integrates on-chain threat intelligence to prioritize findings
    based on real-world exposure scores rather than just CVSS.
    """
    
    def __init__(self):
        self.threat_intel_db: Dict[str, ThreatIntel] = {}
        self.prioritized_findings: List[PrioritizedFinding] = []
        
        # Exposure weightings for priority calculation
        self.exposure_weights = {
            ExposureMetric.TVL: 0.3,
            ExposureMetric.TRANSACTION_VOLUME: 0.25,
            ExposureMetric.ACTIVE_ADDRESSES: 0.15,
            ExposureMetric.DEPENDENTS: 0.15,
            ExposureMetric.PRICE_IMPACT: 0.1,
            ExposureMetric.LIQUIDITY_DEPTH: 0.05,
        }
        
        # Severity mapping
        self.severity_map = {
            'critical': (9.0, 10.0),
            'high': (7.0, 8.9),
            'medium': (4.0, 6.9),
            'low': (0.1, 3.9),
        }
        
        # Chain-specific data sources
        self.chain_explorers = {
            'ethereum': 'https://api.etherscan.io/api',
            'bitcoin': 'https://blockstream.info/api',
            'solana': 'https://api.solscan.io',
            'polygon': 'https://api.polygonscan.com',
            'avalanche': 'https://api.snowtrace.io',
        }
    
    def add_threat_intel(self, intel: ThreatIntel) -> None:
        """Add threat intelligence to the database"""
        self.threat_intel_db[intel.address] = intel
    
    def query_address(self, address: str, chain: str) -> Optional[ThreatIntel]:
        """Query threat intelligence for an address"""
        return self.threat_intel_db.get(address)
    
    def calculate_exposure_score(self, metrics: Dict[ExposureMetric, float]) -> float:
        """Calculate exposure score from metrics"""
        score = 0.0
        
        for metric, weight in self.exposure_weights.items():
            if metric in metrics:
                # Normalize metric to 0-100 range
                normalized = self._normalize_metric(metric, metrics[metric])
                score += normalized * weight
        
        return min(100.0, score)
    
    def _normalize_metric(self, metric: ExposureMetric, value: float) -> float:
        """Normalize a metric to 0-100 range"""
        # Normalization thresholds (example values, should be calibrated)
        thresholds = {
            ExposureMetric.TVL: (0, 1_000_000_000),  # $0 to $1B
            ExposureMetric.TRANSACTION_VOLUME: (0, 10_000_000),  # 0 to 10M tx
            ExposureMetric.ACTIVE_ADDRESSES: (0, 100_000),  # 0 to 100K addresses
            ExposureMetric.DEPENDENTS: (0, 1000),  # 0 to 1K dependents
            ExposureMetric.PRICE_IMPACT: (0, 100),  # 0 to 100%
            ExposureMetric.LIQUIDITY_DEPTH: (0, 10_000_000),  # $0 to $10M
        }
        
        min_val, max_val = thresholds.get(metric, (0, 1))
        if max_val == 0:
            return 0.0
        
        normalized = (value - min_val) / (max_val - min_val) * 100
        return max(0.0, min(100.0, normalized))
    
    def prioritize_finding(self, finding_id: str, original_severity: str,
                          affected_addresses: List[str], 
                          chain: str) -> PrioritizedFinding:
        """Prioritize a security finding based on on-chain exposure"""
        # Collect threat intel for affected addresses
        on_chain_context = []
        total_exposure = 0.0
        address_count = len(affected_addresses)
        
        for address in affected_addresses:
            intel = self.query_address(address, chain)
            if intel:
                on_chain_context.append(intel)
                total_exposure += intel.exposure_score
            else:
                # If no intel exists, estimate from chain data
                estimated_exposure = self._estimate_exposure(address, chain)
                if estimated_exposure > 0:
                    total_exposure += estimated_exposure
        
        # Calculate average exposure
        avg_exposure = total_exposure / address_count if address_count > 0 else 0
        
        # Calculate priority score (70% exposure, 30% CVSS)
        cvss_score = self._severity_to_score(original_severity)
        priority_score = (avg_exposure * 0.7) + (cvss_score * 0.3)
        
        # Determine adjusted severity
        adjusted_severity = self._score_to_severity(priority_score)
        
        # Generate recommendation
        recommendation = self._generate_recommendation(
            original_severity, adjusted_severity, avg_exposure, address_count
        )
        
        # Determine real-world impact
        real_world_impact = self._assess_real_world_impact(
            avg_exposure, on_chain_context
        )
        
        return PrioritizedFinding(
            finding_id=finding_id,
            original_severity=original_severity,
            exposure_score=avg_exposure,
            adjusted_severity=adjusted_severity,
            on_chain_context=on_chain_context,
            real_world_impact=real_world_impact,
            priority_score=priority_score,
            recommendation=recommendation
        )
    
    def _estimate_exposure(self, address: str, chain: str) -> float:
        """Estimate exposure for an address without cached intel"""
        # In a real implementation, this would query chain data APIs
        # For now, return a conservative estimate
        return 10.0  # Conservative low exposure
    
    def _severity_to_score(self, severity: str) -> float:
        """Convert severity to numeric score"""
        score_ranges = self.severity_map.get(severity, (5.0, 5.0))
        return (score_ranges[0] + score_ranges[1]) / 2
    
    def _score_to_severity(self, score: float) -> str:
        """Convert numeric score to severity"""
        for severity, (min_score, max_score) in self.severity_map.items():
            if min_score <= score <= max_score:
                return severity
        return 'medium'
    
    def _generate_recommendation(self, original_severity: str, 
                               adjusted_severity: str, exposure: float,
                               address_count: int) -> str:
        """Generate recommendation based on severity adjustment"""
        if original_severity == adjusted_severity:
            return f"Severity unchanged. Exposure score: {exposure:.1f}/100. Address count: {address_count}"
        
        if adjusted_severity == 'critical' and original_severity != 'critical':
            return f"UPGRADED to CRITICAL due to high exposure ({exposure:.1f}/100) affecting {address_count} addresses"
        
        if adjusted_severity == 'high' and original_severity == 'critical':
            return f"DOWNGRADED to HIGH due to low exposure ({exposure:.1f}/100). Consider resource allocation."
        
        if adjusted_severity == 'medium' and original_severity in ['high', 'critical']:
            return f"DOWNGRADED to MEDIUM due to low exposure ({exposure:.1f}/100). May defer remediation."
        
        if adjusted_severity == 'low' and original_severity in ['high', 'critical', 'medium']:
            return f"DOWNGRADED to LOW due to minimal exposure ({exposure:.1f}/100). Low priority."
        
        return f"Severity adjusted from {original_severity} to {adjusted_severity}"
    
    def _assess_real_world_impact(self, exposure: float, 
                                 context: List[ThreatIntel]) -> str:
        """Assess real-world impact based on exposure and context"""
        if exposure >= 80:
            return "CRITICAL: High exposure indicates significant real-world impact. Immediate action required."
        elif exposure >= 50:
            return "HIGH: Substantial exposure with potential real-world impact. Prioritize remediation."
        elif exposure >= 20:
            return "MEDIUM: Moderate exposure with potential real-world impact. Monitor and plan remediation."
        else:
            return "LOW: Minimal exposure indicates limited real-world impact. Standard remediation timeline."
    
    def batch_prioritize_findings(self, findings: List[Tuple[str, str, List[str], str]]) -> List[PrioritizedFinding]:
        """Batch prioritize multiple findings"""
        prioritized = []
        
        for finding_id, severity, addresses, chain in findings:
            prioritized_finding = self.prioritize_finding(
                finding_id, severity, addresses, chain
            )
            prioritized.append(prioritized_finding)
        
        # Sort by priority score
        prioritized.sort(key=lambda x: x.priority_score, reverse=True)
        self.prioritized_findings.extend(prioritized)
        
        return prioritized
    
    def generate_exposure_report(self) -> str:
        """Generate a comprehensive exposure-based prioritization report"""
        report = "# On-Chain Threat Intel Exposure Report\n\n"
        
        report += "## Summary\n"
        report += f"- Total Threat Intel Entries: {len(self.threat_intel_db)}\n"
        report += f"- Prioritized Findings: {len(self.prioritized_findings)}\n\n"
        
        # Severity adjustments
        severity_adjustments = {}
        for finding in self.prioritized_findings:
            key = f"{finding.original_severity} -> {finding.adjusted_severity}"
            severity_adjustments[key] = severity_adjustments.get(key, 0) + 1
        
        report += "## Severity Adjustments\n"
        for adjustment, count in severity_adjustments.items():
            report += f"- {adjustment}: {count} findings\n"
        
        report += "\n## High-Priority Findings (Exposure > 50)\n"
        for finding in self.prioritized_findings:
            if finding.exposure_score >= 50:
                report += f"- [{finding.finding_id}] {finding.adjusted_severity.upper()}: {finding.real_world_impact}\n"
        
        report += "\n## Exposure Distribution\n"
        exposure_ranges = {
            'Critical (80-100)': 0,
            'High (50-79)': 0,
            'Medium (20-49)': 0,
            'Low (0-19)': 0,
        }
        
        for finding in self.prioritized_findings:
            if finding.exposure_score >= 80:
                exposure_ranges['Critical (80-100)'] += 1
            elif finding.exposure_score >= 50:
                exposure_ranges['High (50-79)'] += 1
            elif finding.exposure_score >= 20:
                exposure_ranges['Medium (20-49)'] += 1
            else:
                exposure_ranges['Low (0-19)'] += 1
        
        for range_name, count in exposure_ranges.items():
            report += f"- {range_name}: {count} findings\n"
        
        return report
