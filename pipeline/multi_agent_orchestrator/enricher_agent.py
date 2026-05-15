"""
Enricher Agent — D3FEND + ATT&CK + Exposure Scoring + Compliance Mapping.

Binds defensive and offensive context to validated findings.
"""
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

from .agent_core import Agent

try:
    from ..threat_intel.shodan_client import ShodanClient
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False

try:
    from ..d3fend.compliance_reporter import ComplianceReporter
    COMPLIANCE_AVAILABLE = True
except ImportError:
    COMPLIANCE_AVAILABLE = False

try:
    from ..d3fend.owasp_cheatsheet_mapper import OWASPCheatSheetMapper
    OWASP_AVAILABLE = True
except ImportError:
    OWASP_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class EnrichmentResult:
    finding_id: str
    d3fend_techniques: List[str]
    attack_techniques: List[str]
    acf_techniques: List[str]  # D3FEND ACF analytic techniques
    exposure_score: float  # 0-100
    shodan_exposure: Optional[Dict[str, Any]]  # External exposure data
    threat_actor_likelihood: str  # 'low' | 'medium' | 'high'
    compliance_controls: List[str]
    compliance_mappings: Optional[List[Dict[str, Any]]]  # CySA+ aligned compliance
    owasp_references: Optional[List[Dict[str, Any]]]  # OWASP Cheat Sheet references
    remediation_priority: str  # 'critical' | 'high' | 'medium' | 'low'
    narrative: str = ""


class EnricherAgent:
    """
    Enriches findings with D3FEND defensive techniques, ATT&CK offensive
    techniques, exposure scoring, Shodan external exposure, and compliance mapping.
    """

    def __init__(self, model_router=None):
        self.model_router = model_router
        self.shodan = ShodanClient() if SHODAN_AVAILABLE else None
        self.compliance = ComplianceReporter() if COMPLIANCE_AVAILABLE else None
        self.d3fend_catalog: Dict[str, Any] = {}
        self.attack_catalog: Dict[str, Any] = {}
        logger.info("EnricherAgent initialized")

    async def enrich(
        self,
        finding: Dict[str, Any],
        cwe: Optional[str] = None,
        attack_ids: Optional[List[str]] = None,
    ) -> EnrichmentResult:
        """
        Enrich a single finding with full context.
        """
        finding_id = finding.get("id", "unknown")
        bug_class = finding.get("bug_class", "unknown")

        # D3FEND binding
        d3fend = self._map_to_d3fend(bug_class, cwe)

        # ATT&CK binding
        attack = self._map_to_attack(bug_class, attack_ids)

        # ACF binding
        acf = self._map_to_acf(bug_class, d3fend)

        # Exposure scoring
        exposure = self._calculate_exposure(finding)

        # Shodan external exposure (if available)
        shodan_data = None
        if self.shodan and self.shodan.is_available():
            try:
                shodan_result = self.shodan.assess_finding_exposure(finding)
                if shodan_result.internet_exposed:
                    shodan_data = {
                        "internet_exposed": True,
                        "host_count": shodan_result.host_count,
                        "exposed_services": shodan_result.exposed_services,
                        "countries": shodan_result.countries,
                        "orgs": shodan_result.orgs,
                        "vulns_matched": shodan_result.vulns_matched,
                        "exposure_score": shodan_result.exposure_score,
                    }
                    # Boost internal exposure score with Shodan data
                    exposure = min(100, (exposure + shodan_result.exposure_score) / 2)
            except Exception as e:
                logger.warning(f"Shodan assessment failed: {e}")

        # Compliance mapping
        compliance = self._map_compliance(d3fend)

        # OWASP Cheat Sheet references
        owasp_refs = None
        if OWASP_AVAILABLE:
            try:
                owasp_refs = OWASPCheatSheetMapper.get_recommendations_for_finding(
                    bug_class=bug_class,
                    d3fend_ids=d3fend,
                    cwe_id=cwe,
                )
            except Exception as e:
                logger.warning(f"OWASP lookup failed: {e}")

        # CySA+ aligned compliance mappings
        compliance_mappings = None
        if self.compliance:
            try:
                mappings = self.compliance.map_finding(finding, d3fend, bug_class)
                if mappings:
                    compliance_mappings = [
                        {
                            "framework": m.framework.value,
                            "control_id": m.control_id,
                            "control_name": m.control_name,
                            "status": m.finding_status,
                            "priority": m.priority,
                            "remediation": m.remediation,
                        }
                        for m in mappings
                    ]
            except Exception as e:
                logger.warning(f"Compliance mapping failed: {e}")

        # Remediation priority
        priority = self._calculate_priority(finding, exposure)

        # Build threat narrative
        narrative = self._build_narrative(finding, d3fend, attack, exposure)

        result = EnrichmentResult(
            finding_id=finding_id,
            d3fend_techniques=d3fend,
            attack_techniques=attack,
            acf_techniques=acf,
            exposure_score=exposure,
            shodan_exposure=shodan_data,
            threat_actor_likelihood="medium" if exposure > 50 else "low",
            compliance_controls=compliance,
            compliance_mappings=compliance_mappings,
            owasp_references=owasp_refs,
            remediation_priority=priority,
            narrative=narrative,
        )

        logger.info(
            f"Enriched {finding_id}: D3FEND={len(d3fend)}, "
            f"ATT&CK={len(attack)}, ACF={len(acf)}, "
            f"exposure={exposure:.1f}"
            f"{', shodan_hosts=' + str(shodan_data['host_count']) if shodan_data else ''}"
            f"{', compliance=' + str(len(compliance_mappings)) if compliance_mappings else ''}"
        )
        return result

    def _map_to_d3fend(self, bug_class: str, cwe: Optional[str]) -> List[str]:
        """Map bug class to D3FEND defensive techniques."""
        # Simplified mapping (in production, use pipeline/d3fend/)
        mappings = {
            "buffer-overflow": ["D3-SCH", "D3-AH", "D3-MA"],
            "use-after-free": ["D3-SCH", "D3-MA", "D3-PA"],
            "race-condition": ["D3-SCH", "D3-MA", "D3-EI"],
            "auth-bypass": ["D3-CH", "D3-AH", "D3-NTA"],
            "integer-overflow": ["D3-SCH", "D3-MA"],
            "deserialization": ["D3-SCH", "D3-AH", "D3-PA"],
            "type-confusion": ["D3-SCH", "D3-MA"],
            "sql-injection": ["D3-AH", "D3-NTA"],
            "xss": ["D3-AH", "D3-NTA"],
            "path-traversal": ["D3-AH", "D3-MA"],
            "reentrancy": ["D3-SCH", "D3-MA"],
            "oracle-manipulation": ["D3-AH", "D3-NTA"],
            "account-confusion": ["D3-CH", "D3-AH"],
            "arithmetic-overflow": ["D3-SCH", "D3-MA"],
            "irp-flaw": ["D3-SCH", "D3-MA", "D3-EI"],
            "vm-escape": ["D3-EI", "D3-MA", "D3-NI"],
        }
        return mappings.get(bug_class, ["D3-SCH", "D3-AH"])

    def _map_to_attack(self, bug_class: str, attack_ids: Optional[List[str]]) -> List[str]:
        """Map bug class to ATT&CK offensive techniques."""
        if attack_ids:
            return attack_ids

        mappings = {
            "buffer-overflow": ["T1203", "T1068"],
            "use-after-free": ["T1203", "T1068"],
            "race-condition": ["T1203", "T1499"],
            "auth-bypass": ["T1078", "T1552"],
            "integer-overflow": ["T1203"],
            "deserialization": ["T1203", "T1059"],
            "type-confusion": ["T1203", "T1068"],
            "sql-injection": ["T1190"],
            "xss": ["T1189", "T1059"],
            "path-traversal": ["T1083", "T1041"],
            "reentrancy": ["T1649"],
            "oracle-manipulation": ["T1649"],
            "account-confusion": ["T1078"],
            "arithmetic-overflow": ["T1203"],
            "irp-flaw": ["T1068", "T1203"],
            "vm-escape": ["T1565", "T1203"],
        }
        return mappings.get(bug_class, ["T1203"])

    def _calculate_exposure(self, finding: Dict[str, Any]) -> float:
        """Calculate real-world exposure score (0-100)."""
        # Factors: severity, exploit difficulty, deployment prevalence
        severity_scores = {
            "critical": 90, "high": 70, "medium": 50, "low": 30
        }
        base = severity_scores.get(finding.get("severity", "medium"), 50)

        # Adjust based on location type
        location = finding.get("location", "")
        if "kernel" in location.lower() or "driver" in location.lower():
            base += 15
        elif "hypervisor" in location.lower():
            base += 20

        # Cap at 100
        return min(100.0, base)

    def _map_compliance(self, d3fend_ids: List[str]) -> List[str]:
        """Map D3FEND IDs to compliance controls."""
        # Simplified CCI-to-NIST mapping
        mappings = {
            "D3-SCH": ["CCI-000366", "CCI-001184"],
            "D3-AH": ["CCI-000213", "CCI-001619"],
            "D3-MA": ["CCI-001453", "CCI-001619"],
            "D3-CH": ["CCI-000366", "CCI-001991"],
            "D3-NI": ["CCI-001414", "CCI-001450"],
            "D3-EI": ["CCI-001414", "CCI-001453"],
            "D3-PA": ["CCI-000366", "CCI-001619"],
            "D3-NTA": ["CCI-000366", "CCI-001414"],
        }
        controls = set()
        for d3 in d3fend_ids:
            for c in mappings.get(d3, []):
                controls.add(c)
        return sorted(list(controls))

    def _calculate_priority(
        self,
        finding: Dict[str, Any],
        exposure: float,
    ) -> str:
        """Calculate remediation priority."""
        severity = finding.get("severity", "medium")
        if severity == "critical" and exposure > 70:
            return "critical"
        elif severity in ("critical", "high") or exposure > 60:
            return "high"
        elif severity == "medium" or exposure > 40:
            return "medium"
        return "low"

    def _build_narrative(
        self,
        finding: Dict[str, Any],
        d3fend: List[str],
        attack: List[str],
        exposure: float,
    ) -> str:
        """Build a threat narrative for the finding."""
        bug_class = finding.get("bug_class", "unknown")
        location = finding.get("location", "unknown")

        return (
            f"A {bug_class} vulnerability at {location} exposes the system to "
            f"offensive techniques {', '.join(attack)}. "
            f"Defensive mitigations include {', '.join(d3fend)}. "
            f"Real-world exposure score: {exposure:.0f}/100."
        )
