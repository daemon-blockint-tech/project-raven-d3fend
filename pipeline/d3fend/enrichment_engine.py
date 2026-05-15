"""
Unified D3FEND + ATT&CK enrichment engine for the pipeline.

Ties pipeline findings to defensive techniques (D3FEND) and offensive context
(ATT&CK), producing fully enriched findings for exposure scoring and reporting.
"""
from typing import Dict, List, Any, Optional
import logging

from .cwe_mapper import CWEMapper
from .ontology_client import D3FENDOntologyClient
from .attack_mapper import ATTACKMapper
from .d3fend_catalog_loader import D3FENDCatalogLoader
from .cci_loader import CCILoader
from ..models import (
    CandidateFinding,
    FinalFinding,
    D3FENDTechnique,
    ATTACKTechnique,
    ProvenFinding,
    ValidatedFinding,
    DeduplicatedFinding
)
from ..threat_intel.onchain_threat_intel import PrioritizedFinding

logger = logging.getLogger(__name__)


class EnrichmentResult:
    """Result of enriching a finding with D3FEND and ATT&CK context."""

    def __init__(
        self,
        cwe_id: Optional[str],
        d3fend_techniques: List[D3FENDTechnique],
        attack_techniques: List[ATTACKTechnique],
        threat_narrative: str,
        defensive_recommendations: List[str],
        offensive_tactics: List[str],
        threat_actor_likelihood: str,
        exposure_adjustment: float
    ):
        self.cwe_id = cwe_id
        self.d3fend_techniques = d3fend_techniques
        self.attack_techniques = attack_techniques
        self.threat_narrative = threat_narrative
        self.defensive_recommendations = defensive_recommendations
        self.offensive_tactics = offensive_tactics
        self.threat_actor_likelihood = threat_actor_likelihood
        self.exposure_adjustment = exposure_adjustment

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cwe_id": self.cwe_id,
            "d3fend_techniques": [t.to_dict() for t in self.d3fend_techniques],
            "attack_techniques": [t.to_dict() for t in self.attack_techniques],
            "threat_narrative": self.threat_narrative,
            "defensive_recommendations": self.defensive_recommendations,
            "offensive_tactics": self.offensive_tactics,
            "threat_actor_likelihood": self.threat_actor_likelihood,
            "exposure_adjustment": self.exposure_adjustment
        }


class D3FENDEnrichmentEngine:
    """
    Unified enrichment engine that binds pipeline findings to:
    - CWE weaknesses
    - D3FEND defensive techniques
    - ATT&CK offensive techniques
    - Exposure scoring adjustments
    """

    def __init__(
        self,
        ontology_client: Optional[D3FENDOntologyClient] = None,
        cwe_mapper: Optional[CWEMapper] = None,
        attack_mapper: Optional[ATTACKMapper] = None,
        catalog_path: Optional[str] = None,
        cci_path: Optional[str] = None
    ):
        """
        Initialize enrichment engine.

        Args:
            ontology_client: D3FEND ontology client (created if None)
            cwe_mapper: CWE to D3FEND mapper (created if None)
            attack_mapper: ATT&CK mapper (created if None)
            catalog_path: Path to D3FEND catalog CSV
            cci_path: Path to CCI mappings JSON
        """
        self.ontology = ontology_client or D3FENDOntologyClient()
        self.cwe_mapper = cwe_mapper or CWEMapper()
        self.attack_mapper = attack_mapper or ATTACKMapper()

        # Load real D3FEND catalog if available
        self.catalog = D3FENDCatalogLoader(catalog_path)
        self.cci = CCILoader(cci_path)

        logger.info(
            "D3FENDEnrichmentEngine initialized (catalog=%d entries, cci=%d mappings)",
            len(self.catalog.entries),
            len(self.cci.entries)
        )

    def enrich_candidate(
        self,
        candidate: CandidateFinding
    ) -> EnrichmentResult:
        """
        Enrich a candidate finding with D3FEND + ATT&CK context.

        Args:
            candidate: Pipeline candidate finding

        Returns:
            EnrichmentResult with defensive and offensive context
        """
        cwe_id = candidate.cwe_id
        bug_class = candidate.bug_class.value

        # 1. Map CWE to D3FEND defensive techniques
        d3fend_techniques = self._map_cwe_to_d3fend(cwe_id)

        # 2. Map bug class/CWE to ATT&CK offensive techniques
        attack_context = self.attack_mapper.enrich_finding(bug_class, cwe_id)
        attack_techniques = [
            ATTACKTechnique(
                id=t["id"],
                name=t["name"],
                tactic=t["tactic"],
                description=t.get("description"),
                url=t.get("url")
            )
            for t in attack_context["attack_techniques"]
        ]

        # 3. Generate defensive recommendations
        defensive_recs = self._generate_defensive_recommendations(
            d3fend_techniques, attack_techniques
        )

        # 4. Calculate exposure adjustment
        exposure_adj = self._calculate_exposure_adjustment(
            attack_context["threat_actor_likelihood"],
            len(attack_techniques),
            len(d3fend_techniques)
        )

        return EnrichmentResult(
            cwe_id=cwe_id,
            d3fend_techniques=d3fend_techniques,
            attack_techniques=attack_techniques,
            threat_narrative=attack_context["threat_narrative"],
            defensive_recommendations=defensive_recs,
            offensive_tactics=attack_context["offensive_tactics"],
            threat_actor_likelihood=attack_context["threat_actor_likelihood"],
            exposure_adjustment=exposure_adj
        )

    def enrich_prioritized_finding(
        self,
        finding: PrioritizedFinding,
        candidate: Optional[CandidateFinding] = None
    ) -> PrioritizedFinding:
        """
        Enrich an on-chain prioritized finding with D3FEND + ATT&CK context.

        Args:
            finding: PrioritizedFinding from threat intel layer
            candidate: Optional original candidate for bug class context

        Returns:
            Updated PrioritizedFinding with enrichment fields populated
        """
        # Determine bug class and CWE
        bug_class = "logic_error"
        cwe_id = None

        if candidate:
            bug_class = candidate.bug_class.value
            cwe_id = candidate.cwe_id
        elif finding.real_world_impact:
            # Infer from impact text (best effort)
            bug_class = self._infer_bug_class_from_impact(finding.real_world_impact)

        # Get enrichment
        attack_context = self.attack_mapper.enrich_finding(bug_class, cwe_id)
        d3fend_techniques = self._map_cwe_to_d3fend(cwe_id)

        # Build ATT&CK technique objects
        attack_techniques = [
            ATTACKTechnique(
                id=t["id"],
                name=t["name"],
                tactic=t["tactic"],
                description=t.get("description"),
                url=t.get("url")
            )
            for t in attack_context["attack_techniques"]
        ]

        # Update finding in place
        finding.d3fend_techniques = d3fend_techniques
        finding.attack_techniques = attack_techniques
        finding.cwe_ids = [cwe_id] if cwe_id else []
        finding.threat_narrative = attack_context["threat_narrative"]
        finding.threat_actor_likelihood = attack_context["threat_actor_likelihood"]

        # Adjust priority score based on threat actor likelihood
        if attack_context["threat_actor_likelihood"] == "HIGH":
            finding.priority_score = min(100.0, finding.priority_score * 1.15)
            finding.adjusted_severity = self._bump_severity(finding.adjusted_severity)

        logger.info(
            "Enriched finding %s with %d D3FEND and %d ATT&CK techniques",
            finding.finding_id,
            len(d3fend_techniques),
            len(attack_techniques)
        )

        return finding

    def enrich_final_finding(
        self,
        final_finding: FinalFinding
    ) -> FinalFinding:
        """
        Enrich a FinalFinding with D3FEND and ATT&CK context.

        Args:
            final_finding: FinalFinding from pipeline output

        Returns:
            Updated FinalFinding with enrichment
        """
        cwe_id = final_finding.cwe_id
        orig = final_finding.proven_finding.deduplicated_finding.representative_finding.original_candidate
        bug_class = orig.bug_class.value

        # D3FEND techniques
        d3fend_techniques = self._map_cwe_to_d3fend(cwe_id)
        if d3fend_techniques:
            final_finding.d3fend_techniques = d3fend_techniques

        # ATT&CK techniques
        attack_context = self.attack_mapper.enrich_finding(bug_class, cwe_id)
        final_finding.attack_techniques = [
            ATTACKTechnique(
                id=t["id"],
                name=t["name"],
                tactic=t["tactic"],
                description=t.get("description"),
                url=t.get("url")
            )
            for t in attack_context["attack_techniques"]
        ]

        # Exposure context
        final_finding.exposure_context = {
            "threat_narrative": attack_context["threat_narrative"],
            "offensive_tactics": attack_context["offensive_tactics"],
            "threat_actor_likelihood": attack_context["threat_actor_likelihood"],
            "defensive_recommendations": self._generate_defensive_recommendations(
                d3fend_techniques, final_finding.attack_techniques
            )
        }

        return final_finding

    def _map_cwe_to_d3fend(
        self,
        cwe_id: Optional[str]
    ) -> List[D3FENDTechnique]:
        """Map a CWE ID to D3FEND techniques using catalog > ontology > mapper."""
        if not cwe_id:
            return []

        techniques = []
        existing_ids = set()

        # 1. Try real D3FEND catalog first (richest data)
        if self.catalog.entries:
            catalog_entries = self.catalog.suggest_for_cwe(cwe_id)
            for entry in catalog_entries:
                d3f = D3FENDTechnique(
                    id=entry.technique_id,
                    label=entry.label,
                    tactic=entry.tactic,
                    description=entry.definition
                )
                techniques.append(d3f)
                existing_ids.add(entry.technique_id)

        # 2. Fallback to ontology client
        if not techniques:
            ontology_techniques = self.ontology.query_cwe_techniques(cwe_id)
            for tech in ontology_techniques:
                tid = tech.get("id", "unknown")
                if tid not in existing_ids:
                    techniques.append(D3FENDTechnique(
                        id=tid,
                        label=tech.get("label", ""),
                        tactic=tech.get("tactic", ""),
                        description=tech.get("description")
                    ))
                    existing_ids.add(tid)

        # 3. Last fallback to CWE mapper
        mapper_techniques = self.cwe_mapper.map_cwe_to_d3fend(cwe_id)
        for tech in mapper_techniques:
            if tech["id"] not in existing_ids:
                techniques.append(D3FENDTechnique(
                    id=tech["id"],
                    label=tech["label"],
                    tactic=tech.get("tactic", "")
                ))
                existing_ids.add(tech["id"])

        return techniques

    def _generate_defensive_recommendations(
        self,
        d3fend_techniques: List[D3FENDTechnique],
        attack_techniques: List[ATTACKTechnique]
    ) -> List[str]:
        """Generate defensive recommendations based on technique mappings."""
        recommendations = []

        # Map offensive tactics to defensive responses
        tactic_countermeasures = {
            "Execution": [
                "Implement application allowlisting (D3FEND: Application Control)"
            ],
            "Privilege Escalation": [
                "Enforce principle of least privilege (D3FEND: Privilege Restriction)",
                "Monitor for anomalous privilege usage"
            ],
            "Defense Evasion": [
                "Enable comprehensive logging and tamper protection",
                "Deploy behavioral detection for obfuscated execution"
            ],
            "Credential Access": [
                "Use hardware security modules for credential storage",
                "Implement multi-factor authentication"
            ],
            "Initial Access": [
                "Harden public-facing interfaces (D3FEND: Attack Surface Reduction)",
                "Deploy Web Application Firewall with known exploit signatures"
            ],
            "Impact": [
                "Implement rate limiting and resource quotas",
                "Deploy automated rollback for integrity violations"
            ],
            "Persistence": [
                "Monitor for unauthorized software installations",
                "Verify integrity of critical binaries at startup"
            ]
        }

        for attack in attack_techniques:
            tactic = attack.tactic
            if tactic in tactic_countermeasures:
                for rec in tactic_countermeasures[tactic]:
                    if rec not in recommendations:
                        recommendations.append(rec)

        # Add D3FEND-specific recommendations
        for d3f in d3fend_techniques:
            rec = f"Apply D3FEND technique {d3f.id}: {d3f.label} ({d3f.tactic} tactic)"
            if rec not in recommendations:
                recommendations.append(rec)

        return recommendations

    def _calculate_exposure_adjustment(
        self,
        threat_actor_likelihood: str,
        attack_technique_count: int,
        d3fend_technique_count: int
    ) -> float:
        """
        Calculate exposure score adjustment based on enrichment data.

        Returns a multiplier (1.0 = no change) to apply to exposure scores.
        """
        base = 1.0

        # Increase exposure if threat actor likelihood is high
        if threat_actor_likelihood == "HIGH":
            base += 0.20
        elif threat_actor_likelihood == "MEDIUM":
            base += 0.10

        # Increase if multiple attack paths exist
        if attack_technique_count >= 3:
            base += 0.10

        # Decrease slightly if strong D3FEND coverage exists
        if d3fend_technique_count >= 3:
            base -= 0.05

        return round(max(1.0, min(1.5, base)), 2)

    def _infer_bug_class_from_impact(self, impact_text: str) -> str:
        """Infer bug class from real-world impact text (best effort)."""
        text = impact_text.lower()
        if "memory" in text or "buffer" in text or "overflow" in text:
            return "memory_corruption"
        if "auth" in text or "access control" in text:
            return "auth_bypass"
        if "reentrancy" in text or "race" in text:
            return "reentrancy"
        if "oracle" in text or "price" in text:
            return "oracle_manipulation"
        if "integer" in text or "arithmetic" in text:
            return "integer_overflow"
        return "logic_error"

    def _bump_severity(self, severity: str) -> str:
        """Bump severity up one level."""
        order = ["low", "medium", "high", "critical"]
        if severity in order:
            idx = order.index(severity)
            return order[min(len(order) - 1, idx + 1)]
        return severity

    def generate_enriched_report(
        self,
        enrichment_results: List[EnrichmentResult]
    ) -> str:
        """Generate a markdown report from multiple enrichment results."""
        report = "# D3FEND + ATT&CK Enrichment Report\n\n"

        # Summary stats
        total_d3fend = sum(len(r.d3fend_techniques) for r in enrichment_results)
        total_attack = sum(len(r.attack_techniques) for r in enrichment_results)
        high_likelihood = sum(
            1 for r in enrichment_results
            if r.threat_actor_likelihood == "HIGH"
        )

        report += "## Summary\n"
        report += f"- Findings enriched: {len(enrichment_results)}\n"
        report += f"- D3FEND techniques mapped: {total_d3fend}\n"
        report += f"- ATT&CK techniques mapped: {total_attack}\n"
        report += f"- High threat-actor likelihood: {high_likelihood}\n\n"

        # Tactic distribution
        all_tactics = []
        for r in enrichment_results:
            all_tactics.extend(r.offensive_tactics)

        tactic_counts = {}
        for t in all_tactics:
            tactic_counts[t] = tactic_counts.get(t, 0) + 1

        if tactic_counts:
            report += "## Offensive Tactic Distribution\n"
            for tactic, count in sorted(tactic_counts.items(), key=lambda x: -x[1]):
                report += f"- {tactic}: {count}\n"
            report += "\n"

        # Per-finding details
        report += "## Enriched Findings\n"
        for i, result in enumerate(enrichment_results, 1):
            report += f"### Finding {i}\n"
            report += f"- CWE: {result.cwe_id or 'N/A'}\n"
            report += f"- Threat actor likelihood: {result.threat_actor_likelihood}\n"
            report += f"- Exposure adjustment: {result.exposure_adjustment}x\n\n"

            if result.d3fend_techniques:
                report += "**D3FEND Techniques:**\n"
                for t in result.d3fend_techniques:
                    report += f"- {t.id}: {t.label} ({t.tactic})\n"
                report += "\n"

            if result.attack_techniques:
                report += "**ATT&CK Techniques:**\n"
                for t in result.attack_techniques:
                    report += f"- [{t.id}]({t.url}): {t.name} ({t.tactic})\n"
                report += "\n"

            if result.threat_narrative:
                report += f"**Threat Narrative:** {result.threat_narrative}\n\n"

            if result.defensive_recommendations:
                report += "**Defensive Recommendations:**\n"
                for rec in result.defensive_recommendations:
                    report += f"- {rec}\n"
                report += "\n"

        return report
