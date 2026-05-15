"""
Triage Agent — DevSecOps routing, owner assignment, severity scoring,
Patch Tuesday scheduling, and false positive filtering.
"""
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


@dataclass
class TriageResult:
    finding_id: str
    severity: str  # 'critical' | 'high' | 'medium' | 'low'
    finding_owner: str
    team: str
    priority: int  # 1-5, 1 = highest
    patch_tuesday_target: str
    false_positive_risk: str  # 'low' | 'medium' | 'high'
    recommended_action: str
    sla_hours: int


class TriageAgent:
    """
    Routes findings through DevSecOps channels.

    Assigns owners, schedules Patch Tuesday fixes, and filters
    probable false positives before human review.
    """

    def __init__(self, model_router=None):
        self.model_router = model_router
        self.owner_db: Dict[str, str] = {}  # component -> owner mapping
        self.historical_fp_rate: Dict[str, float] = {}  # bug class -> FP rate
        logger.info("TriageAgent initialized")

    async def triage(
        self,
        finding: Dict[str, Any],
        enrichment: Optional[Dict] = None,
    ) -> TriageResult:
        """
        Triage a single enriched finding.
        """
        finding_id = finding.get("id", "unknown")
        bug_class = finding.get("bug_class", "unknown")
        location = finding.get("location", "")

        # Severity scoring
        severity = self._calculate_severity(finding, enrichment)

        # Owner assignment
        owner, team = self._assign_owner(location, bug_class)

        # False positive risk
        fp_risk = self._assess_fp_risk(finding, bug_class)

        # Priority
        priority = self._calculate_priority(severity, fp_risk, enrichment)

        # Patch Tuesday scheduling
        patch_tuesday = self._schedule_patch_tuesday(severity, priority)

        # SLA
        sla = self._calculate_sla(severity)

        # Recommended action
        action = self._recommend_action(severity, fp_risk)

        result = TriageResult(
            finding_id=finding_id,
            severity=severity,
            finding_owner=owner,
            team=team,
            priority=priority,
            patch_tuesday_target=patch_tuesday,
            false_positive_risk=fp_risk,
            recommended_action=action,
            sla_hours=sla,
        )

        logger.info(
            f"Triaged {finding_id}: severity={severity}, owner={owner}, "
            f"priority={priority}, patch_tuesday={patch_tuesday}"
        )
        return result

    def _calculate_severity(
        self,
        finding: Dict[str, Any],
        enrichment: Optional[Dict],
    ) -> str:
        """Calculate severity based on finding and enrichment."""
        base_severity = finding.get("severity", "medium")

        if enrichment:
            exposure = enrichment.get("exposure_score", 50)
            if exposure > 80 and base_severity == "high":
                return "critical"
            if exposure > 60 and base_severity == "medium":
                return "high"

        # Boost severity for kernel/driver bugs
        location = finding.get("location", "")
        if "kernel" in location.lower() or "driver" in location.lower():
            if base_severity == "medium":
                return "high"

        return base_severity

    def _assign_owner(self, location: str, bug_class: str) -> tuple:
        """Assign finding owner based on code location and bug class."""
        # Simple heuristic mapping
        if "kernel" in location.lower():
            return ("kernel-security@microsoft.com", "Kernel Security")
        elif "driver" in location.lower():
            return ("driver-security@microsoft.com", "Driver Security")
        elif "hyper-v" in location.lower() or "hyperv" in location.lower():
            return ("hyperv-security@microsoft.com", "Hyper-V Security")
        elif "azure" in location.lower():
            return ("azure-security@microsoft.com", "Azure Security")
        elif "net" in location.lower() or "tcpip" in location.lower():
            return ("networking-security@microsoft.com", "Networking Security")
        elif "crypto" in location.lower():
            return ("crypto-security@microsoft.com", "Crypto Security")
        else:
            return ("security-triage@microsoft.com", "Security Triage")

    def _assess_fp_risk(self, finding: Dict[str, Any], bug_class: str) -> str:
        """Assess false positive risk based on historical patterns."""
        confidence = finding.get("confidence", 0.5)
        debate_votes = finding.get("debate_votes", {})
        for_count = debate_votes.get("for", 0)
        against_count = debate_votes.get("against", 0)
        total = for_count + against_count

        if total > 0 and for_count / total < 0.5:
            return "high"
        if confidence < 0.6:
            return "medium"
        if bug_class in ("race-condition", "type-confusion"):
            return "medium"
        return "low"

    def _calculate_priority(
        self,
        severity: str,
        fp_risk: str,
        enrichment: Optional[Dict],
    ) -> int:
        """Calculate priority (1-5, 1 = highest)."""
        severity_map = {"critical": 1, "high": 2, "medium": 3, "low": 4}
        base = severity_map.get(severity, 3)

        if fp_risk == "high":
            base += 1

        if enrichment:
            exposure = enrichment.get("exposure_score", 50)
            if exposure > 80:
                base = max(1, base - 1)

        return min(5, base)

    def _schedule_patch_tuesday(self, severity: str, priority: int) -> str:
        """Schedule Patch Tuesday target."""
        today = datetime.now()

        # Calculate next Patch Tuesday (second Tuesday of month)
        if today.day <= 14:
            # This month
            patch_tuesday = today.replace(day=14)
            while patch_tuesday.weekday() != 1:  # Tuesday = 1
                patch_tuesday -= timedelta(days=1)
        else:
            # Next month
            next_month = today.replace(day=1) + timedelta(days=32)
            patch_tuesday = next_month.replace(day=14)
            while patch_tuesday.weekday() != 1:
                patch_tuesday -= timedelta(days=1)

        # Adjust based on severity
        if severity == "critical" and priority <= 2:
            # Out-of-band release
            return (today + timedelta(days=7)).strftime("%Y-%m-%d")

        return patch_tuesday.strftime("%Y-%m-%d")

    def _calculate_sla(self, severity: str) -> int:
        """Calculate SLA in hours based on severity."""
        sla_map = {
            "critical": 24,
            "high": 72,
            "medium": 168,  # 1 week
            "low": 720,     # 30 days
        }
        return sla_map.get(severity, 168)

    def _recommend_action(self, severity: str, fp_risk: str) -> str:
        """Recommend next action."""
        if fp_risk == "high":
            return "route-to-investigator"
        if severity in ("critical", "high"):
            return "route-to-defend"
        return "route-to-investigator"
