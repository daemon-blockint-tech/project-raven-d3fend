"""
Compliance Reporter — CySA+ Domain 4 aligned compliance reporting.

Maps Raven findings to major compliance frameworks and generates
auditable compliance reports with stakeholder communication.

Supports: ISO 27001, HIPAA, PCI-DSS, GDPR, SOC 2, NIST SP 800-53
"""
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class ComplianceFramework(Enum):
    """Supported compliance frameworks."""
    ISO_27001 = "ISO 27001"
    HIPAA = "HIPAA"
    PCI_DSS = "PCI-DSS"
    GDPR = "GDPR"
    SOC_2 = "SOC 2"
    NIST_800_53 = "NIST SP 800-53"


@dataclass
class ComplianceMapping:
    """Maps a finding to compliance framework requirements."""
    framework: ComplianceFramework
    control_id: str
    control_name: str
    requirement_description: str
    finding_status: str  # "compliant" | "non-compliant" | "partial"
    evidence: str
    remediation: str
    priority: str  # "critical" | "high" | "medium" | "low"


@dataclass
class ComplianceReport:
    """Generated compliance report for a pipeline run."""
    report_id: str
    generated_at: str
    target: str
    frameworks: List[ComplianceFramework]
    total_findings: int
    compliant_count: int
    non_compliant_count: int
    partial_count: int
    mappings: List[ComplianceMapping]
    executive_summary: str
    action_plan: List[str]
    kpi_metrics: Dict[str, Any]
    stakeholder_recommendations: Dict[str, List[str]]


class ComplianceReporter:
    """
    Generates compliance-aligned reports from Raven findings.

    Aligns with CySA+ Domain 4:
    - 4.1 Vulnerability management reporting
    - 4.2 Incident response reporting
    - Compliance communication to appropriate stakeholders
    """

    # Framework control mappings from D3FEND technique IDs
    FRAMEWORK_MAPPINGS: Dict[ComplianceFramework, Dict[str, List[str]]] = {
        ComplianceFramework.ISO_27001: {
            "A.12.6.1": ["D3-SCH", "D3-AH", "D3-MA"],  # Management of technical vulnerabilities
            "A.16.1.1": ["D3-PA", "D3-NTA"],  # Procedures for information security incidents
            "A.18.2.2": ["D3-CH", "D3-MFA"],  # Compliance with security policies
            "A.9.4.1": ["D3-CH", "D3-AH"],  # Access control policy
            "A.10.1.1": ["D3-MH", "D3-MENCR"],  # Cryptographic controls
        },
        ComplianceFramework.HIPAA: {
            "164.312(a)(1)": ["D3-CH", "D3-AH", "D3-MFA"],  # Access control
            "164.312(b)": ["D3-MH", "D3-MENCR"],  # Audit controls
            "164.312(c)(1)": ["D3-FE", "D3-DENCR"],  # Integrity
            "164.312(d)": ["D3-MAN", "D3-TAAN"],  # Person authentication
            "164.312(e)(1)": ["D3-MENCR", "D3-ET"],  # Transmission security
        },
        ComplianceFramework.PCI_DSS: {
            "Req 6.5": ["D3-SCH", "D3-AH", "D3-MA"],  # Address common coding vulnerabilities
            "Req 8.2": ["D3-CH", "D3-MFA", "D3-PWA"],  # User authentication
            "Req 10.2": ["D3-PA", "D3-NTA"],  # Audit trails
            "Req 11.3.2": ["D3-NVA", "D3-SYSVA"],  # Vulnerability scanning
            "Req 12.10.1": ["D3-PA", "D3-NTA"],  # Incident response plan
        },
        ComplianceFramework.GDPR: {
            "Art 25": ["D3-SCH", "D3-AH", "D3-MA"],  # Data protection by design
            "Art 32": ["D3-FE", "D3-DENCR", "D3-MENCR"],  # Security of processing
            "Art 33": ["D3-PA", "D3-NTA"],  # Breach notification
            "Art 35": ["D3-NVA", "D3-SYSVA"],  # DPIA
        },
        ComplianceFramework.SOC_2: {
            "CC6.1": ["D3-CH", "D3-AH", "D3-MFA"],  # Logical access security
            "CC6.2": ["D3-SCP", "D3-UAP"],  # Access removal
            "CC6.6": ["D3-FE", "D3-DENCR"],  # Encryption
            "CC7.2": ["D3-SYSVA", "D3-NVA"],  # System monitoring
            "CC7.3": ["D3-PA", "D3-NTA"],  # Incident detection
        },
        ComplianceFramework.NIST_800_53: {
            "AC-3": ["D3-CH", "D3-AH"],  # Access enforcement
            "AU-6": ["D3-PA", "D3-NTA"],  # Audit review
            "CM-4": ["D3-SCH", "D3-AH"],  # Security impact analysis
            "IR-4": ["D3-PA", "D3-NTA"],  # Incident handling
            "RA-5": ["D3-NVA", "D3-SYSVA"],  # Vulnerability scanning
            "SC-13": ["D3-MENCR", "D3-FE"],  # Cryptographic protection
        },
    }

    def __init__(self, frameworks: Optional[List[ComplianceFramework]] = None):
        self.frameworks = frameworks or list(ComplianceFramework)
        logger.info(f"ComplianceReporter initialized for {len(self.frameworks)} frameworks")

    def map_finding(
        self,
        finding: Dict[str, Any],
        d3fend_ids: List[str],
        bug_class: str
    ) -> List[ComplianceMapping]:
        """
        Map a single finding to compliance framework controls.

        Args:
            finding: Finding dict
            d3fend_ids: List of D3FEND technique IDs
            bug_class: Bug class string

        Returns:
            List of compliance mappings
        """
        mappings = []

        for framework in self.frameworks:
            framework_map = self.FRAMEWORK_MAPPINGS.get(framework, {})

            for control_id, d3_techniques in framework_map.items():
                # Check if any D3FEND technique overlaps
                if any(d3 in d3fend_ids for d3 in d3_techniques):
                    severity = finding.get("severity", "medium")
                    status = self._determine_status(severity)
                    priority = self._severity_to_priority(severity)

                    mapping = ComplianceMapping(
                        framework=framework,
                        control_id=control_id,
                        control_name=self._get_control_name(framework, control_id),
                        requirement_description=self._get_requirement_desc(
                            framework, control_id
                        ),
                        finding_status=status,
                        evidence=self._build_evidence(finding, d3_techniques),
                        remediation=self._get_remediation(framework, control_id, bug_class),
                        priority=priority,
                    )
                    mappings.append(mapping)

        return mappings

    def generate_report(
        self,
        findings: List[Dict[str, Any]],
        target: str,
        report_id: Optional[str] = None,
    ) -> ComplianceReport:
        """
        Generate a full compliance report from all findings.

        Args:
            findings: List of enriched findings
            target: Target name/identifier
            report_id: Optional report ID

        Returns:
            ComplianceReport with full metrics and action plan
        """
        report_id = report_id or f"RAVEN-COMP-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        all_mappings = []

        for finding in findings:
            d3fend_ids = finding.get("d3fend_techniques", [])
            bug_class = finding.get("bug_class", "unknown")
            finding_mappings = self.map_finding(finding, d3fend_ids, bug_class)
            all_mappings.extend(finding_mappings)

        compliant = sum(1 for m in all_mappings if m.finding_status == "compliant")
        non_compliant = sum(1 for m in all_mappings if m.finding_status == "non-compliant")
        partial = sum(1 for m in all_mappings if m.finding_status == "partial")

        # Build executive summary
        summary = self._build_executive_summary(
            target, len(findings), non_compliant, partial, compliant
        )

        # Build action plan
        action_plan = self._build_action_plan(all_mappings)

        # Calculate KPIs
        kpis = self._calculate_kpis(findings, all_mappings)

        # Stakeholder recommendations
        stakeholders = self._build_stakeholder_recommendations(all_mappings)

        return ComplianceReport(
            report_id=report_id,
            generated_at=datetime.now().isoformat(),
            target=target,
            frameworks=self.frameworks,
            total_findings=len(findings),
            compliant_count=compliant,
            non_compliant_count=non_compliant,
            partial_count=partial,
            mappings=all_mappings,
            executive_summary=summary,
            action_plan=action_plan,
            kpi_metrics=kpis,
            stakeholder_recommendations=stakeholders,
        )

    def _determine_status(self, severity: str) -> str:
        """Map severity to compliance status."""
        if severity in ("critical", "high"):
            return "non-compliant"
        elif severity == "medium":
            return "partial"
        return "compliant"

    def _severity_to_priority(self, severity: str) -> str:
        """Map severity to compliance priority."""
        mapping = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
        }
        return mapping.get(severity, "medium")

    def _get_control_name(self, framework: ComplianceFramework, control_id: str) -> str:
        """Get human-readable control name."""
        names = {
            "A.12.6.1": "Management of Technical Vulnerabilities",
            "A.16.1.1": "Information Security Incident Response",
            "164.312(a)(1)": "Access Control",
            "Req 6.5": "Address Common Coding Vulnerabilities",
            "Art 25": "Data Protection by Design",
            "CC6.1": "Logical Access Security",
            "AC-3": "Access Enforcement",
            "IR-4": "Incident Handling",
        }
        return names.get(control_id, control_id)

    def _get_requirement_desc(
        self, framework: ComplianceFramework, control_id: str
    ) -> str:
        """Get requirement description."""
        descs = {
            ComplianceFramework.ISO_27001: "Establish management processes for identifying and remediating technical vulnerabilities.",
            ComplianceFramework.HIPAA: "Implement technical policies and procedures to allow access only to authorized persons.",
            ComplianceFramework.PCI_DSS: "Develop applications based on secure coding guidelines to prevent common vulnerabilities.",
            ComplianceFramework.GDPR: "Implement appropriate technical and organizational measures to ensure data protection.",
            ComplianceFramework.SOC_2: "Implement logical access security measures to protect against unauthorized access.",
            ComplianceFramework.NIST_800_53: "Enforce approved authorizations for logical access to information and system resources.",
        }
        return descs.get(framework, "Compliance requirement")

    def _build_evidence(
        self, finding: Dict[str, Any], d3_techniques: List[str]
    ) -> str:
        """Build evidence string from finding."""
        location = finding.get("location", "unknown")
        bug_class = finding.get("bug_class", "unknown")
        severity = finding.get("severity", "medium")
        return (
            f"{bug_class} vulnerability detected at {location} "
            f"with severity {severity}. Mapped to D3FEND techniques: "
            f"{', '.join(d3_techniques)}."
        )

    def _get_remediation(
        self, framework: ComplianceFramework, control_id: str, bug_class: str
    ) -> str:
        """Get framework-specific remediation guidance."""
        remediations = {
            "buffer-overflow": "Implement bounds checking, use safe libraries, and enable ASLR/NX.",
            "use-after-free": "Use smart pointers, implement reference nullification after free.",
            "auth-bypass": "Enforce multi-factor authentication, implement principle of least privilege.",
            "sql-injection": "Use parameterized queries, implement input validation and ORM.",
            "xss": "Implement output encoding, Content Security Policy headers, input sanitization.",
        }
        base = remediations.get(bug_class, "Apply security patches and review code.")
        return f"{framework.value}: {control_id} — {base}"

    def _build_executive_summary(
        self,
        target: str,
        total: int,
        non_compliant: int,
        partial: int,
        compliant: int,
    ) -> str:
        """Build executive summary."""
        return (
            f"Compliance assessment for {target}: {total} findings analyzed across "
            f"{len(self.frameworks)} frameworks. "
            f"Non-compliant: {non_compliant}, Partial: {partial}, Compliant: {compliant}. "
            f"Immediate action required for {non_compliant} critical/high findings."
        )

    def _build_action_plan(self, mappings: List[ComplianceMapping]) -> List[str]:
        """Build prioritized action plan."""
        actions = []
        non_compliant = [m for m in mappings if m.finding_status == "non-compliant"]
        non_compliant.sort(key=lambda m: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(m.priority, 4))

        for m in non_compliant[:10]:  # Top 10
            actions.append(
                f"[{m.priority.upper()}] {m.framework.value} {m.control_id}: "
                f"{m.remediation}"
            )

        if not actions:
            actions.append("No immediate action required. Continue monitoring.")

        return actions

    def _calculate_kpis(
        self,
        findings: List[Dict[str, Any]],
        mappings: List[ComplianceMapping],
    ) -> Dict[str, Any]:
        """Calculate compliance KPIs."""
        severities = [f.get("severity", "medium") for f in findings]
        critical_count = severities.count("critical")
        high_count = severities.count("high")

        framework_coverage = {}
        for fw in self.frameworks:
            fw_mappings = [m for m in mappings if m.framework == fw]
            if fw_mappings:
                nc = sum(1 for m in fw_mappings if m.finding_status == "non-compliant")
                framework_coverage[fw.value] = {
                    "total_mapped": len(fw_mappings),
                    "non_compliant": nc,
                    "compliance_rate": (len(fw_mappings) - nc) / len(fw_mappings) * 100,
                }

        return {
            "total_findings": len(findings),
            "critical_findings": critical_count,
            "high_findings": high_count,
            "compliance_mappings": len(mappings),
            "non_compliant_count": sum(1 for m in mappings if m.finding_status == "non-compliant"),
            "framework_coverage": framework_coverage,
            "mean_time_to_remediate_target": "30 days",  # Configurable SLA
        }

    def _build_stakeholder_recommendations(
        self, mappings: List[ComplianceMapping]
    ) -> Dict[str, List[str]]:
        """Build stakeholder-specific recommendations."""
        non_compliant = [m for m in mappings if m.finding_status == "non-compliant"]

        return {
            "executives": [
                f"{len(non_compliant)} non-compliant findings require budget allocation for remediation.",
                "Review risk acceptance for findings exceeding SLA targets.",
                "Ensure board-level awareness of critical compliance gaps.",
            ],
            "security_team": [
                f"Prioritize {len([m for m in non_compliant if m.priority == 'critical'])} critical findings for immediate patching.",
                "Validate compensating controls for partial compliance items.",
                "Update vulnerability management metrics and trending.",
            ],
            "legal": [
                "Review regulatory reporting obligations for non-compliant findings.",
                "Assess breach notification requirements under GDPR/HIPAA if applicable.",
                "Document risk acceptance decisions with executive sign-off.",
            ],
            "operations": [
                "Schedule maintenance windows for patching critical findings.",
                "Test configuration changes in staging before production deployment.",
                "Monitor system stability during remediation activities.",
            ],
            "development": [
                "Apply secure coding guidelines to prevent recurrence of identified bug classes.",
                "Implement automated security testing in CI/CD pipeline.",
                "Conduct code review for all changes to security-critical components.",
            ],
        }
