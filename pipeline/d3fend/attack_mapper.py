"""
MITRE ATT&CK technique mapper for the pipeline.

Maps vulnerability findings to ATT&CK offensive techniques to enrich
exposure scoring with real-world threat actor context.
"""
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)


class ATTACKMapper:
    """Map pipeline findings to MITRE ATT&CK offensive techniques."""

    def __init__(self):
        """Initialize ATT&CK mapper with fallback technique data."""
        self.techniques = self._load_fallback_techniques()
        self.bug_class_to_attack = self._build_bug_class_mappings()
        self.cwe_to_attack = self._build_cwe_mappings()
        logger.info("ATTACKMapper initialized with %d techniques", len(self.techniques))

    def _load_fallback_techniques(self) -> Dict[str, Dict[str, Any]]:
        """Load fallback ATT&CK enterprise technique data."""
        return {
            "T1203": {
                "name": "Exploitation for Client Execution",
                "tactic": "Execution",
                "description": "Adversaries may exploit software vulnerabilities in client applications to execute code."
            },
            "T1068": {
                "name": "Exploitation for Privilege Escalation",
                "tactic": "Privilege Escalation",
                "description": "Adversaries may exploit software vulnerabilities in an attempt to elevate privileges."
            },
            "T1211": {
                "name": "Exploitation for Defense Evasion",
                "tactic": "Defense Evasion",
                "description": "Adversaries may exploit software vulnerabilities to evade detection."
            },
            "T1212": {
                "name": "Exploitation for Credential Access",
                "tactic": "Credential Access",
                "description": "Adversaries may exploit software vulnerabilities to access credentials."
            },
            "T1078": {
                "name": "Valid Accounts",
                "tactic": "Initial Access",
                "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access."
            },
            "T1552": {
                "name": "Unsecured Credentials",
                "tactic": "Credential Access",
                "description": "Adversaries may search compromised systems to find and obtain insecurely stored credentials."
            },
            "T1059": {
                "name": "Command and Scripting Interpreter",
                "tactic": "Execution",
                "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries."
            },
            "T1499": {
                "name": "Endpoint Denial of Service",
                "tactic": "Impact",
                "description": "Adversaries may perform endpoint denial of service to degrade or block availability of services."
            },
            "T1496": {
                "name": "Resource Exhaustion",
                "tactic": "Impact",
                "description": "Adversaries may adversaries may target the availability of resources by impacting their ability to process data."
            },
            "T1565": {
                "name": "Data Manipulation",
                "tactic": "Impact",
                "description": "Adversaries may insert, delete, or manipulate data in order to influence external outcomes."
            },
            "T1505": {
                "name": "Server Software Component",
                "tactic": "Persistence",
                "description": "Adversaries may abuse server software to establish persistence."
            },
            "T1190": {
                "name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "description": "Adversaries may attempt to exploit a weakness in an Internet-facing host or system."
            },
            "T1210": {
                "name": "Exploitation of Remote Services",
                "tactic": "Lateral Movement",
                "description": "Adversaries may exploit a remote service to gain unauthorized access to internal systems."
            },
            "T1550": {
                "name": "Use Alternate Authentication Material",
                "tactic": "Defense Evasion",
                "description": "Adversaries may use alternate authentication material to move laterally within a network."
            },
            "T1098": {
                "name": "Account Manipulation",
                "tactic": "Persistence",
                "description": "Adversaries may manipulate accounts to maintain access to victim systems."
            },
            "T1539": {
                "name": "Steal Web Session Cookie",
                "tactic": "Credential Access",
                "description": "Adversaries may steal web application or service session cookies to gain unauthorized access."
            },
            "T1040": {
                "name": "Network Sniffing",
                "tactic": "Credential Access",
                "description": "Adversaries may sniff network traffic to capture information passed between systems."
            },
            "T1595": {
                "name": "Active Scanning",
                "tactic": "Reconnaissance",
                "description": "Adversaries may execute active scans to identify vulnerable services and endpoints."
            }
        }

    def _build_bug_class_mappings(self) -> Dict[str, List[str]]:
        """Map bug classes to likely ATT&CK techniques."""
        return {
            "memory_corruption": ["T1203", "T1068", "T1211"],
            "integer_overflow": ["T1203", "T1068", "T1496"],
            "race_condition": ["T1203", "T1068", "T1565"],
            "auth_bypass": ["T1078", "T1552", "T1098", "T1550"],
            "deserialization": ["T1203", "T1059", "T1505"],
            "type_confusion": ["T1203", "T1211"],
            "signature_malleability": ["T1550", "T1078", "T1565"],
            "account_confusion": ["T1078", "T1098", "T1550"],
            "oracle_manipulation": ["T1565", "T1499"],
            "reentrancy": ["T1499", "T1565", "T1496"],
            "logic_error": ["T1203", "T1565", "T1499"]
        }

    def _build_cwe_mappings(self) -> Dict[str, List[str]]:
        """Map CWE IDs to likely ATT&CK techniques."""
        return {
            "CWE-119": ["T1203", "T1068"],
            "CWE-120": ["T1203", "T1068"],
            "CWE-121": ["T1203", "T1068"],
            "CWE-122": ["T1203", "T1068"],
            "CWE-125": ["T1203", "T1068", "T1211"],
            "CWE-190": ["T1203", "T1068", "T1496"],
            "CWE-191": ["T1203", "T1068", "T1496"],
            "CWE-362": ["T1203", "T1068", "T1565"],
            "CWE-367": ["T1203", "T1068", "T1565"],
            "CWE-20": ["T1203", "T1190", "T1210"],
            "CWE-78": ["T1059", "T1203"],
            "CWE-79": ["T1189", "T1190"],
            "CWE-89": ["T1190", "T1098"],
            "CWE-94": ["T1059", "T1203"],
            "CWE-287": ["T1078", "T1552", "T1550"],
            "CWE-306": ["T1078", "T1098"],
            "CWE-352": ["T1189", "T1098"],
            "CWE-400": ["T1499", "T1496"],
            "CWE-502": ["T1203", "T1059", "T1505"],
            "CWE-522": ["T1552", "T1078"],
            "CWE-732": ["T1098", "T1078"],
            "CWE-798": ["T1552", "T1078"],
            "CWE-918": ["T1190", "T1210"],
            "CWE-476": ["T1203", "T1499"],
            "CWE-416": ["T1203", "T1068"],
            "CWE-772": ["T1499", "T1496"],
            "CWE-835": ["T1499", "T1496"],
        }

    def get_technique(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific ATT&CK technique by ID."""
        tech = self.techniques.get(technique_id)
        if not tech:
            return None
        return {
            "id": technique_id,
            "name": tech["name"],
            "tactic": tech["tactic"],
            "description": tech["description"],
            "url": f"https://attack.mitre.org/techniques/{technique_id}/"
        }

    def map_bug_class(self, bug_class: str) -> List[Dict[str, Any]]:
        """
        Map a bug class to ATT&CK techniques.

        Args:
            bug_class: Bug class string (e.g., "memory_corruption")

        Returns:
            List of ATT&CK technique dictionaries
        """
        technique_ids = self.bug_class_to_attack.get(bug_class.lower(), [])
        return [self.get_technique(tid) for tid in technique_ids if self.get_technique(tid)]

    def map_cwe(self, cwe_id: Optional[str]) -> List[Dict[str, Any]]:
        """
        Map a CWE ID to ATT&CK techniques.

        Args:
            cwe_id: CWE identifier (e.g., "CWE-119")

        Returns:
            List of ATT&CK technique dictionaries
        """
        if not cwe_id:
            return []
        technique_ids = self.cwe_to_attack.get(cwe_id.upper(), [])
        return [self.get_technique(tid) for tid in technique_ids if self.get_technique(tid)]

    def enrich_finding(
        self,
        bug_class: str,
        cwe_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Enrich a finding with ATT&CK offensive context.

        Args:
            bug_class: Bug class string
            cwe_id: Optional CWE identifier

        Returns:
            Enrichment result with techniques and threat narrative
        """
        attack_techniques = []

        # Map by bug class
        class_techniques = self.map_bug_class(bug_class)
        attack_techniques.extend(class_techniques)

        # Map by CWE
        if cwe_id:
            cwe_techniques = self.map_cwe(cwe_id)
            # Merge without duplicates
            existing_ids = {t["id"] for t in attack_techniques}
            for tech in cwe_techniques:
                if tech["id"] not in existing_ids:
                    attack_techniques.append(tech)

        # Generate threat narrative
        narrative = self._generate_threat_narrative(bug_class, attack_techniques)

        return {
            "attack_techniques": attack_techniques,
            "threat_narrative": narrative,
            "offensive_tactics": list({t["tactic"] for t in attack_techniques}),
            "threat_actor_likelihood": self._estimate_threat_actor_likelihood(
                bug_class, len(attack_techniques)
            )
        }

    def _generate_threat_narrative(
        self,
        bug_class: str,
        techniques: List[Dict[str, Any]]
    ) -> str:
        """Generate a threat narrative based on bug class and techniques."""
        if not techniques:
            return f"No known ATT&CK mapping for {bug_class}. Monitor for anomalous behavior."

        tactic_summary = ", ".join({t["tactic"] for t in techniques[:3]})
        tech_names = ", ".join([f"{t['id']} ({t['name']})" for t in techniques[:3]])

        return (
            f"A {bug_class.replace('_', ' ')} vulnerability may be exploited via "
            f"ATT&CK techniques: {tech_names}. "
            f"Relevant tactics: {tactic_summary}. "
            f"Threat actors commonly chain these techniques to achieve objectives."
        )

    def _estimate_threat_actor_likelihood(
        self,
        bug_class: str,
        technique_count: int
    ) -> str:
        """Estimate likelihood of real-world threat actor exploitation."""
        high_likelihood_classes = {
            "memory_corruption", "auth_bypass", "deserialization",
            "reentrancy", "oracle_manipulation"
        }

        if bug_class.lower() in high_likelihood_classes and technique_count >= 2:
            return "HIGH"
        elif technique_count >= 2:
            return "MEDIUM"
        elif technique_count >= 1:
            return "LOW"
        return "UNKNOWN"

    def get_all_techniques(self) -> List[Dict[str, Any]]:
        """Get all available ATT&CK techniques."""
        return [
            self.get_technique(tid)
            for tid in self.techniques
            if self.get_technique(tid)
        ]
