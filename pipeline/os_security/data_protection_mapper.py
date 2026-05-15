"""
Data Protection Mapper — Protecting Sensitive Data (CySA+ Domain 1)

Maps data loss prevention (DLP), PII, and cardholder data (CHD) concepts
to D3FEND defensive techniques and Raven audit capabilities.
"""
import logging
from typing import Dict, List, Optional, Any, Set
from enum import Enum

logger = logging.getLogger(__name__)


class DataType(Enum):
    """Categories of sensitive data."""
    PII = "personally_identifiable_information"
    PHI = "protected_health_information"      # HIPAA
    CHD = "cardholder_data"                    # PCI-DSS
    PCI_SAD = "sensitive_authentication_data"  # CVV, PIN
    FINANCIAL = "financial_data"
    CREDENTIALS = "credentials"                # Passwords, API keys, tokens
    IP = "intellectual_property"
    CUSTOMER_DATA = "customer_data"


class DLPPolicyAction(Enum):
    """DLP policy enforcement actions."""
    BLOCK = "block"
    ALLOW = "allow"
    QUARANTINE = "quarantine"
    AUDIT = "audit"
    NOTIFY = "notify"
    ENCRYPT = "encrypt"
    REDACT = "redact"


class DataProtectionMapper:
    """
    Maps data protection concepts to D3FEND techniques.
    """

    # Data types → D3FEND techniques for protection
    DATA_TYPE_D3FEND = {
        DataType.PII: {
            "description": "Information that can identify an individual (name, SSN, DOB, address, email, phone)",
            "techniques": ["D3-FE", "D3-DENCR", "D3-MENCR", "D3-CS", "D3-CNS", "D3-ET"],
            "regulations": ["GDPR", "CCPA", "PIPEDA", "LGPD"],
            "risks": [
                "Unauthorized collection or processing",
                "Data breach exposing customer records",
                "Cross-border transfer violations",
                "Insufficient anonymization/pseudonymization",
            ],
            "protection": [
                "Encrypt PII at rest (D3-FE, D3-DENCR)",
                "Encrypt PII in transit (D3-MENCR, D3-ET)",
                "Tokenization or pseudonymization (D3-CNS)",
                "Access control enforcement (D3-UAP, D3-UGPH)",
                "Audit access to PII stores (D3-PA, D3-DI)",
                "DLP for PII in email, cloud, endpoints (D3-CNE, D3-CNS)",
            ],
            "detection": [
                "Monitor database queries accessing PII columns (D3-PA)",
                "Alert on bulk PII exports (D3-PMAD)",
                "Network traffic analysis for PII exfiltration (D3-NTA)",
                "Content format conversion audit (D3-CFC)",
            ],
        },
        DataType.PHI: {
            "description": "Health information protected under HIPAA (medical records, diagnoses, treatment)",
            "techniques": ["D3-FE", "D3-DENCR", "D3-MENCR", "D3-ET", "D3-APA"],
            "regulations": ["HIPAA"],
            "risks": [
                "Unauthorized access by healthcare staff",
                "Data breach exposing patient records",
                "Insider snooping (celebrity records, neighbors)",
            ],
            "protection": [
                "Role-based access control for EHR systems (D3-APA, D3-UAP)",
                "Encryption of PHI at rest and in transit (D3-FE, D3-MENCR, D3-ET)",
                "Audit logging of all PHI access (D3-PA, D3-DI)",
                "DLP to prevent PHI leakage via email/cloud (D3-CNE, D3-CNS)",
            ],
            "detection": [
                "Break-glass access alerts (D3-PA, D3-ANAA)",
                "Anomalous query patterns on PHI databases (D3-PMAD)",
                "After-hours PHI access (D3-NTA)",
            ],
        },
        DataType.CHD: {
            "description": "Primary account number (PAN) — cardholder data under PCI-DSS",
            "techniques": ["D3-FE", "D3-DENCR", "D3-MENCR", "D3-ET", "D3-CS"],
            "regulations": ["PCI-DSS"],
            "risks": [
                "PAN stored unencrypted in logs or databases",
                "Payment card skimming (Magecart-style attacks)",
                "Memory scraping of CHD from payment applications",
            ],
            "protection": [
                "Encrypt PAN at rest (AES-256) (D3-FE, D3-DENCR)",
                "Encrypt PAN in transit (TLS 1.2+) (D3-MENCR, D3-ET)",
                "Tokenization — replace PAN with non-sensitive token (D3-CNS)",
                "Remove CHD from logs (D3-CS)",
                "Network segmentation for payment systems (D3-NI, D3-ITF)",
                "Application hardening of payment endpoints (D3-AH)",
            ],
            "detection": [
                "Monitor for PAN patterns in logs and traffic (D3-FC, D3-NTA)",
                "Alert on unauthorized access to card data environment (D3-PA)",
                "Detect memory scraping behavior (D3-PMAD)",
            ],
        },
        DataType.PCI_SAD: {
            "description": "Sensitive authentication data: CVV, PIN, magnetic stripe data",
            "techniques": ["D3-CS", "D3-FE", "D3-DENCR"],
            "regulations": ["PCI-DSS"],
            "note": "PCI-DSS prohibits storing SAD after authorization — even encrypted",
            "protection": [
                "Never store SAD post-authorization (D3-CS)",
                "Secure deletion of SAD from memory (D3-RN)",
                "Hardware Security Module (HSM) for PIN encryption (D3-PEH)",
            ],
            "detection": [
                "Monitor for SAD in storage (D3-PA, D3-FC)",
                "Alert on unauthorized SAD access attempts (D3-NTA)",
            ],
        },
        DataType.CREDENTIALS: {
            "description": "Passwords, API keys, tokens, certificates, secrets",
            "techniques": ["D3-CS", "D3-FE", "D3-CH", "D3-CRO"],
            "risks": [
                "Hardcoded secrets in source code",
                "Secrets in environment variables or config files",
                "Leaked via logs or error messages",
                "Credential stuffing using stolen passwords",
            ],
            "protection": [
                "Credential scrubbing from source code (D3-CS)",
                "Secrets vault (HashiCorp Vault, AWS Secrets Manager) (D3-FE, D3-CH)",
                "Automated secret rotation (D3-CRO, D3-PR, D3-CERO)",
                "Environment isolation for secrets (D3-EI)",
                "Audit secret access (D3-PA, D3-DI)",
            ],
            "detection": [
                "Static analysis for hardcoded secrets (D3-CS, D3-CIA)",
                "Monitor for secret exfiltration in logs (D3-PA, D3-NTA)",
                "Alert on unauthorized secret access (D3-ANAA)",
            ],
        },
        DataType.FINANCIAL: {
            "description": "Bank account numbers, routing numbers, transaction data",
            "techniques": ["D3-FE", "D3-DENCR", "D3-MENCR", "D3-ET"],
            "protection": [
                "Encrypt financial data at rest (D3-FE, D3-DENCR)",
                "TLS for all financial transactions (D3-MENCR, D3-ET)",
                "DLP for financial document sharing (D3-CNE, D3-CNS)",
            ],
        },
        DataType.IP: {
            "description": "Source code, patents, trade secrets, proprietary algorithms",
            "techniques": ["D3-FE", "D3-DENCR", "D3-APA", "D3-UAP"],
            "protection": [
                "Encryption of source code repositories (D3-FE)",
                "Access control for IP repositories (D3-APA, D3-UAP)",
                "DLP to prevent source code exfiltration (D3-CNE, D3-CNS)",
                "Audit access to IP stores (D3-PA, D3-DI)",
            ],
        },
    }

    # DLP policy actions → D3FEND techniques
    DLP_ACTION_D3FEND = {
        DLPPolicyAction.BLOCK: {
            "description": "Prevent data transfer entirely",
            "techniques": ["D3-EDL", "D3-NTF", "D3-OTF", "D3-ITF"],
            "use_case": "Block USB transfers, block email with PII attachments",
        },
        DLPPolicyAction.QUARANTINE: {
            "description": "Isolate suspicious data for review",
            "techniques": ["D3-EI", "D3-NI"],
            "use_case": "Quarantine files with suspected PII for admin review",
        },
        DLPPolicyAction.ENCRYPT: {
            "description": "Encrypt data before allowing transfer",
            "techniques": ["D3-FE", "D3-MENCR", "D3-ET"],
            "use_case": "Encrypt email attachments containing CHD",
        },
        DLPPolicyAction.REDACT: {
            "description": "Remove or mask sensitive content",
            "techniques": ["D3-CNE", "D3-CNS"],
            "use_case": "Redact SSN from documents before sharing",
        },
        DLPPolicyAction.AUDIT: {
            "description": "Log data transfer for compliance",
            "techniques": ["D3-PA", "D3-DI"],
            "use_case": "Log all CHD access for PCI-DSS audit trail",
        },
        DLPPolicyAction.NOTIFY: {
            "description": "Alert user/admin about policy violation",
            "techniques": ["D3-PA", "D3-NTA"],
            "use_case": "Notify security team when PII detected in outbound email",
        },
    }

    # Data protection attack patterns → D3FEND
    DATA_ATTACK_PATTERNS = {
        "data_exfiltration": {
            "description": "Unauthorized transfer of sensitive data outside the organization",
            "detection": ["D3-NTA", "D3-PMAD", "D3-PHDURA", "D3-CAA"],
            "mitigation": ["D3-NTF", "D3-OTF", "D3-EDL", "D3-DNSDL", "D3-ET"],
        },
        "insider_data_theft": {
            "description": "Authorized user abusing access to steal data",
            "detection": ["D3-PA", "D3-PMAD", "D3-ANAA", "D3-NTCD"],
            "mitigation": ["D3-UAP", "D3-APA", "D3-EI", "D3-FE"],
        },
        "shadow_it_data_leak": {
            "description": "Employees using unsanctioned cloud apps for sensitive data",
            "detection": ["D3-NTA", "D3-DNSTA", "D3-PMAD"],
            "mitigation": ["D3-DNSAL", "D3-DNSDL", "D3-APA"],
        },
        "insecure_data_storage": {
            "description": "Sensitive data stored unencrypted or in public buckets",
            "detection": ["D3-PA", "D3-DI", "D3-AVE"],
            "mitigation": ["D3-FE", "D3-DENCR", "D3-SCP", "D3-UAP"],
        },
        "supply_chain_data_exposure": {
            "description": "Third-party vendor exposes customer data",
            "detection": ["D3-NTA", "D3-CAA"],
            "mitigation": ["D3-ET", "D3-MENCR", "D3-APA"],
        },
    }

    @classmethod
    def get_data_type_protection(cls, data_type: DataType) -> Dict[str, Any]:
        """Get D3FEND techniques and controls for a data type."""
        return cls.DATA_TYPE_D3FEND.get(data_type, {})

    @classmethod
    def get_dlp_action(cls, action: DLPPolicyAction) -> Dict[str, Any]:
        """Get D3FEND mapping for a DLP policy action."""
        return cls.DLP_ACTION_D3FEND.get(action, {})

    @classmethod
    def get_data_attack_defense(cls, attack: str) -> Dict[str, Any]:
        """Get detection and mitigation for a data protection attack."""
        return cls.DATA_ATTACK_PATTERNS.get(attack, {})

    @classmethod
    def get_all_data_protection_techniques(cls) -> List[str]:
        """Get all D3FEND techniques relevant to data protection."""
        techniques = set()
        for data in cls.DATA_TYPE_D3FEND.values():
            techniques.update(data.get("techniques", []))
        for data in cls.DLP_ACTION_D3FEND.values():
            techniques.update(data.get("techniques", []))
        return sorted(list(techniques))

    @classmethod
    def detect_sensitive_data_in_code(
        cls,
        code: str,
        language: str = "python",
    ) -> List[Dict[str, Any]]:
        """
        Detect potential sensitive data exposure in source code.

        Args:
            code: Source code string to analyze
            language: Programming language

        Returns:
            List of findings with data type, location pattern, and recommendation
        """
        findings = []

        # Pattern definitions for common exposures
        patterns = {
            DataType.CREDENTIALS: [
                (r'password\s*=\s*["\'][^"\']+["\']', "Hardcoded password"),
                (r'api_key\s*=\s*["\'][^"\']+["\']', "Hardcoded API key"),
                (r'secret\s*=\s*["\'][^"\']+["\']', "Hardcoded secret"),
                (r'AWS_ACCESS_KEY_ID\s*=\s*["\'][^"\']+["\']', "AWS access key"),
                (r'AKIA[0-9A-Z]{16}', "AWS access key ID pattern"),
                (r'ghp_[a-zA-Z0-9]{36}', "GitHub personal access token"),
            ],
            DataType.PII: [
                (r'\b\d{3}-\d{2}-\d{4}\b', "SSN pattern"),
                (r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', "Credit card number"),
                (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', "Email address"),
            ],
            DataType.CHD: [
                (r'\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', "Visa card number"),
                (r'\b5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', "Mastercard number"),
            ],
        }

        import re
        for data_type, type_patterns in patterns.items():
            for pattern, description in type_patterns:
                for match in re.finditer(pattern, code):
                    findings.append({
                        "data_type": data_type.value,
                        "description": description,
                        "pattern": pattern,
                        "position": (match.start(), match.end()),
                        "d3fend_recommendation": cls._get_recommendation_for_data_type(data_type),
                        "severity": "critical" if data_type == DataType.CREDENTIALS else "high",
                    })

        return findings

    @classmethod
    def _get_recommendation_for_data_type(cls, data_type: DataType) -> str:
        """Get D3FEND recommendation for a detected data type."""
        recommendations = {
            DataType.CREDENTIALS: "D3-CS: Remove hardcoded secret; use secrets vault (D3-FE, D3-CH)",
            DataType.PII: "D3-CNS: Pseudonymize/encrypt PII; D3-CS: Remove from code",
            DataType.CHD: "D3-CS: Remove CHD from code; use tokenization (D3-CNS)",
        }
        return recommendations.get(data_type, "Review and remove sensitive data")

    @classmethod
    def build_dlp_policy(
        cls,
        data_types: List[DataType],
        locations: List[str],  # e.g., ["email", "usb", "cloud", "web_upload"]
        action: DLPPolicyAction = DLPPolicyAction.BLOCK,
    ) -> Dict[str, Any]:
        """
        Build a DLP policy with D3FEND technique mapping.

        Args:
            data_types: Types of data to protect
            locations: Where to enforce the policy
            action: Enforcement action

        Returns:
            Policy definition with D3FEND techniques
        """
        action_info = cls.get_dlp_action(action)
        techniques = set(action_info.get("techniques", []))

        for dt in data_types:
            dt_info = cls.get_data_type_protection(dt)
            techniques.update(dt_info.get("techniques", []))

        return {
            "policy_name": f"DLP-{action.value}-{'-'.join(dt.value for dt in data_types)}",
            "data_types": [dt.value for dt in data_types],
            "locations": locations,
            "action": action.value,
            "d3fend_techniques": sorted(list(techniques)),
            "description": action_info.get("description", ""),
            "use_case": action_info.get("use_case", ""),
        }
