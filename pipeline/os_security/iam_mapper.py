"""
IAM Security Mapper — Common IAM Concepts (CySA+ Domain 1)

Maps identity and access management concepts to D3FEND defensive techniques:
- Multifactor Authentication (MFA)
- Single Sign-On (SSO) / Federation
- Privileged Access Management (PAM)
- Passwordless Authentication
- Cloud Access Security Broker (CASB)
"""
import logging
from typing import Dict, List, Any
from enum import Enum

logger = logging.getLogger(__name__)


class IAMConcept(Enum):
    """IAM security concepts."""
    MFA = "multifactor_authentication"
    SSO = "single_sign_on"
    FEDERATION = "federation"
    PAM = "privileged_access_management"
    PASSWORDLESS = "passwordless"
    CASB = "cloud_access_security_broker"


class IAMMapper:
    """
    Maps IAM concepts to D3FEND techniques and security controls.
    """

    IAM_D3FEND = {
        IAMConcept.MFA: {
            "techniques": ["D3-MFA", "D3-AH"],
            "description": "Require two or more pieces of evidence to authenticate a user",
            "risks_without": [
                "Credential stuffing attacks",
                "Phishing-based credential theft",
                "Brute force password attacks",
            ],
            "implementation": [
                "TOTP authenticator apps (D3-MFA)",
                "Hardware tokens / FIDO2 keys (D3-MFA, D3-CBAN)",
                "Biometric verification (D3-BAN)",
                "SMS/Email OTP as fallback (D3-OTP)",
            ],
            "detection": [
                "Monitor for MFA bypass attempts (D3-PA)",
                "Alert on impossible travel / anomalous MFA locations (D3-NTA)",
            ],
        },
        IAMConcept.SSO: {
            "techniques": ["D3-TBA", "D3-AH", "D3-CP"],
            "description": "Enables user to login to multiple apps in the same domain",
            "risks_without": [
                "Password fatigue leading to credential reuse",
                "Shadow IT with unsanctioned app accounts",
            ],
            "security_considerations": [
                "Token binding to prevent session hijacking (D3-TB)",
                "Certificate pinning for SSO provider (D3-CP)",
                "Session timeout and re-authentication (D3-AH)",
                "Audit token issuance and validation (D3-PA)",
            ],
            "attack_vectors": [
                "Golden SAML attack — forged SAML assertions",
                "Token theft via XSS or malware",
                "SSO provider compromise (single point of failure)",
            ],
            "d3fend_mitigations": [
                "Token-based authentication with binding (D3-TBA, D3-TB)",
                "Application hardening against XSS (D3-AH)",
                "Process auditing of token lifecycle (D3-PA)",
            ],
        },
        IAMConcept.FEDERATION: {
            "techniques": ["D3-TBA", "D3-CBAN", "D3-AH"],
            "description": "Enables user login across multiple domains via Identity Providers (IdP)",
            "providers": ["Okta", "OpenID Connect", "Azure AD", "Google Identity"],
            "risks": [
                "IdP compromise affects all federated SPs",
                "Federation metadata poisoning",
                "Cross-domain trust abuse",
            ],
            "d3fend_mitigations": [
                "Certificate-based authentication for IdP-SP channels (D3-CBAN)",
                "Token binding to prevent replay (D3-TB)",
                "Access policy administration for cross-domain (D3-APA, D3F-UGPH)",
                "Network traffic analysis for anomalous federation flows (D3-NTA)",
            ],
        },
        IAMConcept.PAM: {
            "techniques": ["D3-UAP", "D3-UGPH", "D3-APA", "D3-EI", "D3-CRO"],
            "description": "Comprehensive approach to privileged access — control, audit, monitor all privileged identities",
            "identities": [
                "Human: Root/Admin (domain, local)",
                "Human: SSH key holders",
                "Non-Human: Service accounts",
                "Non-Human: API keys",
            ],
            "controls": [
                "Mandatory key/secrets rotation (D3-CRO, D3-PR, D3-CERO)",
                "Isolate sensitive assets with execution isolation (D3-EI, D3-KBPI)",
                "Enable MFA for all privileged access (D3-MFA)",
                "Just-in-time (JIT) access elevation (D3-APA, D3-UAP)",
                "Session recording and monitoring (D3-PA, D3-RTSD)",
                "Credential vaulting with rotation (D3-CS, D3-CRO)",
            ],
            "detection": [
                "Monitor privileged command execution (D3-PA)",
                "Alert on privilege escalation attempts (D3-NTA)",
                "Detect anomalous off-hours admin activity (D3-PMAD)",
                "Track credential rotation compliance (D3-CRO)",
            ],
            "attack_vectors": [
                "Pass-the-hash / pass-the-ticket",
                "Kerberoasting (TGS-REP attack)",
                "Service account credential theft",
                "Privilege escalation via misconfigured ACLs",
            ],
        },
        IAMConcept.PASSWORDLESS: {
            "techniques": ["D3-BAN", "D3-TBA", "D3-CBAN"],
            "description": "Replace passwords with possession factors, magic links, or biometrics",
            "factors": {
                "possession": [
                    "Authenticator apps (TOTP)",
                    "Hardware tokens (YubiKey, FIDO2)",
                    "SMS/Email OTP",
                ],
                "biometric": [
                    "Fingerprint (D3-BAN)",
                    "Facial recognition",
                    "Iris/retina scan",
                ],
                "magic_links": [
                    "One-time email links",
                    "Push notification approval",
                ],
            },
            "risks": [
                "Device theft leading to possession factor compromise",
                "Biometric spoofing (fingerprint molds, deepfakes)",
                "Magic link interception via email compromise",
            ],
            "d3fend_mitigations": [
                "Biometric authentication with liveness detection (D3-BAN)",
                "Token-based authentication with binding (D3-TBA, D3-TB)",
                "Certificate-based device attestation (D3-CBAN)",
                "Multi-device registration for redundancy",
            ],
        },
        IAMConcept.CASB: {
            "techniques": ["D3-NTA", "D3-PA", "D3-CNS", "D3-FE", "D3-ET"],
            "description": "Cloud Access Security Broker — applies security controls to 3rd-party cloud services",
            "pillars": {
                "visibility": {
                    "description": "Who/What/When/Where/Why/How are cloud services used",
                    "techniques": ["D3-NTA", "D3-PA", "D3-DNSTA"],
                    "capabilities": [
                        "Shadow IT discovery",
                        "Cloud app usage analytics",
                        "User behavior monitoring",
                    ],
                },
                "compliance": {
                    "description": "Built-in regulatory compliance for cloud usage",
                    "techniques": ["D3-PA", "D3-DI", "D3-CI"],
                    "capabilities": [
                        "GDPR data residency enforcement",
                        "HIPAA audit trail generation",
                        "PCI-DSS scope reduction",
                    ],
                },
                "data_security": {
                    "description": "Encryption and DLP for cloud data",
                    "techniques": ["D3-FE", "D3-ET", "D3-DENCR", "D3-MENCR"],
                    "capabilities": [
                        "Cloud data encryption at rest",
                        "Encrypted tunnels for data in transit",
                        "DLP policy enforcement",
                        "Content substitution/redaction (D3-CNS)",
                    ],
                },
                "threat_protection": {
                    "description": "UEBA and malware detection for cloud",
                    "techniques": ["D3-NTA", "D3-PMAD", "D3-ANAA"],
                    "capabilities": [
                        "User and Entity Behavior Analytics (UEBA)",
                        "Malware detection in cloud uploads",
                        "Configuration auditing (CSPM)",
                        "Anomalous access pattern detection",
                    ],
                },
            },
            "granular_controls": [
                "Device connections (BYOD) — D3-APA, D3-UGPH",
                "Cloud apps (M365, GSuite) — D3-NTA, D3-APCA",
                "Data sharing and DLP — D3-FE, D3-CNS",
            ],
        },
    }

    # Common IAM attack patterns → D3FEND
    IAM_ATTACK_PATTERNS = {
        "credential_stuffing": {
            "description": "Automated login attempts with stolen credentials",
            "detection": ["D3-PA", "D3-NTA", "D3-ISVA"],
            "mitigation": ["D3-MFA", "D3-AH", "D3-AL"],
        },
        "privilege_escalation": {
            "description": "Elevating from standard user to admin/root",
            "detection": ["D3-PA", "D3-NTA", "D3-ANAA"],
            "mitigation": ["D3-UAP", "D3-APA", "D3-EI"],
        },
        "session_hijacking": {
            "description": "Stealing or replaying valid session tokens",
            "detection": ["D3-NTA", "D3-RTSD"],
            "mitigation": ["D3-TB", "D3-CP", "D3-TBA"],
        },
        "identity_spoofing": {
            "description": "Impersonating a legitimate user or service account",
            "detection": ["D3-PA", "D3-PMAD"],
            "mitigation": ["D3-MFA", "D3-CBAN", "D3-BAN"],
        },
    }

    @classmethod
    def get_iam_concept(cls, concept: IAMConcept) -> Dict[str, Any]:
        """Get D3FEND techniques and controls for an IAM concept."""
        return cls.IAM_D3FEND.get(concept, {})

    @classmethod
    def get_attack_pattern_defense(cls, pattern: str) -> Dict[str, Any]:
        """Get detection and mitigation for an IAM attack pattern."""
        return cls.IAM_ATTACK_PATTERNS.get(pattern, {})

    @classmethod
    def get_all_iam_techniques(cls) -> List[str]:
        """Get all D3FEND techniques relevant to IAM security."""
        techniques = set()
        for data in cls.IAM_D3FEND.values():
            techniques.update(data.get("techniques", []))
        return sorted(list(techniques))

    @classmethod
    def get_pam_controls_for_identity(cls, identity_type: str) -> List[str]:
        """Get PAM controls for a specific identity type."""
        pam = cls.IAM_D3FEND.get(IAMConcept.PAM, {})
        controls = pam.get("controls", [])

        if identity_type in ("root", "admin", "domain_admin"):
            return controls  # All controls apply
        elif identity_type == "service_account":
            return [c for c in controls if "credential" in c.lower() or "vault" in c.lower()]
        elif identity_type == "api_key":
            return [c for c in controls if "rotation" in c.lower() or "vault" in c.lower()]
        return controls
