"""
Cryptography & PKI Security Mapper — Common Encryption Concepts (CySA+ Domain 1)

Maps PKI components, certificate lifecycle, and SSL inspection to D3FEND
defensive techniques and Raven audit capabilities.

Covers:
- Public Key Infrastructure (PKI) components and process
- Certificate Authorities (CA), Registration Authorities (RA), Validation Authorities (VA)
- Digital certificates, CRL, OCSP
- SSL/TLS inspection (NGFW, proxy, TAP)
- Self-signed vs trusted CA certificates
"""
import logging
from typing import Dict, List, Optional, Any
from enum import Enum

logger = logging.getLogger(__name__)


class PKIComponent(Enum):
    """PKI infrastructure components."""
    CA = "certificate_authority"
    RA = "registration_authority"
    VA = "validation_authority"
    CMS = "certificate_management_system"
    END_USER = "end_user"


class CertType(Enum):
    """Certificate types by trust model."""
    TRUSTED_CA = "trusted_ca_signed"      # Signed by public trusted CA
    PRIVATE_CA = "private_ca_signed"      # Signed by internal/private CA
    SELF_SIGNED = "self_signed"           # Subject == issuer


class SSLInspectionType(Enum):
    """SSL/TLS inspection deployment types."""
    NGFW = "next_gen_firewall"
    PROXY = "ssl_proxy"
    TAP = "network_tap"


class CryptoMapper:
    """
    Maps PKI, certificate, and SSL inspection concepts to D3FEND techniques.
    """

    # PKI Components → D3FEND techniques
    PKI_COMPONENT_D3FEND = {
        PKIComponent.CA: {
            "role": "Issues, validates, revokes, and deletes digital certificates",
            "techniques": ["D3-CBAN", "D3-CP", "D3-CERO"],
            "risks": [
                "CA private key compromise — can issue rogue certs for any domain",
                "Weak CA signing algorithms (SHA-1, RSA-1024)",
                "Insufficient CA/Browser Forum compliance",
                "Certificate mis-issuance via domain validation bypass",
            ],
            "hardening": [
                "Hardware Security Module (HSM) for CA private key (D3-PEH)",
                "Certificate pinning for high-value certs (D3-CP)",
                "Regular CA certificate rotation (D3-CERO)",
                "Monitor for unauthorized certificate issuance (D3-PA)",
                "Certificate Transparency (CT) log monitoring (D3-PA, D3-DNSTA)",
            ],
            "d3fend_mitigations": [
                "Certificate-based authentication enforcement (D3-CBAN)",
                "Certificate pinning in clients (D3-CP)",
                "Automated certificate rotation (D3-CERO)",
                "Process auditing of CA operations (D3-PA)",
            ],
        },
        PKIComponent.RA: {
            "role": "Pre-screens certificate signing requests, verifies subject identity",
            "techniques": ["D3-AM", "D3-AH"],
            "risks": [
                "RA compromise allows fraudulent certificate requests",
                "Weak identity verification (email-only domain validation)",
                "Insider threat at RA approving malicious requests",
            ],
            "hardening": [
                "Multi-person control for certificate approval (D3-UGPH)",
                "Strong authentication for RA operators (D3-MFA)",
                "Audit all RA approval decisions (D3-PA)",
                "Automated identity verification with document checks",
            ],
            "d3fend_mitigations": [
                "Access modeling and role separation (D3-AM)",
                "Application hardening for RA portal (D3-AH)",
                "Multi-factor authentication for RA access (D3-MFA)",
            ],
        },
        PKIComponent.VA: {
            "role": "Validates digital certificates via CRL and OCSP responses",
            "techniques": ["D3-DNSDL", "D3-PA"],
            "risks": [
                "VA unavailability causes application outages (soft-fail vs hard-fail)",
                "OCSP stapling misconfiguration",
                "CRL distribution point unavailability",
                "Replay attacks on OCSP responses",
            ],
            "hardening": [
                "OCSP stapling on servers (reduces VA load, improves privacy)",
                "CRL caching with fallback to OCSP",
                "Monitor VA/OCSP responder availability (D3-PA)",
                "OCSP response signing with short validity windows",
            ],
            "d3fend_mitigations": [
                "DNS denylisting of revoked cert domains (D3-DNSDL)",
                "Process auditing of validation queries (D3-PA)",
                "Network traffic analysis for anomalous validation patterns (D3-NTA)",
            ],
        },
        PKIComponent.CMS: {
            "role": "Software that creates, distributes, stores, and verifies certificates",
            "techniques": ["D3-SWI", "D3-CI", "D3-AVE"],
            "risks": [
                "CMS software vulnerability leading to cert manipulation",
                "Unauthorized certificate store access",
                "Weak key generation in CMS",
            ],
            "hardening": [
                "Software inventory and vulnerability scanning (D3-SWI, D3-AVE)",
                "Configuration inventory for CMS settings (D3-CI)",
                "Regular CMS patching and updates (D3-SU)",
            ],
        },
        PKIComponent.END_USER: {
            "role": "Requests, manages, and uses certificates for authentication/encryption",
            "techniques": ["D3-FE", "D3-MENCR"],
            "risks": [
                "Private key theft or loss",
                "Certificate expiration causing outages",
                "Social engineering to request fraudulent certs",
            ],
            "hardening": [
                "Secure key storage (TPM, smart card, HSM) (D3-FE)",
                "Automated certificate renewal before expiry (D3-SU)",
                "User education on certificate handling",
            ],
        },
    }

    # Certificate trust model → D3FEND
    CERT_TRUST_D3FEND = {
        CertType.TRUSTED_CA: {
            "trust_level": "High — validated by public trust store",
            "techniques": ["D3-CP", "D3-CBAN"],
            "validation": "Browser/OS trust store + Certificate Transparency logs",
            "risks": [
                "Compromised public CA (DigiNotar incident)",
                "Government-mandated certificate interception",
            ],
        },
        CertType.PRIVATE_CA: {
            "trust_level": "Medium — organization-controlled trust",
            "techniques": ["D3-CP", "D3-CBAN", "D3-APA"],
            "validation": "Internal trust store + CRL/OCSP",
            "risks": [
                "Shadow CA without proper governance",
                "Certificate scope creep (wildcard certs everywhere)",
            ],
            "hardening": [
                "Access policy administration for CA operators (D3-APA)",
                "Certificate pinning for critical internal services (D3-CP)",
            ],
        },
        CertType.SELF_SIGNED: {
            "trust_level": "Low — no third-party validation",
            "techniques": ["D3-CP", "D3-AH"],
            "validation": "Manual trust decision by user/admin",
            "risks": [
                "Man-in-the-middle with spoofed self-signed cert",
                "Users trained to click through warnings",
                "No revocation mechanism",
            ],
            "d3fend_mitigations": [
                "Certificate pinning if self-signed is unavoidable (D3-CP)",
                "Application hardening to reject self-signed in production (D3-AH)",
                "Network traffic analysis to detect unexpected self-signed certs (D3-NTA)",
            ],
        },
    }

    # SSL Inspection → D3FEND
    SSL_INSPECTION_D3FEND = {
        SSLInspectionType.NGFW: {
            "description": "Next-Gen Firewall decrypts, inspects, re-encrypts traffic",
            "techniques": ["D3-NTA", "D3-FC", "D3-ET"],
            "risks": [
                "Decryption key compromise on NGFW",
                "Privacy violations (inspecting personal/health data)",
                "Certificate mismatch alerts causing user confusion",
                "Performance bottleneck from full TLS decryption",
            ],
            "hardening": [
                "Selective decryption policies (financial, health exempt) (D3-ET)",
                "Hardware acceleration for TLS operations (D3-PEH)",
                "Audit all decryption events (D3-PA)",
                "Encrypted tunnels for management traffic (D3-ET)",
            ],
            "d3fend_mitigations": [
                "Network traffic analysis for decrypted flows (D3-NTA)",
                "File carving for malware in decrypted traffic (D3-FC)",
                "Protocol metadata anomaly detection (D3-PMAD)",
            ],
        },
        SSLInspectionType.PROXY: {
            "description": "Dedicated SSL proxy for traffic inspection",
            "techniques": ["D3-NTA", "D3-APCA", "D3-CSPP"],
            "risks": [
                "Proxy as single point of failure",
                "Incomplete certificate chain validation",
                "Session key exposure in proxy memory",
            ],
            "hardening": [
                "Application protocol command analysis (D3-APCA)",
                "Client-server payload profiling for anomalies (D3-CSPP)",
                "Process auditing of proxy operations (D3-PA)",
            ],
        },
        SSLInspectionType.TAP: {
            "description": "Network TAP passively copies traffic for out-of-band inspection",
            "techniques": ["D3-NTA", "D3-PLLM", "D3-FC"],
            "risks": [
                "Cannot decrypt without key material",
                "TAP device itself could be compromised",
                "Storage requirements for full packet capture",
            ],
            "advantages": [
                "No inline device — no latency impact",
                "Cannot be bypassed by attacker (passive)",
                "Legally admissible if chain of custody maintained",
            ],
            "d3fend_mitigations": [
                "Passive logical link mapping for traffic analysis (D3-PLLM)",
                "Network traffic analysis on captured flows (D3-NTA)",
                "File carving from reassembled streams (D3-FC)",
            ],
        },
    }

    # PKI Process steps → security controls
    PKI_PROCESS_CONTROLS = {
        1: {  # Subject applies for cert from RA
            "step": "Subject applies for cert",
            "controls": ["D3-AM", "D3-AH"],
            "validation": "Strong identity verification before CSR acceptance",
        },
        2: {  # RA processes request
            "step": "RA verifies subject identity",
            "controls": ["D3-AM", "D3-MFA", "D3-PA"],
            "validation": "Multi-factor identity proofing, audit trail of verification",
        },
        3: {  # CA issues cert
            "step": "CA issues certificate",
            "controls": ["D3-CBAN", "D3-CERO", "D3-PA"],
            "validation": "HSM-backed signing, Certificate Transparency logging",
        },
        4: {  # User receives and uses cert
            "step": "User uses certificate",
            "controls": ["D3-FE", "D3-MENCR"],
            "validation": "Secure private key storage, proper cert chain validation",
        },
        5: {  # Recipient queries VA
            "step": "Recipient validates cert with VA",
            "controls": ["D3-PA", "D3-DNSDL"],
            "validation": "OCSP/CRL check, hard-fail on validation error",
        },
        6: {  # VA verifies cert
            "step": "VA verifies certificate status",
            "controls": ["D3-PA", "D3-NTA"],
            "validation": "Real-time CRL/OCSP response with short TTL",
        },
    }

    # Cryptographic attack patterns → D3FEND
    CRYPTO_ATTACK_PATTERNS = {
        "certificate_pinning_bypass": {
            "description": "Attacker bypasses cert pinning to intercept TLS",
            "detection": ["D3-NTA", "D3-PA"],
            "mitigation": ["D3-CP", "D3-CBAN", "D3-ET"],
        },
        "rogue_ca_certificate": {
            "description": "Compromised or malicious CA issues unauthorized cert",
            "detection": ["D3-PA", "D3-DNSTA"],
            "mitigation": ["D3-CP", "D3-CBAN", "D3-CERO"],
        },
        "ssl_strip": {
            "description": "Downgrade HTTPS to HTTP via MITM",
            "detection": ["D3-NTA", "D3-DNSTA"],
            "mitigation": ["D3-ET", "D3-MENCR", "D3-CP"],
        },
        "heartbleed_style": {
            "description": "TLS implementation vulnerability leaks memory (private keys)",
            "detection": ["D3-PMAD", "D3-NTA"],
            "mitigation": ["D3-SU", "D3-MA"],
        },
        "weak_crypto_downgrade": {
            "description": "Force connection to use weak cipher suites",
            "detection": ["D3-NTA", "D3-PMAD"],
            "mitigation": ["D3-ET", "D3-MENCR"],
        },
    }

    @classmethod
    def get_pki_component(cls, component: PKIComponent) -> Dict[str, Any]:
        """Get D3FEND techniques and controls for a PKI component."""
        return cls.PKI_COMPONENT_D3FEND.get(component, {})

    @classmethod
    def get_cert_trust_model(cls, cert_type: CertType) -> Dict[str, Any]:
        """Get trust model analysis for a certificate type."""
        return cls.CERT_TRUST_D3FEND.get(cert_type, {})

    @classmethod
    def get_ssl_inspection(cls, inspection_type: SSLInspectionType) -> Dict[str, Any]:
        """Get D3FEND mapping for an SSL inspection deployment."""
        return cls.SSL_INSPECTION_D3FEND.get(inspection_type, {})

    @classmethod
    def get_pki_process_control(cls, step: int) -> Dict[str, Any]:
        """Get security controls for a PKI process step (1-6)."""
        return cls.PKI_PROCESS_CONTROLS.get(step, {})

    @classmethod
    def get_crypto_attack_defense(cls, attack: str) -> Dict[str, Any]:
        """Get detection and mitigation for a cryptographic attack pattern."""
        return cls.CRYPTO_ATTACK_PATTERNS.get(attack, {})

    @classmethod
    def get_all_crypto_techniques(cls) -> List[str]:
        """Get all D3FEND techniques relevant to PKI/cryptography."""
        techniques = set()
        for data in cls.PKI_COMPONENT_D3FEND.values():
            techniques.update(data.get("techniques", []))
        for data in cls.CERT_TRUST_D3FEND.values():
            techniques.update(data.get("techniques", []))
        for data in cls.SSL_INSPECTION_D3FEND.values():
            techniques.update(data.get("techniques", []))
        return sorted(list(techniques))

    @classmethod
    def validate_certificate_chain(
        cls,
        cert_chain: List[Dict[str, Any]],
        trust_store: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Validate a certificate chain against D3FEND security criteria.

        Args:
            cert_chain: List of cert dicts with subject, issuer, expiry, algorithm
            trust_store: Optional list of trusted root CA names

        Returns:
            Validation result with status and D3FEND recommendations
        """
        issues = []
        recommendations = []

        for i, cert in enumerate(cert_chain):
            # Check for self-signed in chain (should only be root)
            if cert.get("subject") == cert.get("issuer") and i != len(cert_chain) - 1:
                issues.append(f"Self-signed certificate at position {i} (not root)")
                recommendations.append("D3-CP: Pin only the root CA, reject intermediate self-signed")

            # Check weak algorithms
            algo = cert.get("signature_algorithm", "").upper()
            if "SHA1" in algo or "MD5" in algo:
                issues.append(f"Weak signature algorithm: {algo}")
                recommendations.append("D3-CERO: Rotate to SHA-256 or better")

            # Check key size
            key_size = cert.get("key_size", 0)
            if key_size and key_size < 2048:
                issues.append(f"Weak key size: {key_size} bits")
                recommendations.append("D3-CERO: Re-issue with 2048+ bit key")

            # Check expiry
            expiry = cert.get("not_after")
            if expiry:
                from datetime import datetime
                try:
                    expiry_dt = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
                    if expiry_dt < datetime.now(expiry_dt.tzinfo):
                        issues.append(f"Expired certificate: {cert.get('subject')}")
                        recommendations.append("D3-SU: Renew certificate immediately")
                except:
                    pass

        # Check trust anchor
        root = cert_chain[-1] if cert_chain else {}
        root_issuer = root.get("issuer", "")
        if trust_store and root_issuer not in trust_store:
            issues.append(f"Untrusted root CA: {root_issuer}")
            recommendations.append("D3-CBAN: Validate against trust store or add to allowlist")

        return {
            "valid": len(issues) == 0,
            "issues": issues,
            "recommendations": recommendations,
            "d3fend_techniques": list(set([
                "D3-CP", "D3-CERO", "D3-SU", "D3-CBAN"
            ] + [r.split(":")[0] for r in recommendations if r.startswith("D3-")])),
        }
