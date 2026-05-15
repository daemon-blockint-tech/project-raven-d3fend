"""
OWASP Cheat Sheet Series Mapper

Maps OWASP Cheat Sheet Series topics to D3FEND defensive techniques,
Raven bug classes, and CWE mappings. Provides a knowledge base reference
for security reviewers and auditors.

Source: https://github.com/OWASP/CheatSheetSeries
License: CC BY-SA 4.0
"""
import logging
from typing import Dict, List, Optional, Any, Set
from enum import Enum
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class OWASPCheatSheet:
    """Represents an OWASP Cheat Sheet with D3FEND and bug class mappings."""
    name: str
    url: str
    topics: List[str]
    bug_classes: List[str]
    d3fend_techniques: List[str]
    cwe_ids: List[str]
    description: str
    priority: str  # "critical" | "high" | "medium" | "low"


class OWASPCheatSheetMapper:
    """
    Maps OWASP Cheat Sheet Series to Raven's D3FEND techniques and bug classes.
    
    Provides:
    - Bug class → OWASP cheat sheet lookup
    - D3FEND technique → OWASP guidance lookup
    - Agent knowledge base references
    """

    CHEAT_SHEETS: Dict[str, OWASPCheatSheet] = {
        # Authentication
        "Authentication_Cheat_Sheet": OWASPCheatSheet(
            name="Authentication Cheat Sheet",
            url="https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
            topics=["authentication", "passwords", "session management", "MFA"],
            bug_classes=["auth-bypass", "weak-authentication", "session-hijacking"],
            d3fend_techniques=["D3-PWA", "D3-MFA", "D3-TBA", "D3-CH", "D3-SPP", "D3-CDP"],
            cwe_ids=["CWE-287", "CWE-306", "CWE-798"],
            description="Guidance on implementing secure authentication mechanisms",
            priority="critical",
        ),
        "Authorization_Cheat_Sheet": OWASPCheatSheet(
            name="Authorization Cheat Sheet",
            url="https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
            topics=["authorization", "RBAC", "ABAC", "permissions"],
            bug_classes=["auth-bypass", "privilege-escalation", "idor"],
            d3fend_techniques=["D3-UAP", "D3-UGPH", "D3-APA", "D3-SCP"],
            cwe_ids=["CWE-285", "CWE-639", "CWE-269"],
            description="Secure authorization design patterns",
            priority="critical",
        ),
        "Password_Storage_Cheat_Sheet": OWASPCheatSheet(
            name="Password Storage Cheat Sheet",
            url="https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
            topics=["password hashing", "argon2", "bcrypt", "salt"],
            bug_classes=["weak-crypto", "credential-theft"],
            d3fend_techniques=["D3-CS", "D3-FE", "D3-CH"],
            cwe_ids=["CWE-916", "CWE-759", "CWE-760"],
            description="Secure password storage using modern hashing algorithms",
            priority="critical",
        ),
        "Session_Management_Cheat_Sheet": OWASPCheatSheet(
            name="Session Management Cheat Sheet",
            url="https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
            topics=["session tokens", "cookie security", "logout", "timeout"],
            bug_classes=["session-hijacking", "session-fixation", "auth-bypass"],
            d3fend_techniques=["D3-TB", "D3-CP", "D3-ET", "D3-MAN", "D3-AH"],
            cwe_ids=["CWE-384", "CWE-798", "CWE-539"],
            description="Secure session management practices",
            priority="critical",
        ),
        "Multifactor_Authentication_Cheat_Sheet": OWASPCheatSheet(
            name="Multifactor Authentication Cheat Sheet",
            url="https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html",
            topics=["MFA", "TOTP", "FIDO2", "biometrics", "push notifications"],
            bug_classes=["auth-bypass", "mfa-bypass"],
            d3fend_techniques=["D3-MFA", "D3-BAN", "D3-TBA", "D3-CBAN"],
            cwe_ids=["CWE-287", "CWE-308"],
            description="Implementing secure multi-factor authentication",
            priority="high",
        ),
        
        # Input Validation & Injection
        "SQL_Injection_Prevention_Cheat_Sheet": OWASPCheatSheet(
            name="SQL Injection Prevention Cheat Sheet",
            url="https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            topics=["parameterized queries", "ORM", "whitelist", "escaping"],
            bug_classes=["sql-injection"],
            d3fend_techniques=["D3-TL", "D3-DLV", "D3-APCA", "D3-AH"],
            cwe_ids=["CWE-89"],
            description="Preventing SQL injection vulnerabilities",
            priority="critical",
        ),
        "Cross_Site_Scripting_Prevention_Cheat_Sheet": OWASPCheatSheet(
            name="Cross Site Scripting Prevention Cheat Sheet",
            url="https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            topics=["output encoding", "CSP", "XSS", "contextual escaping"],
            bug_classes=["xss", "reflected-xss", "stored-xss", "dom-xss"],
            d3fend_techniques=["D3-DLV", "D3-CS", "D3-ACH", "D3-MH"],
            cwe_ids=["CWE-79"],
            description="Preventing cross-site scripting (XSS) attacks",
            priority="critical",
        ),
        "OS_Command_Injection_Defense_Cheat_Sheet": OWASPCheatSheet(
            name="OS Command Injection Defense Cheat Sheet",
            url="https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
            topics=["command injection", "shell exec", "parameterization"],
            bug_classes=["command-injection", "os-command-injection"],
            d3fend_techniques=["D3-DLV", "D3-EI", "D3-AH"],
            cwe_ids=["CWE-78"],
            description="Defending against OS command injection",
            priority="critical",
        ),
        "LDAP_Injection_Prevention_Cheat_Sheet": OWASPCheatSheet(
            name="LDAP Injection Prevention Cheat Sheet",
            url="https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html",
            topics=["LDAP injection", "filter encoding", "parameterization"],
            bug_classes=["ldap-injection"],
            d3fend_techniques=["D3-DLV", "D3-AH"],
            cwe_ids=["CWE-90"],
            description="Preventing LDAP injection attacks",
            priority="high",
        ),
        "XML_Security_Cheat_Sheet": OWASPCheatSheet(
            name="XML Security Cheat Sheet",
            url="https://cheatsheetseries.owasp.org/cheatsheets/XML_Security_Cheat_Sheet.html",
            topics=["XXE", "XML injection", "DTD", "XSLT"],
            bug_classes=["xxe", "xml-injection"],
            d3fend_techniques=["D3-DLV", "D3-EI", "D3-AH"],
            cwe_ids=["CWE-611", "CWE-91"],
            description="Securing XML parsers and preventing XXE",
            priority="high",
        ),
        "Deserialization_Cheat_Sheet": OWASPCheatSheet(
            name="Deserialization Cheat Sheet",
            url="https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
            topics=["deserialization", "serialization", "RCE", "object injection"],
            bug_classes=["deserialization", "object-injection", "rce"],
            d3fend_techniques=["D3-DLV", "D3-EI", "D3-AH", "D3-PA"],
            cwe_ids=["CWE-502", "CWE-915"],
            description="Preventing insecure deserialization vulnerabilities",
            priority="critical",
        ),
        "File_Upload_Cheat_Sheet": OWASPCheatSheet(
            name="File Upload Cheat Sheet",
            url="https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
            topics=["file upload", "malware", "extension validation", "magic bytes"],
            bug_classes=["path-traversal", "file-upload", "rce", "xss"],
            d3fend_techniques=["D3-DLV", "D3-EI", "D3-EDL", "D3-AH"],
            cwe_ids=["CWE-434", "CWE-22"],
            description="Secure file upload handling",
            priority="high",
        ),
        
        # Cryptography
        "Cryptographic_Storage_Cheat_Sheet": OWASPCheatSheet(
            name="Cryptographic Storage Cheat Sheet",
            url="https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
            topics=["encryption", "key management", "hashing", "randomness"],
            bug_classes=["weak-crypto", "information-disclosure"],
            d3fend_techniques=["D3-FE", "D3-DENCR", "D3-MENCR", "D3-CP"],
            cwe_ids=["CWE-327", "CWE-330", "CWE-798"],
            description="Secure cryptographic storage practices",
            priority="critical",
        ),
        "Transport_Layer_Security_Cheat_Sheet": OWASPCheatSheet(
            name="Transport Layer Security Cheat Sheet",
            url="https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
            topics=["TLS", "SSL", "cipher suites", "certificate pinning", "HSTS"],
            bug_classes=["weak-crypto", "mitm", "session-hijacking"],
            d3fend_techniques=["D3-ET", "D3-CP", "D3-MENCR", "D3-TB"],
            cwe_ids=["CWE-319", "CWE-326", "CWE-295"],
            description="Implementing secure TLS/SSL",
            priority="critical",
        ),
        "TLS_Cipher_String_Cheat_Sheet": OWASPCheatSheet(
            name="TLS Cipher String Cheat Sheet",
            url="https://cheatsheetseries.owasp.org/cheatsheets/TLS_Cipher_String_Cheat_Sheet.html",
            topics=["cipher suites", "TLS configuration", "perfect forward secrecy"],
            bug_classes=["weak-crypto"],
            d3fend_techniques=["D3-ET", "D3-MENCR"],
            cwe_ids=["CWE-326"],
            description="Recommended TLS cipher configurations",
            priority="high",
        ),
        
        # Application Security
        "Content_Security_Policy_Cheat_Sheet": OWASPCheatSheet(
            name="Content Security Policy Cheat Sheet",
            url="https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
            topics=["CSP", "XSS prevention", "script-src", "policy directives"],
            bug_classes=["xss", "clickjacking", "data-injection"],
            d3fend_techniques=["D3-ACH", "D3-AH", "D3-NTF"],
            cwe_ids=["CWE-79", "CWE-1021"],
            description="Implementing effective Content Security Policies",
            priority="high",
        ),
        "Clickjacking_Defense_Cheat_Sheet": OWASPCheatSheet(
            name="Clickjacking Defense Cheat Sheet",
            url="https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
            topics=["X-Frame-Options", "CSP frame-ancestors", "UI redressing"],
            bug_classes=["clickjacking", "ui-redressing"],
            d3fend_techniques=["D3-ACH", "D3-AH"],
            cwe_ids=["CWE-1021"],
            description="Defending against clickjacking attacks",
            priority="medium",
        ),
        "CSRF_Prevention_Cheat_Sheet": OWASPCheatSheet(
            name="Cross-Site Request Forgery Prevention Cheat Sheet",
            url="https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
            topics=["CSRF tokens", "SameSite cookies", "double submit cookie"],
            bug_classes=["csrf", "request-forgery"],
            d3fend_techniques=["D3-MAN", "D3-AH", "D3-DLV"],
            cwe_ids=["CWE-352"],
            description="Preventing cross-site request forgery",
            priority="high",
        ),
        "DOM_based_XSS_Prevention_Cheat_Sheet": OWASPCheatSheet(
            name="DOM based XSS Prevention Cheat Sheet",
            url="https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html",
            topics=["DOM XSS", "sink validation", "safe DOM manipulation"],
            bug_classes=["dom-xss", "xss"],
            d3fend_techniques=["D3-DLV", "D3-AH", "D3-ACH"],
            cwe_ids=["CWE-79"],
            description="Preventing DOM-based XSS vulnerabilities",
            priority="high",
        ),
        "Injection_Prevention_Cheat_Sheet": OWASPCheatSheet(
            name="Injection Prevention Cheat Sheet",
            url="https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html",
            topics=["injection", "parameterization", "whitelist", "escaping"],
            bug_classes=["sql-injection", "command-injection", "ldap-injection", "xml-injection", "xpath-injection"],
            d3fend_techniques=["D3-TL", "D3-DLV", "D3-APCA", "D3-AH"],
            cwe_ids=["CWE-89", "CWE-78", "CWE-90", "CWE-91", "CWE-93"],
            description="General injection prevention guidance",
            priority="critical",
        ),
        "Input_Validation_Cheat_Sheet": OWASPCheatSheet(
            name="Input Validation Cheat Sheet",
            url="https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
            topics=["input validation", "whitelist", "sanitization", "canonicalization"],
            bug_classes=["injection", "path-traversal", "buffer-overflow", "integer-overflow"],
            d3fend_techniques=["D3-DLV", "D3-IRV", "D3-VTV", "D3-AH"],
            cwe_ids=["CWE-20", "CWE-128", "CWE-22"],
            description="Secure input validation practices",
            priority="critical",
        ),
        "Logging_Cheat_Sheet": OWASPCheatSheet(
            name="Logging Cheat Sheet",
            url="https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
            topics=["logging", "log injection", "PII in logs", "security events"],
            bug_classes=["log-injection", "information-disclosure"],
            d3fend_techniques=["D3-PA", "D3-DI", "D3-CS", "D3-ACH"],
            cwe_ids=["CWE-117", "CWE-532", "CWE-778"],
            description="Secure logging practices and preventing log injection",
            priority="high",
        ),
        "Error_Handling_Cheat_Sheet": OWASPCheatSheet(
            name="Error Handling Cheat Sheet",
            url="https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html",
            topics=["error handling", "stack traces", "information disclosure", "exceptions"],
            bug_classes=["information-disclosure", "verbose-error"],
            d3fend_techniques=["D3-CS", "D3-AH", "D3-EHPV"],
            cwe_ids=["CWE-209", "CWE-532"],
            description="Secure error handling without information leakage",
            priority="medium",
        ),
        
        # Network & Infrastructure
        "Secure_Headers_Cheat_Sheet": OWASPCheatSheet(
            name="Secure Headers Cheat Sheet",
            url="https://cheatsheetseries.owasp.org/cheatsheets/Secure_Headers_Cheat_Sheet.html",
            topics=["HTTP headers", "HSTS", "XSS protection", "CSP", "referrer policy"],
            bug_classes=["xss", "clickjacking", "mitm", "information-disclosure"],
            d3fend_techniques=["D3-ACH", "D3-AH", "D3-ET", "D3-NTF"],
            cwe_ids=["CWE-79", "CWE-1021", "CWE-319"],
            description="Implementing security-enhancing HTTP headers",
            priority="high",
        ),
        "CORS_Cheat_Sheet": OWASPCheatSheet(
            name="Cross-Origin Resource Sharing Cheat Sheet",
            url="https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html",
            topics=["CORS", "Origin", "preflight", "credentials"],
            bug_classes=["cors-misconfiguration", "information-disclosure"],
            d3fend_techniques=["D3-ACH", "D3-APA", "D3-NTF"],
            cwe_ids=["CWE-942"],
            description="Secure CORS configuration",
            priority="medium",
        ),
        "Server_Side_Request_Forgery_Prevention_Cheat_Sheet": OWASPCheatSheet(
            name="Server Side Request Forgery Prevention Cheat Sheet",
            url="https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
            topics=["SSRF", "URL validation", "DNS rebinding", "IP allowlist"],
            bug_classes=["ssrf", "request-forgery"],
            d3fend_techniques=["D3-DLV", "D3-DNSDL", "D3-ITF", "D3-APA"],
            cwe_ids=["CWE-918"],
            description="Preventing Server-Side Request Forgery",
            priority="critical",
        ),
        
        # APIs
        "REST_Security_Cheat_Sheet": OWASPCheatSheet(
            name="REST Security Cheat Sheet",
            url="https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html",
            topics=["REST API", "authentication", "rate limiting", "JWT", "OAuth"],
            bug_classes=["auth-bypass", "idor", "rate-limiting-bypass", "jwt-weakness"],
            d3fend_techniques=["D3-UAP", "D3-APA", "D3-TBA", "D3-MFA"],
            cwe_ids=["CWE-285", "CWE-639", "CWE-307"],
            description="Securing RESTful APIs",
            priority="critical",
        ),
        "GraphQL_Cheat_Sheet": OWASPCheatSheet(
            name="GraphQL Cheat Sheet",
            url="https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
            topics=["GraphQL", "query depth", "introspection", "batching"],
            bug_classes=["dos", "information-disclosure", "auth-bypass"],
            d3fend_techniques=["D3-DLV", "D3-APA", "D3-EI"],
            cwe_ids=["CWE-770", "CWE-20"],
            description="Securing GraphQL APIs",
            priority="high",
        ),
        "JSON_Web_Token_for_Java_Cheat_Sheet": OWASPCheatSheet(
            name="JSON Web Token for Java Cheat Sheet",
            url="https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
            topics=["JWT", "JOSE", "algorithm confusion", "key confusion"],
            bug_classes=["jwt-weakness", "algorithm-confusion", "auth-bypass"],
            d3fend_techniques=["D3-TBA", "D3-CP", "D3-MAN", "D3-AH"],
            cwe_ids=["CWE-347", "CWE-287"],
            description="Secure JWT implementation and validation",
            priority="high",
        ),
        
        # Web-specific
        "HTML5_Security_Cheat_Sheet": OWASPCheatSheet(
            name="HTML5 Security Cheat Sheet",
            url="https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html",
            topics=["HTML5", "localStorage", "WebSockets", "Web Workers", "CORS"],
            bug_classes=["xss", "cors-misconfiguration", "client-side-storage"],
            d3fend_techniques=["D3-ACH", "D3-AH", "D3-APA"],
            cwe_ids=["CWE-79", "CWE-942"],
            description="Securing HTML5 applications",
            priority="medium",
        ),
        "Web_Service_Security_Cheat_Sheet": OWASPCheatSheet(
            name="Web Service Security Cheat Sheet",
            url="https://cheatsheetseries.owasp.org/cheatsheets/Web_Service_Security_Cheat_Sheet.html",
            topics=["SOAP", "WSDL", "XML security", "WS-Security"],
            bug_classes=["xxe", "xml-injection", "ws-security-weakness"],
            d3fend_techniques=["D3-DLV", "D3-EI", "D3-MENCR", "D3-MAN"],
            cwe_ids=["CWE-611", "CWE-91"],
            description="Securing web services (SOAP/WSDL)",
            priority="medium",
        ),
        
        # Mobile
        "Mobile_Application_Security_Cheat_Sheet": OWASPCheatSheet(
            name="Mobile Application Security Cheat Sheet",
            url="https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html",
            topics=["mobile", "certificate pinning", "root detection", "code obfuscation"],
            bug_classes=["certificate-pinning-bypass", "root-detection-bypass", "hardcoded-secrets"],
            d3fend_techniques=["D3-CP", "D3-FE", "D3-AH", "D3-PH"],
            cwe_ids=["CWE-295", "CWE-798"],
            description="Securing mobile applications",
            priority="high",
        ),
        
        # DevOps & CI/CD
        "Secrets_Management_Cheat_Sheet": OWASPCheatSheet(
            name="Secrets Management Cheat Sheet",
            url="https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
            topics=["secrets", "vault", "rotation", "environment variables", "CI/CD"],
            bug_classes=["hardcoded-secrets", "credential-exposure", "supply-chain"],
            d3fend_techniques=["D3-CS", "D3-FE", "D3-CRO", "D3-CH"],
            cwe_ids=["CWE-798", "CWE-798"],
            description="Managing secrets securely in applications and CI/CD",
            priority="critical",
        ),
        "Infrastructure_as_Code_Security_Cheat_Sheet": OWASPCheatSheet(
            name="Infrastructure as Code Security Cheat Sheet",
            url="https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html",
            topics=["IaC", "Terraform", "CloudFormation", "misconfiguration", "CSPM"],
            bug_classes=["misconfiguration", "cloud-weakness", "iam-misconfiguration"],
            d3fend_techniques=["D3-CI", "D3-AVE", "D3-APA", "D3-UAP"],
            cwe_ids=["CWE-16", "CWE-269"],
            description="Securing Infrastructure as Code deployments",
            priority="high",
        ),
        
        # AI/ML
        "AI_Agent_Security_Cheat_Sheet": OWASPCheatSheet(
            name="AI Agent Security Cheat Sheet",
            url="https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html",
            topics=["AI agent", "LLM", "prompt injection", "RAG", "tool calling"],
            bug_classes=["prompt-injection", "agent-hijacking", "tool-abuse", "data-extraction"],
            d3fend_techniques=["D3-DLV", "D3-EI", "D3-APA", "D3-NTA"],
            cwe_ids=["CWE-20", "CWE-78"],
            description="Securing AI agents and LLM-powered applications",
            priority="high",
        ),
        "AI_Security_Privacy_Cheat_Sheet": OWASPCheatSheet(
            name="AI Security and Privacy Cheat Sheet",
            url="https://cheatsheetseries.owasp.org/cheatsheets/AI_Security_and_Privacy_Cheat_Sheet.html",
            topics=["AI model", "privacy", "training data", "model inversion", "membership inference"],
            bug_classes=["model-inversion", "membership-inference", "data-poisoning", "model-extraction"],
            d3fend_techniques=["D3-FE", "D3-DENCR", "D3-PA", "D3-DI"],
            cwe_ids=["CWE-200", "CWE-327"],
            description="Securing AI/ML models and protecting training data privacy",
            priority="high",
        ),
    }

    @classmethod
    def get_cheat_sheet(cls, name: str) -> Optional[OWASPCheatSheet]:
        """Get an OWASP cheat sheet by name."""
        return cls.CHEAT_SHEETS.get(name)

    @classmethod
    def get_by_bug_class(cls, bug_class: str) -> List[OWASPCheatSheet]:
        """Find all cheat sheets relevant to a bug class."""
        results = []
        for cs in cls.CHEAT_SHEETS.values():
            if bug_class.lower() in [b.lower() for b in cs.bug_classes]:
                results.append(cs)
        return results

    @classmethod
    def get_by_d3fend(cls, d3fend_id: str) -> List[OWASPCheatSheet]:
        """Find all cheat sheets that reference a D3FEND technique."""
        results = []
        for cs in cls.CHEAT_SHEETS.values():
            if d3fend_id.upper() in [d.upper() for d in cs.d3fend_techniques]:
                results.append(cs)
        return results

    @classmethod
    def get_by_cwe(cls, cwe_id: str) -> List[OWASPCheatSheet]:
        """Find all cheat sheets that map to a CWE."""
        results = []
        cwe_upper = cwe_id.upper()
        for cs in cls.CHEAT_SHEETS.values():
            if cwe_upper in [c.upper() for c in cs.cwe_ids]:
                results.append(cs)
        return results

    @classmethod
    def get_recommendations_for_finding(
        cls,
        bug_class: str,
        d3fend_ids: Optional[List[str]] = None,
        cwe_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get OWASP cheat sheet recommendations for a finding.

        Args:
            bug_class: The bug class of the finding
            d3fend_ids: Optional D3FEND technique IDs
            cwe_id: Optional CWE ID

        Returns:
            List of recommendation dicts with cheat sheet references
        """
        results = []
        seen = set()

        # Search by bug class
        for cs in cls.get_by_bug_class(bug_class):
            key = cs.name
            if key not in seen:
                seen.add(key)
                results.append({
                    "cheat_sheet": cs.name,
                    "url": cs.url,
                    "description": cs.description,
                    "priority": cs.priority,
                    "d3fend_techniques": cs.d3fend_techniques,
                    "cwe_ids": cs.cwe_ids,
                })

        # Search by D3FEND
        if d3fend_ids:
            for d3 in d3fend_ids:
                for cs in cls.get_by_d3fend(d3):
                    key = cs.name
                    if key not in seen:
                        seen.add(key)
                        results.append({
                            "cheat_sheet": cs.name,
                            "url": cs.url,
                            "description": cs.description,
                            "priority": cs.priority,
                            "d3fend_techniques": cs.d3fend_techniques,
                            "cwe_ids": cs.cwe_ids,
                        })

        # Search by CWE
        if cwe_id:
            for cs in cls.get_by_cwe(cwe_id):
                key = cs.name
                if key not in seen:
                    seen.add(key)
                    results.append({
                        "cheat_sheet": cs.name,
                        "url": cs.url,
                        "description": cs.description,
                        "priority": cs.priority,
                        "d3fend_techniques": cs.d3fend_techniques,
                        "cwe_ids": cs.cwe_ids,
                    })

        # Sort by priority
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        results.sort(key=lambda r: priority_order.get(r["priority"], 4))

        return results

    @classmethod
    def get_all_cheat_sheet_names(cls) -> List[str]:
        """Get all available cheat sheet names."""
        return sorted(list(cls.CHEAT_SHEETS.keys()))

    @classmethod
    def get_stats(cls) -> Dict[str, Any]:
        """Get statistics about the cheat sheet mappings."""
        total = len(cls.CHEAT_SHEETS)
        bug_class_coverage = set()
        d3fend_coverage = set()
        cwe_coverage = set()
        priority_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for cs in cls.CHEAT_SHEETS.values():
            bug_class_coverage.update(cs.bug_classes)
            d3fend_coverage.update(cs.d3fend_techniques)
            cwe_coverage.update(cs.cwe_ids)
            priority_counts[cs.priority] = priority_counts.get(cs.priority, 0) + 1

        return {
            "total_cheat_sheets": total,
            "unique_bug_classes": len(bug_class_coverage),
            "unique_d3fend_techniques": len(d3fend_coverage),
            "unique_cwes": len(cwe_coverage),
            "priority_distribution": priority_counts,
            "bug_class_coverage": sorted(list(bug_class_coverage)),
            "d3fend_coverage": sorted(list(d3fend_coverage)),
            "cwe_coverage": sorted(list(cwe_coverage)),
        }
