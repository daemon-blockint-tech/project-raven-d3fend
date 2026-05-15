"""
Infrastructure Security Mapper — Common Infrastructure Concepts

Maps serverless, virtualization, and containerization to D3FEND
defensive techniques and Raven audit capabilities.

Aligns with CySA+ Domain 1: System and Network Architecture.
"""
import logging
from typing import Dict, List, Any
from enum import Enum

logger = logging.getLogger(__name__)


class InfraType(Enum):
    """Infrastructure deployment types."""
    SERVERLESS = "serverless"       # Lambda, Cloud Functions, Azure Functions
    VIRTUALIZATION = "virtualization"  # VMs (Type I/II hypervisors)
    CONTAINERIZATION = "containerization"  # Docker, containerd, Kubernetes
    BARE_METAL = "bare_metal"       # Physical servers


class HypervisorType(Enum):
    """Virtualization hypervisor types."""
    TYPE_I = "type_i"               # Bare metal (ESXi, Xen, Hyper-V)
    TYPE_II = "type_ii"             # Hosted (VirtualBox, VMware Workstation)


class InfrastructureMapper:
    """
    Maps infrastructure concepts to D3FEND techniques and security risks.
    """

    # Infrastructure type → D3FEND techniques
    INFRA_D3FEND = {
        InfraType.SERVERLESS: {
            "techniques": ["D3-EI", "D3-PA", "D3-NTA"],
            "risks": [
                "Function-level privilege escalation via IAM misconfiguration",
                "Cold start side-channel timing attacks",
                "Dependency confusion in deployment packages",
                "Event injection via API Gateway/trigger poisoning",
            ],
            "hardening": [
                "Least-privilege IAM roles per function (D3-UAP)",
                "Function isolation via sandboxing (D3-EI)",
                "VPC networking for sensitive functions (D3-NI)",
                "Runtime monitoring and anomaly detection (D3-PA, D3-NTA)",
            ],
            "audit_tools": ["CloudTrail", "VPC Flow Logs", "Lambda Insights"],
        },
        InfraType.VIRTUALIZATION: {
            "techniques": ["D3-EI", "D3-HBPI", "D3-PH", "D3-MA"],
            "risks": [
                "VM escape via hypervisor vulnerability (VM-escape bug class)",
                "Side-channel attacks (Spectre, Meltdown, L1TF)",
                "Resource exhaustion / noisy neighbor",
                "Snapshot tampering or unauthorized cloning",
            ],
            "hardening": [
                "Hardware-based process isolation (D3-HBPI)",
                "Kernel-based process isolation (D3-KBPI)",
                "VM sandboxing and resource quotas (D3-EI)",
                "Memory allocation hardening (D3-MA)",
                "Physical enclosure hardening (D3-PEH)",
            ],
            "audit_tools": ["hypervisor logs", "vCenter audit", "virt-manager"],
            "hypervisor_specific": {
                HypervisorType.TYPE_I: {
                    "attack_surface": "Lower — runs directly on hardware",
                    "common_vulns": ["hypervisor escape", "DMA attacks", "firmware compromise"],
                    "d3fend_extra": ["D3-BA", "D3-TBI"],  # Bootloader auth, TPM boot integrity
                },
                HypervisorType.TYPE_II: {
                    "attack_surface": "Higher — hosted on general-purpose OS",
                    "common_vulns": ["host OS compromise", "guest-to-host escape", "shared folder abuse"],
                    "d3fend_extra": ["D3-SU", "D3-DLIC"],  # Software update, driver load integrity
                },
            },
        },
        InfraType.CONTAINERIZATION: {
            "techniques": ["D3-EI", "D3-ABPI", "D3-CIA", "D3-SU"],
            "risks": [
                "Container escape via privileged mode or kernel exploit",
                "Image vulnerability (outdated base images, CVEs)",
                "Secret leakage in image layers or environment variables",
                "Host namespace sharing (PID, network, IPC)",
                "Supply chain poisoning via compromised registries",
            ],
            "hardening": [
                "Run containers as non-root (D3-UAP)",
                "Drop capabilities, use seccomp profiles (D3-EI)",
                "Read-only root filesystem (D3-HBWP)",
                "Container image analysis and signing (D3-CIA)",
                "Resource limits (CPU/memory) to prevent DoS (D3-EI)",
                "Network segmentation between containers (D3-NI)",
                "Regular base image updates (D3-SU)",
            ],
            "audit_tools": [
                "docker ps / docker inspect",
                "docker scan / Trivy / Snyk",
                " Falco (runtime security)",
                "sysdig",
                "kube-bench (CIS Kubernetes)",
            ],
            "docker_commands": {
                "docker pull": "Image download — verify registry authenticity",
                "docker run": "Container execution — check --privileged, -v mounts, --network",
                "docker ps": "List running containers — detect unexpected containers",
                "docker stop/rm": "Lifecycle management — ensure clean termination",
            },
        },
        InfraType.BARE_METAL: {
            "techniques": ["D3-PH", "D3-TBI", "D3-BA", "D3-HBWP"],
            "risks": [
                "Physical access to hardware",
                "Firmware/BIOS compromise",
                "Hardware-level side channels",
            ],
            "hardening": [
                "TPM boot integrity (D3-TBI)",
                "Bootloader authentication (D3-BA)",
                "Hardware-based write protection (D3-HBWP)",
                "Physical enclosure hardening (D3-PEH)",
            ],
        },
    }

    # Container-specific vulnerability classes → D3FEND
    CONTAINER_VULN_D3FEND = {
        "container-escape": {
            "description": "Escape from container to host via privileged mode, kernel exploit, or misconfigured capabilities",
            "techniques": ["D3-EI", "D3-HBPI", "D3-ABPI"],
            "detection": "Monitor for host-namespace access from containers",
        },
        "image-vulnerability": {
            "description": "CVE in base image or installed packages",
            "techniques": ["D3-CIA", "D3-AVE", "D3-SU"],
            "detection": "Container image analysis with vulnerability scanning",
        },
        "secret-leakage": {
            "description": "Credentials or tokens exposed in image layers or env vars",
            "techniques": ["D3-CS", "D3-FE"],
            "detection": "Static analysis of image layers for secrets",
        },
        "supply-chain-poisoning": {
            "description": "Compromised container image or registry",
            "techniques": ["D3-MAN", "D3-CIA"],
            "detection": "Image signing verification and registry monitoring",
        },
        "insecure-capabilities": {
            "description": "Container granted dangerous Linux capabilities (CAP_SYS_ADMIN, etc.)",
            "techniques": ["D3-EI", "D3-SCP"],
            "detection": "Audit container runtime configs for cap_add",
        },
    }

    # Serverless-specific vulnerability classes
    SERVERLESS_VULN_D3FEND = {
        "iam-escalation": {
            "description": "Function assumes overly permissive IAM role",
            "techniques": ["D3-UAP", "D3-UGPH"],
            "detection": "IAM policy analysis for function roles",
        },
        "event-injection": {
            "description": "Malicious payload via API Gateway or event trigger",
            "techniques": ["D3-APCA", "D3-DLV"],
            "detection": "Input validation on event payloads",
        },
        "dependency-confusion": {
            "description": "Malicious package in deployment artifact",
            "techniques": ["D3-SWI", "D3-CIA"],
            "detection": "SBOM scanning of deployment packages",
        },
    }

    @classmethod
    def get_infra_security(cls, infra_type: InfraType) -> Dict[str, Any]:
        """Get D3FEND techniques, risks, and hardening for an infrastructure type."""
        return cls.INFRA_D3FEND.get(infra_type, {})

    @classmethod
    def get_hypervisor_security(cls, hv_type: HypervisorType) -> Dict[str, Any]:
        """Get hypervisor-specific security guidance."""
        virt = cls.INFRA_D3FEND.get(InfraType.VIRTUALIZATION, {})
        return virt.get("hypervisor_specific", {}).get(hv_type, {})

    @classmethod
    def get_container_vuln(cls, vuln_type: str) -> Dict[str, Any]:
        """Get D3FEND mapping for a container vulnerability class."""
        return cls.CONTAINER_VULN_D3FEND.get(vuln_type, {})

    @classmethod
    def get_serverless_vuln(cls, vuln_type: str) -> Dict[str, Any]:
        """Get D3FEND mapping for a serverless vulnerability class."""
        return cls.SERVERLESS_VULN_D3FEND.get(vuln_type, {})

    @classmethod
    def get_docker_security_flags(cls, command: str) -> List[str]:
        """Get security-critical flags to check in docker commands."""
        flags = {
            "docker run": [
                "--privileged",      # DANGER: full host access
                "--cap-add",         # Check added capabilities
                "--network host",    # DANGER: shares host network namespace
                "--pid host",        # DANGER: shares host PID namespace
                "-v /:/host",        # DANGER: mounts host filesystem
                "--security-opt",    # Check seccomp/AppArmor options
            ],
            "docker pull": [
                "registry authenticity",  # Verify signed images
                "image digest",           # Pin to immutable digest
            ],
        }
        return flags.get(command, [])

    @classmethod
    def get_all_infra_techniques(cls) -> List[str]:
        """Get all D3FEND techniques relevant to infrastructure security."""
        techniques = set()
        for data in cls.INFRA_D3FEND.values():
            techniques.update(data.get("techniques", []))
        return sorted(list(techniques))
