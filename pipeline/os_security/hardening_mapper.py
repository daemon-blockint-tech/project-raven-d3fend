"""
OS Security Concepts Mapper — Common Operating System Hardening

Maps Windows Registry, system processes, file structure, and hardware
architecture to D3FEND defensive techniques and audit capabilities.

Useful for:
- Binary analysis (Windows PE files, registry access patterns)
- Process auditing (D3-PA) — Task Manager, Procmon, top/htop
- System hardening validation
- Compliance reporting (NIST 800-53, PCI-DSS)
"""
import logging
from typing import Dict, List, Optional, Any
from enum import Enum

logger = logging.getLogger(__name__)


class OSType(Enum):
    """Operating system types."""
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    UNKNOWN = "unknown"


class RegistryHive(Enum):
    """Windows Registry hives with security relevance."""
    HKEY_CLASSES_ROOT = "HKCR"    # App associations — can be hijacked for persistence
    HKEY_CURRENT_USER = "HKCU"    # User profile — credential artifacts
    HKEY_LOCAL_MACHINE = "HKLM"  # System-wide config — privilege escalation target
    HKEY_USERS = "HKU"            # All user profiles — lateral movement artifacts
    HKEY_CURRENT_CONFIG = "HKCC" # Hardware profile — boot-time tampering


class ProcessMonitor(Enum):
    """System process monitoring tools."""
    TASK_MANAGER = "taskmgr"      # Windows GUI process list
    PROCMON = "procmon"           # Windows real-time process/file/registry monitor
    TOP = "top"                   # Linux/Unix process viewer
    HTOP = "htop"                 # Enhanced Linux process viewer
    PS = "ps"                     # Unix process status
    LSOF = "lsof"                 # List open files/processes


class HardwareArch(Enum):
    """Hardware architectures Raven supports for binary analysis."""
    X86 = "x86"                   # 32-bit Intel/AMD
    X86_64 = "x86_64"             # 64-bit Intel/AMD (amd64, x64)
    ARM = "arm"                   # ARM 32-bit
    ARM64 = "aarch64"             # ARM 64-bit
    MIPS = "mips"                 # MIPS architecture


class OSHardeningMapper:
    """
    Maps operating system security concepts to D3FEND techniques
    and Raven pipeline capabilities.
    """

    # Registry hives → D3FEND techniques for hardening/auditing
    REGISTRY_D3FEND = {
        RegistryHive.HKEY_CLASSES_ROOT: {
            "techniques": ["D3-SCH", "D3-AH"],
            "risk": "File association hijacking, COM object abuse",
            "audit": "Monitor HKCR changes for unauthorized app associations",
        },
        RegistryHive.HKEY_CURRENT_USER: {
            "techniques": ["D3-CH", "D3-AH"],
            "risk": "User credential theft, profile-based persistence",
            "audit": "Monitor HKCU run keys, credential artifacts",
        },
        RegistryHive.HKEY_LOCAL_MACHINE: {
            "techniques": ["D3-SCH", "D3-AH", "D3-PH", "D3-MA"],
            "risk": "System-wide privilege escalation, kernel driver abuse",
            "audit": "Monitor HKLM\SYSTEM\CurrentControlSet\Services for unauthorized drivers",
        },
        RegistryHive.HKEY_USERS: {
            "techniques": ["D3-PA", "D3-NTA"],
            "risk": "Lateral movement via user profile artifacts",
            "audit": "Cross-user registry comparison for anomalies",
        },
        RegistryHive.HKEY_CURRENT_CONFIG: {
            "techniques": ["D3-PH"],
            "risk": "Boot-time hardware tampering",
            "audit": "Verify hardware profile integrity at startup",
        },
    }

    # OS file structure → D3FEND techniques
    FILE_STRUCTURE_D3FEND = {
        "C:\\Windows\\System32": {
            "os": OSType.WINDOWS,
            "techniques": ["D3-SCH", "D3-AH", "D3-PH"],
            "risk": "DLL search order hijacking, system file tampering",
            "audit": "Monitor file integrity of System32 contents",
        },
        "/etc": {
            "os": OSType.LINUX,
            "techniques": ["D3-SCP", "D3-CI", "D3-AH"],
            "risk": "Configuration tampering, unauthorized service addition",
            "audit": "Monitor /etc for unauthorized config changes",
        },
        "/var": {
            "os": OSType.LINUX,
            "techniques": ["D3-PA", "D3-DI"],
            "risk": "Log tampering, data exfiltration",
            "audit": "Monitor /var/log integrity, detect deletion",
        },
        "/root": {
            "os": OSType.LINUX,
            "techniques": ["D3-UAP", "D3-CH"],
            "risk": "Root credential compromise",
            "audit": "Monitor /root for unauthorized access",
        },
        "/": {
            "os": OSType.LINUX,
            "techniques": ["D3-SCP", "D3-UAP"],
            "risk": "Filesystem-level tampering",
            "audit": "Filesystem integrity monitoring (FIM)",
        },
    }

    # Process monitoring tools → D3FEND techniques
    PROCESS_MONITOR_D3FEND = {
        ProcessMonitor.TASK_MANAGER: {
            "techniques": ["D3-PA"],
            "capabilities": ["process_listing", "cpu_memory_monitoring"],
            "limitations": "No real-time file/registry correlation",
        },
        ProcessMonitor.PROCMON: {
            "techniques": ["D3-PA", "D3-NTA"],
            "capabilities": ["real_time_monitoring", "file_access_tracking", "registry_monitoring", "network_activity"],
            "limitations": "Windows-only, requires admin privileges",
        },
        ProcessMonitor.TOP: {
            "techniques": ["D3-PA"],
            "capabilities": ["process_listing", "resource_usage"],
            "limitations": "Basic, no historical data",
        },
        ProcessMonitor.HTOP: {
            "techniques": ["D3-PA"],
            "capabilities": ["process_listing", "resource_usage", "tree_view"],
            "limitations": "No file/registry correlation",
        },
    }

    # Hardware architecture → analysis capabilities
    ARCH_CAPABILITIES = {
        HardwareArch.X86: {
            "bitness": 32,
            "ghidra_support": True,
            "common_vulns": ["buffer-overflow", "integer-overflow", "format-string"],
            "calling_convention": "cdecl/stdcall",
        },
        HardwareArch.X86_64: {
            "bitness": 64,
            "ghidra_support": True,
            "common_vulns": ["buffer-overflow", "use-after-free", "type-confusion"],
            "calling_convention": "System V AMD64 ABI / Windows x64",
        },
        HardwareArch.ARM: {
            "bitness": 32,
            "ghidra_support": True,
            "common_vulns": ["buffer-overflow", "integer-overflow"],
            "calling_convention": "AAPCS",
        },
        HardwareArch.ARM64: {
            "bitness": 64,
            "ghidra_support": True,
            "common_vulns": ["buffer-overflow", "race-condition"],
            "calling_convention": "AAPCS64",
        },
    }

    @classmethod
    def get_registry_risks(cls, hive: RegistryHive) -> Dict[str, Any]:
        """Get D3FEND techniques and risks for a Windows registry hive."""
        return cls.REGISTRY_D3FEND.get(hive, {})

    @classmethod
    def get_file_structure_risks(cls, path: str) -> Dict[str, Any]:
        """Get D3FEND techniques for a critical file system path."""
        # Normalize path for lookup
        normalized = path.replace("\\", "/").lower()
        for key, value in cls.FILE_STRUCTURE_D3FEND.items():
            if normalized == key.lower().replace("\\", "/"):
                return value
        return {}

    @classmethod
    def get_process_monitor_capabilities(cls, tool: ProcessMonitor) -> Dict[str, Any]:
        """Get capabilities and D3FEND mapping for a process monitor."""
        return cls.PROCESS_MONITOR_D3FEND.get(tool, {})

    @classmethod
    def get_arch_capabilities(cls, arch: HardwareArch) -> Dict[str, Any]:
        """Get vulnerability and analysis capabilities for a hardware architecture."""
        return cls.ARCH_CAPABILITIES.get(arch, {})

    @classmethod
    def detect_os_from_path(cls, path: str) -> OSType:
        """Detect OS type from file path structure."""
        if path.startswith("C:\\") or path.startswith("HK"):
            return OSType.WINDOWS
        elif path.startswith("/"):
            return OSType.LINUX
        return OSType.UNKNOWN

    @classmethod
    def get_hardening_recommendations(cls, os_type: OSType) -> List[str]:
        """Get system hardening recommendations per OS."""
        recommendations = {
            OSType.WINDOWS: [
                "Enable Windows Defender Credential Guard (D3-CH)",
                "Configure AppLocker/WDAC for executable allowlisting (D3-EAL)",
                "Enable ASLR and DEP for all processes (D3-SAOR, D3-PSEP)",
                "Monitor HKLM\\SYSTEM\\CurrentControlSet\\Services with Procmon (D3-PA)",
                "Enable audit policies for registry and file system (D3-PA)",
            ],
            OSType.LINUX: [
                "Configure SELinux/AppArmor in enforcing mode (D3-EAL)",
                "Enable Address Space Layout Randomization (D3-SAOR)",
                "Mount /tmp with noexec, nodev, nosuid (D3-PH)",
                "Monitor /etc and /bin with AIDE/Tripwire (D3-CI)",
                "Restrict /root access with proper UMASK (D3-UAP)",
                "Enable auditd for syscall and file monitoring (D3-PA)",
            ],
            OSType.MACOS: [
                "Enable System Integrity Protection (SIP) (D3-PH)",
                "Configure Gatekeeper for signed app enforcement (D3-EAL)",
                "Enable FileVault for disk encryption (D3-DENCR)",
            ],
        }
        return recommendations.get(os_type, [])

    @classmethod
    def get_all_registry_techniques(cls) -> List[str]:
        """Get all D3FEND techniques relevant to Windows registry security."""
        techniques = set()
        for data in cls.REGISTRY_D3FEND.values():
            techniques.update(data.get("techniques", []))
        return sorted(list(techniques))

    @classmethod
    def get_all_file_structure_techniques(cls) -> List[str]:
        """Get all D3FEND techniques relevant to file system security."""
        techniques = set()
        for data in cls.FILE_STRUCTURE_D3FEND.values():
            techniques.update(data.get("techniques", []))
        return sorted(list(techniques))
