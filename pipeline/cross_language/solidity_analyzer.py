"""
Solidity-Native Call Analyzer for Blockchain Security

Analyzes Solidity smart contracts for security vulnerabilities
at the boundary between Solidity and native code calls.
"""

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


class SolidityVulnerabilityType(Enum):
    """Types of Solidity-native vulnerabilities"""
    DELEGATECALL_RISK = "delegatecall_risk"
    EXTCODE_SIZE = "extcode_size"
    SELFDESTRUCT = "selfdestruct"
    ADDRESS_PREDICTABILITY = "address_predictability"
    REENTRANCY = "reentrancy"
    UNCHECKED_RETURN = "unchecked_return"
    STORAGE_POINTER = "storage_pointer"
    CALL_INJECTION = "call_injection"
    GAS_LIMIT = "gas_limit"
    ACCESS_CONTROL = "access_control"
    TIMESTAMP_MANIPULATION = "timestamp_manipulation"


@dataclass
class SolidityNativeBoundary:
    """Represents a Solidity to native code boundary"""
    boundary_id: str
    contract_name: str
    function_name: str
    file_path: str
    line_number: int
    native_call_type: str  # delegatecall, extcode, staticcall, callcode
    target_address: str
    vulnerabilities: List[SolidityVulnerabilityType]
    gas_usage: int
    value_transfer: bool
    description: str


class SolidityNativeAnalyzer:
    """
    Analyzes Solidity smart contracts for vulnerabilities
    at the native code boundary.
    """
    
    def __init__(self):
        self.boundaries: List[SolidityNativeBoundary] = []
        
        # Native call patterns
        self.native_call_patterns = {
            'delegatecall': r'delegatecall\s*\(',
            'staticcall': r'staticcall\s*\(',
            'callcode': r'callcode\s*\(',
            'extcode': r'extcode\(',
            'extcodesize': r'extcodesize\(',
            'selfdestruct': r'selfdestruct\s*\(',
            'suicide': r'suicide\s*\(',
            'address.call': r'\.call\s*\{',
            'address.delegatecall': r'\.delegatecall\s*\(',
            'address.staticcall': r'\.staticcall\s*\(',
            'address.send': r'\.send\s*\(',
            'address.transfer': r'\.transfer\s*\(',
            'call.value': r'\.call\.value\s*\(',
            'call.gas': r'\.call\.gas\s*\(',
            'extcodecopy': r'extcodecopy\(',
            'create': r'create\s*\(',
            'create2': r'create2\s*\('
        }
        
        # Vulnerability patterns
        self.vulnerability_patterns = {
            SolidityVulnerabilityType.DELEGATECALL_RISK: [
                r'delegatecall\s*\([^)]*\)',
                r'address\.delegatecall',
                r'function\s+\w+\s*\(\s*address\s+\w+\s*\)'
            ],
            SolidityVulnerabilityType.EXTCODE_SIZE: [
                r'extcodesize\s*\([^)]*\)\s*>\s*0',
                r'extcodecopy\s*\([^)]*\)'
            ],
            SolidityVulnerabilityType.REENTRANCY: [
                r'call\.value\s*\([^)]*\)',
                r'\.call\s*\{[^}]*\.value\s*',
                r'external\s+call\s+before\s+update'
            ],
            SolidityVulnerabilityType.UNCHECKED_RETURN: [
                r'call\s*\([^)]*\)[^;]*;(?!\s*require)',
                r'delegatecall\s*\([^)]*\)[^;]*;(?!\s*require)',
                r'staticcall\s*\([^)]*\)[^;]*;(?!\s*require)'
            ],
            SolidityVulnerabilityType.CALL_INJECTION: [
                r'call\s*\([^)]*address\([^)]*\)[^)]*\)',
                r'delegatecall\s*\([^)]*abi\.encodeWithSelector'
            ],
            SolidityVulnerabilityType.GAS_LIMIT: [
                r'call\s*\{\s*gas:\s*\d+\s*\}',
                r'\.call\s*\{[^}]*gas:\s*\d+'
            ],
            SolidityVulnerabilityType.ACCESS_CONTROL: [
                r'function\s+\w+\s*\(\s*\)\s*public',
                r'function\s+\w+\s*\(\s*\)\s*external',
                r'onlyOwner\s*\(\s*\)\s*public'
            ],
            SolidityVulnerabilityType.ADDRESS_PREDICTABILITY: [
                r'block\.timestamp',
                r'blockhash\s*\(',
                r'block\.number'
            ]
        }
    
    def analyze_file(self, file_path: Path) -> List[SolidityNativeBoundary]:
        """Analyze a Solidity file for native code boundaries"""
        if not file_path.suffix.lower() in ['.sol']:
            return []
        
        with open(file_path, 'r') as f:
            content = f.read()
        
        boundaries = []
        
        # Extract contract name
        contract_name = self._extract_contract_name(content)
        
        # Detect native calls
        for call_type, pattern in self.native_call_patterns.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                boundary = self._create_boundary(
                    file_path, contract_name, call_type, match, content
                )
                if boundary:
                    boundaries.append(boundary)
        
        self.boundaries.extend(boundaries)
        return boundaries
    
    def analyze_directory(self, directory: Path) -> List[SolidityNativeBoundary]:
        """Analyze all Solidity files in a directory"""
        all_boundaries = []
        
        for file_path in directory.rglob('*.sol'):
            boundaries = self.analyze_file(file_path)
            all_boundaries.extend(boundaries)
        
        return all_boundaries
    
    def _extract_contract_name(self, content: str) -> str:
        """Extract contract name from Solidity code"""
        contract_match = re.search(r'contract\s+(\w+)\s*is', content)
        if contract_match:
            return contract_match.group(1)
        
        contract_match = re.search(r'contract\s+(\w+)\s*\{', content)
        if contract_match:
            return contract_match.group(1)
        
        return "Unknown"
    
    def _create_boundary(self, file_path: Path, contract_name: str,
                       call_type: str, match, content: str) -> Optional[SolidityNativeBoundary]:
        """Create a SolidityNativeBoundary from a pattern match"""
        line_number = content[:match.start()].count('\n') + 1
        
        # Extract function name if possible
        function_match = re.search(r'function\s+(\w+)', content[max(0, match.start()-200):match.start()])
        function_name = function_match.group(1) if function_match else "unknown"
        
        # Detect vulnerabilities
        vulnerabilities = self._detect_vulnerabilities(
            content, match.start(), match.end(), call_type
        )
        
        # Detect value transfer
        value_transfer = self._detect_value_transfer(content, match.start(), match.end())
        
        # Detect gas usage
        gas_usage = self._detect_gas_usage(content, match.start(), match.end())
        
        # Extract target address if possible
        target_address = self._extract_target_address(content, match.start(), match.end())
        
        return SolidityNativeBoundary(
            boundary_id=f"{contract_name}:{function_name}:{line_number}:{call_type}",
            contract_name=contract_name,
            function_name=function_name,
            file_path=str(file_path),
            line_number=line_number,
            native_call_type=call_type,
            target_address=target_address,
            vulnerabilities=vulnerabilities,
            gas_usage=gas_usage,
            value_transfer=value_transfer,
            description=f"{call_type} in {function_name} with {len(vulnerabilities)} vulnerabilities"
        )
    
    def _detect_vulnerabilities(self, content: str, start: int, 
                             end: int, call_type: str) -> List[SolidityVulnerabilityType]:
        """Detect vulnerabilities near the native call"""
        # Extract context around the call
        context_start = max(0, start - 300)
        context_end = min(len(content), end + 300)
        context = content[context_start:context_end]
        
        vulnerabilities = []
        
        # Call-specific vulnerability checks
        if call_type == 'delegatecall':
            if 'onlyOwner' not in context and 'require' not in context:
                vulnerabilities.append(SolidityVulnerabilityType.ACCESS_CONTROL)
            if 'update' not in context.lower():
                vulnerabilities.append(SolidityVulnerabilityType.REENTRANCY)
        
        elif call_type == 'extcode':
            if 'extcodesize' in context and '0' not in context.split('extcodesize')[1][:10]:
                vulnerabilities.append(SolidityVulnerabilityType.EXTCODE_SIZE)
        
        elif call_type in ['call', 'staticcall', 'callcode']:
            if 'require' not in context:
                vulnerabilities.append(SolidityVulnerabilityType.UNCHECKED_RETURN)
        
        # General vulnerability patterns
        for vuln_type, patterns in self.vulnerability_patterns.items():
            if vuln_type not in vulnerabilities:  # Avoid duplicates
                for pattern in patterns:
                    if re.search(pattern, context, re.IGNORECASE):
                        vulnerabilities.append(vuln_type)
                        break
        
        return vulnerabilities
    
    def _detect_value_transfer(self, content: str, start: int, end: int) -> bool:
        """Detect if the call involves value transfer"""
        context = content[max(0, start-100):end+100]
        return bool(re.search(r'\.value\s*\(|msg\.value', context))
    
    def _detect_gas_usage(self, content: str, start: int, end: int) -> int:
        """Detect gas usage in the call"""
        context = content[max(0, start-50):end+50]
        gas_match = re.search(r'gas:\s*(\d+)', context)
        if gas_match:
            return int(gas_match.group(1))
        return 0
    
    def _extract_target_address(self, content: str, start: int, end: int) -> str:
        """Extract the target address from the call"""
        context = content[start:end+200]
        address_match = re.search(r'address\s*\(\s*([^)]+)\s*\)', context)
        if address_match:
            return address_match.group(1)
        return "unknown"
    
    def analyze_reentrancy_patterns(self, file_path: Path) -> List[dict]:
        """Analyze specific reentrancy patterns in Solidity"""
        with open(file_path, 'r') as f:
            content = f.read()
        
        reentrancy_issues = []
        
        # Check for external calls before state updates
        external_call_pattern = r'(\w+\.call\s*\([^)]*\)|delegatecall\s*\([^)]*\)|staticcall\s*\([^)]*\))'
        state_update_pattern = r'(balance\[|totalSupply|allowance\[|mapping\[)'
        
        external_calls = list(re.finditer(external_call_pattern, content))
        state_updates = list(re.finditer(state_update_pattern, content))
        
        for i, external_call in enumerate(external_calls):
            call_pos = external_call.start()
            
            # Check if there are state updates after this call
            for state_update in state_updates:
                if state_update.start() > call_pos:
                    # Check if there's a require/check between them
                    between_text = content[call_pos:state_update.start()]
                    if 'require' not in between_text and 'if' not in between_text:
                        reentrancy_issues.append({
                            'line_number': content[:call_pos].count('\n') + 1,
                            'external_call': external_call.group(),
                            'state_update': state_update.group(),
                            'description': f"External call before state update without check"
                        })
                        break
        
        return reentrancy_issues
    
    def get_boundary_statistics(self) -> Dict:
        """Get statistics about detected native boundaries"""
        if not self.boundaries:
            return {}
        
        stats = {
            'total_boundaries': len(self.boundaries),
            'by_contract': {},
            'by_call_type': {},
            'vulnerability_frequency': {},
            'high_risk_boundaries': 0,
            'value_transfers': 0,
            'average_gas_usage': 0
        }
        
        total_gas = 0
        
        for boundary in self.boundaries:
            # Count by contract
            stats['by_contract'][boundary.contract_name] = \
                stats['by_contract'].get(boundary.contract_name, 0) + 1
            
            # Count by call type
            stats['by_call_type'][boundary.native_call_type] = \
                stats['by_call_type'].get(boundary.native_call_type, 0) + 1
            
            # Count vulnerabilities
            for vuln in boundary.vulnerabilities:
                stats['vulnerability_frequency'][vuln.value] = \
                    stats['vulnerability_frequency'].get(vuln.value, 0) + 1
            
            # Track high-risk boundaries
            if len(boundary.vulnerabilities) >= 2:
                stats['high_risk_boundaries'] += 1
            
            # Track value transfers
            if boundary.value_transfer:
                stats['value_transfers'] += 1
            
            # Accumulate gas usage
            total_gas += boundary.gas_usage
        
        if stats['total_boundaries'] > 0:
            stats['average_gas_usage'] = total_gas // stats['total_boundaries']
        
        return stats
    
    def generate_report(self) -> str:
        """Generate a comprehensive Solidity-native analysis report"""
        stats = self.get_boundary_statistics()
        
        report = "# Solidity-Native Boundary Analysis Report\n\n"
        
        if not stats:
            report += "No Solidity-native boundaries detected.\n"
            return report
        
        report += f"## Summary\n"
        report += f"- Total Native Boundaries: {stats['total_boundaries']}\n"
        report += f"- Contracts Analyzed: {len(stats['by_contract'])}\n"
        report += f"- High-Risk Boundaries: {stats['high_risk_boundaries']}\n"
        report += f"- Value Transfers: {stats['value_transfers']}\n"
        report += f"- Average Gas Usage: {stats['average_gas_usage']}\n\n"
        
        report += "## Contracts\n"
        for contract, count in stats['by_contract'].items():
            report += f"- {contract}: {count} boundaries\n"
        
        report += "\n## Native Call Types\n"
        for call_type, count in stats['by_call_type'].items():
            report += f"- {call_type}: {count} calls\n"
        
        report += "\n## Vulnerability Frequency\n"
        for vuln, count in sorted(stats['vulnerability_frequency'].items(),
                                    key=lambda x: x[1], reverse=True):
            report += f"- {vuln}: {count} occurrences\n"
        
        return report
