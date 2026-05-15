"""
WASM Runtime Analyzer for WebAssembly Security

Analyzes WebAssembly modules for security vulnerabilities
at the runtime boundary between WASM and host systems.
"""

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


class WASMVulnerabilityType(Enum):
    """Types of WASM runtime vulnerabilities"""
    LINEAR_MEMORY_OVERFLOW = "linear_memory_overflow"
    TABLE_OUT_OF_BOUNDS = "table_out_of_bounds"
    UNINITIALIZED_MEMORY = "uninitialized_memory"
    INTEGER_OVERFLOW = "integer_overflow"
    FLOATING_POINT_EXCEPTION = "floating_point_exception"
    STACK_OVERFLOW = "stack_overflow"
    CALL_STACK_OVERFLOW = "call_stack_overflow"
    HOST_IMPORT_INJECTION = "host_import_injection"
    SIDE_CHANNEL = "side_channel"
    MEMORY_LEAK = "memory_leak"
    TYPE_CONFUSION = "type_confusion"
    ABNORMAL_TERMINATION = "abnormal_termination"
    UNSAFE_HOST_CALL = "unsafe_host_call"


@dataclass
class WASMRuntimeBoundary:
    """Represents a WASM runtime boundary"""
    boundary_id: str
    module_name: str
    function_name: str
    file_path: str
    line_number: int
    boundary_type: str  # import, export, memory_access, table_access
    vulnerabilities: List[WASMVulnerabilityType]
    memory_offset: int
    table_index: int
    host_function: str
    description: str


class WASMRuntimeAnalyzer:
    """
    Analyzes WebAssembly modules for runtime boundary vulnerabilities
    between WASM and host systems.
    """
    
    def __init__(self):
        self.boundaries: List[WASMRuntimeBoundary] = []
        
        # WASM boundary patterns
        self.wasm_patterns = {
            'memory_access': [
                r'i32\.load',
                r'i64\.load',
                r'f32\.load',
                r'f64\.load',
                r'i32\.store',
                r'i64\.store',
                r'f32\.store',
                r'f64\.store'
            ],
            'table_access': [
                r'call_indirect',
                r'table\.get',
                r'table\.set',
                r'table\.grow',
                r'table\.size'
            ],
            'host_import': [
                r'call\s+import',
                r'import\s+\w+',
                r'\.import'
            ],
            'export': [
                r'export\s+',
                r'\(export\s+"'
            ]
        }
        
        # Vulnerability patterns
        self.vulnerability_patterns = {
            WASMVulnerabilityType.LINEAR_MEMORY_OVERFLOW: [
                r'i32\.load.*\+\s*\d+\s*\)',
                r'i64\.load.*\+\s*\d+\s*\)',
                r'memory\.grow'
            ],
            WASMVulnerabilityType.UNINITIALIZED_MEMORY: [
                r'i32\.load\s*\(\s*0\s*\)',
                r'i64\.load\s*\(\s*0\s*\)'
            ],
            WASMVulnerabilityType.STACK_OVERFLOW: [
                r'call\s+\w+\s*[^)]*\)',
                r'call_indirect'
            ],
            WASMVulnerabilityType.HOST_IMPORT_INJECTION: [
                r'import\s*["\'].*["\']\s*',
                r'env\.get'
            ],
            WASMVulnerabilityType.SIDE_CHANNEL: [
                r'global\.get',
                r'global\.set',
                r'performance\.now'
            ],
            WASMVulnerabilityType.UNSAFE_HOST_CALL: [
                r'import\s+env',
                r'import\s+process',
                r'import\s+fs'
            ]
        }
    
    def analyze_wat_file(self, file_path: Path) -> List[WASMRuntimeBoundary]:
        """Analyze a WebAssembly text (.wat) file for runtime boundaries"""
        if not file_path.suffix.lower() in ['.wat', '.wast']:
            return []
        
        with open(file_path, 'r') as f:
            content = f.read()
        
        boundaries = []
        
        # Extract module name
        module_name = self._extract_module_name(content)
        
        # Detect different boundary types
        for boundary_type, patterns in self.wasm_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content)
                for match in matches:
                    boundary = self._create_boundary(
                        file_path, module_name, boundary_type, match, content
                    )
                    if boundary:
                        boundaries.append(boundary)
        
        self.boundaries.extend(boundaries)
        return boundaries
    
    def analyze_wasm_binary(self, file_path: Path) -> List[WASMRuntimeBoundary]:
        """Analyze a WebAssembly binary (.wasm) file"""
        # For binary files, we would use a WASM disassembler
        # This is a placeholder for future implementation
        return []
    
    def analyze_directory(self, directory: Path) -> List[WASMRuntimeBoundary]:
        """Analyze all WASM files in a directory"""
        all_boundaries = []
        
        for file_path in directory.rglob('*.wat'):
            boundaries = self.analyze_wat_file(file_path)
            all_boundaries.extend(boundaries)
        
        for file_path in directory.rglob('*.wasm'):
            boundaries = self.analyze_wasm_binary(file_path)
            all_boundaries.extend(boundaries)
        
        return all_boundaries
    
    def _extract_module_name(self, content: str) -> str:
        """Extract module name from WASM code"""
        module_match = re.search(r'\(module\s+(\w+)', content)
        if module_match:
            return module_match.group(1)
        return "unknown"
    
    def _create_boundary(self, file_path: Path, module_name: str,
                       boundary_type: str, match, content: str) -> Optional[WASMRuntimeBoundary]:
        """Create a WASMRuntimeBoundary from a pattern match"""
        line_number = content[:match.start()].count('\n') + 1
        
        # Extract function name if possible
        func_match = re.search(r'func\s+\$?\w+', content[max(0, match.start()-50):match.start()])
        function_name = func_match.group(0) if func_match else "unknown"
        
        # Detect vulnerabilities
        vulnerabilities = self._detect_vulnerabilities(
            content, match.start(), match.end(), boundary_type
        )
        
        # Extract memory offset if applicable
        memory_offset = self._extract_memory_offset(content, match.start(), match.end())
        
        # Extract table index if applicable
        table_index = self._extract_table_index(content, match.start(), match.end())
        
        # Extract host function if applicable
        host_function = self._extract_host_function(content, match.start(), match.end())
        
        return WASMRuntimeBoundary(
            boundary_id=f"{module_name}:{function_name}:{line_number}:{boundary_type}",
            module_name=module_name,
            function_name=function_name,
            file_path=str(file_path),
            line_number=line_number,
            boundary_type=boundary_type,
            vulnerabilities=vulnerabilities,
            memory_offset=memory_offset,
            table_index=table_index,
            host_function=host_function,
            description=f"{boundary_type} in {function_name} with {len(vulnerabilities)} vulnerabilities"
        )
    
    def _detect_vulnerabilities(self, content: str, start: int, 
                             end: int, boundary_type: str) -> List[WASMVulnerabilityType]:
        """Detect vulnerabilities near the WASM boundary"""
        context = content[max(0, start-200):end+200]
        
        vulnerabilities = []
        
        for vuln_type, patterns in self.vulnerability_patterns.items():
            for pattern in patterns:
                if re.search(pattern, context, re.IGNORECASE):
                    vulnerabilities.append(vuln_type)
                    break
        
        return vulnerabilities
    
    def _extract_memory_offset(self, content: str, start: int, end: int) -> int:
        """Extract memory offset from the boundary"""
        context = content[start:end+100]
        offset_match = re.search(r'offset\s*=\s*(\d+)', context)
        if offset_match:
            return int(offset_match.group(1))
        return -1
    
    def _extract_table_index(self, content: str, start: int, end: int) -> int:
        """Extract table index from the boundary"""
        context = content[start:end+100]
        table_match = re.search(r'table\s*=\s*(\d+)', context)
        if table_match:
            return int(table_match.group(1))
        return -1
    
    def _extract_host_function(self, content: str, start: int, end: int) -> str:
        """Extract host function name from the boundary"""
        context = content[start:end+100]
        import_match = re.search(r'import\s*["\']([^"\']+)["\']', context)
        if import_match:
            return import_match.group(1)
        return "unknown"
    
    def get_boundary_statistics(self) -> Dict:
        """Get statistics about detected WASM boundaries"""
        if not self.boundaries:
            return {}
        
        stats = {
            'total_boundaries': len(self.boundaries),
            'by_module': {},
            'by_boundary_type': {},
            'vulnerability_frequency': {},
            'high_risk_boundaries': 0
        }
        
        for boundary in self.boundaries:
            # Count by module
            stats['by_module'][boundary.module_name] = \
                stats['by_module'].get(boundary.module_name, 0) + 1
            
            # Count by boundary type
            stats['by_boundary_type'][boundary.boundary_type] = \
                stats['by_boundary_type'].get(boundary.boundary_type, 0) + 1
            
            # Count vulnerabilities
            for vuln in boundary.vulnerabilities:
                stats['vulnerability_frequency'][vuln.value] = \
                    stats['vulnerability_frequency'].get(vuln.value, 0) + 1
            
            # Track high-risk boundaries
            if len(boundary.vulnerabilities) >= 2:
                stats['high_risk_boundaries'] += 1
        
        return stats
    
    def generate_report(self) -> str:
        """Generate a comprehensive WASM runtime analysis report"""
        stats = self.get_boundary_statistics()
        
        report = "# WASM Runtime Boundary Analysis Report\n\n"
        
        if not stats:
            report += "No WASM runtime boundaries detected.\n"
            return report
        
        report += f"## Summary\n"
        report += f"- Total Runtime Boundaries: {stats['total_boundaries']}\n"
        report += f"- Modules Analyzed: {len(stats['by_module'])}\n"
        report += f"- High-Risk Boundaries: {stats['high_risk_boundaries']}\n\n"
        
        report += "## Modules\n"
        for module, count in stats['by_module'].items():
            report += f"- {module}: {count} boundaries\n"
        
        report += "\n## Boundary Types\n"
        for boundary_type, count in stats['by_boundary_type'].items():
            report += f"- {boundary_type}: {count} boundaries\n"
        
        report += "\n## Vulnerability Frequency\n"
        for vuln, count in sorted(stats['vulnerability_frequency'].items(),
                                    key=lambda x: x[1], reverse=True):
            report += f"- {vuln}: {count} occurrences\n"
        
        return report
