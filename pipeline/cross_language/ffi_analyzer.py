"""
FFI Boundary Analyzer for Cross-Language Security

Analyzes Foreign Function Interface (FFI) boundaries between languages
to detect security vulnerabilities at language boundaries.
"""

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
import ast


class FFIVulnerabilityType(Enum):
    """Types of FFI vulnerabilities"""
    UNSAFE_BLOCK = "unsafe_block"
    TYPE_MISMATCH = "type_mismatch"
    BUFFER_OVERFLOW = "buffer_overflow"
    MEMORY_LEAK = "memory_leak"
    RACE_CONDITION = "race_condition"
    EXCEPTION_UNWINDING = "exception_unwinding"
    THREAD_SAFETY = "thread_safety"
    CALLBACK_LIFETIME = "callback_lifetime"
    STRING_ENCODING = "string_encoding"
    ABI_MISMATCH = "abi_mismatch"


@dataclass
class FFIBoundary:
    """Represents an FFI boundary between languages"""
    boundary_id: str
    source_language: str  # e.g., "rust", "go", "python"
    target_language: str  # e.g., "c", "cpp"
    boundary_function: str
    file_path: str
    line_number: int
    ffi_type: str  # e.g., "extern \"C\"", "ctypes", "cgo"
    vulnerabilities: List[FFIVulnerabilityType]
    parameters: List[dict]
    return_type: str
    description: str


class FFIBoundaryAnalyzer:
    """
    Analyzes FFI boundaries to detect security vulnerabilities
    at language interfaces.
    """
    
    def __init__(self):
        self.boundaries: List[FFIBoundary] = []
        
        # FFI pattern definitions
        self.ffi_patterns = {
            'rust': {
                'extern_c': r'extern\s*"C"\s*fn\s+(\w+)',
                'unsafe_block': r'unsafe\s*\{',
                'repr_c': r'#\[repr\(C\)\]',
                'no_mangle': r'#\[no_mangle\]'
            },
            'python': {
                'ctypes': r'ctypes\.',
                'cffi': r'cffi\.',
                'pybind11': r'pybind11::',
                'cython': r'cdef\s+extern'
            },
            'go': {
                'cgo': r'//\s*#include\s*"C"',
                'cimport': r'C\.',
                'unsafe_pointer': r'unsafe\.Pointer'
            },
            'node': {
                'napi': r'napi_',
                'node_ffi': r'node-ffi',
                'neon': r'neon\.'
            },
            'java': {
                'jni': r'JNI_',
                'native': r'native\s+\w+\('
            }
        }
        
        # Vulnerability patterns
        self.vulnerability_patterns = {
            FFIVulnerabilityType.UNSAFE_BLOCK: [
                r'unsafe\s*\{[^}]*\}\s*\)',
                r'transmute_copy',
                r'raw_pointer'
            ],
            FFIVulnerabilityType.BUFFER_OVERFLOW: [
                r'memcpy.*\+',
                r'strcpy.*\+',
                r'buffer.*size.*\+'
            ],
            FFIVulnerabilityType.MEMORY_LEAK: [
                r'malloc.*without.*free',
                r'new.*without.*delete',
                r'Box::leak'
            ],
            FFIVulnerabilityType.RACE_CONDITION: [
                r'Arc::clone',
                r'Rc::clone',
                r'static.*mut'
            ],
            FFIVulnerabilityType.CALLBACK_LIFETIME: [
                r'callback.*lifetime',
                r'closure.*lifetime',
                r'static.*callback'
            ],
            FFIVulnerabilityType.STRING_ENCODING: [
                r'string.*null.*terminated',
                r'CStr\(',
                r'CString::'
            ]
        }
    
    def analyze_file(self, file_path: Path) -> List[FFIBoundary]:
        """Analyze a file for FFI boundaries"""
        language = self._detect_language(file_path)
        
        if language not in self.ffi_patterns:
            return []
        
        with open(file_path, 'r') as f:
            content = f.read()
        
        boundaries = []
        
        # Detect FFI function declarations
        for pattern_name, pattern in self.ffi_patterns[language].items():
            matches = re.finditer(pattern, content)
            for match in matches:
                boundary = self._create_boundary(
                    file_path, language, match, pattern_name, content
                )
                if boundary:
                    boundaries.append(boundary)
        
        self.boundaries.extend(boundaries)
        return boundaries
    
    def analyze_directory(self, directory: Path) -> List[FFIBoundary]:
        """Analyze all files in a directory for FFI boundaries"""
        all_boundaries = []
        
        for file_path in directory.rglob('*'):
            if file_path.is_file() and self._is_code_file(file_path):
                boundaries = self.analyze_file(file_path)
                all_boundaries.extend(boundaries)
        
        return all_boundaries
    
    def _detect_language(self, file_path: Path) -> Optional[str]:
        """Detect the programming language from file extension"""
        ext_map = {
            '.rs': 'rust',
            '.py': 'python',
            '.pyx': 'python',
            '.go': 'go',
            '.js': 'node',
            '.ts': 'node',
            '.java': 'java',
            '.c': 'c',
            '.cpp': 'cpp',
            '.h': 'c',
            '.hpp': 'cpp'
        }
        
        ext = file_path.suffix.lower()
        return ext_map.get(ext)
    
    def _is_code_file(self, file_path: Path) -> bool:
        """Check if file is a code file"""
        code_extensions = {'.rs', '.py', '.pyx', '.go', '.js', '.ts', 
                        '.java', '.c', '.cpp', '.h', '.hpp'}
        return file_path.suffix.lower() in code_extensions
    
    def _create_boundary(self, file_path: Path, language: str, 
                       match, pattern_name: str, content: str) -> Optional[FFIBoundary]:
        """Create an FFIBoundary object from a pattern match"""
        line_number = content[:match.start()].count('\n') + 1
        
        # Extract function name
        if pattern_name == 'extern_c':
            function_name = match.group(1)
        else:
            function_name = f"boundary_{match.start()}"
        
        # Determine target language (usually C/C++)
        target_language = 'c' if language in ['rust', 'go'] else 'cpp'
        
        # Detect vulnerabilities
        vulnerabilities = self._detect_vulnerabilities(
            content, match.start(), match.end()
        )
        
        return FFIBoundary(
            boundary_id=f"{file_path.name}:{line_number}:{function_name}",
            source_language=language,
            target_language=target_language,
            boundary_function=function_name,
            file_path=str(file_path),
            line_number=line_number,
            ffi_type=pattern_name,
            vulnerabilities=vulnerabilities,
            parameters=[],
            return_type="unknown",
            description=f"{language} to {target_language} FFI boundary at line {line_number}"
        )
    
    def _detect_vulnerabilities(self, content: str, 
                              start: int, end: int) -> List[FFIVulnerabilityType]:
        """Detect vulnerabilities near the FFI boundary"""
        # Extract context around the boundary
        context_start = max(0, start - 500)
        context_end = min(len(content), end + 500)
        context = content[context_start:context_end]
        
        vulnerabilities = []
        
        for vuln_type, patterns in self.vulnerability_patterns.items():
            for pattern in patterns:
                if re.search(pattern, context, re.IGNORECASE):
                    vulnerabilities.append(vuln_type)
                    break  # One match per vulnerability type
        
        return vulnerabilities
    
    def analyze_rust_ffi(self, file_path: Path) -> List[FFIBoundary]:
        """Specialized analysis for Rust FFI boundaries"""
        with open(file_path, 'r') as f:
            content = f.read()
        
        boundaries = []
        
        # Detect extern "C" functions
        extern_c_matches = re.finditer(r'extern\s*"C"\s*\{([^}]+)\}', content)
        for match in extern_c_matches:
            block_content = match.group(1)
            functions = re.findall(r'fn\s+(\w+)\s*\([^)]*\)', block_content)
            
            for func in functions:
                line_number = content[:match.start()].count('\n') + 1 + \
                            block_content[:block_content.find(func)].count('\n')
                
                vulnerabilities = []
                
                # Check for unsafe blocks in extern C
                if 'unsafe' in block_content:
                    vulnerabilities.append(FFIVulnerabilityType.UNSAFE_BLOCK)
                
                # Check for manual memory management
                if any(keyword in block_content.lower() for keyword in 
                       ['malloc', 'free', 'alloc', 'dealloc']):
                    vulnerabilities.append(FFIVulnerabilityType.MEMORY_LEAK)
                
                # Check for raw pointers
                if '*mut' in block_content or '*const' in block_content:
                    vulnerabilities.append(FFIVulnerabilityType.UNSAFE_BLOCK)
                
                boundaries.append(FFIBoundary(
                    boundary_id=f"{file_path.name}:{line_number}:{func}",
                    source_language="rust",
                    target_language="c",
                    boundary_function=func,
                    file_path=str(file_path),
                    line_number=line_number,
                    ffi_type="extern_c",
                    vulnerabilities=vulnerabilities,
                    parameters=[],
                    return_type="unknown",
                    description=f"Rust extern C function {func} with {len(vulnerabilities)} vulnerabilities"
                ))
        
        return boundaries
    
    def analyze_python_ctypes(self, file_path: Path) -> List[FFIBoundary]:
        """Specialized analysis for Python ctypes FFI"""
        with open(file_path, 'r') as f:
            content = f.read()
        
        boundaries = []
        
        # Detect ctypes usage
        ctypes_patterns = [
            r'ctypes\.CDLL\(([^)]+)\)',
            r'ctypes\.WinDLL\(([^)]+)\)',
            r'ctypes\.CFUNCTYPE\(([^)]+)\)',
            r'ctypes\.POINTER\(([^)]+)\)'
        ]
        
        for pattern in ctypes_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                vulnerabilities = []
                
                # Check for unsafe patterns
                if 'POINTER' in match.group() and 'c_void_p' not in match.group():
                    vulnerabilities.append(FFIVulnerabilityType.TYPE_MISMATCH)
                
                boundaries.append(FFIBoundary(
                    boundary_id=f"{file_path.name}:{line_number}:{match.group()[:30]}",
                    source_language="python",
                    target_language="c",
                    boundary_function=match.group(),
                    file_path=str(file_path),
                    line_number=line_number,
                    ffi_type="ctypes",
                    vulnerabilities=vulnerabilities,
                    parameters=[],
                    return_type="unknown",
                    description=f"Python ctypes boundary with {len(vulnerabilities)} vulnerabilities"
                ))
        
        return boundaries
    
    def get_boundary_statistics(self) -> Dict:
        """Get statistics about detected FFI boundaries"""
        if not self.boundaries:
            return {}
        
        stats = {
            'total_boundaries': len(self.boundaries),
            'by_source_language': {},
            'by_target_language': {},
            'by_ffi_type': {},
            'vulnerability_frequency': {},
            'most_vulnerable_files': {}
        }
        
        for boundary in self.boundaries:
            # Count by source language
            stats['by_source_language'][boundary.source_language] = \
                stats['by_source_language'].get(boundary.source_language, 0) + 1
            
            # Count by target language
            stats['by_target_language'][boundary.target_language] = \
                stats['by_target_language'].get(boundary.target_language, 0) + 1
            
            # Count by FFI type
            stats['by_ffi_type'][boundary.ffi_type] = \
                stats['by_ffi_type'].get(boundary.ffi_type, 0) + 1
            
            # Count vulnerabilities
            for vuln in boundary.vulnerabilities:
                stats['vulnerability_frequency'][vuln.value] = \
                    stats['vulnerability_frequency'].get(vuln.value, 0) + 1
            
            # Track most vulnerable files
            file_path = boundary.file_path
            if file_path not in stats['most_vulnerable_files']:
                stats['most_vulnerable_files'][file_path] = 0
            stats['most_vulnerable_files'][file_path] += len(boundary.vulnerabilities)
        
        return stats
    
    def generate_report(self) -> str:
        """Generate a comprehensive FFI analysis report"""
        stats = self.get_boundary_statistics()
        
        report = "# FFI Boundary Analysis Report\n\n"
        
        if not stats:
            report += "No FFI boundaries detected.\n"
            return report
        
        report += f"## Summary\n"
        report += f"- Total FFI Boundaries: {stats['total_boundaries']}\n"
        report += f"- Source Languages: {len(stats['by_source_language'])}\n"
        report += f"- Target Languages: {len(stats['by_target_language'])}\n"
        report += f"- Vulnerabilities Found: {sum(stats['vulnerability_frequency'].values())}\n\n"
        
        report += "## Source Languages\n"
        for lang, count in stats['by_source_language'].items():
            report += f"- {lang}: {count} boundaries\n"
        
        report += "\n## FFI Types\n"
        for ffi_type, count in stats['by_ffi_type'].items():
            report += f"- {ffi_type}: {count} boundaries\n"
        
        report += "\n## Vulnerability Frequency\n"
        for vuln, count in sorted(stats['vulnerability_frequency'].items(),
                                    key=lambda x: x[1], reverse=True):
            report += f"- {vuln}: {count} occurrences\n"
        
        report += "\n## Most Vulnerable Files\n"
        sorted_files = sorted(stats['most_vulnerable_files'].items(),
                             key=lambda x: x[1], reverse=True)
        for file_path, vuln_count in sorted_files[:10]:
            report += f"- {file_path}: {vuln_count} vulnerabilities\n"
        
        return report
