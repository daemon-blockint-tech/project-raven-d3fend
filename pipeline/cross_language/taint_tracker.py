"""
Cross-Language Taint Tracking for Security Analysis

Tracks data flow across language boundaries to detect security vulnerabilities
that arise from improper handling of tainted data at FFI boundaries, native calls,
and cross-language interfaces.
"""

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


class TaintSource(Enum):
    """Types of taint sources"""
    USER_INPUT = "user_input"
    NETWORK = "network"
    FILE = "file"
    DATABASE = "database"
    ENVIRONMENT = "environment"
    CRYPTO = "crypto"
    EXTERNAL_API = "external_api"
    UNTRUSTED_DATA = "untrusted_data"


class TaintSink(Enum):
    """Types of taint sinks (vulnerable operations)"""
    SQL_QUERY = "sql_query"
    COMMAND_EXECUTION = "command_execution"
    FILE_WRITE = "file_write"
    NETWORK_SEND = "network_send"
    CODE_EVAL = "code_eval"
    MEMORY_WRITE = "memory_write"
    CRYPTO_OPERATION = "crypto_operation"
    ACCESS_CONTROL = "access_control"


@dataclass
class TaintFlow:
    """Represents a taint flow from source to sink"""
    flow_id: str
    source_type: TaintSource
    source_location: str  # file:line
    sink_type: TaintSink
    sink_location: str  # file:line
    language_boundary: str  # e.g., "Python->C", "Rust->JavaScript"
    path: List[str]  # intermediate functions/operations
    vulnerability_type: str
    confidence: float
    description: str


@dataclass
class TaintAnalysisResult:
    """Result of taint analysis on a codebase"""
    total_flows: int
    flows: List[TaintFlow]
    by_language_pair: Dict[str, int]
    by_vulnerability_type: Dict[str, int]
    high_confidence_flows: int
    cross_boundary_flows: int


class CrossLanguageTaintTracker:
    """
    Tracks taint flow across language boundaries to detect
    security vulnerabilities at FFI interfaces and cross-language calls.
    """
    
    def __init__(self):
        self.flows: List[TaintFlow] = []
        
        # Taint source patterns per language
        self.source_patterns = {
            'python': {
                TaintSource.USER_INPUT: [
                    r'input\s*\(',
                    r'sys\.argv',
                    r'os\.environ',
                    r'request\.args',
                    r'request\.form',
                    r'request\.json',
                    r'flask\.request',
                ],
                TaintSource.NETWORK: [
                    r'urllib\.request',
                    r'requests\.get',
                    r'httpx\.get',
                    r'aiohttp\.get',
                    r'socket\.recv',
                ],
                TaintSource.FILE: [
                    r'open\s*\(',
                    r'with open\s*\(',
                    r'Path\.read_text',
                    r'json\.load',
                ],
            },
            'rust': {
                TaintSource.USER_INPUT: [
                    r'stdin\(\)',
                    r'env::var',
                    r'args\(\)',
                ],
                TaintSource.NETWORK: [
                    r'reqwest::get',
                    r'ureq::get',
                    r'hyper::get',
                ],
                TaintSource.FILE: [
                    r'File::open',
                    r'std::fs::read_to_string',
                ],
            },
            'javascript': {
                TaintSource.USER_INPUT: [
                    r'prompt\s*\(',
                    r'process\.argv',
                    r'process\.env',
                    r'require\(["\']body-parser["\']\)',
                ],
                TaintSource.NETWORK: [
                    r'fetch\s*\(',
                    r'axios\.get',
                    r'XMLHttpRequest',
                    r'WebSocket',
                ],
                TaintSource.FILE: [
                    r'fs\.readFileSync',
                    r'fs\.readFile',
                    r'require\(["\']fs["\']\)',
                ],
            },
            'go': {
                TaintSource.USER_INPUT: [
                    r'fmt\.Scan',
                    r'os\.Args',
                    r'os\.Getenv',
                ],
                TaintSource.NETWORK: [
                    r'http\.Get',
                    r'net/http\.Get',
                ],
                TaintSource.FILE: [
                    r'ioutil\.ReadFile',
                    r'os\.Open',
                ],
            },
        }
        
        # Taint sink patterns per language
        self.sink_patterns = {
            'python': {
                TaintSink.SQL_QUERY: [
                    r'cursor\.execute',
                    r'cursor\.executemany',
                    r'\.execute\s*\(',
                    r'sqlite3\.execute',
                ],
                TaintSink.COMMAND_EXECUTION: [
                    r'subprocess\.(call|run|Popen)',
                    r'os\.system',
                    r'eval\s*\(',
                    r'exec\s*\(',
                ],
                TaintSink.FILE_WRITE: [
                    r'\.write\s*\(',
                    r'\.writelines\s*\(',
                    r'open\s*\([^)]*,\s*["\']w["\']',
                ],
                TaintSink.NETWORK_SEND: [
                    r'requests\.(post|put|patch)',
                    r'urllib\.request\.urlopen',
                    r'socket\.send',
                ],
            },
            'rust': {
                TaintSink.SQL_QUERY: [
                    r'conn\.execute',
                    r'query\.execute',
                ],
                TaintSink.COMMAND_EXECUTION: [
                    r'Command::new',
                    r'std::process::Command::new',
                ],
                TaintSink.FILE_WRITE: [
                    r'File::create',
                    r'std::fs::write',
                ],
                TaintSink.MEMORY_WRITE: [
                    r'ptr::write',
                    r'std::ptr::write',
                ],
            },
            'javascript': {
                TaintSink.SQL_QUERY: [
                    r'query\.(exec|execute)',
                    r'db\.query',
                ],
                TaintSink.COMMAND_EXECUTION: [
                    r'child_process\.(exec|spawn)',
                    r'eval\s*\(',
                    r'Function\s*\(',
                ],
                TaintSink.FILE_WRITE: [
                    r'fs\.writeFileSync',
                    r'fs\.writeFile',
                ],
                TaintSink.CODE_EVAL: [
                    r'eval\s*\(',
                    r'new Function',
                ],
            },
            'go': {
                TaintSink.SQL_QUERY: [
                    r'db\.Exec',
                    r'query\.Exec',
                ],
                TaintSink.COMMAND_EXECUTION: [
                    r'exec\.Command',
                    r'os/exec\.Command',
                ],
                TaintSink.FILE_WRITE: [
                    r'ioutil\.WriteFile',
                ],
            },
        }
        
        # FFI boundary patterns
        self.ffi_patterns = {
            'python': [
                r'ctypes\.',
                r'cffi\.',
                r'pybind11',
                r'swig',
            ],
            'rust': [
                r'extern "C"',
                r'#\[no_mangle\]',
                r'unsafe\s+fn',
                r'libc::',
                r'winapi::',
            ],
            'javascript': [
                r'WebAssembly\.',
                r'wasm\.',
                r'FFI\.',
                r'N-API\.',
            ],
            'go': [
                r'import "C"',
                r'//extern',
                r'#cgo',
            ],
        }
    
    def analyze_directory(self, directory: Path) -> TaintAnalysisResult:
        """Analyze a directory for cross-language taint flows"""
        all_flows = []
        
        # Scan all supported language files
        for lang in self.source_patterns.keys():
            for file_path in self._find_language_files(directory, lang):
                flows = self.analyze_file(file_path, lang)
                all_flows.extend(flows)
        
        self.flows.extend(all_flows)
        return self._generate_analysis_result(all_flows)
    
    def _find_language_files(self, directory: Path, language: str) -> List[Path]:
        """Find files of a specific language"""
        extensions = {
            'python': ['.py'],
            'rust': ['.rs'],
            'javascript': ['.js', '.ts', '.jsx', '.tsx'],
            'go': ['.go'],
        }
        
        lang_exts = extensions.get(language, [])
        files = []
        for ext in lang_exts:
            files.extend(directory.rglob(f'*{ext}'))
        
        return files
    
    def analyze_file(self, file_path: Path, language: str) -> List[TaintFlow]:
        """Analyze a single file for taint flows"""
        with open(file_path, 'r') as f:
            content = f.read()
        
        flows = []
        
        # Detect FFI boundaries
        ffi_boundaries = self._detect_ffi_boundaries(content, language)
        
        # Find taint sources
        sources = self._find_taint_sources(content, language, file_path)
        
        # Find taint sinks
        sinks = self._find_taint_sinks(content, language, file_path)
        
        # Match sources to sinks with path analysis
        for source in sources:
            for sink in sinks:
                if self._is_potential_flow(source, sink, content):
                    flow = self._create_taint_flow(
                        source, sink, ffi_boundaries, content, file_path
                    )
                    if flow:
                        flows.append(flow)
        
        return flows
    
    def _detect_ffi_boundaries(self, content: str, language: str) -> List[str]:
        """Detect FFI boundary markers in code"""
        boundaries = []
        patterns = self.ffi_patterns.get(language, [])
        
        for pattern in patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                boundaries.append(f"{pattern}:{line_num}")
        
        return boundaries
    
    def _find_taint_sources(self, content: str, language: str, 
                           file_path: Path) -> List[Tuple[TaintSource, str, int]]:
        """Find taint sources in code"""
        sources = []
        patterns = self.source_patterns.get(language, {})
        
        for source_type, regex_patterns in patterns.items():
            for pattern in regex_patterns:
                matches = re.finditer(pattern, content)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    location = f"{file_path.name}:{line_num}"
                    sources.append((source_type, location, match.start()))
        
        return sources
    
    def _find_taint_sinks(self, content: str, language: str,
                         file_path: Path) -> List[Tuple[TaintSink, str, int]]:
        """Find taint sinks in code"""
        sinks = []
        patterns = self.sink_patterns.get(language, {})
        
        for sink_type, regex_patterns in patterns.items():
            for pattern in regex_patterns:
                matches = re.finditer(pattern, content)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    location = f"{file_path.name}:{line_num}"
                    sinks.append((sink_type, location, match.start()))
        
        return sinks
    
    def _is_potential_flow(self, source: Tuple, sink: Tuple, 
                          content: str) -> bool:
        """Check if a source could flow to a sink"""
        source_type, source_loc, source_pos = source
        sink_type, sink_loc, sink_pos = sink
        
        # Sink must come after source
        if sink_pos <= source_pos:
            return False
        
        # Check for sanitization between source and sink
        between_text = content[source_pos:sink_pos]
        
        # Common sanitization patterns
        sanitization_patterns = [
            r'\.strip\s*\(',
            r'\.lower\s*\(',
            r'\.upper\s*\(',
            r're\.sub\s*\(',
            r'replace\s*\(',
            r'validate',
            r'sanitize',
            r'escape',
            r'clean',
        ]
        
        for pattern in sanitization_patterns:
            if re.search(pattern, between_text, re.IGNORECASE):
                return False  # Flow is sanitized
        
        return True
    
    def _create_taint_flow(self, source: Tuple, sink: Tuple,
                          ffi_boundaries: List[str], content: str,
                          file_path: Path) -> Optional[TaintFlow]:
        """Create a taint flow object"""
        source_type, source_loc, _ = source
        sink_type, sink_loc, _ = sink
        
        # Determine vulnerability type based on source-sink pair
        vuln_type = self._classify_vulnerability(source_type, sink_type)
        
        # Calculate confidence based on proximity and FFI boundaries
        distance = content.find(sink_loc.split(':')[0]) - content.find(source_loc.split(':')[0])
        confidence = min(1.0, max(0.3, 1.0 - (distance / 1000)))
        
        # Check if flow crosses language boundary
        language_boundary = "none"
        if ffi_boundaries:
            language_boundary = f"{file_path.suffix[1:]}->native"
        
        # Extract path (simplified)
        path = [source_loc, sink_loc]
        
        flow_id = f"{source_loc}->{sink_loc}"
        
        return TaintFlow(
            flow_id=flow_id,
            source_type=source_type,
            source_location=source_loc,
            sink_type=sink_type,
            sink_location=sink_loc,
            language_boundary=language_boundary,
            path=path,
            vulnerability_type=vuln_type,
            confidence=confidence,
            description=f"{vuln_type}: {source_type.value} at {source_loc} flows to {sink_type.value} at {sink_loc}"
        )
    
    def _classify_vulnerability(self, source: TaintSource, 
                             sink: TaintSink) -> str:
        """Classify the vulnerability type"""
        vuln_map = {
            (TaintSource.USER_INPUT, TaintSink.SQL_QUERY): "SQL Injection",
            (TaintSource.USER_INPUT, TaintSink.COMMAND_EXECUTION): "Command Injection",
            (TaintSource.USER_INPUT, TaintSink.FILE_WRITE): "Path Traversal",
            (TaintSource.USER_INPUT, TaintSink.CODE_EVAL): "Code Injection",
            (TaintSource.NETWORK, TaintSink.SQL_QUERY): "Second-Order SQL Injection",
            (TaintSource.NETWORK, TaintSink.COMMAND_EXECUTION): "Remote Code Execution",
            (TaintSource.NETWORK, TaintSink.CODE_EVAL): "Remote Code Execution",
            (TaintSource.FILE, TaintSink.SQL_QUERY): "File-based SQL Injection",
            (TaintSource.FILE, TaintSink.COMMAND_EXECUTION): "Command Injection from File",
            (TaintSource.DATABASE, TaintSink.SQL_QUERY): "Second-Order SQL Injection",
            (TaintSource.DATABASE, TaintSink.COMMAND_EXECUTION): "Command Injection from DB",
            (TaintSource.ENVIRONMENT, TaintSink.SQL_QUERY): "Environment-based SQL Injection",
            (TaintSource.ENVIRONMENT, TaintSink.COMMAND_EXECUTION): "Environment-based Command Injection",
        }
        
        return vuln_map.get((source, sink), "Unsanitized Data Flow")
    
    def _generate_analysis_result(self, flows: List[TaintFlow]) -> TaintAnalysisResult:
        """Generate analysis result statistics"""
        by_lang_pair = {}
        by_vuln_type = {}
        high_confidence = 0
        cross_boundary = 0
        
        for flow in flows:
            # Count by language pair
            lang_pair = flow.language_boundary
            by_lang_pair[lang_pair] = by_lang_pair.get(lang_pair, 0) + 1
            
            # Count by vulnerability type
            vuln_type = flow.vulnerability_type
            by_vuln_type[vuln_type] = by_vuln_type.get(vuln_type, 0) + 1
            
            # Count high confidence flows
            if flow.confidence >= 0.7:
                high_confidence += 1
            
            # Count cross-boundary flows
            if flow.language_boundary != "none":
                cross_boundary += 1
        
        return TaintAnalysisResult(
            total_flows=len(flows),
            flows=flows,
            by_language_pair=by_lang_pair,
            by_vulnerability_type=by_vuln_type,
            high_confidence_flows=high_confidence,
            cross_boundary_flows=cross_boundary
        )
    
    def generate_report(self) -> str:
        """Generate a comprehensive taint analysis report"""
        result = self._generate_analysis_result(self.flows)
        
        report = "# Cross-Language Taint Analysis Report\n\n"
        
        if result.total_flows == 0:
            report += "No taint flows detected.\n"
            return report
        
        report += "## Summary\n"
        report += f"- Total Taint Flows: {result.total_flows}\n"
        report += f"- High Confidence Flows: {result.high_confidence_flows}\n"
        report += f"- Cross-Boundary Flows: {result.cross_boundary_flows}\n\n"
        
        report += "## Language Boundaries\n"
        for lang_pair, count in result.by_language_pair.items():
            report += f"- {lang_pair}: {count} flows\n"
        
        report += "\n## Vulnerability Types\n"
        for vuln_type, count in sorted(result.by_vulnerability_type.items(),
                                      key=lambda x: x[1], reverse=True):
            report += f"- {vuln_type}: {count} occurrences\n"
        
        report += "\n## High-Risk Flows\n"
        for flow in result.flows:
            if flow.confidence >= 0.7:
                report += f"- [{flow.flow_id}] {flow.description} (confidence: {flow.confidence:.2f})\n"
        
        return report
