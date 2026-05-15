"""
Symbolic Execution and Formal Verification for Prove Stage

Extends the prove stage with symbolic execution for logic bugs and
formal verification for cryptographic properties.
"""

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from abc import ABC, abstractmethod


class VerificationType(Enum):
    """Types of verification methods"""
    SYMBOLIC_EXECUTION = "symbolic_execution"
    MODEL_CHECKING = "model_checking"
    THEOREM_PROVING = "theorem_proving"
    SAT_SOLVING = "sat_solving"
    BOUNDED_MODEL_CHECKING = "bounded_model_checking"
    ABSTRACT_INTERPRETATION = "abstract_interpretation"


class PropertyType(Enum):
    """Types of properties to verify"""
    MEMORY_SAFETY = "memory_safety"
    THREAD_SAFETY = "thread_safety"
    ARITHMETIC_CORRECTNESS = "arithmetic_correctness"
    CRYPTOGRAPHIC_CORRECTNESS = "cryptographic_correctness"
    FUNCTIONAL_CORRECTNESS = "functional_correctness"
    RESOURCE_LEAK = "resource_leak"
    DIVISION_BY_ZERO = "division_by_zero"
    BUFFER_OVERFLOW = "buffer_overflow"
    INTEGER_OVERFLOW = "integer_overflow"
    NULL_DEREFERENCE = "null_dereference"
    TYPE_SAFETY = "type_safety"


@dataclass
class VerificationTarget:
    """Represents a target for verification"""
    target_id: str
    file_path: str
    function_name: str
    line_number: int
    property_type: PropertyType
    description: str
    confidence: float


@dataclass
class VerificationResult:
    """Result of a verification attempt"""
    result_id: str
    target_id: str
    verification_type: VerificationType
    status: str  # "verified", "violated", "unknown", "error"
    counterexample: Optional[str]
    proof_trace: Optional[str]
    confidence: float
    execution_time: float
    solver_used: str


@dataclass
class FormalVerificationReport:
    """Comprehensive report of formal verification results"""
    report_id: str
    total_targets: int
    verified: int
    violated: int
    unknown: int
    errors: int
    results: List[VerificationResult]
    by_property_type: Dict[ PropertyType, Dict[str, int] ]
    by_verification_type: Dict[ VerificationType, Dict[str, int] ]


class SymbolicExecutor(ABC):
    """Base class for symbolic execution engines"""
    
    @abstractmethod
    def execute(self, target: VerificationTarget) -> VerificationResult:
        """Execute symbolic execution on a target"""
        pass
    
    @abstractmethod
    def get_solver_info(self) -> str:
        """Get information about the solver"""
        pass


class CBMCExecutor(SymbolicExecutor):
    """CBMC (C Bounded Model Checker) symbolic execution"""
    
    def __init__(self):
        self.solver_name = "CBMC"
    
    def execute(self, target: VerificationTarget) -> VerificationResult:
        """Execute CBMC on a target"""
        # In a real implementation, this would invoke CBMC via subprocess
        # For now, return a placeholder result
        return VerificationResult(
            result_id=f"cbmc_{target.target_id}",
            target_id=target.target_id,
            verification_type=VerificationType.BOUNDED_MODEL_CHECKING,
            status="unknown",
            counterexample=None,
            proof_trace=None,
            confidence=0.5,
            execution_time=0.0,
            solver_used=self.solver_name
        )
    
    def get_solver_info(self) -> str:
        """Get CBMC solver information"""
        return f"{self.solver_name} (C Bounded Model Checker) - C/C++"


class KLEEExecutor(SymbolicExecutor):
    """KLEE symbolic execution engine"""
    
    def __init__(self):
        self.solver_name = "KLEE"
    
    def execute(self, target: VerificationTarget) -> VerificationResult:
        """Execute KLEE on a target"""
        return VerificationResult(
            result_id=f"klee_{target.target_id}",
            target_id=target.target_id,
            verification_type=VerificationType.SYMBOLIC_EXECUTION,
            status="unknown",
            counterexample=None,
            proof_trace=None,
            confidence=0.5,
            execution_time=0.0,
            solver_used=self.solver_name_name
        )
    
    def get_solver_info(self) -> str:
        return f"{self.solver_name} (KLEE Symbolic Execution Engine) - C/C++"


class Z3Solver(SymbolicExecutor):
    """Z3 SMT solver for theorem proving"""
    
    def __init__(self):
        self.solver_name = "Z3"
    
    def execute(self, target: VerificationTarget) -> VerificationResult:
        """Execute Z3 on a target"""
        return VerificationResult(
            result_id=f"z3_{target.target_id}",
            target_id=target.target_id,
            verification_type=VerificationType.SAT_SOLVING,
            status="unknown",
            counterexample=None,
            proof_trace=None,
            confidence=0.5,
            execution_time=0.0,
            solver_used=self.solver_name
        )
    
    def get_solver_info(self) -> str:
        return f"{self.solver_name} (Z3 SMT Solver) - Multi-theory"


class CryptographicVerifier:
    """Verifier for cryptographic properties"""
    
    def __init__(self):
        self.crypto_properties = {
            PropertyType.CRYPTOGRAPHIC_CORRECTNESS: [
                'key_size',
                'nonce_reuse',
                'padding_oracle',
                'timing_attack',
                'side_channel',
                'weak_randomness'
            ],
        }
    
    def verify_property(self, target: VerificationTarget) -> VerificationResult:
        """Verify a cryptographic property"""
        # Check for common crypto vulnerabilities in code
        with open(target.file_path, 'r') as f:
            content = f.read()
        
        vulnerabilities = []
        
        # Check for hardcoded keys
        if re.search(r'(key|secret|password)\s*=\s*["\'].*["\']', content, re.IGNORECASE):
            vulnerabilities.append("hardcoded_secret")
        
        # Check for weak crypto patterns
        weak_patterns = [
            (r'MD5', 'md5'),
            (r'SHA1', 'sha1'),
            (r'DES', 'des'),
            (r'RC4', 'rc4'),
        ]
        
        for pattern, name in weak_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                vulnerabilities.append(f"weak_algorithm_{name}")
        
        if vulnerabilities:
            return VerificationResult(
                result_id=f"crypto_{target.target_id}",
                target_id=target.target_id,
                verification_type=VerificationType.THEOREM_PROVING,
                status="violated",
                counterexample=', '.join(vulnerabilities),
                proof_trace=None,
                confidence=0.8,
                execution_time=0.0,
                solver_used="static_analysis"
            )
        
        return VerificationResult(
            result_id=f"crypto_{target.target_id}",
            target_id=target.target_id,
            verification_type=VerificationType.THEOREM_PROVING,
            status="verified",
            counterexample=None,
            proof_trace="No crypto vulnerabilities found",
            confidence=0.7,
            execution_time=0.0,
            solver_used="static_analysis"
        )


class FormalVerificationEngine:
    """
    Orchestrates symbolic execution and formal verification
    for the prove stage.
    """
    
    def __init__(self):
        self.executors: Dict[str, SymbolicExecutor] = {
            'cbmc': CBMCExecutor(),
            'klee': KLEEExecutor(),
            'z3': Z3Solver(),
        }
        self.crypto_verifier = CryptographicVerifier()
        self.targets: List[VerificationTarget] = []
        self.results: List[VerificationResult] = []
        
        # Property patterns to detect
        self.property_patterns = {
            PropertyType.MEMORY_SAFETY: [
                r'(malloc|free|alloc|dealloc)',
                r'(new\s+|delete\s+)',
                r'(unique_ptr|shared_ptr)',
            ],
            PropertyType.THREAD_SAFETY: [
                r'(pthread|thread\s+|mutex\s+)',
                r'(lock|unlock|atomic)',
                r'(race|deadlock)',
            ],
            PropertyType.ARITHMETIC_CORRECTNESS: [
                r'(\+\+|\-\-|\*|\/)',
                r'(overflow|underflow)',
                r'(division|modulo)',
            ],
            PropertyType.BUFFER_OVERFLOW: [
                r'(strcpy|strcat|memcpy)',
                r'(buffer|sprintf)',
                r'(gets|scanf)',
            ],
            PropertyType.NULL_DEREFERENCE: [
                r'\*\s*(?!0)',
                r'->\s*(?!NULL)',
                r'\.+\s*(?!nullptr)',
            ],
            PropertyType.TYPE_SAFETY: [
                r'(cast|reinterpret_cast)',
                r'(void\s*\*)',
                r'(union\s*\{)',
            ],
        }
    
    def identify_verification_targets(self, code_path: Path, 
                                     language: str = 'c') -> List[VerificationTarget]:
        """Identify targets for formal verification from code"""
        targets = []
        
        if language == 'c':
            targets.extend(self._identify_c_targets(code_path))
        elif language == 'rust':
            targets.extend(self._identify_rust_targets(code_path))
        elif language == 'python':
            targets.extend(self._identify_python_targets(code_path))
        
        self.targets.extend(targets)
        return targets
    
    def _identify_c_targets(self, code_path: Path) -> List[VerificationTarget]:
        """Identify C/C++ targets for verification"""
        targets = []
        
        for file_path in code_path.rglob('*.c'):
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Find function definitions
            func_pattern = r'(\w+)\s*\([^)]*\)\s*\{'
            matches = re.finditer(func_pattern, content)
            
            for match in matches:
                func_name = match.group(1)
                line_num = content[:match.start()].count('\n') + 1
                
                # Determine property type based on function context
                property_type = self._classify_function_property(
                    content, match.start(), match.end()
                )
                
                target = VerificationTarget(
                    target_id=f"{file_path.name}:{func_name}:{line_num}",
                    file_path=str(file_path),
                    function_name=func_name,
                    line_number=line_num,
                    property_type=property_type,
                    description=f"Function {func_name} may have {property_type.value} issues",
                    confidence=0.6
                )
                targets.append(target)
        
        return targets
    
    def _identify_rust_targets(self, code_path: Path) -> List[VerificationTarget]:
        """Identify Rust targets for verification"""
        targets = []
        
        for file_path in code_path.rglob('*.rs'):
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Find unsafe blocks
            unsafe_pattern = r'unsafe\s*\{'
            matches = re.finditer(unsafe_pattern, content)
            
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                
                target = VerificationTarget(
                    target_id=f"{file_path.name}:unsafe:{line_num}",
                    file_path=str(file_path),
                    function_name="unsafe_block",
                    line_number=line_num,
                    property_type=PropertyType.MEMORY_SAFETY,
                    description="Unsafe block requires verification",
                    confidence=0.9
                )
                targets.append(target)
        
        return targets
    
    def _identify_python_targets(self, code_path: Path) -> List[VerificationTarget]:
        """Identify Python targets for verification"""
        targets = []
        
        for file_path in code_path.rglob('*.py'):
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Find functions with potential issues
            patterns = {
                PropertyType.MEMORY_SAFETY: [
                    r'(del|__del__|gc\.)',
                    r'(weakref|finalize)',
                ],
                PropertyType.THREAD_SIFTY: [
                    r'(threading|Thread|asyncio\.create_task)',
                    r'(lock|Lock|Semaphore)',
                ],
            }
            
            for property_type, regex_patterns in patterns.items():
                for pattern in regex_patterns:
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        
                        target = VerificationTarget(
                            target_id=f"{file_path.name}:{property_type.value}:{line_num}",
                            file_path=str(file_path),
                            function_name="unknown",
                            line_number=line_num,
                            property_type=property_type,
                            description=f"Potential {property_type.value} issue",
                            confidence=0.5
                        )
                        targets.append(target)
        
        return targets
    
    def _classify_function_property(self, content: str, start: int, end: int) -> PropertyType:
        """Classify the property type based on function context"""
        context = content[max(0, start-200):end+200]
        
        # Check for memory operations
        if re.search(r'(malloc|free|alloc|pointer)', context):
            return PropertyType.MEMORY_SAFETY
        
        # Check for threading operations
        if re.search(r'(thread|lock|mutex|atomic)', context):
            return PropertyType.THREAD_SAFETY
        
        # Check for arithmetic operations
        if re.search(r'[+\-*/]', context):
            return PropertyType.ARITHMETIC_CORRECTNESS
        
        return PropertyType.FUNCTIONAL_CORRECTNESS
    
    def run_verification(self, target: VerificationTarget, 
                       executor_name: str = 'cbmc') -> VerificationResult:
        """Run verification on a target using specified executor"""
        executor = self.executors.get(executor_name)
        if not executor:
            raise ValueError(f"Unknown executor: {executor_name}")
        
        if target.property_type == PropertyType.CRYPTOGRAPHIC_CORRECTNESS:
            return self.crypto_verifier.verify_property(target)
        
        return executor.execute(target)
    
    def run_batch_verification(self, executor_name: str = 'cbmc') -> FormalVerificationReport:
        """Run verification on all targets"""
        results = []
        
        for target in self.targets:
            try:
                result = self.run_verification(target, executor_name)
                results.append(result)
            except Exception as e:
                error_result = VerificationResult(
                    result_id=f"error_{target.target_id}",
                    target_id=target.target_id,
                    verification_type=VerificationType.SYMBOLIC_EXECUTION,
                    status="error",
                    counterexample=str(e),
                    proof_trace=None,
                    confidence=0.0,
                    execution_time=0.0,
                    solver_used=executor_name
                )
                results.append(error_result)
        
        self.results.extend(results)
        return self._generate_report(results)
    
    def _generate_report(self, results: List[VerificationResult]) -> FormalVerificationReport:
        """Generate a formal verification report"""
        total = len(results)
        verified = sum(1 for r in results if r.status == "verified")
        violated = sum(1 for r in results if r.status == "violated")
        unknown = sum(1 for r in results if r.status == "unknown")
        errors = sum(1 for r in results if r.status == "error")
        
        # Count by property type
        by_property = defaultdict(lambda: {"verified": 0, "violated": 0, "unknown": 0, "error": 0})
        
        # Count by verification type
        by_verif_type = defaultdict(lambda: {"verified": 0, "violated": 0, "unknown": 0, "error": 0})
        
        for result in results:
            # Get target to determine property type
            target = next((t for t in self.targets if t.target_id == result.target_id), None)
            if target:
                by_property[target.property_type][result.status] += 1
            by_verif_type[result.verification_type][result.status] += 1
        
        return FormalVerificationReport(
            report_id=f"verification_report_{len(self.results)}",
            total_targets=total,
            verified=verified,
            violated=violated,
            unknown=unknown,
            errors=errors,
            results=results,
            by_property_type=dict(by_property),
            by_verification_type=dict(by_verif_type)
        )
    
    def generate_report(self) -> str:
        """Generate a comprehensive formal verification report"""
        report = self._generate_report(self.results)
        
        output = "# Formal Verification Report\n\n"
        output += "## Summary\n"
        output += f"- Total Targets: {report.total_targets}\n"
        output += f"- Verified: {report.verified}\n"
        output += f"- Violated: {report.violated}\n"
        output += f"- Unknown: {report.unknown}\n"
        output += f"- Errors: {report.errors}\n\n"
        
        output += "## By Property Type\n"
        for prop_type, counts in report.by_property_type.items():
            output += f"- {prop_type.value}:\n"
            output += f"  - Verified: {counts['verified']}\n"
            output += f"  - Violated: {counts['violated']}\n"
            output += f"  - Unknown: {counts['unknown']}\n"
            output += f"  - Errors: {counts['error']}\n"
        
        output += "\n## By Verification Type\n"
        for verif_type, counts in report.by_verification_type.items():
            output += f"- {verif_type.value}:\n"
            output += f"  - Verified: {counts['verified']}\n"
            output += f"  - Violated: {counts['violated}\n"
            output += f"  - Unknown: {counts['unknown']}\n"
            output += f"  - Errors: {counts['error']}\n"
        
        output += "\n## Violations\n"
        for result in report.results:
            if result.status == "violated":
                output += f"- [{result.target_id}] {result.counterexample}\n"
        
        return output
