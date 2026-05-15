"""
Fuzzer for the Prove stage - generates fuzzing inputs for vulnerability testing.
"""
from typing import List, Dict, Any, Optional
import logging
import random
import string

logger = logging.getLogger(__name__)


class Fuzzer:
    """Generate fuzzing inputs for vulnerability testing."""
    
    def __init__(self, max_iterations: int = 1000):
        """
        Initialize fuzzer.
        
        Args:
            max_iterations: Maximum number of fuzzing iterations
        """
        self.max_iterations = max_iterations
        logger.info(f"Fuzzer initialized with max_iterations: {max_iterations}")
    
    def generate_inputs(
        self,
        bug_class: str,
        precondition: str,
        language: str = "python"
    ) -> List[Dict[str, Any]]:
        """
        Generate fuzzing inputs based on bug class and precondition.
        
        Args:
            bug_class: Bug class identifier
            precondition: Precondition for vulnerability
            language: Programming language
            
        Returns:
            List of fuzzing input dictionaries
        """
        inputs = []
        
        # Generate inputs based on bug class
        if bug_class == "memory_corruption":
            inputs.extend(self._generate_buffer_overflow_inputs())
        elif bug_class == "integer_overflow":
            inputs.extend(self._generate_integer_overflow_inputs())
        elif bug_class == "race_condition":
            inputs.extend(self._generate_race_condition_inputs())
        elif bug_class == "string_injection":
            inputs.extend(self._generate_injection_inputs())
        else:
            inputs.extend(self._generate_generic_inputs())
        
        # Add inputs based on precondition analysis
        precondition_inputs = self._analyze_precondition(precondition)
        inputs.extend(precondition_inputs)
        
        logger.info(f"Generated {len(inputs)} fuzzing inputs for {bug_class}")
        return inputs
    
    def _generate_buffer_overflow_inputs(self) -> List[Dict[str, Any]]:
        """Generate inputs for buffer overflow testing."""
        inputs = []
        
        # Large strings
        for size in [100, 1000, 10000, 100000]:
            inputs.append({
                "type": "large_string",
                "value": "A" * size,
                "description": f"String of length {size}"
            })
        
        # Pattern-based inputs
        patterns = ["%s%n%n%n%n", "AAAA", "ABCD", "\x00\x00\x00\x00"]
        for pattern in patterns:
            inputs.append({
                "type": "pattern",
                "value": pattern * 100,
                "description": f"Pattern: {repr(pattern)}"
            })
        
        return inputs
    
    def _generate_integer_overflow_inputs(self) -> List[Dict[str, Any]]:
        """Generate inputs for integer overflow testing."""
        inputs = []
        
        # Boundary values
        boundary_values = [
            2**31 - 1,  # INT_MAX
            2**32 - 1,  # UINT_MAX
            -2**31,       # INT_MIN
            2**63 - 1,   # LONG_MAX
            2**64 - 1,   # ULLONG_MAX
        ]
        
        for value in boundary_values:
            inputs.append({
                "type": "boundary_value",
                "value": str(value),
                "description": f"Boundary value: {value}"
            })
        
        # Arithmetic operations
        arithmetic_inputs = [
            {"type": "addition", "value": "2147483647 + 1"},
            {"type": "multiplication", "value": "46341 * 46341"},
            {"type": "shift", "value": "1 << 63"}
        ]
        
        inputs.extend(arithmetic_inputs)
        
        return inputs
    
    def _generate_race_condition_inputs(self) -> List[Dict[str, Any]]:
        """Generate inputs for race condition testing."""
        inputs = []
        
        # Concurrent operations
        inputs.append({
            "type": "concurrent_write",
            "value": "parallel_write_test",
            "description": "Test concurrent writes"
        })
        
        inputs.append({
            "type": "check_then_act",
            "value": "toctou_test",
            "description": "Time-of-check to time-of-use test"
        })
        
        return inputs
    
    def _generate_injection_inputs(self) -> List[Dict[str, Any]]:
        """Generate inputs for injection testing."""
        inputs = []
        
        # SQL injection patterns
        sql_patterns = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "1 UNION SELECT * FROM users"
        ]
        
        for pattern in sql_patterns:
            inputs.append({
                "type": "sql_injection",
                "value": pattern,
                "description": f"SQL injection pattern"
            })
        
        # Command injection patterns
        cmd_patterns = [
            "; cat /etc/passwd",
            "| whoami",
            "$(whoami)"
        ]
        
        for pattern in cmd_patterns:
            inputs.append({
                "type": "command_injection",
                "value": pattern,
                "description": f"Command injection pattern"
            })
        
        return inputs
    
    def _generate_generic_inputs(self) -> List[Dict[str, Any]]:
        """Generate generic fuzzing inputs."""
        inputs = []
        
        # Random strings
        for _ in range(10):
            length = random.randint(10, 1000)
            chars = string.ascii_letters + string.digits + string.punctuation
            random_string = ''.join(random.choice(chars) for _ in range(length))
            
            inputs.append({
                "type": "random_string",
                "value": random_string,
                "description": f"Random string of length {length}"
            })
        
        # Special characters
        special_chars = [
            "\x00", "\x0a", "\x0d", "\xff", "\x1a",
            "<script>", "</script>", "onerror=", "javascript:"
        ]
        
        for char in special_chars:
            inputs.append({
                "type": "special_char",
                "value": char,
                "description": f"Special character: {repr(char)}"
            })
        
        return inputs
    
    def _analyze_precondition(self, precondition: str) -> List[Dict[str, Any]]:
        """Analyze precondition and generate targeted inputs."""
        inputs = []
        
        precondition_lower = precondition.lower()
        
        # Extract keywords from precondition
        if "length" in precondition_lower:
            # Generate length-based inputs
            for multiplier in [0.5, 1.0, 2.0, 10.0, 100.0]:
                inputs.append({
                    "type": "length_variant",
                    "value": f"length_{multiplier}x",
                    "description": f"Length multiplier: {multiplier}x"
                })
        
        if "user" in precondition_lower or "input" in precondition_lower:
            # Generate user input variations
            user_inputs = [
                {"type": "empty_input", "value": "", "description": "Empty input"},
                {"type": "null_input", "value": "null", "description": "Null input"},
                {"type": "max_length", "value": "A" * 10000, "description": "Max length input"}
            ]
            inputs.extend(user_inputs)
        
        if "file" in precondition_lower:
            # Generate file-related inputs
            file_inputs = [
                {"type": "special_file", "value": "/dev/null", "description": "/dev/null"},
                {"type": "special_file", "value": "/proc/self/environ", "description": "/proc/self/environ"},
                {"type": "path_traversal", "value": "../../../etc/passwd", "description": "Path traversal"}
            ]
            inputs.extend(file_inputs)
        
        return inputs
