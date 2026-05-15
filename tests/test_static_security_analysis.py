"""
Static Security Analysis Tests
Scans Raven's codebase for AI security anti-patterns
"""

import pytest
import re
import ast
from pathlib import Path
from typing import List, Tuple


class TestStaticSecurityAnalysis:
    """
    Static analysis tests that scan code for security vulnerabilities.
    These tests fail if dangerous patterns are introduced.
    """
    
    # Files that must pass security checks
    CRITICAL_FILES = [
        'pipeline/validate/debate_orchestrator.py',
        'pipeline/scan/agent_router.py',
        'pipeline/prepare/threat_modeler.py',
        'pipeline/openrouter_integration/client.py',
        'pipeline/feedback/cve_parser.py',
        'pipeline/feedback/false_negative_tracker.py',
        'pipeline/prove/poc_generator.py',
        'pipeline/orchestrator.py',
    ]
    
    def test_no_eval_or_exec_in_codebase(self):
        """
        Critical: Ensure no eval() or exec() calls exist in the codebase.
        These are code injection vulnerabilities.
        """
        dangerous_patterns = [
            (r'\beval\s*\(', 'eval() call detected'),
            (r'\bexec\s*\(', 'exec() call detected'),
            (r'\bcompile\s*\(', 'compile() call detected - review carefully'),
            (r'__import__\s*\(', 'Dynamic import detected - review carefully'),
        ]
        
        violations = self._scan_for_patterns(dangerous_patterns)
        
        if violations:
            error_msg = "CRITICAL SECURITY VIOLATIONS:\n"
            for file, line, pattern, reason in violations:
                error_msg += f"  {file}:{line} - {reason}\n"
            pytest.fail(error_msg)
    
    def test_no_hardcoded_api_keys(self):
        """
        Ensure no hardcoded API keys or secrets in source code.
        """
        secret_patterns = [
            (r'sk-[a-zA-Z0-9]{48}', 'OpenAI API key pattern'),
            (r'claude-[a-zA-Z0-9]{40,}', 'Claude API key pattern'),
            (r'[a-zA-Z0-9]{32}-[a-zA-Z0-9]{16}', 'Generic API key pattern'),
            (r'password\s*=\s*[\'"][^\'"]+[\'"]', 'Hardcoded password'),
            (r'secret\s*=\s*[\'"][^\'"]{20,}[\'"]', 'Hardcoded secret'),
        ]
        
        violations = self._scan_for_patterns(secret_patterns)
        
        # Filter out test files and examples
        real_violations = [
            v for v in violations 
            if 'test_' not in v[0] and 'example' not in v[0].lower()
        ]
        
        if real_violations:
            error_msg = "POTENTIAL SECRETS IN CODE:\n"
            for file, line, pattern, reason in real_violations[:5]:  # Show first 5
                error_msg += f"  {file}:{line} - {reason}\n"
            pytest.fail(error_msg)
    
    def test_secure_http_headers(self):
        """
        Ensure HTTP requests use secure headers and verification.
        """
        insecure_patterns = [
            (r'verify\s*=\s*False', 'TLS verification disabled'),
            (r'disable_warnings', 'Security warnings disabled'),
            (r'CERT_NONE|CERT_OPTIONAL', 'Insecure SSL certificate mode'),
        ]
        
        violations = self._scan_for_patterns(insecure_patterns)
        
        if violations:
            error_msg = "INSECURE HTTP CONFIGURATION:\n"
            for file, line, pattern, reason in violations:
                error_msg += f"  {file}:{line} - {reason}\n"
            pytest.fail(error_msg)
    
    def test_prompt_construction_security(self):
        """
        Verify secure prompt construction patterns.
        """
        # Look for direct user input concatenation in prompts
        dangerous_patterns = [
            (r'f[\'"].*\{.*code.*\}.*\{.*user', 'Potential prompt injection'),
            (r'prompt.*=.*\+.*user', 'String concatenation in prompt'),
            (r'\.format\(.*user', 'Format string with user input'),
        ]
        
        violations = self._scan_for_patterns_in_critical_files(dangerous_patterns)
        
        if violations:
            error_msg = "UNSAFE PROMPT CONSTRUCTION:\n"
            for file, line, pattern, reason in violations:
                error_msg += f"  {file}:{line} - {reason}\n"
            error_msg += "\nUse parameterized prompts with delimiters instead."
            pytest.fail(error_msg)
    
    def test_no_debug_mode_in_production(self):
        """
        Ensure debug mode is not enabled in production code.
        """
        debug_patterns = [
            (r'debug\s*=\s*True', 'Debug mode enabled'),
            (r'DEBUG\s*=\s*True', 'DEBUG constant set to True'),
            (r'app\.run.*debug\s*=\s*True', 'Flask/Django debug mode'),
        ]
        
        violations = self._scan_for_patterns(debug_patterns)
        
        if violations:
            error_msg = "DEBUG MODE ENABLED:\n"
            for file, line, pattern, reason in violations:
                error_msg += f"  {file}:{line} - {reason}\n"
            pytest.fail(error_msg)
    
    def test_input_validation_exists(self):
        """
        Verify that input validation functions exist for external inputs.
        """
        required_validations = [
            'sanitize_code',
            'validate_input',
            'check_bounds',
            'verify_signature',
        ]
        
        codebase = self._load_codebase()
        
        missing_validations = []
        for validation in required_validations:
            if validation not in codebase:
                missing_validations.append(validation)
        
        if missing_validations:
            pytest.fail(
                f"Missing input validation functions: {', '.join(missing_validations)}"
            )
    
    def test_feedback_loop_has_approval_gate(self):
        """
        Verify feedback loop includes human approval checks.
        """
        required_checks = [
            'human_in_the_loop',
            'requires_approval',
            'validate_feedback',
        ]
        
        feedback_files = [
            'pipeline/feedback/cve_patch_analyzer.py',
            'pipeline/feedback/false_negative_tracker.py',
        ]
        
        for file_path in feedback_files:
            if Path(file_path).exists():
                content = Path(file_path).read_text()
                
                found_checks = sum(1 for check in required_checks if check in content)
                
                if found_checks < 2:
                    pytest.fail(
                        f"{file_path} missing security checks. "
                        f"Found {found_checks}/{len(required_checks)} required. "
                        f"Required: {', '.join(required_checks)}"
                    )
    
    def test_rate_limiting_implemented(self):
        """
        Verify rate limiting is implemented in API clients.
        """
        client_files = [
            'pipeline/openrouter_integration/client.py',
        ]
        
        for file_path in client_files:
            if Path(file_path).exists():
                content = Path(file_path).read_text()
                
                # Check for rate limiting patterns
                has_rate_limit = any(
                    pattern in content 
                    for pattern in ['rate_limit', 'RateLimiter', '@limit', 'throttle']
                )
                
                if not has_rate_limit:
                    pytest.fail(
                        f"{file_path} missing rate limiting. "
                        f"Add @rate_limit decorator or RateLimiter class."
                    )
    
    def test_sandboxing_for_poc_execution(self):
        """
        Verify PoC execution uses sandboxing.
        """
        poc_file = 'pipeline/prove/poc_generator.py'
        
        if Path(poc_file).exists():
            content = Path(poc_file).read_text()
            
            # Check for sandboxing patterns
            has_sandbox = any(
                pattern in content
                for pattern in ['sandbox', 'container', 'docker', 'firecracker', 'isolate']
            )
            
            # Check for direct execution (dangerous)
            has_direct_exec = any(
                pattern in content
                for pattern in ['os.system', 'subprocess.call', 'exec(', 'eval(']
            )
            
            if has_direct_exec and not has_sandbox:
                pytest.fail(
                    f"{poc_file} executes code without sandboxing. "
                    f"Use containerization (Docker/Firecracker) for isolation."
                )
    
    def test_secure_logging_no_secrets(self):
        """
        Ensure logs don't contain sensitive data.
        """
        # Look for logging of sensitive data
        dangerous_logging = [
            (r'log.*\{.*password', 'Password logged'),
            (r'log.*\{.*api_key', 'API key logged'),
            (r'log.*\{.*secret', 'Secret logged'),
            (r'log.*\{.*token', 'Token logged'),
        ]
        
        violations = self._scan_for_patterns(dangerous_logging)
        
        if violations:
            error_msg = "SENSITIVE DATA IN LOGS:\n"
            for file, line, pattern, reason in violations:
                error_msg += f"  {file}:{line} - {reason}\n"
            pytest.fail(error_msg)
    
    def test_csp_and_security_headers(self):
        """
        Verify security headers for any web components.
        """
        # If there are web components, check for security headers
        web_files = list(Path('.').rglob('*.html')) + list(Path('.').rglob('*.js'))
        
        for web_file in web_files[:10]:  # Check first 10
            content = web_file.read_text()
            
            # Check for inline scripts (XSS risk)
            if '<script>' in content and 'nonce' not in content:
                pytest.fail(
                    f"{web_file} has inline script without CSP nonce. "
                    f"Use external scripts or add CSP nonce."
                )
    
    def _scan_for_patterns(self, patterns: List[Tuple[str, str]]) -> List[Tuple]:
        """Scan codebase for dangerous patterns."""
        violations = []
        
        # Get all Python files
        python_files = list(Path('.').rglob('*.py'))
        
        for file_path in python_files:
            # Skip test files and virtual environments
            if 'test_' in str(file_path) or 'venv' in str(file_path) or '__pycache__' in str(file_path):
                continue
            
            try:
                content = file_path.read_text()
                lines = content.split('\n')
                
                for line_num, line in enumerate(lines, 1):
                    for pattern, reason in patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            violations.append((
                                str(file_path),
                                line_num,
                                pattern,
                                reason
                            ))
            except Exception:
                continue
        
        return violations
    
    def _scan_for_patterns_in_critical_files(self, patterns: List[Tuple[str, str]]) -> List[Tuple]:
        """Scan only critical files for patterns."""
        violations = []
        
        for file_path_str in self.CRITICAL_FILES:
            file_path = Path(file_path_str)
            if not file_path.exists():
                continue
            
            try:
                content = file_path.read_text()
                lines = content.split('\n')
                
                for line_num, line in enumerate(lines, 1):
                    for pattern, reason in patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            violations.append((
                                str(file_path),
                                line_num,
                                pattern,
                                reason
                            ))
            except Exception:
                continue
        
        return violations
    
    def _load_codebase(self) -> str:
        """Load all Python code for analysis."""
        all_code = []
        
        for file_path in Path('.').rglob('*.py'):
            if 'venv' not in str(file_path) and '__pycache__' not in str(file_path):
                try:
                    all_code.append(file_path.read_text())
                except Exception:
                    continue
        
        return '\n'.join(all_code)


class TestASTSecurityAnalysis:
    """
    AST-based security analysis for deeper inspection.
    """
    
    def test_no_shell_injection_vulnerabilities(self):
        """
        Use AST to detect shell injection vulnerabilities.
        """
        dangerous_calls = ['os.system', 'subprocess.call', 'subprocess.Popen']
        
        for file_path in Path('.').rglob('*.py'):
            if 'venv' in str(file_path) or '__pycache__' in str(file_path):
                continue
            
            try:
                tree = ast.parse(file_path.read_text())
                
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        # Check for dangerous calls
                        if isinstance(node.func, ast.Attribute):
                            call_name = f"{node.func.value.id}.{node.func.attr}" if isinstance(node.func.value, ast.Name) else ""
                            
                            if call_name in dangerous_calls:
                                # Check if arguments contain user input
                                for arg in node.args:
                                    if self._is_user_input(arg):
                                        pytest.fail(
                                            f"Shell injection in {file_path}: "
                                            f"User input passed to {call_name}"
                                        )
            except SyntaxError:
                continue
    
    def _is_user_input(self, node) -> bool:
        """Check if AST node represents user input."""
        if isinstance(node, ast.Name):
            return node.id in ['user_input', 'code', 'target', 'prompt', 'request']
        
        if isinstance(node, ast.BinOp):  # String concatenation
            return True
        
        if isinstance(node, ast.JoinedStr):  # f-string
            return True
        
        return False


# Security test markers
pytestmark = [
    pytest.mark.security,
    pytest.mark.static_analysis,
    pytest.mark.ci_required,  # Must pass in CI
]

if __name__ == '__main__':
    pytest.main([__file__, '-v'])
