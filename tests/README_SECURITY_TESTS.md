# AI Security Regression Test Suite

Comprehensive security tests to prevent AI-specific vulnerabilities from being reintroduced into Raven's codebase.

## Quick Start

```bash
# Run all security tests
pytest tests/test_ai_security_regression.py -v

# Run only critical tests
pytest tests/test_ai_security_regression.py -m critical -v

# Run static analysis tests
pytest tests/test_static_security_analysis.py -v

# Run all security tests with coverage
pytest tests/ -m security --cov=pipeline --cov-report=html
```

## Test Categories

### 1. Prompt Injection Prevention (`test_ai_security_regression.py`)
Tests to prevent prompt injection vulnerabilities in LLM interactions.

**Critical Tests:**
- `test_code_input_is_sanitized_before_prompt_construction` - Verifies sanitization
- `test_prompt_uses_delimiter_pattern` - Checks secure prompt structure
- `test_no_direct_fstring_concatenation_in_prompts` - Static analysis check

**Vulnerabilities Covered:**
- Direct f-string concatenation of user code
- Missing input validation in prompt construction
- Delimiter escape attacks
- Role-playing injection attempts

### 2. Data Poisoning Prevention (`test_ai_security_regression.py`)
Tests to prevent poisoning through feedback loops and external data.

**Critical Tests:**
- `test_cve_data_integrity_verification` - Cryptographic verification
- `test_feedback_loop_requires_human_approval` - Human-in-the-loop gate
- `test_feedback_data_sanitization` - Input sanitization

**Vulnerabilities Covered:**
- Automatic prompt updates without approval
- Unvalidated external CVE data
- XSS payloads in feedback
- Supply chain attacks via compromised sources

### 3. Model Extraction Prevention (`test_ai_security_regression.py`)
Tests to prevent model extraction and information leakage.

**High Priority Tests:**
- `test_error_messages_do_not_leak_model_details` - Generic error messages
- `test_rate_limiting_enforced` - Request throttling
- `test_budget_enforcement_prevents_exhaustion` - Cost controls

**Vulnerabilities Covered:**
- Verbose error messages exposing internals
- Missing rate limiting
- Resource exhaustion attacks
- Model enumeration through responses

### 4. Adversarial Input Prevention (`test_ai_security_regression.py`)
Tests to prevent adversarial input attacks.

**High Priority Tests:**
- `test_input_size_limits_enforced` - DoS prevention
- `test_code_complexity_limits` - Parser protection
- `test_malicious_file_upload_prevention` - Upload validation

**Vulnerabilities Covered:**
- Oversized code submissions
- Deeply nested adversarial code
- Path traversal attacks
- Binary injection

### 5. Insecure Model Serving Prevention (`test_ai_security_regression.py`)
Tests for secure model serving configurations.

**High Priority Tests:**
- `test_tls_verification_enforced` - MITM prevention
- `test_poc_execution_is_sandboxed` - Code isolation
- `test_configuration_file_permissions` - Access controls

**Vulnerabilities Covered:**
- Disabled TLS verification
- Unsandboxed code execution
- World-readable config files
- Hardcoded secrets

### 6. Static Security Analysis (`test_static_security_analysis.py`)
Automated static analysis tests that scan the codebase.

**CI-Required Tests:**
- `test_no_eval_or_exec_in_codebase` - Code injection prevention
- `test_no_hardcoded_api_keys` - Secret detection
- `test_secure_http_headers` - TLS enforcement
- `test_prompt_construction_security` - Pattern detection
- `test_no_debug_mode_in_production` - Debug flag check

**Automated Scans:**
- Shell injection vulnerabilities (AST-based)
- Dangerous function calls
- Insecure logging patterns
- CSP header validation

## Test Markers

Use markers to run specific test categories:

```bash
pytest tests/ -m security          # All security tests
pytest tests/ -m critical          # Critical priority only
pytest tests/ -m ai_security       # AI-specific security
pytest tests/ -m static_analysis   # Static code analysis
pytest tests/ -m ci_required       # CI-required tests
```

## Critical Test Results

If critical tests fail, the test suite will output:

```
======================================================================
CRITICAL SECURITY TEST FAILURES
======================================================================
  - tests/test_ai_security_regression.py::TestPromptInjectionPrevention::test_code_input_is_sanitized_before_prompt_construction
======================================================================
DO NOT DEPLOY - Critical security vulnerabilities detected!
======================================================================
```

## Integration with CI/CD

Add to your CI pipeline:

```yaml
# .github/workflows/security.yml
name: Security Tests

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          pip install pytest pytest-cov pyyaml
      
      - name: Run security tests
        run: |
          pytest tests/ -m ci_required -v --tb=short
      
      - name: Run static analysis
        run: |
          pytest tests/test_static_security_analysis.py -v
      
      - name: Generate security report
        run: |
          pytest tests/test_ai_security_regression.py \
            --json-report --json-report-file=security-report.json
      
      - name: Upload report
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: security-report.json
```

## Adding New Security Tests

When adding new security tests:

1. **Use the appropriate marker:**
   ```python
   @pytest.mark.security
   @pytest.mark.critical  # If it's a critical vulnerability
   def test_new_security_check(self):
       ...
   ```

2. **Document the vulnerability:**
   ```python
   def test_vulnerability_description(self):
       """
       Critical Test: Brief description of what this tests.
       
       Vulnerability: What vulnerability this prevents
       Location: Where it was found (file:line)
       Impact: What could happen if not prevented
       """
       ...
   ```

3. **Provide remediation hints:**
   ```python
   assert result['secure'] is True, (
       "Vulnerability found! Remediation: "
       "Use parameterized queries instead of string concatenation."
   )
   ```

## Security Test Fixtures

Common fixtures available in `conftest.py`:

- `secure_prompt_template` - Secure prompt template with delimiters
- `malicious_prompt_injection_attempts` - Known attack patterns
- `adversarial_inputs` - Malformed inputs for testing
- `secure_config_defaults` - Expected secure configuration
- `cve_poisoning_attempts` - CVE data poisoning examples

## Coverage Requirements

Security tests must cover:

- [x] All LLM prompt construction paths
- [x] All external data ingestion paths
- [x] All feedback loop paths
- [x] All model API interaction paths
- [x] All PoC/code generation paths
- [x] All configuration loading paths
- [x] All user input validation paths

## Failure Response

When security tests fail:

1. **STOP** - Do not deploy
2. **Investigate** - Review the specific failing test
3. **Fix** - Implement the recommended remediation
4. **Verify** - Re-run tests to confirm fix
5. **Document** - Add regression test if new vulnerability type

## References

- OWASP Top 10 for LLM Applications 2025
- NIST AI Risk Management Framework
- MITRE ATLAS (Adversarial Threat Landscape for AI Systems)
- Project Raven D3FEND Implementation

## Contact

For security test questions or to report new vulnerability patterns:
- Open an issue with the `security-test` label
- Include the vulnerability type and suggested test
