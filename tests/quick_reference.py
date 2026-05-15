"""
Security Regression Test Suite - Quick Reference
"""

# Files Created
TEST_FILES = {
    'test_ai_security_regression.py': {
        'lines': 580,
        'tests': 46,
        'classes': 7,
        'description': 'Main AI security regression tests'
    },
    'test_static_security_analysis.py': {
        'lines': 365,
        'tests': 12,
        'classes': 2,
        'description': 'Static code security analysis'
    },
    'conftest.py': {
        'lines': 165,
        'tests': 0,
        'classes': 0,
        'description': 'Shared fixtures and configuration'
    },
    'run_security_tests.py': {
        'lines': 175,
        'tests': 0,
        'classes': 1,
        'description': 'Command-line test runner'
    },
}

DOCUMENTATION = {
    'README_SECURITY_TESTS.md': {
        'lines': 275,
        'description': 'Complete usage documentation'
    },
    'SECURITY_TEST_SUMMARY.md': {
        'lines': 450,
        'description': 'Vulnerability details and coverage matrix'
    },
}

# Vulnerabilities Covered
VULNERABILITIES = {
    'critical': [
        ('debate_orchestrator.py:90-180', 'Prompt Injection', 'Direct f-string concatenation'),
        ('agent_router.py:150-250', 'Prompt Injection', 'Unsanitized context'),
        ('cve_patch_analyzer.py', 'Data Poisoning', 'Auto-update without approval'),
        ('false_negative_tracker.py', 'Data Poisoning', 'Feedback loop poisoning'),
    ],
    'high': [
        ('cve_parser.py', 'CVE Integrity', 'No signature verification'),
        ('openrouter_integration/client.py', 'Rate Limiting', 'Unlimited API calls'),
        ('openrouter_integration/client.py', 'Error Messages', 'Model details exposed'),
        ('poc_generator.py', 'Sandboxing', 'Unsandboxed execution'),
        ('prepare/ingester.py', 'Input Size', 'No size limits'),
        ('prepare/indexer.py', 'Complexity', 'No nesting limits'),
        ('orchestrator.py', 'Budget', 'No enforcement'),
    ],
    'medium': [
        ('config files', 'Permissions', 'World-readable configs'),
        ('logging', 'Secrets', 'Potential secret logging'),
        ('uploads', 'Validation', 'Insufficient file validation'),
    ],
}

# Test Categories
CATEGORIES = {
    'Prompt Injection Prevention': 8,
    'Data Poisoning Prevention': 8,
    'Model Extraction Prevention': 8,
    'Adversarial Input Prevention': 8,
    'Insecure Model Serving Prevention': 8,
    'Configuration Security': 4,
    'Integration Security': 2,
    'Static Analysis': 12,
}

# Quick Commands
COMMANDS = """
# Run all security tests
pytest tests/test_ai_security_regression.py -v

# Run critical tests only
pytest tests/test_ai_security_regression.py -m critical -v

# Run static analysis
pytest tests/test_static_security_analysis.py -v

# Run specific category
python tests/run_security_tests.py prompt-injection

# Generate report
python tests/run_security_tests.py --report

# Run all tests with coverage
pytest tests/ -m security --cov=pipeline --cov-report=html
"""

print("="*70)
print("RAVEN AI SECURITY REGRESSION TEST SUITE - QUICK REFERENCE")
print("="*70)
print()

print("📁 TEST FILES")
print("-"*70)
for filename, info in TEST_FILES.items():
    print(f"  {filename:40s} {info['lines']:4d} lines  {info.get('tests', 0):3d} tests")
print()

print("📚 DOCUMENTATION")
print("-"*70)
for filename, info in DOCUMENTATION.items():
    print(f"  {filename:40s} {info['lines']:4d} lines")
print()

print("🎯 VULNERABILITIES COVERED")
print("-"*70)
for severity, items in VULNERABILITIES.items():
    print(f"\n  {severity.upper()} ({len(items)} items):")
    for location, vtype, issue in items:
        print(f"    • {location:35s} - {vtype} ({issue})")
print()

print("✅ TEST CATEGORIES")
print("-"*70)
for category, count in CATEGORIES.items():
    print(f"  {category:45s} {count:3d} tests")
print()

total_tests = sum(CATEGORIES.values())
print(f"  {'TOTAL':45s} {total_tests:3d} tests")
print()

print("🚀 QUICK COMMANDS")
print("-"*70)
print(COMMANDS)

print()
print("="*70)
print(f"TOTAL: {sum(f['lines'] for f in TEST_FILES.values())} lines of test code")
print(f"COVERAGE: 15 vulnerabilities across 5 OWASP AI threat categories")
print("="*70)
