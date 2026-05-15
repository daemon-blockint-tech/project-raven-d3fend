#!/usr/bin/env python3
"""
Raven AI Security Regression Test Runner
Quick script to run security tests with proper reporting
"""

import subprocess
import sys
from pathlib import Path


class SecurityTestRunner:
    """Runner for Raven's AI security regression tests."""
    
    def __init__(self):
        self.test_dir = Path(__file__).parent
        self.results = {
            'passed': [],
            'failed': [],
            'skipped': [],
        }
    
    def run_all_security_tests(self):
        """Run all security regression tests."""
        print("="*70)
        print("RAVEN AI SECURITY REGRESSION TEST SUITE")
        print("="*70)
        print()
        
        # Run critical tests first
        print("1. Running CRITICAL security tests...")
        critical_result = self._run_pytest(['-m', 'critical', '-v', '--tb=short'])
        
        if critical_result.returncode != 0:
            print("\n❌ CRITICAL TESTS FAILED - DO NOT DEPLOY")
            self._print_failures(critical_result)
            return False
        else:
            print("✅ All critical tests passed\n")
        
        # Run all AI security tests
        print("2. Running AI security tests...")
        ai_result = self._run_pytest(['-m', 'ai_security', '-v', '--tb=short'])
        
        if ai_result.returncode != 0:
            print("\n⚠️  Some AI security tests failed")
            self._print_failures(ai_result)
        else:
            print("✅ All AI security tests passed\n")
        
        # Run static analysis
        print("3. Running static security analysis...")
        static_result = self._run_pytest(
            ['tests/test_static_security_analysis.py', '-v', '--tb=short']
        )
        
        if static_result.returncode != 0:
            print("\n⚠️  Static analysis found issues")
            self._print_failures(static_result)
        else:
            print("✅ Static analysis passed\n")
        
        # Generate summary
        print("="*70)
        print("TEST SUMMARY")
        print("="*70)
        
        if critical_result.returncode == 0 and ai_result.returncode == 0:
            print("\n✅ ALL SECURITY TESTS PASSED")
            print("The codebase meets minimum security requirements.")
            return True
        else:
            print("\n❌ SECURITY TESTS FAILED")
            print("Review failures above before deployment.")
            return False
    
    def run_specific_category(self, category):
        """Run tests for a specific vulnerability category."""
        categories = {
            'prompt-injection': 'TestPromptInjectionPrevention',
            'data-poisoning': 'TestDataPoisoningPrevention',
            'model-extraction': 'TestModelExtractionPrevention',
            'adversarial-input': 'TestAdversarialInputPrevention',
            'insecure-serving': 'TestInsecureModelServingPrevention',
            'static': 'test_static_security_analysis',
        }
        
        if category not in categories:
            print(f"Unknown category: {category}")
            print(f"Available: {', '.join(categories.keys())}")
            return False
        
        test_pattern = categories[category]
        
        print(f"Running {category} tests...")
        result = self._run_pytest(['-k', test_pattern, '-v'])
        
        return result.returncode == 0
    
    def generate_security_report(self, output_file='security-report.json'):
        """Generate a JSON security report."""
        print("Generating security report...")
        
        result = self._run_pytest([
            '--json-report',
            f'--json-report-file={output_file}',
            '-m', 'security',
            '--tb=no',
        ])
        
        if result.returncode == 0:
            print(f"✅ Report generated: {output_file}")
        else:
            print(f"⚠️  Report generated with failures: {output_file}")
        
        return output_file
    
    def _run_pytest(self, args):
        """Run pytest with given arguments."""
        cmd = ['python', '-m', 'pytest'] + args + ['tests/']
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=self.test_dir.parent
        )
        
        # Print output
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(result.stderr, file=sys.stderr)
        
        return result
    
    def _print_failures(self, result):
        """Print failure details from pytest output."""
        if 'FAILED' in result.stdout:
            lines = result.stdout.split('\n')
            for line in lines:
                if 'FAILED' in line:
                    print(f"  - {line}")


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Raven AI Security Test Runner'
    )
    parser.add_argument(
        'category',
        nargs='?',
        choices=['prompt-injection', 'data-poisoning', 'model-extraction',
                 'adversarial-input', 'insecure-serving', 'static', 'all'],
        default='all',
        help='Test category to run'
    )
    parser.add_argument(
        '--report',
        '-r',
        action='store_true',
        help='Generate JSON report'
    )
    parser.add_argument(
        '--output',
        '-o',
        default='security-report.json',
        help='Output file for report'
    )
    
    args = parser.parse_args()
    
    runner = SecurityTestRunner()
    
    if args.category == 'all':
        success = runner.run_all_security_tests()
    else:
        success = runner.run_specific_category(args.category)
    
    if args.report:
        runner.generate_security_report(args.output)
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
