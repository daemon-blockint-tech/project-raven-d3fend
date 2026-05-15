"""
Sanitizer runner for the Prove stage - executes code with sanitizers to detect bugs.
"""
from typing import Dict, Any, List, Optional
import logging
import subprocess
import os
from pathlib import Path

logger = logging.getLogger(__name__)


class SanitizerRunner:
    """Execute code with sanitizers to detect vulnerabilities dynamically."""
    
    def __init__(self, work_dir: str = "/tmp/raven_sanitizers"):
        """
        Initialize sanitizer runner.
        
        Args:
            work_dir: Working directory for sanitizer output
        """
        self.work_dir = Path(work_dir)
        self.work_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"SanitizerRunner initialized with work_dir: {self.work_dir}")
    
    def run_with_sanitizers(
        self,
        harness_path: str,
        language: str,
        sanitizers: List[str],
        timeout_seconds: int = 30
    ) -> Dict[str, Any]:
        """
        Run harness with specified sanitizers.
        
        Args:
            harness_path: Path to harness file
            language: Programming language
            sanitizers: List of sanitizers to enable
            timeout_seconds: Timeout for execution
            
        Returns:
            Dictionary with sanitizer results
        """
        results = {
            "sanitizers": sanitizers,
            "language": language,
            "findings": []
        }
        
        if language == "c" or language == "cpp":
            results = self._run_c_sanitizers(harness_path, sanitizers, timeout_seconds)
        elif language == "rust":
            results = self._run_rust_sanitizers(harness_path, sanitizers, timeout_seconds)
        elif language == "python":
            results = self._run_python_sanitizers(harness_path, timeout_seconds)
        else:
            logger.warning(f"Sanitizer not implemented for language: {language}")
            results["status"] = "skipped"
        
        return results
    
    def _run_c_sanitizers(
        self,
        harness_path: str,
        sanitizers: List[str],
        timeout_seconds: int
    ) -> Dict[str, Any]:
        """Run C/C++ code with sanitizers."""
        results = {
            "status": "success",
            "findings": []
        }
        
        # Build compilation command with sanitizers
        sanitizer_flags = []
        if "address" in sanitizers:
            sanitizer_flags.extend(["-fsanitize=address"])
        if "undefined" in sanitizers:
            sanitizer_flags.extend(["-fsanitize=undefined"])
        if "thread" in sanitizers:
            sanitizer_flags.extend(["-fsanitize=thread"])
        
        # Set environment variables
        env = os.environ.copy()
        env["ASAN_OPTIONS"] = "detect_leaks=1:halt_on_error=0"
        env["UBSAN_OPTIONS"] = "abort_on_error=1:print_stacktrace=1"
        
        try:
            # Compile with sanitizers
            compile_cmd = [
                "gcc", "-g", "-O0",
                *sanitizer_flags,
                "-fno-omit-frame-pointer",
                "-o", f"{self.work_dir}/harness_sanitized",
                harness_path,
                "-ldl", "-lpthread"
            ]
            
            compile_result = subprocess.run(
                compile_cmd,
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
                env=env
            )
            
            if compile_result.returncode != 0:
                results["status"] = "compile_failed"
                results["compile_error"] = compile_result.stderr
                logger.warning(f"Compilation failed: {compile_result.stderr[:200]}")
                return results
            
            # Run the instrumented binary
            run_result = subprocess.run(
                [f"{self.work_dir}/harness_sanitized"],
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                env=env
            )
            
            # Parse sanitizer output
            if run_result.stderr:
                findings = self._parse_sanitizer_output(run_result.stderr)
                results["findings"] = findings
            
            if run_result.returncode != 0:
                # Non-zero exit might indicate sanitizer detected an issue
                if not results["findings"]:
                    results["findings"].append({
                        "sanitizer": "runtime",
                        "message": f"Process exited with code {run_result.returncode}",
                        "severity": "warning"
                    })
        
        except subprocess.TimeoutExpired:
            results["status"] = "timeout"
            logger.warning(f"Sanitizer execution timed out after {timeout_seconds}s")
        except Exception as e:
            results["status"] = "error"
            results["error"] = str(e)
            logger.error(f"Sanitizer execution failed: {e}")
        
        return results
    
    def _run_rust_sanitizers(
        self,
        harness_path: str,
        sanitizers: List[str],
        timeout_seconds: int
    ) -> Dict[str, Any]:
        """Run Rust code with sanitizers."""
        results = {
            "status": "success",
            "findings": []
        }
        
        # Set environment variables for Rust sanitizers
        env = os.environ.copy()
        env["RUSTFLAGS"] = "-Zsanitizer=address -Zsanitizer=leak -Zsanitizer=thread"
        env["RUST_BACKTRACE"] = "1"
        
        try:
            # Run with cargo if Cargo.toml exists
            if Path(harness_path).parent / "Cargo.toml".exists():
                run_result = subprocess.run(
                    ["cargo", "run"],
                    cwd=Path(harness_path).parent,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=timeout_seconds,
                    env=env
                )
            else:
                # Direct run for single file
                run_result = subprocess.run(
                    ["cargo", "run", "--bin", "raven-harness"],
                    cwd=Path(harness_path).parent,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=timeout_seconds,
                    env=env
                )
            
            # Parse sanitizer output
            if run_result.stderr:
                findings = self._parse_sanitizer_output(run_result.stderr)
                results["findings"] = findings
            
            if run_result.returncode != 0:
                if not results["findings"]:
                    results["findings"].append({
                        "sanitizer": "runtime",
                        "message": f"Process exited with code {run_result.returncode}",
                        "severity": "warning"
                    })
        
        except subprocess.TimeoutExpired:
            results["status"] = "timeout"
            logger.warning(f"Rust sanitizer execution timed out after {timeout_seconds}s")
        except Exception as e:
            results["status"] = "error"
            results["error"] = str(e)
            logger.error(f"Rust sanitizer execution failed: {e}")
        
        return results
    
    def _run_python_sanitizers(
        self,
        harness_path: str,
        timeout_seconds: int
    ) -> Dict[str, Any]:
        """Run Python code (Python doesn't have compile-time sanitizers)."""
        results = {
            "status": "success",
            "findings": []
        }
        
        try:
            # Python uses runtime tools like bandit, pylint
            # For now, just run the script and check for errors
            run_result = subprocess.run(
                ["python", harness_path],
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout_seconds
            )
            
            if run_result.returncode != 0:
                results["findings"].append({
                    "sanitizer": "python_runtime",
                    "message": run_result.stderr[:500],
                    "severity": "warning"
                })
        
        except subprocess.TimeoutExpired:
            results["status"] = "timeout"
        except Exception as e:
            results["status"] = "error"
            results["error"] = str(e)
        
        return results
    
    def _parse_sanitizer_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse sanitizer output for findings."""
        findings = []
        
        # Common sanitizer patterns
        patterns = {
            "address_sanitizer": [
                "heap-buffer-overflow",
                "stack-buffer-overflow",
                "use-after-free",
                "double-free",
                "negative-size-as-size",
                "heap-use-after-free"
            ],
            "undefined_sanitizer": [
                "undefined-behavior",
                "shift-exponent",
                "division-by-zero"
            ],
            "thread_sanitizer": [
                "data race",
                "lock-order-inversion",
                "thread-leak"
            ]
        }
        
        for sanitizer_name, bug_patterns in patterns.items():
            for pattern in bug_patterns:
                if pattern in output.lower():
                    findings.append({
                        "sanitizer": sanitizer_name,
                        "message": f"Detected: {pattern}",
                        "severity": "error"
                    })
        
        return findings
