"""
Sandbox manager for the Prove stage - manages Docker sandbox for safe PoC execution.
"""
from typing import Dict, Any, Optional
import logging
import subprocess
import os
from pathlib import Path

logger = logging.getLogger(__name__)


class SandboxManager:
    """Manage Docker sandbox for safe PoC execution."""
    
    def __init__(self, work_dir: str = "/tmp/raven_sandbox"):
        """
        Initialize sandbox manager.
        
        Args:
            work_dir: Working directory for sandbox files
        """
        self.work_dir = Path(work_dir)
        self.work_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"SandboxManager initialized with work_dir: {self.work_dir}")
    
    def create_dockerfile(
        self,
        language: str,
        sanitizers: list
    ) -> str:
        """
        Create Dockerfile for sandboxed execution.
        
        Args:
            language: Programming language
            sanitizers: List of sanitizers to enable
            
        Returns:
            Path to created Dockerfile
        """
        dockerfile_path = self.work_dir / "Dockerfile"
        
        if language == "c" or language == "cpp":
            dockerfile_content = f"""# Dockerfile for C/C++ PoC execution with sanitizers
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \\
    gcc \\
    g++ \\
    make \\
    libssl-dev \\
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy harness
COPY harness_* ./

# Compile with sanitizers
RUN gcc -g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer \\
    -o harness harness.c -ldl -lpthread

# Set environment for sanitizers
ENV ASAN_OPTIONS=detect_leaks=1:halt_on_error=0
ENV UBSAN_OPTIONS=abort_on_error=1:print_stacktrace=1

CMD ["./harness"]
"""
        elif language == "rust":
            dockerfile_content = """# Dockerfile for Rust PoC execution with sanitizers
FROM rust:1.75

WORKDIR /app

# Copy Cargo.toml and source
COPY Cargo.toml ./
COPY harness_*.rs ./

# Build with sanitizers
ENV RUSTFLAGS=-Zsanitizer=address -Zsanitizer=leak -Zsanitizer=thread
RUN cargo build

# Set environment for sanitizers
ENV ASAN_OPTIONS=detect_leaks=1:halt_on_error=0
ENV RUST_BACKTRACE=1

CMD ["./target/debug/raven-harness"]
"""
        elif language == "python":
            dockerfile_content = """# Dockerfile for Python PoC execution
FROM python:3.11-slim

WORKDIR /app

# Copy harness
COPY harness_*.py ./

# Install dependencies if needed
RUN pip install --no-cache-dir pytest

# Run harness
CMD ["python", "harness_*.py"]
"""
        else:
            dockerfile_content = f"""# Dockerfile for {language} PoC execution
FROM ubuntu:22.04

WORKDIR /app

# Copy harness
COPY harness_* ./

# Default command
CMD ["echo", "No specific runtime configured"]
"""
        
        dockerfile_path.write_text(dockerfile_content)
        
        logger.info(f"Created Dockerfile for {language} with sanitizers: {sanitizers}")
        return str(dockerfile_path)
    
    def build_image(
        self,
        dockerfile_path: str,
        image_name: str
    ) -> bool:
        """
        Build Docker image from Dockerfile.
        
        Args:
            dockerfile_path: Path to Dockerfile
            image_name: Name for Docker image
            
        Returns:
            True if build successful, False otherwise
        """
        try:
            result = subprocess.run(
                ["docker", "build", "-t", image_name, "-f", dockerfile_path, str(self.work_dir)],
                check=True,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            logger.info(f"Built Docker image: {image_name}")
            return True
        
        except subprocess.TimeoutExpired:
            logger.error(f"Docker build timed out for {image_name}")
            return False
        except subprocess.CalledProcessError as e:
            logger.error(f"Docker build failed for {image_name}: {e.stderr}")
            return False
        except FileNotFoundError:
            logger.error("Docker not found. Docker sandboxing requires Docker to be installed.")
            return False
    
    def run_container(
        self,
        image_name: str,
        timeout_seconds: int = 30
    ) -> Dict[str, Any]:
        """
        Run Docker container and capture output.
        
        Args:
            image_name: Name of Docker image to run
            timeout_seconds: Timeout for container execution
            
        Returns:
            Dictionary with execution results
        """
        try:
            result = subprocess.run(
                ["docker", "run", "--rm", image_name],
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout_seconds
            )
            
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
        
        except subprocess.TimeoutExpired:
            logger.error(f"Container execution timed out after {timeout_seconds}s")
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Execution timed out after {timeout_seconds}s",
                "returncode": -1
            }
        except subprocess.CalledProcessError as e:
            logger.error(f"Container execution failed: {e}")
            return {
                "success": False,
                "stdout": e.stdout if hasattr(e, 'stdout') else "",
                "stderr": e.stderr if hasattr(e, 'stderr') else str(e),
                "returncode": e.returncode if hasattr(e, 'returncode') else -1
            }
        except FileNotFoundError:
            logger.error("Docker not found. Docker sandboxing requires Docker to be installed.")
            return {
                "success": False,
                "stdout": "",
                "stderr": "Docker not found",
                "returncode": -1
            }
    
    def cleanup(self, image_name: Optional[str] = None):
        """
        Clean up Docker resources.
        
        Args:
            image_name: Optional Docker image name to remove
        """
        if image_name:
            try:
                subprocess.run(
                    ["docker", "rmi", image_name],
                    check=False,
                    capture_output=True,
                    text=True
                )
                logger.info(f"Removed Docker image: {image_name}")
            except Exception as e:
                logger.warning(f"Failed to remove Docker image {image_name}: {e}")
