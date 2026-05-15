"""
Codebase ingester for the Prepare stage.
"""
import os
import shutil
import subprocess
from typing import Optional, Dict, Any
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class CodebaseIngester:
    """Ingest codebase from various sources (git, local file, etc.)."""
    
    def __init__(self, work_dir: str = "/tmp/raven_pipeline"):
        """
        Initialize codebase ingester.
        
        Args:
            work_dir: Working directory for ingested codebases
        """
        self.work_dir = Path(work_dir)
        self.work_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"CodebaseIngester initialized with work_dir: {self.work_dir}")
    
    def ingest_from_git(
        self,
        repo_url: str,
        commit: Optional[str] = None,
        branch: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Ingest codebase from git repository.
        
        Args:
            repo_url: Git repository URL
            commit: Specific commit hash to checkout (optional)
            branch: Specific branch to checkout (optional)
            
        Returns:
            Dictionary with ingestion metadata
        """
        repo_name = repo_url.split("/")[-1].replace(".git", "")
        repo_path = self.work_dir / repo_name
        
        # Clone repository
        logger.info(f"Cloning repository: {repo_url}")
        try:
            if branch:
                subprocess.run(
                    ["git", "clone", "-b", branch, repo_url, str(repo_path)],
                    check=True,
                    capture_output=True,
                    text=True
                )
            else:
                subprocess.run(
                    ["git", "clone", repo_url, str(repo_path)],
                    check=True,
                    capture_output=True,
                    text=True
                )
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to clone repository: {e.stderr}")
            raise
        
        # Checkout specific commit if provided
        if commit:
            logger.info(f"Checking out commit: {commit}")
            subprocess.run(
                ["git", "checkout", commit],
                cwd=repo_path,
                check=True,
                capture_output=True,
                text=True
            )
        
        # Get repository metadata
        metadata = self._get_git_metadata(repo_path)
        
        return {
            "source": "git",
            "repo_url": repo_url,
            "local_path": str(repo_path),
            "commit": commit or metadata.get("current_commit"),
            "branch": branch or metadata.get("current_branch"),
            "metadata": metadata
        }
    
    def ingest_from_local(self, local_path: str) -> Dict[str, Any]:
        """
        Ingest codebase from local directory.
        
        Args:
            local_path: Local directory path
            
        Returns:
            Dictionary with ingestion metadata
        """
        local_path = Path(local_path)
        if not local_path.exists():
            raise ValueError(f"Local path does not exist: {local_path}")
        
        repo_name = local_path.name
        repo_path = self.work_dir / repo_name
        
        # Copy to work directory
        if repo_path.exists():
            shutil.rmtree(repo_path)
        shutil.copytree(local_path, repo_path)
        
        # Check if it's a git repository
        is_git = (repo_path / ".git").exists()
        metadata = {}
        
        if is_git:
            metadata = self._get_git_metadata(repo_path)
        
        return {
            "source": "local",
            "original_path": str(local_path),
            "local_path": str(repo_path),
            "is_git": is_git,
            "metadata": metadata
        }
    
    def _get_git_metadata(self, repo_path: Path) -> Dict[str, Any]:
        """
        Get git repository metadata.
        
        Args:
            repo_path: Path to git repository
            
        Returns:
            Dictionary with git metadata
        """
        metadata = {}
        
        try:
            # Get current commit
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repo_path,
                check=True,
                capture_output=True,
                text=True
            )
            metadata["current_commit"] = result.stdout.strip()
            
            # Get current branch
            result = subprocess.run(
                ["git", "branch", "--show-current"],
                cwd=repo_path,
                check=True,
                capture_output=True,
                text=True
            )
            metadata["current_branch"] = result.stdout.strip()
            
            # Get remote URL
            result = subprocess.run(
                ["git", "config", "--get", "remote.origin.url"],
                cwd=repo_path,
                check=True,
                capture_output=True,
                text=True
            )
            metadata["remote_url"] = result.stdout.strip()
            
            # Get commit count
            result = subprocess.run(
                ["git", "rev-list", "--count", "HEAD"],
                cwd=repo_path,
                check=True,
                capture_output=True,
                text=True
            )
            metadata["commit_count"] = int(result.stdout.strip())
            
        except subprocess.CalledProcessError as e:
            logger.warning(f"Failed to get git metadata: {e}")
        
        return metadata
    
    def cleanup(self, repo_path: str):
        """
        Clean up ingested codebase.
        
        Args:
            repo_path: Path to repository to clean up
        """
        repo_path = Path(repo_path)
        if repo_path.exists() and repo_path.is_dir():
            shutil.rmtree(repo_path)
            logger.info(f"Cleaned up: {repo_path}")
