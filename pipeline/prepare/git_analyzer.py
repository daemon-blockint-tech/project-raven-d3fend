"""
Git analyzer for the Prepare stage - analyzes past commits for CVE patches.
"""
import subprocess
from typing import Dict, List, Any, Optional
import logging
from pathlib import Path
import re

logger = logging.getLogger(__name__)


class GitAnalyzer:
    """Analyze git history for CVE patches and security-relevant commits."""
    
    def __init__(self):
        """Initialize git analyzer."""
        self.cve_keywords = [
            "cve", "security", "fix", "patch", "vulnerability",
            "exploit", "buffer overflow", "integer overflow", "race condition",
            "use-after-free", "double free", "null pointer", "injection"
        ]
        logger.info("GitAnalyzer initialized")
    
    def analyze_history(self, repo_path: str, max_commits: int = 100) -> Dict[str, Any]:
        """
        Analyze git history for security-relevant commits.
        
        Args:
            repo_path: Path to git repository
            max_commits: Maximum number of commits to analyze
            
        Returns:
            Dictionary with git analysis results
        """
        repo_path = Path(repo_path)
        
        if not (repo_path / ".git").exists():
            logger.warning(f"Not a git repository: {repo_path}")
            return {"is_git": False}
        
        # Get commit history
        commits = self._get_commit_history(repo_path, max_commits)
        
        # Identify security-relevant commits
        security_commits = self._identify_security_commits(commits)
        
        # Extract CVE patches
        cve_patches = self._extract_cve_patches(security_commits)
        
        # Analyze patch patterns
        patch_patterns = self._analyze_patch_patterns(cve_patches)
        
        return {
            "is_git": True,
            "total_commits_analyzed": len(commits),
            "security_commits_count": len(security_commits),
            "cve_patches_count": len(cve_patches),
            "security_commits": security_commits,
            "cve_patches": cve_patches,
            "patch_patterns": patch_patterns
        }
    
    def _get_commit_history(self, repo_path: Path, max_commits: int) -> List[Dict[str, Any]]:
        """Get commit history from repository."""
        commits = []
        
        try:
            # Get commit log with format
            result = subprocess.run(
                [
                    "git", "log",
                    f"-{max_commits}",
                    "--pretty=format:%H|%an|%ae|%ad|%s",
                    "--date=iso"
                ],
                cwd=repo_path,
                check=True,
                capture_output=True,
                text=True
            )
            
            for line in result.stdout.strip().split('\n'):
                if line:
                    parts = line.split('|')
                    if len(parts) >= 5:
                        commit_hash = parts[0]
                        commits.append({
                            "hash": commit_hash,
                            "author": parts[1],
                            "email": parts[2],
                            "date": parts[3],
                            "message": parts[4]
                        })
        
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to get commit history: {e}")
        
        return commits
    
    def _identify_security_commits(self, commits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify security-relevant commits based on message keywords."""
        security_commits = []
        
        for commit in commits:
            message_lower = commit["message"].lower()
            
            # Check for security keywords
            if any(keyword in message_lower for keyword in self.cve_keywords):
                security_commits.append({
                    **commit,
                    "security_keywords": [
                        kw for kw in self.cve_keywords if kw in message_lower
                    ]
                })
        
        return security_commits
    
    def _extract_cve_patches(self, security_commits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract CVE patches from security commits."""
        cve_patches = []
        
        cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
        
        for commit in security_commits:
            # Look for CVE IDs in commit message
            cve_matches = cve_pattern.findall(commit["message"])
            
            if cve_matches:
                cve_patches.append({
                    **commit,
                    "cve_ids": cve_matches,
                    "is_cve_patch": True
                })
        
        return cve_patches
    
    def _analyze_patch_patterns(self, cve_patches: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze patterns in CVE patches."""
        patterns = {
            "common_bug_types": {},
            "affected_files": {},
            "common_fixes": {}
        }
        
        for patch in cve_patches:
            # Extract bug type from commit message
            message_lower = patch["message"].lower()
            
            bug_types = []
            if "buffer" in message_lower or "overflow" in message_lower:
                bug_types.append("buffer_overflow")
            if "integer" in message_lower:
                bug_types.append("integer_overflow")
            if "race" in message_lower:
                bug_types.append("race_condition")
            if "use-after-free" in message_lower:
                bug_types.append("use_after_free")
            if "null" in message_lower:
                bug_types.append("null_pointer")
            
            for bug_type in bug_types:
                patterns["common_bug_types"][bug_type] = \
                    patterns["common_bug_types"].get(bug_type, 0) + 1
        
        return patterns
    
    def get_file_changes(self, repo_path: str, commit_hash: str) -> Dict[str, Any]:
        """
        Get file changes for a specific commit.
        
        Args:
            repo_path: Path to git repository
            commit_hash: Commit hash
            
        Returns:
            Dictionary with file changes
        """
        repo_path = Path(repo_path)
        
        try:
            # Get changed files
            result = subprocess.run(
                ["git", "diff-tree", "--no-commit-id", "--name-only", "-r", commit_hash],
                cwd=repo_path,
                check=True,
                capture_output=True,
                text=True
            )
            
            changed_files = result.stdout.strip().split('\n') if result.stdout.strip() else []
            
            # Get diff for each file
            diffs = {}
            for file_path in changed_files:
                try:
                    diff_result = subprocess.run(
                        ["git", "show", f"{commit_hash}:{file_path}"],
                        cwd=repo_path,
                        check=True,
                        capture_output=True,
                        text=True
                    )
                    diffs[file_path] = diff_result.stdout
                except subprocess.CalledProcessError:
                    diffs[file_path] = None  # File was deleted
            
            return {
                "commit_hash": commit_hash,
                "changed_files": changed_files,
                "diffs": diffs
            }
        
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to get file changes for {commit_hash}: {e}")
            return {"commit_hash": commit_hash, "changed_files": [], "diffs": {}}
