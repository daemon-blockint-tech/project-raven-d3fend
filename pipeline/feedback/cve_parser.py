"""
CVE Patch Parser for Retrospective Learning

Parses CVE patches from various sources to extract bug patterns,
vulnerability classes, and code changes that can be used to update
agent context and improve future detection.
"""

import re
import subprocess
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import json
from datetime import datetime
import requests

from .false_negative_tracker import BugClass


class PatchSource(Enum):
    """Sources for CVE patches"""
    GITHUB_SECURITY_ADVISORY = "github_security_advisory"
    NVD = "nvd"
    OSSF_CVE_BENCHMARK = "ossf_cve_benchmark"
    MITRE = "mitre"
    COMMIT_DIFF = "commit_diff"


@dataclass
class PatchAnalysis:
    """Analysis result from parsing a CVE patch"""
    cve_id: str
    patch_source: PatchSource
    bug_class: BugClass
    language: str
    affected_files: List[str]
    vulnerability_description: str
    code_patterns: List[str]
    fix_patterns: List[str]
    pre_patch_code: str
    post_patch_code: str
    root_cause: str
    severity: str
    references: List[str]
    
    def to_dict(self) -> dict:
        return {
            'cve_id': self.cve_id,
            'patch_source': self.patch_source.value,
            'bug_class': self.bug_class.value,
            'language': self.language,
            'affected_files': self.affected_files,
            'vulnerability_description': self.vulnerability_description,
            'code_patterns': self.code_patterns,
            'fix_patterns': self.fix_patterns,
            'pre_patch_code': self.pre_patch_code,
            'post_patch_code': self.post_patch_code,
            'root_cause': self.root_cause,
            'severity': self.severity,
            'references': self.references
        }


class CVEPatchParser:
    """
    Parses CVE patches from multiple sources to extract actionable
    patterns for agent improvement.
    """
    
    def __init__(self, cache_dir: Path = Path("./pipeline/feedback/cache")):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Pattern detection rules
        self.bug_class_patterns = {
            BugClass.BUFFER_OVERFLOW: [
                r'strcpy|strcat|sprintf|gets\(',
                r'memcpy.*len.*\+',
                r'buffer.*overflow',
                r'stack.*smash'
            ],
            BugClass.USE_AFTER_FREE: [
                r'free\([^)]+\)[\s\S]*?\1',
                r'delete.*[\s\S]*?\1',
                r'pointer.*after.*free',
                r'dangling.*pointer'
            ],
            BugClass.INTEGER_OVERFLOW: [
                r'\+\s*\+.*\*',
                r'\*\s*\*.*\+',
                r'malloc.*\+.*\+',
                r'size.*overflow'
            ],
            BugClass.RACE_CONDITION: [
                r'check.*then.*act',
                r'time.*of.*check.*time.*of.*use',
                r'toctou',
                r'race.*condition'
            ],
            BugClass.NULL_DEREFERENCE: [
                r'->.*\?',
                r'\*\s*[a-z_]+\s*\?',
                r'null.*dereference',
                r'if\s*\([^)]+\)\s*\1'
            ],
            BugClass.MEMORY_LEAK: [
                r'malloc.*without.*free',
                r'new.*without.*delete',
                r'realloc.*leak',
                r'leak.*memory'
            ],
            BugClass.DOUBLE_FREE: [
                r'free\([^)]+\)[\s\S]*?free\(\1\)',
                r'delete.*delete',
                r'double.*free'
            ],
            BugClass.AUTH_BYPASS: [
                r'auth.*bypass',
                r'permission.*check.*missing',
                r'access.*control.*bypass',
                r'role.*check.*missing'
            ],
            BugClass.INJECTION: [
                r'exec\(',
                r'system\(',
                r'eval\(',
                r'\.format\(',
                r'f["\'].*\{.*\}'
            ],
            BugClass.SQL_INJECTION: [
                r'SELECT.*\+',
                r'query.*format',
                r'execute.*\+',
                r'union.*select'
            ],
            BugClass.REENTRANCY: [
                r'call.*before.*update',
                r'external.*call.*state.*change',
                r'reentrancy',
                r'checks.*effects.*interactions'
            ],
            BugClass.FFI_BOUNDARY: [
                r'extern.*"C"',
                r'#[repr\(C\)]',
                r'from.*ffi',
                r'ctypes\.',
                r'unsafe.*block'
            ],
            BugClass.CROSS_LANGUAGE: [
                r'jni.*call',
                r'native.*method',
                r'interop',
                r'cross.*language'
            ],
            BugClass.WASM_RUNTIME: [
                r'wasm.*memory',
                r'linear.*memory',
                r'wasm.*instantiate',
                r'memory.*grow'
            ],
            BugClass.SOLIDITY_NATIVE: [
                r'call\.delegatecall',
                r'extcodesize',
                r'selfdestruct',
                r'delegate.*call'
            ]
        }
    
    def parse_github_security_advisory(self, advisory_url: str) -> Optional[PatchAnalysis]:
        """Parse a GitHub Security Advisory to extract patch information"""
        try:
            # Extract CVE ID from URL
            cve_match = re.search(r'CVE-\d{4}-\d+', advisory_url)
            if not cve_match:
                return None
            
            cve_id = cve_match.group()
            
            # Fetch advisory data
            response = requests.get(advisory_url)
            if response.status_code != 200:
                return None
            
            data = response.json()
            
            # Extract vulnerability information
            severity = data.get('severity', 'unknown')
            description = data.get('description', '')
            
            # Get affected commits
            commits = []
            for reference in data.get('references', []):
                if reference.get('type') == 'advisory':
                    continue
                url = reference.get('url', '')
                if 'github.com' in url and 'commit' in url:
                    commits.append(url)
            
            if not commits:
                return None
            
            # Analyze the first commit for patterns
            return self._analyze_commit(commits[0], cve_id, description, severity)
            
        except Exception as e:
            print(f"Error parsing GitHub advisory: {e}")
            return None
    
    def parse_ossf_cve_benchmark(self, cve_id: str, benchmark_path: Path) -> Optional[PatchAnalysis]:
        """Parse a CVE from the OSSF CVE Benchmark"""
        try:
            cve_dir = benchmark_path / "CVEs" / cve_id
            if not cve_dir.exists():
                return None
            
            # Read CVE metadata
            metadata_file = cve_dir / f"{cve_id}.json"
            if not metadata_file.exists():
                return None
            
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
            
            # Get vulnerability details
            description = metadata.get('description', '')
            severity = metadata.get('severity', 'unknown')
            
            # Get affected files
            affected_files = metadata.get('affected_files', [])
            
            # Get patch information
            patch_info = metadata.get('patch', {})
            pre_patch = patch_info.get('pre_patch', '')
            post_patch = patch_info.get('post_patch', '')
            
            # Classify the bug
            bug_class = self._classify_bug(description, pre_patch, post_patch)
            
            # Extract patterns
            code_patterns = self._extract_code_patterns(pre_patch, bug_class)
            fix_patterns = self._extract_fix_patterns(pre_patch, post_patch)
            
            return PatchAnalysis(
                cve_id=cve_id,
                patch_source=PatchSource.OSSF_CVE_BENCHMARK,
                bug_class=bug_class,
                language=metadata.get('language', 'unknown'),
                affected_files=affected_files,
                vulnerability_description=description,
                code_patterns=code_patterns,
                fix_patterns=fix_patterns,
                pre_patch_code=pre_patch,
                post_patch_code=post_patch,
                root_cause=metadata.get('root_cause', ''),
                severity=severity,
                references=metadata.get('references', [])
            )
            
        except Exception as e:
            print(f"Error parsing OSSF CVE: {e}")
            return None
    
    def parse_commit_diff(self, repo_url: str, commit_hash: str) -> Optional[PatchAnalysis]:
        """Parse a git commit diff to extract vulnerability patterns"""
        try:
            # Clone repository if not already cached
            repo_name = repo_url.split('/')[-1].replace('.git', '')
            repo_path = self.cache_dir / repo_name
            
            if not repo_path.exists():
                subprocess.run(['git', 'clone', repo_url, str(repo_path)], 
                             check=True, capture_output=True)
            
            # Get commit diff
            result = subprocess.run(
                ['git', '-C', str(repo_path), 'show', commit_hash],
                check=True, capture_output=True, text=True
            )
            
            diff_output = result.stdout
            
            # Extract pre and post patch code
            pre_patch, post_patch = self._extract_diff_sections(diff_output)
            
            # Classify the bug
            bug_class = self._classify_bug(diff_output, pre_patch, post_patch)
            
            # Extract patterns
            code_patterns = self._extract_code_patterns(pre_patch, bug_class)
            fix_patterns = self._extract_fix_patterns(pre_patch, post_patch)
            
            # Detect language
            language = self._detect_language_from_diff(diff_output)
            
            # Extract affected files
            affected_files = self._extract_affected_files(diff_output)
            
            return PatchAnalysis(
                cve_id=f"commit-{commit_hash[:8]}",
                patch_source=PatchSource.COMMIT_DIFF,
                bug_class=bug_class,
                language=language,
                affected_files=affected_files,
                vulnerability_description="Commit-based vulnerability analysis",
                code_patterns=code_patterns,
                fix_patterns=fix_patterns,
                pre_patch_code=pre_patch,
                post_patch_code=post_patch,
                root_cause="Analyzed from commit diff",
                severity="unknown",
                references=[repo_url]
            )
            
        except Exception as e:
            print(f"Error parsing commit diff: {e}")
            return None
    
    def _analyze_commit(self, commit_url: str, cve_id: str, 
                      description: str, severity: str) -> Optional[PatchAnalysis]:
        """Analyze a specific commit for vulnerability patterns"""
        try:
            # Extract repo and commit hash from URL
            parts = commit_url.split('/')
            repo_url = '/'.join(parts[:5])
            commit_hash = parts[-1]
            
            return self.parse_commit_diff(repo_url, commit_hash)
            
        except Exception as e:
            print(f"Error analyzing commit: {e}")
            return None
    
    def _classify_bug(self, description: str, pre_patch: str, 
                    post_patch: str) -> BugClass:
        """Classify the bug based on description and code patterns"""
        combined_text = f"{description} {pre_patch} {post_patch}".lower()
        
        # Check each bug class for pattern matches
        scores = {}
        for bug_class, patterns in self.bug_class_patterns.items():
            score = 0
            for pattern in patterns:
                matches = len(re.findall(pattern, combined_text, re.IGNORECASE))
                score += matches
            scores[bug_class] = score
        
        # Return the class with highest score
        if scores:
            return max(scores.items(), key=lambda x: x[1])[0]
        
        return BugClass.LOGIC_ERROR  # Default
    
    def _extract_code_patterns(self, code: str, bug_class: BugClass) -> List[str]:
        """Extract specific code patterns related to the bug class"""
        patterns = []
        
        if bug_class in self.bug_class_patterns:
            for pattern in self.bug_class_patterns[bug_class]:
                matches = re.finditer(pattern, code, re.IGNORECASE)
                for match in matches:
                    # Get context around the match
                    start = max(0, match.start() - 50)
                    end = min(len(code), match.end() + 50)
                    context = code[start:end].strip()
                    patterns.append(context)
        
        return patterns[:5]  # Limit to top 5 patterns
    
    def _extract_fix_patterns(self, pre_patch: str, post_patch: str) -> List[str]:
        """Extract patterns that represent the fix"""
        fix_patterns = []
        
        # Look for common fix patterns
        fix_indicators = [
            (r'add.*check', 'Added validation check'),
            (r'add.*null.*check', 'Added null pointer check'),
            (r'add.*bounds.*check', 'Added bounds check'),
            (r'use.*safe.*function', 'Replaced with safe function'),
            (r'add.*lock', 'Added locking mechanism'),
            (r'add.*sanitize', 'Added input sanitization'),
            (r'change.*size', 'Fixed buffer size'),
            (r'add.*length.*check', 'Added length check'),
            (r'remove.*unsafe', 'Removed unsafe operation'),
            (r'initialize.*variable', 'Added variable initialization')
        ]
        
        for pattern, description in fix_indicators:
            if re.search(pattern, post_patch, re.IGNORECASE):
                fix_patterns.append(description)
        
        return fix_patterns
    
    def _extract_diff_sections(self, diff: str) -> Tuple[str, str]:
        """Extract pre and post patch code from git diff"""
        lines = diff.split('\n')
        pre_lines = []
        post_lines = []
        
        for line in lines:
            if line.startswith('-') and not line.startswith('---'):
                pre_lines.append(line[1:])
            elif line.startswith('+') and not line.startswith('+++'):
                post_lines.append(line[1:])
        
        return '\n'.join(pre_lines), '\n'.join(post_lines)
    
    def _detect_language_from_diff(self, diff: str) -> str:
        """Detect the programming language from the diff"""
        # Check file extensions
        extensions = re.findall(r'\.(c|cpp|h|hpp|js|ts|py|rs|go|java|sol|wat)', diff)
        
        if not extensions:
            return 'unknown'
        
        ext_counts = {}
        for ext in extensions:
            ext_counts[ext] = ext_counts.get(ext, 0) + 1
        
        # Map extensions to languages
        lang_map = {
            'c': 'c',
            'cpp': 'cpp',
            'h': 'c',
            'hpp': 'cpp',
            'js': 'javascript',
            'ts': 'typescript',
            'py': 'python',
            'rs': 'rust',
            'go': 'go',
            'java': 'java',
            'sol': 'solidity',
            'wat': 'wasm'
        }
        
        most_common_ext = max(ext_counts.items(), key=lambda x: x[1])[0]
        return lang_map.get(most_common_ext, 'unknown')
    
    def _extract_affected_files(self, diff: str) -> List[str]:
        """Extract list of affected files from diff"""
        files = re.findall(r'[\+\-]{3} [ab]/(.+)', diff)
        return list(set(files))
    
    def batch_parse_ossf_cves(self, benchmark_path: Path, 
                             limit: Optional[int] = None) -> List[PatchAnalysis]:
        """Parse multiple CVEs from OSSF benchmark"""
        analyses = []
        
        cve_dir = benchmark_path / "CVEs"
        if not cve_dir.exists():
            return analyses
        
        cve_folders = [f for f in cve_dir.iterdir() if f.is_dir()]
        
        if limit:
            cve_folders = cve_folders[:limit]
        
        for cve_folder in cve_folders:
            cve_id = cve_folder.name
            analysis = self.parse_ossf_cve_benchmark(cve_id, benchmark_path)
            if analysis:
                analyses.append(analysis)
        
        return analyses
