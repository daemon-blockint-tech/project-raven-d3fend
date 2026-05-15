"""
Plugin Synthesis Agent for Domain Invariant Extraction

Automatically extracts domain invariants from documentation, source history,
and commit messages to generate plugin specifications without manual encoding.
"""

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict
import subprocess


class InvariantType(Enum):
    """Types of domain invariants"""
    PRECONDITION = "precondition"
    POSTCONDITION = "postcondition"
    INVARIANT = "invariant"
    CONSTRAINT = "constraint"
    ASSUMPTION = "assumption"
    GUARANTEE = "guarantee"
    PROPERTY = "property"


class InvariantSource(Enum):
    """Sources of invariant extraction"""
    DOCUMENTATION = "documentation"
    COMMIT_MESSAGE = "commit_message"
    SOURCE_CODE = "source_code"
    TEST_CASE = "test_case"
    ISSUE_TRACKER = "issue_tracker"
    CODE_COMMENT = "code_comment"


@dataclass
class DomainInvariant:
    """Represents a domain invariant extracted from codebase"""
    invariant_id: str
    invariant_type: InvariantType
    source: InvariantSource
    location: str  # file:line or commit hash
    description: str
    formal_expression: Optional[str]
    confidence: float
    related_invariants: List[str]
    domain: str
    plugin_relevance: float  # How relevant this invariant is for plugin generation


@dataclass
class PluginSpecification:
    """Generated plugin specification from invariants"""
    plugin_id: str
    plugin_name: str
    domain: str
    invariants: List[DomainInvariant]
    preconditions: List[str]
    postconditions: List[str]
    invariants_list: List[str]
    constraints: List[str]
    confidence: float
    generated_code: Optional[str]
    test_cases: List[str]


class PluginSynthesisAgent:
    """
    Automatically extracts domain invariants from documentation,
    source history, and commit messages to generate plugin specifications.
    """
    
    def __init__(self):
        self.invariants: List[DomainInvariant] = []
        self.plugins: List[PluginSpecification] = []
        
        # Pattern libraries for invariant extraction
        self.precondition_patterns = [
            r'(must|should|shall|require|need|must not)\s+(\w+)',
            r'(before|prior to|precondition for)\s+(\w+)',
            r'(assumes?|assumption)\s+(that|the)',
            r'(requires?|requirement)\s+(that|the)',
        ]
        
        self.postcondition_patterns = [
            r'(ensures?|guarantees?|will|shall)\s+(\w+)',
            r'(after|postcondition for)\s+(\w+)',
            r'(returns?|result)\s+(is|should be)',
            r'(output)\s+(must|should)',
        ]
        
        self.invariant_patterns = [
            r'(always|never|must)\s+(\w+)',
            r'(invariant|property)\s+(of|for)\s+(\w+)',
            r'(maintains?|preserves?)\s+(\w+)',
            r'(cannot|must not)\s+(\w+)',
        ]
        
        self.constraint_patterns = [
            r'(constraint|limit|restriction)\s+(on|for)\s+(\w+)',
            r'(maximum|minimum)\s+(\w+)',
            r'(at most|at least)\s+(\d+)',
            r'(range)\s+(between|of)',
        ]
        
        # Domain-specific patterns
        self.domain_keywords = {
            'security': [
                'vulnerability', 'exploit', 'attack', 'mitigation',
                'threat', 'risk', 'protection', 'defense', 'secure'
            ],
            'database': [
                'transaction', 'consistency', 'isolation', 'durability',
                'query', 'index', 'schema', 'migration'
            ],
            'network': [
                'protocol', 'connection', 'latency', 'throughput',
                'packet', 'socket', 'bandwidth', 'timeout'
            ],
            'crypto': [
                'encryption', 'decryption', 'key', 'signature',
                'hash', 'certificate', 'authentication', 'integrity'
            ],
            'filesystem': [
                'file', 'directory', 'permission', 'access',
                'inode', 'mount', 'path', 'lock'
            ],
        }
    
    def extract_from_documentation(self, docs_path: Path) -> List[DomainInvariant]:
        """Extract invariants from documentation files"""
        invariants = []
        
        # Find documentation files
        doc_files = []
        for ext in ['.md', '.rst', '.txt', '.docx']:
            doc_files.extend(docs_path.rglob(f'*{ext}'))
        
        for doc_file in doc_files:
            with open(doc_file, 'r', errors='ignore') as f:
                content = f.read()
            
            file_invariants = self._extract_invariants_from_text(
                content, str(doc_file), InvariantSource.DOCUMENTATION
            )
            invariants.extend(file_invariants)
        
        self.invariants.extend(invariants)
        return invariants
    
    def extract_from_commit_history(self, repo_path: Path, max_commits: int = 100) -> List[DomainInvariant]:
        """Extract invariants from git commit messages"""
        invariants = []
        
        try:
            # Get commit messages
            result = subprocess.run(
                ['git', 'log', f'-{max_commits}', '--pretty=format:%H %s'],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                commits = result.stdout.strip().split('\n')
                for commit in commits:
                    if not commit:
                        continue
                    parts = commit.split(' ', 1)
                    commit_hash = parts[0]
                    message = parts[1] if len(parts) > 1 else ''
                    
                    commit_invariants = self._extract_invariants_from_text(
                        message, commit_hash, InvariantSource.COMMIT_MESSAGE
                    )
                    invariants.extend(commit_invariants)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass  # Git not available or timeout
        
        self.invariants.extend(invariants)
        return invariants
    
    def extract_from_source_code(self, code_path: Path) -> List[DomainInvariant]:
        """Extract invariants from source code comments and assertions"""
        invariants = []
        
        # Find source code files
        code_files = []
        for ext in ['.py', '.js', '.ts', '.rs', '.go', '.java']:
            code_files.extend(code_path.rglob(f'*{ext}'))
        
        for code_file in code_files:
            with open(code_file, 'r', errors='ignore') as f:
                content = f.read()
            
            # Extract from comments
            comment_invariants = self._extract_from_comments(
                content, str(code_file)
            )
            invariants.extend(comment_invariants)
            
            # Extract from assertions
            assertion_invariants = self._extract_from_assertions(
                content, str(code_file)
            )
            invariants.extend(assertion_invariants)
        
        self.invariants.extend(invariants)
        return invariants
    
    def _extract_from_comments(self, content: str, location: str) -> List[DomainInvariant]:
        """Extract invariants from code comments"""
        invariants = []
        
        # Multi-line comments
        for pattern in [r'/\*([^*]|[\r\n]|(\*(?!/))*\*/', r'"""([^"]|[\r\n])*"""', r"'''([^']|[\r\n])*'''"]:
            matches = re.finditer(pattern, content, re.MULTILINE | re.DOTALL)
            for match in matches:
                comment_text = match.group()
                comment_invariants = self._extract_invariants_from_text(
                    comment_text, location, InvariantSource.CODE_COMMENT
                )
                invariants.extend(comment_invariants)
        
        # Single-line comments
        for line in content.split('\n'):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                comment_invariants = self._extract_invariants_from_text(
                    stripped, location, InvariantSource.CODE_COMMENT
                )
                invariants.extend(comment_invariants)
        
        return invariants
    
    def _extract_from_assertions(self, content: str, location: str) -> List[DomainInvariant]:
        """Extract invariants from assertions in code"""
        invariants = []
        
        # Assertion patterns
        assertion_patterns = [
            r'assert\s+(.+)',
            r'assertEqual\s*\((.+),\s*(.+)\)',
            r'assertTrue\s*\((.+)\)',
            r'assertFalse\s*\((.+)\)',
            r'assertRaises\s*\((.+)\)',
            r'invariant\s*\((.+)\)',
            r'assume\s*\((.+)\)',
            r'require\s*\((.+)\)',
        ]
        
        for pattern in assertion_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                invariant_text = match.group(1)
                
                invariant = DomainInvariant(
                    invariant_id=f"{location}:{line_num}",
                    invariant_type=InvariantType.INVARIANT,
                    source=InvariantSource.SOURCE_CODE,
                    location=f"{location}:{line_num}",
                    description=invariant_text,
                    formal_expression=self._extract_formal_expression(invariant_text),
                    confidence=0.8,
                    related_invariants=[],
                    domain=self._classify_domain(invariant_text),
                    plugin_relevance=self._calculate_plugin_relevance(invariant_text)
                )
                invariants.append(invariant)
        
        return invariants
    
    def _extract_invariants_from_text(self, text: str, location: str,
                                     source: InvariantSource) -> List[DomainInvariant]:
        """Extract invariants from text content"""
        invariants = []
        
        lines = text.split('\n')
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or len(line) < 10:
                continue
            
            # Try each invariant type pattern
            for inv_type, patterns in [
                (InvariantType.PRECONDITION, self.precondition_patterns),
                (InvariantType.POSTCONDITION, self.postcondition_patterns),
                (InvariantType.INVARIANT, self.invariant_patterns),
                (InvariantType.CONSTRAINT, self.constraint_patterns),
            ].items():
                for pattern in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        invariant = DomainInvariant(
                            invariant_id=f"{location}:{line_num}",
                            invariant_type=inv_type,
                            source=source,
                            location=f"{location}:{line_num}",
                            description=line,
                            formal_expression=self._extract_formal_expression(line),
                            confidence=0.6,
                            related_invariants=[],
                            domain=self._classify_domain(line),
                            plugin_relevance=self._calculate_plugin_relevance(line)
                        )
                        invariants.append(invariant)
                        break
        
        return invariants
    
    def _extract_formal_expression(self, text: str) -> Optional[str]:
        """Extract formal expression from natural language"""
        # Try to identify mathematical/logical expressions
        math_patterns = [
            r'[<>]=?\s*\d+',
            r'[a-zA-Z_]\w*\s*[<>!=]=\s*[a-zA-Z_]\w*',
            r'\b(true|false|null|undefined)\b',
            r'\b(and|or|not|if|then|else)\b',
        ]
        
        expressions = []
        for pattern in math_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            expressions.extend(matches)
        
        if expressions:
            return ', '.join(expressions)
        return None
    
    def _classify_domain(self, text: str) -> str:
        """Classify the domain of an invariant"""
        text_lower = text.lower()
        domain_scores = defaultdict(int)
        
        for domain, keywords in self.domain_keywords.items():
            for keyword in keywords:
                if keyword in text_lower:
                    domain_scores[domain] += 1
        
        if domain_scores:
            return max(domain_scores.items(), key=lambda x: x[1])[0]
        return 'general'
    
    def _calculate_plugin_relevance(self, text: str) -> float:
        """Calculate how relevant an invariant is for plugin generation"""
        relevance_indicators = [
            'must', 'shall', 'require', 'ensure', 'guarantee',
            'invariant', 'property', 'constraint', 'condition',
            'assert', 'assume', 'precondition', 'postcondition'
        ]
        
        text_lower = text.lower()
        score = 0
        for indicator in relevance_indicators:
            if indicator in text_lower:
                score += 0.2
        
        return min(1.0, score)
    
    def cluster_invariants_by_domain(self) -> Dict[str, List[DomainInvariant]]:
        """Cluster invariants by their domain"""
        clusters = defaultdict(list)
        for invariant in self.invariants:
            clusters[invariant.domain].append(invariant)
        return dict(clusters)
    
    def generate_plugin_specification(self, domain: str,
                                    min_confidence: float = 0.5) -> PluginSpecification:
        """Generate a plugin specification from domain invariants"""
        domain_invariants = [
            inv for inv in self.invariants
            if inv.domain == domain and inv.confidence >= min_confidence
        ]
        
        # Sort by plugin relevance
        domain_invariants.sort(key=lambda x: x.plugin_relevance, reverse=True)
        
        # Extract preconditions, postconditions, invariants, constraints
        preconditions = []
        postconditions = []
        invariants_list = []
        constraints = []
        
        for inv in domain_invariants[:20]:  # Limit to top 20 invariants
            if inv.invariant_type == InvariantType.PRECONDITION:
                preconditions.append(inv.description)
            elif inv.invariant_type == InvariantType.POSTCONDITION:
                postconditions.append(inv.description)
            elif inv.invariant_type == InvariantType.INVARIANT:
                invariants_list.append(inv.description)
            elif inv.invariant_type == InvariantType.CONSTRAINT:
                constraints.append(inv.description)
        
        # Calculate overall confidence
        avg_confidence = sum(inv.confidence for inv in domain_invariants) / len(domain_invariants) if domain_invariants else 0.0
        
        # Generate plugin ID
        plugin_id = f"{domain}_plugin_{len(self.plugins)}"
        
        plugin = PluginSpecification(
            plugin_id=plugin_id,
            plugin_name=f"{domain.capitalize()} Plugin",
            domain=domain,
            invariants=domain_invariants,
            preconditions=preconditions,
            postconditions=postconditions,
            invariants_list=invariants_list,
            constraints=constraints,
            confidence=avg_confidence,
            generated_code=None,
            test_cases=[]
        )
        
        self.plugins.append(plugin)
        return plugin
    
    def generate_all_plugins(self) -> List[PluginSpecification]:
        """Generate plugin specifications for all domains"""
        domain_clusters = self.cluster_invariants_by_domain()
        plugins = []
        
        for domain in domain_clusters.keys():
            plugin = self.generate_plugin_specification(domain)
            plugins.append(plugin)
        
        return plugins
    
    def generate_report(self) -> str:
        """Generate a comprehensive plugin synthesis report"""
        report = "# Plugin Synthesis Agent Report\n\n"
        
        report += "## Invariant Summary\n"
        report += f"- Total Invariants Extracted: {len(self.invariants)}\n"
        
        # Count by source
        source_counts = defaultdict(int)
        for inv in self.invariants:
            source_counts[inv.source.value] += 1
        report += "\n### By Source\n"
        for source, count in source_counts.items():
            report += f"- {source}: {count} invariants\n"
        
        # Count by type
        type_counts = defaultdict(int)
        for inv in self.invariants:
            type_counts[inv.invariant_type.value] += 1
        report += "\n### By Type\n"
        for inv_type, count in type_counts.items():
            report += f"- {inv_type}: {count} invariants\n"
        
        # Count by domain
        domain_counts = defaultdict(int)
        for inv in self.invariants:
            domain_counts[inv.domain] += 1
        report += "\n### By Domain\n"
        for domain, count in domain_counts.items():
            report += f"- {domain}: {count} invariants\n"
        
        report += "\n## Generated Plugins\n"
        for plugin in self.plugins:
            report += f"\n### {plugin.plugin_name}\n"
            report += f"- Domain: {plugin.domain}\n"
            report += f"- Confidence: {plugin.confidence:.2f}\n"
            report += f"- Preconditions: {len(plugin.preconditions)}\n"
            report += f"- Postconditions: {len(plugin.postconditions)}\n"
            report += f"- Invariants: {len(plugin.invariants_list)}\n"
            report += f"- Constraints: {len(plugin.constraints)}\n"
        
        return report
