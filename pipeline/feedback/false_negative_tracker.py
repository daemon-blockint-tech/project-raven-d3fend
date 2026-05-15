"""
False Negative Tracker for Pipeline Self-Learning

Tracks missed bugs across pipeline runs, maintains historical data,
and provides insights for agent improvement.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Set
import json
from pathlib import Path


class BugClass(Enum):
    """Standardized bug classification categories"""
    BUFFER_OVERFLOW = "buffer_overflow"
    USE_AFTER_FREE = "use_after_free"
    INTEGER_OVERFLOW = "integer_overflow"
    RACE_CONDITION = "race_condition"
    NULL_DEREFERENCE = "null_dereference"
    MEMORY_LEAK = "memory_leak"
    DOUBLE_FREE = "double_free"
    TYPE_CONFUSION = "type_confusion"
    AUTH_BYPASS = "auth_bypass"
    INJECTION = "injection"
    XSS = "xss"
    CSRF = "csrf"
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    REENTRANCY = "reentrancy"
    LOGIC_ERROR = "logic_error"
    CONFIGURATION_ERROR = "configuration_error"
    CRYPTO_ERROR = "crypto_error"
    FFI_BOUNDARY = "ffi_boundary"
    CROSS_LANGUAGE = "cross_language"
    WASM_RUNTIME = "wasm_runtime"
    SOLIDITY_NATIVE = "solidity_native"


@dataclass
class MissedBug:
    """Represents a bug that was missed by the pipeline"""
    bug_id: str
    cve_id: Optional[str]
    bug_class: BugClass
    language: str
    file_path: str
    line_number: int
    description: str
    patch_diff: str
    severity: str  # critical, high, medium, low
    discovered_at: datetime
    pipeline_stage: str  # prepare, scan, validate, dedup, prove
    agent_id: Optional[str] = None
    model_used: Optional[str] = None
    root_cause_analysis: Optional[str] = None
    similar_patterns: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            'bug_id': self.bug_id,
            'cve_id': self.cve_id,
            'bug_class': self.bug_class.value,
            'language': self.language,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'description': self.description,
            'patch_diff': self.patch_diff,
            'severity': self.severity,
            'discovered_at': self.discovered_at.isoformat(),
            'pipeline_stage': self.pipeline_stage,
            'agent_id': self.agent_id,
            'model_used': self.model_used,
            'root_cause_analysis': self.root_cause_analysis,
            'similar_patterns': self.similar_patterns
        }


class FalseNegativeTracker:
    """
    Tracks false negatives across pipeline runs and provides analytics
    for agent improvement and pattern recognition.
    """
    
    def __init__(self, storage_path: Path = Path("./pipeline/feedback/data")):
        self.storage_path = storage_path
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        self.missed_bugs: Dict[str, MissedBug] = {}
        self.bug_class_frequency: Dict[BugClass, int] = {}
        self.language_frequency: Dict[str, int] = {}
        self.stage_frequency: Dict[str, int] = {}
        self.agent_performance: Dict[str, Dict] = {}
        
        self._load_state()
    
    def add_missed_bug(self, missed_bug: MissedBug) -> None:
        """Add a missed bug to the tracker"""
        self.missed_bugs[missed_bug.bug_id] = missed_bug
        
        # Update frequency counters
        self.bug_class_frequency[missed_bug.bug_class] = \
            self.bug_class_frequency.get(missed_bug.bug_class, 0) + 1
        self.language_frequency[missed_bug.language] = \
            self.language_frequency.get(missed_bug.language, 0) + 1
        self.stage_frequency[missed_bug.pipeline_stage] = \
            self.stage_frequency.get(missed_bug.pipeline_stage, 0) + 1
        
        # Track agent performance if agent_id is available
        if missed_bug.agent_id:
            if missed_bug.agent_id not in self.agent_performance:
                self.agent_performance[missed_bug.agent_id] = {
                    'total_missed': 0,
                    'bug_classes': set(),
                    'languages': set()
                }
            
            perf = self.agent_performance[missed_bug.agent_id]
            perf['total_missed'] += 1
            perf['bug_classes'].add(missed_bug.bug_class.value)
            perf['languages'].add(missed_bug.language)
        
        self._save_state()
    
    def get_missed_bugs_by_class(self, bug_class: BugClass) -> List[MissedBug]:
        """Get all missed bugs of a specific class"""
        return [bug for bug in self.missed_bugs.values() 
                if bug.bug_class == bug_class]
    
    def get_missed_bugs_by_language(self, language: str) -> List[MissedBug]:
        """Get all missed bugs in a specific language"""
        return [bug for bug in self.missed_bugs.values() 
                if bug.language == language]
    
    def get_missed_bugs_by_stage(self, stage: str) -> List[MissedBug]:
        """Get all missed bugs from a specific pipeline stage"""
        return [bug for bug in self.missed_bugs.values() 
                if bug.pipeline_stage == stage]
    
    def get_trending_bug_classes(self, limit: int = 10) -> List[tuple]:
        """Get the most frequently missed bug classes"""
        sorted_classes = sorted(
            self.bug_class_frequency.items(),
            key=lambda x: x[1],
            reverse=True
        )
        return sorted_classes[:limit]
    
    def get_agent_weaknesses(self, agent_id: str) -> Dict:
        """Get weakness analysis for a specific agent"""
        if agent_id not in self.agent_performance:
            return {}
        
        perf = self.agent_performance[agent_id]
        agent_bugs = [bug for bug in self.missed_bugs.values() 
                      if bug.agent_id == agent_id]
        
        return {
            'total_missed': perf['total_missed'],
            'bug_classes': list(perf['bug_classes']),
            'languages': list(perf['languages']),
            'recent_misses': [bug.to_dict() for bug in agent_bugs[-5:]]
        }
    
    def get_patterns_for_improvement(self) -> Dict[str, List[str]]:
        """
        Analyze missed bugs to identify patterns that should be added
        to agent context for future runs.
        """
        patterns = {
            'high_priority_classes': [],
            'language_specific_patterns': [],
            'stage_specific_patterns': []
        }
        
        # High priority bug classes (frequently missed)
        trending = self.get_trending_bug_classes(limit=5)
        for bug_class, count in trending:
            if count >= 3:  # Threshold for high priority
                patterns['high_priority_classes'].append({
                    'class': bug_class.value,
                    'frequency': count,
                    'examples': [bug.to_dict() for bug in 
                               self.get_missed_bugs_by_class(bug_class)[:3]]
                })
        
        # Language-specific patterns
        for language, count in self.language_frequency.items():
            if count >= 2:
                language_bugs = self.get_missed_bugs_by_language(language)
                patterns['language_specific_patterns'].append({
                    'language': language,
                    'frequency': count,
                    'common_classes': list(set([bug.bug_class.value 
                                                  for bug in language_bugs]))
                })
        
        # Stage-specific patterns
        for stage, count in self.stage_frequency.items():
            if count >= 2:
                stage_bugs = self.get_missed_bugs_by_stage(stage)
                patterns['stage_specific_patterns'].append({
                    'stage': stage,
                    'frequency': count,
                    'common_classes': list(set([bug.bug_class.value 
                                                  for bug in stage_bugs]))
                })
        
        return patterns
    
    def _load_state(self) -> None:
        """Load tracker state from disk"""
        state_file = self.storage_path / "false_negatives.json"
        if state_file.exists():
            try:
                with open(state_file, 'r') as f:
                    data = json.load(f)
                    
                # Reconstruct MissedBug objects
                for bug_data in data.get('missed_bugs', []):
                    bug = MissedBug(
                        bug_id=bug_data['bug_id'],
                        cve_id=bug_data.get('cve_id'),
                        bug_class=BugClass(bug_data['bug_class']),
                        language=bug_data['language'],
                        file_path=bug_data['file_path'],
                        line_number=bug_data['line_number'],
                        description=bug_data['description'],
                        patch_diff=bug_data['patch_diff'],
                        severity=bug_data['severity'],
                        discovered_at=datetime.fromisoformat(bug_data['discovered_at']),
                        pipeline_stage=bug_data['pipeline_stage'],
                        agent_id=bug_data.get('agent_id'),
                        model_used=bug_data.get('model_used'),
                        root_cause_analysis=bug_data.get('root_cause_analysis'),
                        similar_patterns=bug_data.get('similar_patterns', [])
                    )
                    self.missed_bugs[bug.bug_id] = bug
                
                # Load frequency counters
                for class_name, count in data.get('bug_class_frequency', {}).items():
                    self.bug_class_frequency[BugClass(class_name)] = count
                
                self.language_frequency = data.get('language_frequency', {})
                self.stage_frequency = data.get('stage_frequency', {})
                self.agent_performance = data.get('agent_performance', {})
                
            except Exception as e:
                print(f"Error loading state: {e}")
    
    def _save_state(self) -> None:
        """Save tracker state to disk"""
        state_file = self.storage_path / "false_negatives.json"
        state = {
            'missed_bugs': [bug.to_dict() for bug in self.missed_bugs.values()],
            'bug_class_frequency': {
                cls.value: count 
                for cls, count in self.bug_class_frequency.items()
            },
            'language_frequency': self.language_frequency,
            'stage_frequency': self.stage_frequency,
            'agent_performance': self.agent_performance
        }
        
        with open(state_file, 'w') as f:
            json.dump(state, f, indent=2)
    
    def generate_report(self) -> str:
        """Generate a comprehensive report of false negative analysis"""
        patterns = self.get_patterns_for_improvement()
        
        report = f"""
# False Negative Analysis Report

## Summary
- Total Missed Bugs: {len(self.missed_bugs)}
- Unique Bug Classes: {len(self.bug_class_frequency)}
- Languages Covered: {len(self.language_frequency)}
- Pipeline Stages: {len(self.stage_frequency)}

## High Priority Bug Classes (Frequently Missed)
"""
        for item in patterns['high_priority_classes']:
            report += f"\n### {item['class'].upper()}\n"
            report += f"- Frequency: {item['frequency']}\n"
            report += f"- Recent Examples:\n"
            for example in item['examples'][:2]:
                report += f"  - {example['bug_id']}: {example['description'][:100]}...\n"
        
        report += "\n## Language-Specific Patterns\n"
        for item in patterns['language_specific_patterns']:
            report += f"\n### {item['language']}\n"
            report += f"- Frequency: {item['frequency']}\n"
            report += f"- Common Classes: {', '.join(item['common_classes'])}\n"
        
        report += "\n## Stage-Specific Patterns\n"
        for item in patterns['stage_specific_patterns']:
            report += f"\n### {item['stage'].upper()} Stage\n"
            report += f"- Frequency: {item['frequency']}\n"
            report += f"- Common Classes: {', '.join(item['common_classes'])}\n"
        
        return report
