"""
Agent Context Updater for Self-Learning

Automatically updates agent context, examples, and prompt regimes
based on patterns learned from missed bugs and CVE patches.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set
from datetime import datetime
import re

from .cve_parser import PatchAnalysis
from .false_negative_tracker import MissedBug, BugClass


@dataclass
class AgentContext:
    """Represents the context and examples for a specific agent"""
    agent_id: str
    agent_type: str  # scanner, validator, dedup, prover
    language_specialization: str
    current_examples: List[dict] = field(default_factory=list)
    bug_class_examples: Dict[str, List[dict]] = field(default_factory=dict)
    prompt_regime: dict = field(default_factory=dict)
    last_updated: datetime = field(default_factory=datetime.now)
    performance_metrics: dict = field(default_factory=dict)


class AgentContextUpdater:
    """
    Updates agent context based on learned patterns from missed bugs
    and CVE patch analysis.
    """
    
    def __init__(self, context_dir: Path = Path("./pipeline/feedback/contexts")):
        self.context_dir = context_dir
        self.context_dir.mkdir(parents=True, exist_ok=True)
        
        self.agent_contexts: Dict[str, AgentContext] = {}
        self._load_contexts()
    
    def update_from_missed_bug(self, missed_bug: MissedBug) -> None:
        """Update agent context based on a missed bug"""
        agent_id = missed_bug.agent_id or "default"
        
        # Get or create agent context
        if agent_id not in self.agent_contexts:
            self.agent_contexts[agent_id] = AgentContext(
                agent_id=agent_id,
                agent_type=self._infer_agent_type(missed_bug.pipeline_stage),
                language_specialization=missed_bug.language
            )
        
        context = self.agent_contexts[agent_id]
        
        # Add example to bug class examples
        bug_class = missed_bug.bug_class.value
        if bug_class not in context.bug_class_examples:
            context.bug_class_examples[bug_class] = []
        
        example = {
            'bug_id': missed_bug.bug_id,
            'cve_id': missed_bug.cve_id,
            'description': missed_bug.description,
            'file_path': missed_bug.file_path,
            'line_number': missed_bug.line_number,
            'patch_diff': missed_bug.patch_diff,
            'severity': missed_bug.severity,
            'discovered_at': missed_bug.discovered_at.isoformat(),
            'root_cause': missed_bug.root_cause_analysis
        }
        
        context.bug_class_examples[bug_class].append(example)
        
        # Update performance metrics
        if 'missed_count' not in context.performance_metrics:
            context.performance_metrics['missed_count'] = 0
        context.performance_metrics['missed_count'] += 1
        
        # Update last modified
        context.last_updated = datetime.now()
        
        self._save_context(agent_id)
    
    def update_from_patch_analysis(self, patch_analysis: PatchAnalysis) -> None:
        """Update agent context based on CVE patch analysis"""
        # Determine which agents should receive this update
        target_agents = self._determine_target_agents(patch_analysis)
        
        for agent_id in target_agents:
            if agent_id not in self.agent_contexts:
                self.agent_contexts[agent_id] = AgentContext(
                    agent_id=agent_id,
                    agent_type="scanner",  # Default to scanner
                    language_specialization=patch_analysis.language
                )
            
            context = self.agent_contexts[agent_id]
            
            # Add to bug class examples
            bug_class = patch_analysis.bug_class.value
            if bug_class not in context.bug_class_examples:
                context.bug_class_examples[bug_class] = []
            
            example = {
                'cve_id': patch_analysis.cve_id,
                'description': patch_analysis.vulnerability_description,
                'code_patterns': patch_analysis.code_patterns,
                'fix_patterns': patch_analysis.fix_patterns,
                'pre_patch_code': patch_analysis.pre_patch_code,
                'post_patch_code': patch_analysis.post_patch_code,
                'root_cause': patch_analysis.root_cause,
                'severity': patch_analysis.severity,
                'affected_files': patch_analysis.affected_files,
                'references': patch_analysis.references
            }
            
            context.bug_class_examples[bug_class].append(example)
            
            # Update prompt regime based on patterns
            self._update_prompt_regime(context, patch_analysis)
            
            context.last_updated = datetime.now()
            self._save_context(agent_id)
    
    def _infer_agent_type(self, pipeline_stage: str) -> str:
        """Infer agent type from pipeline stage"""
        stage_to_agent = {
            'prepare': 'preparer',
            'scan': 'scanner',
            'validate': 'validator',
            'dedup': 'deduplicator',
            'prove': 'prover'
        }
        return stage_to_agent.get(pipeline_stage, 'scanner')
    
    def _determine_target_agents(self, patch_analysis: PatchAnalysis) -> List[str]:
        """Determine which agents should receive this patch analysis"""
        agents = []
        
        # Always add language-specialized scanner
        language = patch_analysis.language
        if language:
            agents.append(f"scanner_{language}")
        
        # Add specialized agents for cross-language patterns
        if patch_analysis.bug_class in [BugClass.FFI_BOUNDARY, BugClass.CROSS_LANGUAGE]:
            agents.append("scanner_cross_language")
        
        if patch_analysis.bug_class == BugClass.WASM_RUNTIME:
            agents.append("scanner_wasm")
        
        if patch_analysis.bug_class == BugClass.SOLIDITY_NATIVE:
            agents.append("scanner_solidity")
        
        # Add default scanner if no specialized agent
        if not agents:
            agents.append("scanner_default")
        
        return agents
    
    def _update_prompt_regime(self, context: AgentContext, 
                             patch_analysis: PatchAnalysis) -> None:
        """Update prompt regime based on learned patterns"""
        # Extract key patterns to emphasize in prompts
        bug_class = patch_analysis.bug_class.value
        
        if 'emphasized_patterns' not in context.prompt_regime:
            context.prompt_regime['emphasized_patterns'] = {}
        
        # Add code patterns to emphasize
        for pattern in patch_analysis.code_patterns[:3]:  # Top 3 patterns
            if bug_class not in context.prompt_regime['emphasized_patterns']:
                context.prompt_regime['emphasized_patterns'][bug_class] = []
            
            context.prompt_regime['emphasized_patterns'][bug_class].append(pattern)
        
        # Add fix patterns as positive examples
        if 'fix_patterns' not in context.prompt_regime:
            context.prompt_regime['fix_patterns'] = {}
        
        context.prompt_regime['fix_patterns'][bug_class] = patch_analysis.fix_patterns
        
        # Update detection priority based on frequency
        if 'detection_priority' not in context.prompt_regime:
            context.prompt_regime['detection_priority'] = {}
        
        current_priority = context.prompt_regime['detection_priority'].get(bug_class, 0)
        context.prompt_regime['detection_priority'][bug_class] = current_priority + 1
    
    def get_agent_context(self, agent_id: str) -> Optional[AgentContext]:
        """Get context for a specific agent"""
        return self.agent_contexts.get(agent_id)
    
    def get_improved_prompt(self, agent_id: str, base_prompt: str) -> str:
        """Generate an improved prompt with learned patterns"""
        context = self.get_agent_context(agent_id)
        if not context:
            return base_prompt
        
        improved_prompt = base_prompt
        
        # Add emphasized patterns section
        if context.prompt_regime.get('emphasized_patterns'):
            patterns_section = "\n\n# Recently Missed Patterns to Watch For:\n"
            for bug_class, patterns in context.prompt_regime['emphasized_patterns'].items():
                patterns_section += f"\n## {bug_class.upper()}\n"
                for pattern in patterns[-3:]:  # Most recent 3
                    patterns_section += f"- {pattern}\n"
            
            improved_prompt += patterns_section
        
        # Add fix patterns as positive examples
        if context.prompt_regime.get('fix_patterns'):
            fixes_section = "\n\n# Common Fix Patterns:\n"
            for bug_class, fixes in context.prompt_regime['fix_patterns'].items():
                fixes_section += f"\n## {bug_class.upper()}\n"
                for fix in fixes[:2]:  # Top 2 fixes
                    fixes_section += f"- {fix}\n"
            
            improved_prompt += fixes_section
        
        # Add detection priority guidance
        if context.prompt_regime.get('detection_priority'):
            priority_section = "\n\n# Detection Priority:\n"
            sorted_priorities = sorted(
                context.prompt_regime['detection_priority'].items(),
                key=lambda x: x[1],
                reverse=True
            )
            for bug_class, priority in sorted_priorities[:5]:
                priority_section += f"- {bug_class} (frequency: {priority})\n"
            
            improved_prompt += priority_section
        
        return improved_prompt
    
    def get_examples_for_agent(self, agent_id: str, 
                            bug_class: Optional[str] = None) -> List[dict]:
        """Get relevant examples for an agent"""
        context = self.get_agent_context(agent_id)
        if not context:
            return []
        
        if bug_class:
            return context.bug_class_examples.get(bug_class, [])
        
        # Return examples from most frequent bug classes
        all_examples = []
        for bug_class, examples in context.bug_class_examples.items():
            all_examples.extend(examples)
        
        return all_examples
    
    def _load_contexts(self) -> None:
        """Load agent contexts from disk"""
        for context_file in self.context_dir.glob("*.json"):
            try:
                with open(context_file, 'r') as f:
                    data = json.load(f)
                
                context = AgentContext(
                    agent_id=data['agent_id'],
                    agent_type=data['agent_type'],
                    language_specialization=data['language_specialization'],
                    current_examples=data.get('current_examples', []),
                    bug_class_examples=data.get('bug_class_examples', {}),
                    prompt_regime=data.get('prompt_regime', {}),
                    last_updated=datetime.fromisoformat(data['last_updated']),
                    performance_metrics=data.get('performance_metrics', {})
                )
                
                self.agent_contexts[context.agent_id] = context
                
            except Exception as e:
                print(f"Error loading context from {context_file}: {e}")
    
    def _save_context(self, agent_id: str) -> None:
        """Save agent context to disk"""
        context = self.agent_contexts[agent_id]
        context_file = self.context_dir / f"{agent_id}.json"
        
        data = {
            'agent_id': context.agent_id,
            'agent_type': context.agent_type,
            'language_specialization': context.language_specialization,
            'current_examples': context.current_examples,
            'bug_class_examples': context.bug_class_examples,
            'prompt_regime': context.prompt_regime,
            'last_updated': context.last_updated.isoformat(),
            'performance_metrics': context.performance_metrics
        }
        
        with open(context_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def generate_context_report(self) -> str:
        """Generate a comprehensive report of agent contexts"""
        report = "# Agent Context Update Report\n\n"
        
        for agent_id, context in self.agent_contexts.items():
            report += f"## Agent: {agent_id}\n"
            report += f"- Type: {context.agent_type}\n"
            report += f"- Language: {context.language_specialization}\n"
            report += f"- Last Updated: {context.last_updated}\n"
            report += f"- Total Bug Classes: {len(context.bug_class_examples)}\n"
            report += f"- Performance: {context.performance_metrics}\n"
            
            report += "\n### Bug Class Examples:\n"
            for bug_class, examples in context.bug_class_examples.items():
                report += f"- {bug_class}: {len(examples)} examples\n"
            
            report += "\n### Prompt Regime:\n"
            if context.prompt_regime.get('detection_priority'):
                report += "Detection Priority:\n"
                for bug_class, priority in sorted(
                    context.prompt_regime['detection_priority'].items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:5]:
                    report += f"  - {bug_class}: {priority}\n"
            
            report += "\n"
        
        return report
