"""
Retrospective Feedback Agent for Pipeline Self-Learning

Orchestrates the feedback loop by:
1. Analyzing pipeline results to identify missed bugs
2. Parsing CVE patches to extract learning patterns
3. Updating agent contexts with new examples and prompt regimes
4. Providing recommendations for pipeline improvement
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set
from datetime import datetime, timedelta
import json

from .false_negative_tracker import FalseNegativeTracker, MissedBug, BugClass
from .cve_parser import CVEPatchParser, PatchAnalysis
from .context_updater import AgentContextUpdater


@dataclass
class FeedbackResult:
    """Result of a feedback loop iteration"""
    iteration_id: str
    timestamp: datetime
    bugs_analyzed: int
    new_patterns_learned: int
    agents_updated: List[str]
    context_improvements: Dict[str, List[str]]
    recommendations: List[str]
    
    def to_dict(self) -> dict:
        return {
            'iteration_id': self.iteration_id,
            'timestamp': self.timestamp.isoformat(),
            'bugs_analyzed': self.bugs_analyzed,
            'new_patterns_learned': self.new_patterns_learned,
            'agents_updated': self.agents_updated,
            'context_improvements': self.context_improvements,
            'recommendations': self.recommendations
        }


class RetrospectiveFeedbackAgent:
    """
    Main feedback agent that orchestrates learning from pipeline results
    and continuously improves agent performance.
    """
    
    def __init__(self, feedback_dir: Path = Path("./pipeline/feedback")):
        self.feedback_dir = feedback_dir
        self.feedback_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize components
        self.false_negative_tracker = FalseNegativeTracker(
            feedback_dir / "data"
        )
        self.cve_parser = CVEPatchParser(
            feedback_dir / "cache"
        )
        self.context_updater = AgentContextUpdater(
            feedback_dir / "contexts"
        )
        
        # Feedback history
        self.feedback_history: List[FeedbackResult] = []
        self._load_history()
        
        # Configuration
        self.learning_threshold = 3  # Minimum occurrences before pattern is learned
        self.feedback_interval = timedelta(days=1)  # Run feedback daily
    
    def analyze_pipeline_run(self, run_results: dict) -> FeedbackResult:
        """
        Analyze a pipeline run to identify missed bugs and trigger learning.
        
        Args:
            run_results: Dictionary containing pipeline execution results
                - detected_bugs: List of bugs detected
                - total_bugs: List of all bugs in the codebase
                - stage_results: Results from each pipeline stage
                - agents_used: List of agent IDs used in the run
        """
        iteration_id = f"feedback-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        # Identify missed bugs
        missed_bugs = self._identify_missed_bugs(run_results)
        
        # Track missed bugs
        for bug in missed_bugs:
            self.false_negative_tracker.add_missed_bug(bug)
        
        # Analyze patterns and learn
        patterns = self.false_negative_tracker.get_patterns_for_improvement()
        
        # Parse CVE patches for additional learning
        patch_analyses = self._learn_from_cve_patches()
        
        # Update agent contexts
        agents_updated = []
        context_improvements = {}
        
        for bug in missed_bugs:
            self.context_updater.update_from_missed_bug(bug)
            if bug.agent_id and bug.agent_id not in agents_updated:
                agents_updated.append(bug.agent_id)
        
        for patch_analysis in patch_analyses:
            self.context_updater.update_from_patch_analysis(patch_analysis)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(patterns, missed_bugs)
        
        # Create feedback result
        result = FeedbackResult(
            iteration_id=iteration_id,
            timestamp=datetime.now(),
            bugs_analyzed=len(missed_bugs),
            new_patterns_learned=len(patterns['high_priority_classes']),
            agents_updated=agents_updated,
            context_improvements=context_improvements,
            recommendations=recommendations
        )
        
        self.feedback_history.append(result)
        self._save_history()
        
        return result
    
    def _identify_missed_bugs(self, run_results: dict) -> List[MissedBug]:
        """Identify bugs that were missed by the pipeline"""
        detected_bugs = set(run_results.get('detected_bugs', []))
        total_bugs = run_results.get('total_bugs', [])
        
        missed_bugs = []
        
        for bug_info in total_bugs:
            bug_id = bug_info.get('id')
            if bug_id not in detected_bugs:
                # Create MissedBug object
                missed_bug = MissedBug(
                    bug_id=bug_id,
                    cve_id=bug_info.get('cve_id'),
                    bug_class=self._classify_bug(bug_info),
                    language=bug_info.get('language', 'unknown'),
                    file_path=bug_info.get('file_path', ''),
                    line_number=bug_info.get('line_number', 0),
                    description=bug_info.get('description', ''),
                    patch_diff=bug_info.get('patch_diff', ''),
                    severity=bug_info.get('severity', 'unknown'),
                    discovered_at=datetime.now(),
                    pipeline_stage=bug_info.get('missed_at_stage', 'unknown'),
                    agent_id=bug_info.get('agent_id'),
                    model_used=bug_info.get('model_used'),
                    root_cause_analysis=bug_info.get('root_cause')
                )
                missed_bugs.append(missed_bug)
        
        return missed_bugs
    
    def _classify_bug(self, bug_info: dict) -> BugClass:
        """Classify a bug based on its information"""
        bug_class_str = bug_info.get('bug_class', '')
        description = bug_info.get('description', '').lower()
        
        # Try to map string to enum
        try:
            return BugClass(bug_class_str)
        except ValueError:
            # Fallback to keyword matching
            if 'buffer' in description and 'overflow' in description:
                return BugClass.BUFFER_OVERFLOW
            elif 'use after free' in description:
                return BugClass.USE_AFTER_FREE
            elif 'integer' in description and 'overflow' in description:
                return BugClass.INTEGER_OVERFLOW
            elif 'race' in description:
                return BugClass.RACE_CONDITION
            elif 'null' in description and 'dereference' in description:
                return BugClass.NULL_DEREFERENCE
            elif 'injection' in description:
                return BugClass.INJECTION
            elif 'reentrancy' in description:
                return BugClass.REENTRANCY
            elif 'ffi' in description or 'extern' in description:
                return BugClass.FFI_BOUNDARY
            elif 'wasm' in description:
                return BugClass.WASM_RUNTIME
            elif 'solidity' in description or 'delegatecall' in description:
                return BugClass.SOLIDITY_NATIVE
            else:
                return BugClass.LOGIC_ERROR
    
    def _learn_from_cve_patches(self) -> List[PatchAnalysis]:
        """Learn from CVE patches in benchmark datasets"""
        analyses = []
        
        # Try to learn from OSSF CVE benchmark if available
        ossf_benchmark_path = Path("/Volumes/RadeNugroho/project-raven-d3fend/benchmark/ossf-cve-benchmark")
        if ossf_benchmark_path.exists():
            try:
                analyses = self.cve_parser.batch_parse_ossf_cves(
                    ossf_benchmark_path,
                    limit=10  # Limit to 10 recent CVEs
                )
            except Exception as e:
                print(f"Error learning from OSSF CVE benchmark: {e}")
        
        return analyses
    
    def _generate_recommendations(self, patterns: dict, 
                                missed_bugs: List[MissedBug]) -> List[str]:
        """Generate recommendations for pipeline improvement"""
        recommendations = []
        
        # Analyze high priority bug classes
        if patterns['high_priority_classes']:
            for item in patterns['high_priority_classes']:
                if item['frequency'] >= self.learning_threshold:
                    recommendations.append(
                        f"Add specialized training for {item['class']} bug class "
                        f"(frequency: {item['frequency']})"
                    )
        
        # Analyze language-specific patterns
        if patterns['language_specific_patterns']:
            for item in patterns['language_specific_patterns']:
                if item['frequency'] >= self.learning_threshold:
                    recommendations.append(
                        f"Deploy language-specialized agent for {item['language']} "
                        f"(common classes: {', '.join(item['common_classes'])})"
                    )
        
        # Analyze stage-specific patterns
        if patterns['stage_specific_patterns']:
            for item in patterns['stage_specific_patterns']:
                if item['frequency'] >= self.learning_threshold:
                    recommendations.append(
                        f"Improve {item['stage']} stage detection for "
                        f"{', '.join(item['common_classes'])}"
                    )
        
        # Cross-language recommendations
        cross_lang_bugs = [bug for bug in missed_bugs 
                          if bug.bug_class in [BugClass.FFI_BOUNDARY, 
                                              BugClass.CROSS_LANGUAGE,
                                              BugClass.WASM_RUNTIME,
                                              BugClass.SOLIDITY_NATIVE]]
        
        if cross_lang_bugs:
            recommendations.append(
                f"Deploy cross-language reasoning agents "
                f"({len(cross_lang_bugs)} cross-language bugs missed)"
            )
        
        # Agent-specific recommendations
        agent_performance = {}
        for bug in missed_bugs:
            if bug.agent_id:
                if bug.agent_id not in agent_performance:
                    agent_performance[bug.agent_id] = 0
                agent_performance[bug.agent_id] += 1
        
        for agent_id, missed_count in agent_performance.items():
            if missed_count >= self.learning_threshold:
                recommendations.append(
                    f"Retrain or update {agent_id} agent "
                    f"(missed {missed_count} bugs)"
                )
        
        return recommendations
    
    def run_scheduled_feedback(self) -> FeedbackResult:
        """Run feedback loop on schedule (e.g., daily)"""
        # This would be called by a scheduler
        # For now, trigger analysis from recent pipeline runs
        recent_runs = self._get_recent_pipeline_runs()
        
        if not recent_runs:
            # If no recent runs, analyze from CVE patches
            patch_analyses = self._learn_from_cve_patches()
            
            for analysis in patch_analyses:
                self.context_updater.update_from_patch_analysis(analysis)
            
            return FeedbackResult(
                iteration_id=f"scheduled-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                timestamp=datetime.now(),
                bugs_analyzed=len(patch_analyses),
                new_patterns_learned=len(patch_analyses),
                agents_updated=[],
                context_improvements={},
                recommendations=["Learned from CVE patches"]
            )
        
        # Analyze most recent run
        latest_run = recent_runs[0]
        return self.analyze_pipeline_run(latest_run)
    
    def _get_recent_pipeline_runs(self) -> List[dict]:
        """Get recent pipeline run results from storage"""
        # This would read from pipeline execution logs
        # For now, return empty list
        return []
    
    def get_improved_prompts(self) -> Dict[str, str]:
        """Get improved prompts for all agents based on learned patterns"""
        improved_prompts = {}
        
        for agent_id in self.context_updater.agent_contexts:
            base_prompt = self._get_base_prompt_for_agent(agent_id)
            improved_prompt = self.context_updater.get_improved_prompt(
                agent_id, base_prompt
            )
            improved_prompts[agent_id] = improved_prompt
        
        return improved_prompts
    
    def _get_base_prompt_for_agent(self, agent_id: str) -> str:
        """Get the base prompt for an agent"""
        # This would read from agent configuration
        # For now, return a generic prompt
        return "Analyze the code for security vulnerabilities."
    
    def _load_history(self) -> None:
        """Load feedback history from disk"""
        history_file = self.feedback_dir / "feedback_history.json"
        if history_file.exists():
            try:
                with open(history_file, 'r') as f:
                    data = json.load(f)
                
                for result_data in data:
                    result = FeedbackResult(
                        iteration_id=result_data['iteration_id'],
                        timestamp=datetime.fromisoformat(result_data['timestamp']),
                        bugs_analyzed=result_data['bugs_analyzed'],
                        new_patterns_learned=result_data['new_patterns_learned'],
                        agents_updated=result_data['agents_updated'],
                        context_improvements=result_data['context_improvements'],
                        recommendations=result_data['recommendations']
                    )
                    self.feedback_history.append(result)
                    
            except Exception as e:
                print(f"Error loading feedback history: {e}")
    
    def _save_history(self) -> None:
        """Save feedback history to disk"""
        history_file = self.feedback_dir / "feedback_history.json"
        
        data = [result.to_dict() for result in self.feedback_history]
        
        with open(history_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def generate_feedback_report(self) -> str:
        """Generate a comprehensive feedback report"""
        report = "# Retrospective Feedback Report\n\n"
        
        report += f"## Feedback History Summary\n"
        report += f"- Total Feedback Iterations: {len(self.feedback_history)}\n"
        
        if self.feedback_history:
            latest = self.feedback_history[-1]
            report += f"- Last Analysis: {latest.timestamp}\n"
            report += f"- Bugs Analyzed: {latest.bugs_analyzed}\n"
            report += f"- Patterns Learned: {latest.new_patterns_learned}\n"
            report += f"- Agents Updated: {len(latest.agents_updated)}\n"
        
        report += "\n## False Negative Analysis\n"
        report += self.false_negative_tracker.generate_report()
        
        report += "\n## Agent Context Updates\n"
        report += self.context_updater.generate_context_report()
        
        report += "\n## Recent Recommendations\n"
        if self.feedback_history:
            for result in self.feedback_history[-3:]:  # Last 3 iterations
                report += f"\n### {result.iteration_id}\n"
                for rec in result.recommendations:
                    report += f"- {rec}\n"
        
        return report
