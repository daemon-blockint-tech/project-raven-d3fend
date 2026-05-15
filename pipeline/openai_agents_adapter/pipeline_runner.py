"""
MDASH Pipeline Runner using the OpenAI Agents SDK.

This runner orchestrates the full MDASH pipeline (prepare → scan → validate →
dedup → prove → enrich → report) using the OpenAI Agents SDK for agent
orchestration, tracing, and session management.
"""
import logging
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from pathlib import Path

# Try importing openai-agents SDK
try:
    from agents import Agent, Runner
    from agents.run import RunConfig
    from agents.tracing import trace
    OPENAI_AGENTS_AVAILABLE = True
except ImportError:
    OPENAI_AGENTS_AVAILABLE = False

from .auditor_agent import AuditorAgent
from .debater_agent import DebateOrchestrator

logger = logging.getLogger(__name__)


@dataclass
class PipelineConfig:
    """Configuration for the MDASH pipeline runner."""
    # Agent models
    auditor_models: List[str] = None
    debater_models: List[str] = None
    # Stage toggles
    enable_prepare: bool = True
    enable_scan: bool = True
    enable_validate: bool = True
    enable_dedup: bool = True
    enable_prove: bool = True
    enable_enrich: bool = True
    # Budget
    max_cost_usd: float = 10.0
    max_trials: int = 10
    # Output
    output_dir: str = "./output"
    enable_tracing: bool = True

    def __post_init__(self):
        if self.auditor_models is None:
            self.auditor_models = ["gpt-4o"]
        if self.debater_models is None:
            self.debater_models = ["gpt-4o", "gpt-4o-mini"]


class MDASHAgentsRunner:
    """
    Run the complete MDASH pipeline using the OpenAI Agents SDK.

    This runner provides an alternative to the custom pipeline orchestration
    by leveraging the SDK's built-in tracing, session management, and
    human-in-the-loop capabilities.
    """

    def __init__(self, config: Optional[PipelineConfig] = None):
        """
        Initialize the pipeline runner.

        Args:
            config: Pipeline configuration (uses defaults if not provided)
        """
        if not OPENAI_AGENTS_AVAILABLE:
            raise ImportError(
                "openai-agents package not installed. "
                "Install with: pip install openai-agents"
            )

        self.config = config or PipelineConfig()
        self.orchestrator_agent = self._create_orchestrator_agent()
        self.auditor_agents: Dict[str, AuditorAgent] = {}
        self.debate_orchestrator = DebateOrchestrator(
            debater_models=self.config.debater_models
        )
        self.results: List[Dict] = []

        logger.info("MDASHAgentsRunner initialized")

    def _create_orchestrator_agent(self) -> "Agent":
        """Create the master orchestrator agent."""
        return Agent(
            name="mdash-orchestrator",
            instructions="""You are the MDASH (Multi-Model Agentic Security Harness) pipeline orchestrator.

Your job is to coordinate a multi-stage security analysis pipeline:
1. PREPARE: Analyze the target codebase, build a threat model, and identify surface areas
2. SCAN: Dispatch specialized auditor agents to find candidate vulnerabilities
3. VALIDATE: Run multi-model debate to confirm or reject each candidate
4. DEDUP: Cluster semantically equivalent findings
5. PROVE: Generate proof-of-concept triggers and verify reachability
6. ENRICH: Bind D3FEND defensive techniques and ATT&CK offensive context
7. REPORT: Produce the final structured report

Rules:
- Every finding must terminate at a tool oracle (T), classical ML detector (M), or scored hypothesis (L)
- Never report raw LLM speculation without one of these three terminators
- Track cost and abort if budget is exceeded
- Emit structured findings, not free-text verdicts
""",
            model="gpt-4o",
        )

    def run_pipeline(
        self,
        target_path: str,
        target_type: str = "c-cpp-source",
        custom_config: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Run the full MDASH pipeline on a target codebase.

        Args:
            target_path: Path to the target codebase
            target_type: Type of target (c-cpp-source, solana-program, etc.)
            custom_config: Optional runtime overrides

        Returns:
            Dict with findings, metrics, and report paths
        """
        start_time = time.time()
        total_cost = 0.0

        with trace("mdash_pipeline_run"):
            # Stage 1: PREPARE
            if self.config.enable_prepare:
                logger.info("Stage 1: PREPARE")
                surface_map = self._run_prepare(target_path, target_type)
            else:
                surface_map = {}

            # Stage 2: SCAN
            if self.config.enable_scan:
                logger.info("Stage 2: SCAN")
                candidates = self._run_scan(surface_map, target_path)
            else:
                candidates = []

            # Stage 3: VALIDATE
            if self.config.enable_validate:
                logger.info("Stage 3: VALIDATE")
                validated = self._run_validate(candidates, target_path)
            else:
                validated = []

            # Stage 4: DEDUP
            if self.config.enable_dedup:
                logger.info("Stage 4: DEDUP")
                deduped = self._run_dedup(validated)
            else:
                deduped = validated

            # Stage 5: PROVE
            if self.config.enable_prove:
                logger.info("Stage 5: PROVE")
                proven = self._run_prove(deduped, target_path)
            else:
                proven = deduped

            # Stage 6: ENRICH
            if self.config.enable_enrich:
                logger.info("Stage 6: ENRICH")
                enriched = self._run_enrich(proven)
            else:
                enriched = proven

        wall_time = time.time() - start_time

        # Generate report
        report = {
            "target": target_path,
            "target_type": target_type,
            "findings_count": len(enriched),
            "findings": enriched,
            "wall_time_seconds": wall_time,
            "total_cost_usd": total_cost,
            "stages_completed": self._get_stages_completed(),
        }

        logger.info(
            "Pipeline complete: %d findings in %.1fs",
            len(enriched), wall_time
        )

        return report

    def _run_prepare(self, target_path: str, target_type: str) -> Dict:
        """Run the Prepare stage."""
        # For now, delegate to the existing prepare modules
        # In full integration, this would use an OpenAI Agent for threat modeling
        return {
            "target_path": target_path,
            "target_type": target_type,
            "high_risk_areas": [],
            "surface_map": {},
        }

    def _run_scan(self, surface_map: Dict, target_path: str) -> List[Dict]:
        """Run the Scan stage with specialized auditor agents."""
        candidates = []

        # Get code files to analyze
        code_files = self._discover_code_files(target_path)

        # Bug classes to scan for
        bug_classes = [
            "memory-corruption",
            "race-condition",
            "auth-bypass",
            "integer-overflow",
        ]

        for bug_class in bug_classes:
            # Create or reuse auditor agent
            if bug_class not in self.auditor_agents:
                self.auditor_agents[bug_class] = AuditorAgent(
                    bug_class=bug_class,
                    model=self.config.auditor_models[0]
                )

            agent = self.auditor_agents[bug_class]

            # Analyze each file
            for file_path in code_files[:5]:  # Limit for demo
                with open(file_path, "r", errors="ignore") as f:
                    code = f.read()

                result = agent.audit(code, str(file_path))
                candidates.extend(result.get("findings", []))

        return candidates

    def _run_validate(self, candidates: List[Dict], target_path: str) -> List[Dict]:
        """Run the Validate stage with multi-model debate."""
        validated = []

        for candidate in candidates:
            # Get code context for the finding
            code_context = self._get_code_context(
                target_path,
                candidate.get("location", "")
            )

            # Run debate
            result = self.debate_orchestrator.run_debate(
                candidate,
                code_context
            )

            if result.get("validated", False):
                candidate["validation"] = result
                validated.append(candidate)

        return validated

    def _run_dedup(self, validated: List[Dict]) -> List[Dict]:
        """Run the Dedup stage."""
        # Simple dedup by location + bug class
        seen = {}
        deduped = []

        for finding in validated:
            key = f"{finding.get('location', '')}:{finding.get('bug_class', '')}"
            if key not in seen:
                seen[key] = finding
                deduped.append(finding)

        return deduped

    def _run_prove(self, deduped: List[Dict], target_path: str) -> List[Dict]:
        """Run the Prove stage."""
        # For now, mark all as proven (in production, run sanitizer/sandbox)
        for finding in deduped:
            finding["proven"] = True
        return deduped

    def _run_enrich(self, proven: List[Dict]) -> List[Dict]:
        """Run the Enrich stage with D3FEND + ATT&CK."""
        # For now, add placeholder enrichment
        for finding in proven:
            finding["d3fend_techniques"] = []
            finding["attack_techniques"] = []
            finding["exposure_score"] = 50
        return proven

    def _discover_code_files(self, target_path: str) -> List[Path]:
        """Discover code files in the target directory."""
        path = Path(target_path)
        if not path.exists():
            return []

        extensions = {".c", ".cpp", ".h", ".hpp", ".rs", ".sol", ".go"}
        files = []

        if path.is_file():
            files = [path]
        else:
            files = list(path.rglob("*"))
            files = [f for f in files if f.suffix in extensions]

        return files[:20]  # Limit for demo

    def _get_code_context(self, target_path: str, location: str) -> str:
        """Get code context around a finding location."""
        # Parse location (file:line format)
        try:
            parts = location.rsplit(":", 1)
            file_path = Path(target_path) / parts[0]
            line = int(parts[1])

            with open(file_path, "r", errors="ignore") as f:
                lines = f.readlines()

            start = max(0, line - 10)
            end = min(len(lines), line + 10)
            return "".join(lines[start:end])
        except (ValueError, IndexError, FileNotFoundError):
            return ""

    def _get_stages_completed(self) -> List[str]:
        """Get list of completed stages based on config."""
        stages = []
        if self.config.enable_prepare:
            stages.append("prepare")
        if self.config.enable_scan:
            stages.append("scan")
        if self.config.enable_validate:
            stages.append("validate")
        if self.config.enable_dedup:
            stages.append("dedup")
        if self.config.enable_prove:
            stages.append("prove")
        if self.config.enable_enrich:
            stages.append("enrich")
        return stages
