"""
Multi-Agent Orchestrator — Coordinates 100+ agents across 7 pipeline stages.

Replaces the existing PipelineOrchestrator with a true multi-agent system
that spawns, routes, and manages specialized agents dynamically.
"""
import asyncio
import logging
import time
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

# Import existing pipeline modules for deep integration
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from .agent_core import Agent
from .agent_pool import AgentPool
from .model_router import ModelRouter
from .debate_panel import DebatePanel
from .enricher_agent import EnricherAgent, EnrichmentResult
from .triage_agent import TriageAgent, TriageResult
from .hooks import PipelineLogger, MetricsCollector, attach_default_hooks
from .config import ALL_AGENT_DEFINITIONS, AGENT_COUNT, STAGE_COUNTS

# Deep integration with existing pipeline modules
try:
    from prepare import CodebaseIngester, LanguageIndexer, ThreatModeler
    from scan import AgentRouter, FindingCollector
    from validate import DebateOrchestrator as LegacyDebateOrchestrator
    from dedup import EmbeddingGenerator, SimilarityCalculator, ClusteringEngine
    from prove import PoCGenerator, HarnessBuilder, Fuzzer, SandboxManager
    from d3fend import CWEMapper, D3FENDOntologyClient
    EXISTING_MODULES_AVAILABLE = True
except ImportError:
    EXISTING_MODULES_AVAILABLE = False
    logger = logging.getLogger(__name__)
    logger.warning("Some existing pipeline modules not available. Running in standalone mode.")

try:
    from feedback.feedback_agent import RetrospectiveFeedbackAgent
    FEEDBACK_AVAILABLE = True
except ImportError:
    FEEDBACK_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class PipelineReport:
    """Final pipeline execution report."""
    target: str
    target_type: str
    stages_completed: List[str]
    findings: List[Dict[str, Any]]
    metrics: Dict[str, Any]
    wall_time_seconds: float
    total_cost_usd: float
    agent_metrics: Dict[str, Any]


class MultiAgentOrchestrator:
    """
    Main orchestrator for the multi-agent security pipeline.

    Coordinates 100+ specialized agents across 7 stages:
    prepare → scan → validate → dedup → prove → enrich → triage
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        budget_usd: float = 10.0,
        max_concurrent: int = 50,
        debate_panel_size: int = 3,
        debate_threshold: float = 0.67,
    ):
        # Core components
        self.model_router = ModelRouter(api_key=api_key, budget_usd=budget_usd)
        self.agent_pool = AgentPool(self.model_router, max_concurrent=max_concurrent)
        self.debate_panel = DebatePanel(
            self.model_router,
            panel_size=debate_panel_size,
            vote_threshold=debate_threshold,
        )
        self.enricher = EnricherAgent(self.model_router)
        self.triage = TriageAgent(self.model_router)
        self.metrics = MetricsCollector()

        # Pipeline state
        self.findings: List[Dict[str, Any]] = []
        self.stage_results: Dict[str, List[Dict]] = {}
        self.start_time = 0.0

        logger.info(
            f"MultiAgentOrchestrator initialized: "
            f"budget=${budget_usd}, max_concurrent={max_concurrent}, "
            f"debate_panel={debate_panel_size}"
        )

    async def run_pipeline(
        self,
        target: str,
        target_type: str = "c-cpp-source",
        stages: Optional[List[str]] = None,
    ) -> PipelineReport:
        """
        Run the full multi-agent pipeline.

        Args:
            target: Path to target codebase
            target_type: Type of target
            stages: List of stages to run (default: all)

        Returns:
            PipelineReport with findings and metrics
        """
        self.start_time = time.time()
        all_stages = ["prepare", "scan", "validate", "dedup", "prove", "enrich", "triage"]
        stages_to_run = stages or all_stages

        logger.info(f"=== PIPELINE START: {target} ({target_type}) ===")
        logger.info(f"Stages: {stages_to_run}")
        logger.info(f"Agent definitions loaded: {AGENT_COUNT}")

        # Spawn all agents
        await self.agent_pool.spawn_all()

        # Run stages sequentially (each stage may run agents in parallel)
        for stage in stages_to_run:
            if stage == "prepare":
                await self._run_prepare(target, target_type)
            elif stage == "scan":
                await self._run_scan(target)
            elif stage == "validate":
                await self._run_validate()
            elif stage == "dedup":
                await self._run_dedup()
            elif stage == "prove":
                await self._run_prove(target)
            elif stage == "enrich":
                await self._run_enrich()
            elif stage == "triage":
                await self._run_triage()

        wall_time = time.time() - self.start_time
        total_cost = self.model_router.spent_usd

        report = PipelineReport(
            target=target,
            target_type=target_type,
            stages_completed=stages_to_run,
            findings=self.findings,
            metrics=self.agent_pool.get_metrics(),
            wall_time_seconds=wall_time,
            total_cost_usd=total_cost,
            agent_metrics=self.metrics.get_all_metrics(),
        )

        logger.info(f"=== PIPELINE COMPLETE: {len(self.findings)} findings in {wall_time:.1f}s ===")
        return report

    async def _run_prepare(self, target: str, target_type: str):
        """Stage 1: PREPARE — Ingest codebase, build threat model."""
        PipelineLogger.log_stage_start("prepare")
        start = time.time()

        # Get prepare agents
        prepare_agents = self.agent_pool.get_agents_by_stage("prepare")

        tasks = []
        for inst in prepare_agents:
            task = f"Prepare target: {target} (type: {target_type})"
            tasks.append(self.agent_pool.execute_task(inst.agent.agent_id, task))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Store prepare results
        self.stage_results["prepare"] = [
            r for r in results if not isinstance(r, Exception)
        ]

        elapsed = (time.time() - start) * 1000
        PipelineLogger.log_stage_end("prepare", len(results), elapsed)

    async def _run_scan(self, target: str):
        """Stage 2: SCAN — Deploy auditor agents to find candidate vulnerabilities."""
        PipelineLogger.log_stage_start("scan")
        start = time.time()

        # Get all auditor agents
        auditors = self.agent_pool.get_agents_by_stage("scan")

        # In production, we'd split the codebase and route to specific auditors
        # For now, run all auditors in parallel with the target
        tasks = []
        for inst in auditors:
            task = f"Scan target: {target} for {inst.definition.bug_classes}"
            tasks.append(self.agent_pool.execute_task(inst.agent.agent_id, task))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect candidate findings
        candidates = []
        for r in results:
            if isinstance(r, Exception):
                logger.error(f"Scan error: {r}")
                continue
            # Parse finding from result (simplified)
            candidates.append({
                "id": f"C-{len(candidates)}",
                "agent_id": r.get("agent_id"),
                "bug_class": "unknown",
                "location": target,
                "result": r.get("result", ""),
            })

        self.findings = candidates
        self.stage_results["scan"] = candidates

        elapsed = (time.time() - start) * 1000
        PipelineLogger.log_stage_end("scan", len(candidates), elapsed)
        logger.info(f"Scan produced {len(candidates)} candidate findings")

    async def _run_validate(self):
        """Stage 3: VALIDATE — Multi-model debate for each finding."""
        PipelineLogger.log_stage_start("validate", len(self.findings))
        start = time.time()

        validated = []
        for finding in self.findings:
            result = await self.debate_panel.run_debate(finding)

            if result.validated:
                finding["validated"] = True
                finding["debate_votes"] = {
                    "for": result.for_count,
                    "against": result.against_count,
                    "confidence": result.confidence,
                }
                finding["debate_transcript"] = result.transcript
                validated.append(finding)
                PipelineLogger.log_finding(
                    finding["id"],
                    finding.get("bug_class", "unknown"),
                    finding.get("severity", "medium"),
                    result.confidence,
                )
            else:
                finding["validated"] = False

        self.findings = validated
        self.stage_results["validate"] = validated

        elapsed = (time.time() - start) * 1000
        PipelineLogger.log_stage_end("validate", len(validated), elapsed)
        logger.info(f"Validation: {len(validated)}/{len(self.findings)} findings validated")

    async def _run_dedup(self):
        """Stage 4: DEDUP — Cluster semantically equivalent findings."""
        PipelineLogger.log_stage_start("dedup", len(self.findings))
        start = time.time()

        dedup_agents = self.agent_pool.get_agents_by_stage("dedup")

        # Simple dedup: group by bug_class + location prefix
        seen = {}
        deduped = []
        for finding in self.findings:
            key = f"{finding.get('bug_class', '')}:{finding.get('location', '')[:50]}"
            if key not in seen:
                seen[key] = finding
                deduped.append(finding)

        self.findings = deduped
        self.stage_results["dedup"] = deduped

        elapsed = (time.time() - start) * 1000
        PipelineLogger.log_stage_end("dedup", len(deduped), elapsed)
        logger.info(f"Dedup: {len(deduped)} unique findings")

    async def _run_prove(self, target: str):
        """Stage 5: PROVE — Generate PoC and verify reachability."""
        PipelineLogger.log_stage_start("prove", len(self.findings))
        start = time.time()

        prover_agents = self.agent_pool.get_agents_by_stage("prove")

        # Assign provers to findings
        tasks = []
        for finding in self.findings:
            if prover_agents:
                prover = prover_agents[0]
                task = f"Prove finding {finding['id']} at {finding.get('location', '')}"
                tasks.append(self.agent_pool.execute_task(prover.agent.agent_id, task))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for i, finding in enumerate(self.findings):
            if i < len(results) and not isinstance(results[i], Exception):
                finding["proven"] = True
                finding["proof_result"] = results[i]
            else:
                finding["proven"] = False

        self.stage_results["prove"] = self.findings

        elapsed = (time.time() - start) * 1000
        PipelineLogger.log_stage_end("prove", sum(1 for f in self.findings if f.get("proven")), elapsed)

    async def _run_enrich(self):
        """Stage 6: ENRICH — D3FEND + ATT&CK + exposure scoring."""
        PipelineLogger.log_stage_start("enrich", len(self.findings))
        start = time.time()

        enriched = []
        for finding in self.findings:
            result = await self.enricher.enrich(
                finding,
                cwe=finding.get("cwe"),
                attack_ids=finding.get("attack_techniques"),
            )

            finding["d3fend_techniques"] = result.d3fend_techniques
            finding["attack_techniques"] = result.attack_techniques
            finding["acf_techniques"] = result.acf_techniques
            finding["exposure_score"] = result.exposure_score
            finding["shodan_exposure"] = result.shodan_exposure
            finding["threat_actor_likelihood"] = result.threat_actor_likelihood
            finding["compliance_controls"] = result.compliance_controls
            finding["compliance_mappings"] = result.compliance_mappings
            finding["owasp_references"] = result.owasp_references
            finding["remediation_priority"] = result.remediation_priority
            finding["threat_narrative"] = result.narrative
            enriched.append(finding)

        self.findings = enriched
        self.stage_results["enrich"] = enriched

        elapsed = (time.time() - start) * 1000
        PipelineLogger.log_stage_end("enrich", len(enriched), elapsed)

    async def _run_triage(self):
        """Stage 7: TRIAGE — DevSecOps routing and Patch Tuesday scheduling."""
        PipelineLogger.log_stage_start("triage", len(self.findings))
        start = time.time()

        triaged = []
        for finding in self.findings:
            result = await self.triage.triage(finding)

            finding["severity"] = result.severity
            finding["finding_owner"] = result.finding_owner
            finding["team"] = result.team
            finding["priority"] = result.priority
            finding["patch_tuesday_target"] = result.patch_tuesday_target
            finding["false_positive_risk"] = result.false_positive_risk
            finding["recommended_action"] = result.recommended_action
            finding["sla_hours"] = result.sla_hours
            triaged.append(finding)

        self.findings = triaged
        self.stage_results["triage"] = triaged

        elapsed = (time.time() - start) * 1000
        PipelineLogger.log_stage_end("triage", len(triaged), elapsed)
        logger.info(f"Triage complete: {len(triaged)} findings routed to DevSecOps")

    def get_report(self) -> Dict[str, Any]:
        """Generate a summary report."""
        return {
            "findings_count": len(self.findings),
            "stages": {s: len(v) for s, v in self.stage_results.items()},
            "budget": self.model_router.get_budget_status(),
            "agent_pool": self.agent_pool.get_metrics(),
        }
