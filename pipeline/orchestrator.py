"""
Main pipeline orchestrator - coordinates all 5 stages of the multi-model agentic security pipeline.
"""
import os
import sys
import logging
import yaml
from typing import Dict, Any, Optional, List
from pathlib import Path
from datetime import datetime

from .openrouter_integration.client import OpenRouterClient
from .openrouter_integration.model_selector import ModelSelector
from .openrouter_integration.cost_tracker import CostTracker
from .models import (
    SurfaceMap, ThreatModel, CandidateFinding, ValidatedFinding,
    DeduplicatedFinding, ProvenFinding, FinalFinding, PipelineReport
)
from .prepare import CodebaseIngester, LanguageIndexer, ThreatModeler, GitAnalyzer
from .scan import AgentRouter, FindingCollector
from .validate import DebateOrchestrator
from .dedup import EmbeddingGenerator, SimilarityCalculator, ClusteringEngine, FindingMerger
from .prove import PoCGenerator, HarnessBuilder, Fuzzer, SandboxManager, SanitizerRunner
from .d3fend import CWEMapper, D3FENDOntologyClient, RemediationEngine
from .threat_intel import ShodanClient
from .feedback.feedback_agent import RetrospectiveFeedbackAgent

logger = logging.getLogger(__name__)


class PipelineOrchestrator:
    """Orchestrates the 5-stage multi-model agentic security pipeline."""
    
    def __init__(self, config_path: Optional[str] = None, feedback_enabled: bool = True):
        """
        Initialize pipeline orchestrator.
        
        OpenRouter API key must be set in OPENROUTER_API_KEY environment variable.
        
        Args:
            config_path: Path to pipeline configuration file (defaults to pipeline/config.yaml)
            feedback_enabled: Whether to run the retrospective feedback loop after pipeline completion
        """
        # Load configuration
        if config_path is None:
            config_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "config.yaml"
            )
        
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        # Initialize OpenRouter client
        self.openrouter_client = OpenRouterClient(
            api_key=os.getenv("OPENROUTER_API_KEY"),
            base_url=self.config["openrouter"]["base_url"],
            timeout_seconds=self.config["openrouter"]["timeout_seconds"],
            max_retries=self.config["openrouter"]["max_retries"]
        )
        
        # Initialize model selector
        self.model_selector = ModelSelector(self.config.get("model_mappings", {}))
        
        # Initialize cost tracker
        self.cost_tracker = CostTracker(self.config["budget"])
        
        # Initialize stage components
        self.prepare_ingester = CodebaseIngester()
        self.prepare_indexer = LanguageIndexer()
        self.prepare_threat_modeler = ThreatModeler(
            self.openrouter_client,
            self.model_selector,
            self.config["pipeline"]["stages"]["prepare"]
        )
        self.prepare_git_analyzer = GitAnalyzer()
        
        self.scan_agent_router = AgentRouter(
            self.openrouter_client,
            self.model_selector,
            self.cost_tracker,
            self.config["pipeline"]["stages"]["scan"]
        )
        self.scan_finding_collector = FindingCollector()
        
        self.validate_orchestrator = DebateOrchestrator(
            self.openrouter_client,
            self.model_selector,
            self.cost_tracker,
            self.config["pipeline"]["stages"]["validate"]
        )
        
        self.dedup_embedding_generator = EmbeddingGenerator(
            self.openrouter_client,
            self.model_selector,
            self.cost_tracker,
            self.config["pipeline"]["stages"]["dedup"]
        )
        self.dedup_similarity = SimilarityCalculator(
            self.config["pipeline"]["stages"]["dedup"]["similarity_threshold"]
        )
        self.dedup_clustering = ClusteringEngine(
            self.config["pipeline"]["stages"]["dedup"]["clustering_algorithm"],
            self.config["pipeline"]["stages"]["dedup"]["eps"],
            self.config["pipeline"]["stages"]["dedup"]["min_samples"],
            self.config["pipeline"]["stages"]["dedup"]["similarity_threshold"]
        )
        self.dedup_merger = FindingMerger()
        
        self.prove_poc_generator = PoCGenerator(
            self.openrouter_client,
            self.model_selector,
            self.cost_tracker,
            self.config["pipeline"]["stages"]["prove"]
        )
        self.prove_harness_builder = HarnessBuilder()
        self.prove_fuzzer = Fuzzer()
        self.prove_sandbox = SandboxManager()
        self.prove_sanitizer_runner = SanitizerRunner()
        
        self.d3fend_cwe_mapper = CWEMapper()
        self.d3fend_ontology = D3FENDOntologyClient()
        self.d3fend_remediation = RemediationEngine(
            self.openrouter_client,
            self.model_selector,
            self.cost_tracker,
            self.config.get("d3fend", {})
        )
        
        # Initialize Shodan threat intel for network-facing targets
        self.shodan_client = ShodanClient()
        
        # Initialize feedback loop
        self.feedback_enabled = feedback_enabled
        self.feedback_agent = RetrospectiveFeedbackAgent() if feedback_enabled else None
        
        logger.info("PipelineOrchestrator initialized")
    
    def run_pipeline(
        self,
        target: str,
        target_type: str,
        trials: int = 10
    ) -> PipelineReport:
        """
        Run the complete 5-stage pipeline on a target.
        
        Args:
            target: Target repository URL or file path
            target_type: Target type (solana-program, evm-contract, c-cpp-source, etc.)
            trials: Number of trial runs
            
        Returns:
            PipelineReport with final findings
        """
        logger.info(f"Starting pipeline for target: {target} (type: {target_type})")
        
        stages_completed = []
        total_start = datetime.utcnow()
        
        # Stage 1: Prepare
        logger.info("=== Stage 1: Prepare ===")
        self.cost_tracker.start_stage("prepare")
        
        try:
            # Ingest codebase
            if target.startswith(("http://", "https://", "git@")):
                ingestion = self.prepare_ingester.ingest_from_git(target)
            else:
                ingestion = self.prepare_ingester.ingest_from_local(target)
            
            # Build language index
            language_index = self.prepare_indexer.build_index(ingestion["local_path"])
            
            # Analyze git history
            git_analysis = self.prepare_git_analyzer.analyze_history(ingestion["local_path"])
            
            # Generate surface map
            surface_map = SurfaceMap(
                target=target,
                target_type=target_type,
                entry_points=language_index.get("entry_points", []),
                syscalls_of_interest=[],  # TODO: extract from language_index
                abi_boundaries=language_index.get("abi_boundaries", []),
                language_index=language_index
            )
            
            # Generate threat model
            threat_model = self.prepare_threat_modeler.generate_threat_model(
                surface_map,
                language_index
            )
            
            self.cost_tracker.end_stage("prepare")
            stages_completed.append("prepare")
            
        except Exception as e:
            logger.error(f"Prepare stage failed: {e}")
            return self._create_error_report(target, target_type, stages_completed, str(e))
        
        # Stage 2: Scan
        logger.info("=== Stage 2: Scan ===")
        self.cost_tracker.start_stage("scan")
        
        candidate_findings = []
        
        try:
            candidate_findings = self.scan_agent_router.route_and_scan(
                threat_model,
                surface_map,
                language_index
            )
            
            self.cost_tracker.end_stage("scan")
            stages_completed.append("scan")
            
        except Exception as e:
            logger.error(f"Scan stage failed: {e}")
            return self._create_error_report(target, target_type, stages_completed, str(e))
        
        # Stage 3: Validate
        logger.info("=== Stage 3: Validate ===")
        self.cost_tracker.start_stage("validate")
        
        validated_findings = []
        
        try:
            validated_findings = self.validate_orchestrator.validate_findings(candidate_findings)
            
            self.cost_tracker.end_stage("validate")
            stages_completed.append("validate")
            
        except Exception as e:
            logger.error(f"Validate stage failed: {e}")
            return self._create_error_report(target, target_type, stages_completed, str(e))
        
        # Stage 4: Dedup
        logger.info("=== Stage 4: Dedup ===")
        self.cost_tracker.start_stage("dedup")
        
        deduplicated_findings = []
        
        try:
            # Generate embeddings for validated findings
            finding_texts = [
                f"{f.original_candidate.bug_class.value} at {f.original_candidate.location}: {f.original_candidate.precondition}"
                for f in validated_findings
            ]
            
            embeddings = self.dedup_embedding_generator.generate_batch_embeddings(finding_texts)
            
            # Calculate similarity and cluster
            if embeddings:
                similarity_matrix = self.dedup_similarity.calculate_similarity_matrix(embeddings)
                clustering_results = self.dedup_clustering.cluster_findings(embeddings, similarity_matrix)
                representatives = self.dedup_clustering.get_cluster_representatives(
                    clustering_results["cluster_labels"],
                    embeddings,
                    validated_findings
                )
                
                # Merge findings
                deduplicated_findings = self.dedup_merger.merge_findings(
                    validated_findings,
                    clustering_results["cluster_labels"],
                    representatives
                )
            else:
                # Fallback to location-based deduplication
                deduplicated_findings = self.dedup_merger.merge_by_location(validated_findings)
            
            self.cost_tracker.end_stage("dedup")
            stages_completed.append("dedup")
            
        except Exception as e:
            logger.error(f"Dedup stage failed: e")
            return self._create_error_report(target, target_type, stages_completed, str(e))
        
        # Stage 5: Prove
        logger.info("=== Stage 5: Prove ===")
        self.cost_tracker.start_stage("prove")
        
        proven_findings = []
        network_facing_targets = {
            "live-host",
            "network-range-own-assets",
        }
        is_network_facing = target_type in network_facing_targets
        
        try:
            for dedup_finding in deduplicated_findings:
                # Generate PoC
                poc_artifacts = self.prove_poc_generator.generate_poc(
                    dedup_finding,
                    language="python"  # TODO: detect from target_type
                )
                
                # Assess external exposure via Shodan for network-facing targets
                shodan_exposure = None
                if is_network_facing and self.shodan_client.is_available():
                    try:
                        finding_dict = {
                            "id": dedup_finding.id,
                            "cwe_id": dedup_finding.representative_finding.original_candidate.cwe_id or "",
                            "bug_class": dedup_finding.representative_finding.original_candidate.bug_class.value,
                            "location": dedup_finding.representative_finding.original_candidate.location,
                        }
                        shodan_exposure = self.shodan_client.assess_finding_exposure(finding_dict)
                        logger.info(
                            "Shodan exposure for %s: score=%.1f, hosts=%d",
                            dedup_finding.id,
                            shodan_exposure.exposure_score,
                            shodan_exposure.total_count,
                        )
                    except Exception as exc:
                        logger.warning("Shodan exposure assessment failed for %s: %s", dedup_finding.id, exc)
                
                # For now, mark as unproven since we're not actually executing
                # In production, this would run the PoC in sandbox
                proven_finding = ProvenFinding(
                    id=f"P-{dedup_finding.id}",
                    deduplicated_finding=dedup_finding,
                    poc_status="unproven",  # Not actually executing in this implementation
                    poc_artifacts=poc_artifacts,
                    sanitizer_results={},
                    grounding_type=dedup_finding.representative_finding.grounding_type
                )
                
                # Attach Shodan exposure data if available
                if shodan_exposure:
                    proven_finding.poc_artifacts["shodan_exposure"] = {
                        "internet_exposed": shodan_exposure.internet_exposed,
                        "host_count": shodan_exposure.host_count,
                        "total_count": shodan_exposure.total_count,
                        "exposure_score": shodan_exposure.exposure_score,
                        "exposed_services": shodan_exposure.exposed_services,
                        "countries": shodan_exposure.countries,
                        "orgs": shodan_exposure.orgs,
                        "vulns_matched": shodan_exposure.vulns_matched,
                    }
                
                proven_findings.append(proven_finding)
            
            self.cost_tracker.end_stage("prove")
            stages_completed.append("prove")
            
        except Exception as e:
            logger.error(f"Prove stage failed: {e}")
            return self._create_error_report(target, target_type, stages_completed, str(e))
        
        # D3FEND Binding
        logger.info("=== D3FEND Binding ===")
        
        final_findings = []
        
        try:
            for proven_finding in proven_findings:
                # Get CWE ID from original finding
                cwe_id = proven_finding.deduplicated_finding.representative_finding.original_candidate.cwe_id
                
                if cwe_id:
                    # Map to D3FEND techniques
                    d3fend_techniques = [
                        self.d3fend_cwe_mapper.map_cwe_to_d3fend(cwe_id)
                    ]
                    # Flatten technique list
                    technique_list = []
                    for tech_list in d3fend_techniques:
                        for tech in tech_list:
                            technique_list.append(self.d3fend_ontology.query_technique(tech["id"]))
                else:
                    technique_list = []
                
                # Generate remediation
                remediation = self.d3fend_remediation.generate_remediation(
                    proven_finding,
                    technique_list
                )
                
                # Create final finding
                final_finding = FinalFinding(
                    id=f"F-{proven_finding.id}",
                    proven_finding=proven_finding,
                    cwe_id=cwe_id or "CWE-UNKNOWN",
                    d3fend_techniques=technique_list,
                    recommended_remediation=remediation,
                    confidence="validated" if proven_finding.poc_status == "proven" else "high"
                )
                
                final_findings.append(final_finding)
            
        except Exception as e:
            logger.error(f"D3FEND binding failed: {e}")
            # Continue with findings without D3FEND binding
            final_findings = [
                FinalFinding(
                    id=f"F-{pf.id}",
                    proven_finding=pf,
                    cwe_id="CWE-UNKNOWN",
                    d3fend_techniques=[],
                    recommended_remediation="D3FEND binding failed",
                    confidence="high"
                )
                for pf in proven_findings
            ]
        
        # Generate final report
        cost_summary = self.cost_tracker.get_summary()
        
        report = PipelineReport(
            target=target,
            target_type=target_type,
            stages_completed=stages_completed,
            total_cost_usd=cost_summary["total_cost_usd"],
            trial_budget={
                "trials": trials,
                "cost_cap_usd": self.config["budget"]["max_cost_usd"]
            },
            findings=final_findings,
            unconfirmed_hypotheses=[],
            false_positives=[],
            d3fend_coverage=[t.id for f in final_findings for t in f.d3fend_techniques],
            reproducibility_kit={
                "commit": "N/A",  # TODO: get from git analysis
                "datasets": "N/A",
                "random_seeds": "N/A",
                "scoring_rubric": "N/A"
            }
        )
        
        logger.info(f"Pipeline completed with {len(final_findings)} findings, cost: ${cost_summary['total_cost_usd']:.2f}")
        
        # Run retrospective feedback loop if enabled
        if self.feedback_enabled and self.feedback_agent:
            try:
                logger.info("=== Feedback Loop ===")
                run_results = {
                    "detected_bugs": [f.id for f in final_findings],
                    "total_bugs": [],  # Requires ground truth; populated by benchmark runner
                    "stage_results": {stage: len(final_findings) for stage in stages_completed},
                    "agents_used": list(self.cost_tracker.agent_costs.keys()) if hasattr(self.cost_tracker, 'agent_costs') else [],
                    "findings": [
                        {
                            "id": f.id,
                            "bug_class": f.proven_finding.deduplicated_finding.representative_finding.original_candidate.bug_class.value if f.proven_finding else "unknown",
                            "severity": f.proven_finding.deduplicated_finding.representative_finding.original_candidate.severity if f.proven_finding else "unknown",
                            "location": f.proven_finding.deduplicated_finding.representative_finding.original_candidate.location if f.proven_finding else "unknown",
                            "confidence": f.confidence,
                        }
                        for f in final_findings
                    ]
                }
                feedback_result = self.feedback_agent.analyze_pipeline_run(run_results)
                logger.info(
                    f"Feedback complete: {feedback_result.bugs_analyzed} bugs analyzed, "
                    f"{feedback_result.new_patterns_learned} patterns learned, "
                    f"{len(feedback_result.agents_updated)} agents updated"
                )
            except Exception as e:
                logger.error(f"Feedback loop failed: {e}")
        
        return report
    
    def _create_error_report(
        self,
        target: str,
        target_type: str,
        stages_completed: List[str],
        error_message: str
    ) -> PipelineReport:
        """Create error report when pipeline fails."""
        return PipelineReport(
            target=target,
            target_type=target_type,
            stages_completed=stages_completed,
            total_cost_usd=self.cost_tracker.get_total_cost(),
            trial_budget={
                "trials": 0,
                "cost_cap_usd": self.config["budget"]["max_cost_usd"]
            },
            findings=[],
            unconfirmed_hypotheses=[],
            false_positives=[],
            d3fend_coverage=[],
            reproducibility_kit={}
        )
