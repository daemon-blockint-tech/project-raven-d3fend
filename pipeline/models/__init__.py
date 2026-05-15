"""
Data models for the multi-model agentic security pipeline.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum
import hashlib
import json
from datetime import datetime

class BugClass(Enum):
    """Bug classification categories."""
    MEMORY_CORRUPTION = "memory_corruption"
    INTEGER_OVERFLOW = "integer_overflow"
    RACE_CONDITION = "race_condition"
    AUTH_BYPASS = "auth_bypass"
    DESERIALIZATION = "deserialization"
    TYPE_CONFUSION = "type_confusion"
    SIGNATURE_MALLEABILITY = "signature_malleability"
    ACCOUNT_CONFUSION = "account_confusion"
    ORACLE_MANIPULATION = "oracle_manipulation"
    REENTRANCY = "reentrancy"
    LOGIC_ERROR = "logic_error"

class GroundingType(Enum):
    """CDP grounding types."""
    TOOL_ORACLE = "T"  # Deterministic tool oracle
    ML_DETECTOR = "M"  # ML detector with calibrated score
    SCORED_HYPOTHESIS = "L"  # Scored hypothesis with falsification test

@dataclass
class SurfaceMap:
    """Output from Prepare stage - attack surface mapping."""
    target: str
    target_type: str
    entry_points: List[Dict[str, Any]] = field(default_factory=list)
    syscalls_of_interest: List[str] = field(default_factory=list)
    abi_boundaries: List[Dict[str, Any]] = field(default_factory=list)
    known_good_baselines: Dict[str, Any] = field(default_factory=dict)
    language_index: Dict[str, Any] = field(default_factory=dict)
    generated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "target_type": self.target_type,
            "entry_points": self.entry_points,
            "syscalls_of_interest": self.syscalls_of_interest,
            "abi_boundaries": self.abi_boundaries,
            "known_good_baselines": self.known_good_baselines,
            "language_index": self.language_index,
            "generated_at": self.generated_at
        }

@dataclass
class ThreatModel:
    """Output from Prepare stage - threat model."""
    target: str
    attack_surface: List[Dict[str, Any]] = field(default_factory=list)
    high_risk_areas: List[Dict[str, Any]] = field(default_factory=list)
    threat_hypotheses: List[Dict[str, Any]] = field(default_factory=list)
    model_used: str = ""
    confidence: float = 0.0
    generated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "attack_surface": self.attack_surface,
            "high_risk_areas": self.high_risk_areas,
            "threat_hypotheses": self.threat_hypotheses,
            "model_used": self.model_used,
            "confidence": self.confidence,
            "generated_at": self.generated_at
        }

@dataclass
class CandidateFinding:
    """Output from Scan stage - candidate finding with hypothesis score."""
    id: str
    bug_class: BugClass
    location: str  # file:lines or function symbol
    precondition: str
    evidence: str
    hypothesis_score: float  # [0, 1]
    cwe_id: Optional[str] = None
    agent_used: str = ""
    generated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def __post_init__(self):
        if not self.id:
            self.id = hashlib.sha256(
                f"{self.bug_class.value}:{self.location}".encode()
            ).hexdigest()[:16]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "bug_class": self.bug_class.value,
            "location": self.location,
            "precondition": self.precondition,
            "evidence": self.evidence,
            "hypothesis_score": self.hypothesis_score,
            "cwe_id": self.cwe_id,
            "agent_used": self.agent_used,
            "generated_at": self.generated_at
        }

@dataclass
class DebateTranscript:
    """Debate transcript from Validate stage."""
    finding_id: str
    debaters: List[Dict[str, Any]] = field(default_factory=list)
    votes: List[bool] = field(default_factory=list)  # True = vulnerable, False = not vulnerable
    result: bool = False
    confidence: float = 0.0
    transcript: str = ""
    generated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "debaters": self.debaters,
            "votes": self.votes,
            "result": self.result,
            "confidence": self.confidence,
            "transcript": self.transcript,
            "generated_at": self.generated_at
        }

@dataclass
class ValidatedFinding:
    """Output from Validate stage - validated finding with debate result."""
    id: str
    original_candidate: CandidateFinding
    debate_transcript: DebateTranscript
    validation_status: str  # "validated", "unconfirmed", "false_positive"
    confidence: float
    grounding_type: GroundingType = GroundingType.SCORED_HYPOTHESIS
    generated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "original_candidate": self.original_candidate.to_dict(),
            "debate_transcript": self.debate_transcript.to_dict(),
            "validation_status": self.validation_status,
            "confidence": self.confidence,
            "grounding_type": self.grounding_type.value,
            "generated_at": self.generated_at
        }

@dataclass
class DeduplicatedFinding:
    """Output from Dedup stage - deduplicated finding."""
    id: str
    cluster_id: str
    cluster_size: int
    representative_finding: ValidatedFinding
    merged_findings: List[str] = field(default_factory=list)
    similarity_scores: List[float] = field(default_factory=list)
    embedding_model: str = ""
    generated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "cluster_id": self.cluster_id,
            "cluster_size": self.cluster_size,
            "representative_finding": self.representative_finding.to_dict(),
            "merged_findings": self.merged_findings,
            "similarity_scores": self.similarity_scores,
            "embedding_model": self.embedding_model,
            "generated_at": self.generated_at
        }

@dataclass
class PoCArtifact:
    """PoC artifact from Prove stage."""
    type: str  # "self_contained", "reachability_harness", "fuzzing_input"
    content: str
    language: str
    execution_result: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "content": self.content,
            "language": self.language,
            "execution_result": self.execution_result
        }

@dataclass
class ProvenFinding:
    """Output from Prove stage - proven finding with PoC."""
    id: str
    deduplicated_finding: DeduplicatedFinding
    poc_status: str  # "proven", "unproven", "error"
    poc_artifacts: List[PoCArtifact] = field(default_factory=list)
    sanitizer_results: Dict[str, Any] = field(default_factory=dict)
    grounding_type: GroundingType = GroundingType.TOOL_ORACLE
    generated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "deduplicated_finding": self.deduplicated_finding.to_dict(),
            "poc_status": self.poc_status,
            "poc_artifacts": [a.to_dict() for a in self.poc_artifacts],
            "sanitizer_results": self.sanitizer_results,
            "grounding_type": self.grounding_type.value,
            "generated_at": self.generated_at
        }

@dataclass
class D3FENDTechnique:
    """D3FEND technique reference."""
    id: str
    label: str
    tactic: str
    description: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "tactic": self.tactic,
            "description": self.description
        }

@dataclass
class ATTACKTechnique:
    """MITRE ATT&CK technique reference for offensive context enrichment."""
    id: str
    name: str
    tactic: str
    description: Optional[str] = None
    url: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "tactic": self.tactic,
            "description": self.description,
            "url": self.url
        }


@dataclass
class FinalFinding:
    """Final finding with D3FEND binding and ATT&CK enrichment."""
    id: str
    proven_finding: ProvenFinding
    cwe_id: str
    d3fend_techniques: List[D3FENDTechnique] = field(default_factory=list)
    attack_techniques: List[ATTACKTechnique] = field(default_factory=list)
    exposure_score: float = 0.0
    exposure_context: Dict[str, Any] = field(default_factory=dict)
    recommended_remediation: Optional[str] = None
    confidence: str = "validated"  # "validated", "high", "medium"
    generated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "proven_finding": self.proven_finding.to_dict(),
            "cwe_id": self.cwe_id,
            "d3fend_techniques": [t.to_dict() for t in self.d3fend_techniques],
            "attack_techniques": [t.to_dict() for t in self.attack_techniques],
            "exposure_score": self.exposure_score,
            "exposure_context": self.exposure_context,
            "recommended_remediation": self.recommended_remediation,
            "confidence": self.confidence,
            "generated_at": self.generated_at
        }

@dataclass
class PipelineReport:
    """Final pipeline report."""
    target: str
    target_type: str
    stages_completed: List[str]
    total_cost_usd: float
    trial_budget: Dict[str, Any]
    findings: List[FinalFinding]
    unconfirmed_hypotheses: List[Dict[str, Any]] = field(default_factory=list)
    false_positives: List[Dict[str, Any]] = field(default_factory=list)
    d3fend_coverage: List[str] = field(default_factory=list)
    reproducibility_kit: Dict[str, Any] = field(default_factory=dict)
    generated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "target_type": self.target_type,
            "stages_completed": self.stages_completed,
            "total_cost_usd": self.total_cost_usd,
            "trial_budget": self.trial_budget,
            "findings": [f.to_dict() for f in self.findings],
            "unconfirmed_hypotheses": self.unconfirmed_hypotheses,
            "false_positives": self.false_positives,
            "d3fend_coverage": self.d3fend_coverage,
            "reproducibility_kit": self.reproducibility_kit,
            "generated_at": self.generated_at
        }
    
    def to_markdown(self) -> str:
        """Generate markdown report."""
        md = f"""# Multi-Model Agentic Security Scan — {self.target}

## Pipeline Execution
- Target: {self.target}
- Target type: {self.target_type}
- Stages completed: {', '.join(self.stages_completed)}
- Total cost: ${self.total_cost_usd:.2f}
- Trial budget: {self.trial_budget.get('trials', 'N/A')} trials / ${self.trial_budget.get('cost_cap_usd', 0):.2f}

## Findings ({len(self.findings)})

"""
        for i, finding in enumerate(self.findings, 1):
            orig = finding.proven_finding.deduplicated_finding.representative_finding.original_candidate
            debate = finding.proven_finding.deduplicated_finding.representative_finding.debate_transcript
            dedup = finding.proven_finding.deduplicated_finding
            
            md += f"""### Finding F-{i}: {orig.bug_class.value.replace('_', ' ').title()}
- Bug class: {orig.bug_class.value}
- Location: {orig.location}
- CWE: {finding.cwe_id}
- Stage 2 score: {orig.hypothesis_score:.2f}
- Stage 3 debate: {[d['model'] for d in debate.debaters]} → {debate.result} (confidence: {debate.confidence:.2f})
- Stage 4 cluster: {dedup.cluster_id} ({dedup.cluster_size} findings merged)
- Stage 5 proof: {finding.proven_finding.poc_status}
- D3FEND techniques: {', '.join([f"{t.id} ({t.tactic})" for t in finding.d3fend_techniques])}
- Confidence: {finding.confidence}

"""
        
        if self.unconfirmed_hypotheses:
            md += f"""## Unconfirmed Hypotheses ({len(self.unconfirmed_hypotheses)})
| Candidate | Prior | Why Unconfirmed |
|-----------|-------|-----------------|
"""
            for hyp in self.unconfirmed_hypotheses:
                md += f"| {hyp.get('location', 'N/A')} | {hyp.get('score', 0):.2f} | {hyp.get('reason', 'N/A')} |\n"
        
        if self.false_positives:
            md += f"""## False Positives Suppressed ({len(self.false_positives)})
| Candidate | Reason |
|-----------|--------|
"""
            for fp in self.false_positives:
                md += f"| {fp.get('location', 'N/A')} | {fp.get('reason', 'N/A')} |\n"
        
        if self.d3fend_coverage:
            md += f"""## D3FEND Coverage
Techniques exercised in this scan:
{', '.join(self.d3fend_coverage)}
"""
        
        md += f"""## Reproducibility Kit
- Commit: {self.reproducibility_kit.get('commit', 'N/A')}
- Datasets: {self.reproducibility_kit.get('datasets', 'N/A')}
- Random seeds: {self.reproducibility_kit.get('random_seeds', 'N/A')}
- Scoring rubric: {self.reproducibility_kit.get('scoring_rubric', 'N/A')}
"""
        return md
