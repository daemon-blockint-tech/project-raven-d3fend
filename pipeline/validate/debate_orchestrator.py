"""
Debate orchestrator for the Validate stage - coordinates multi-model debate.
"""
from typing import Dict, List, Any, Optional
import logging
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from openrouter_integration.client import OpenRouterClient
from openrouter_integration.model_selector import ModelSelector
from openrouter_integration.cost_tracker import CostTracker
from ..models import CandidateFinding, ValidatedFinding, DebateTranscript, GroundingType

logger = logging.getLogger(__name__)


class DebateOrchestrator:
    """Orchestrate multi-model debate for validating candidate findings."""
    
    def __init__(
        self,
        openrouter_client: OpenRouterClient,
        model_selector: ModelSelector,
        cost_tracker: CostTracker,
        config: Dict[str, Any]
    ):
        """
        Initialize debate orchestrator.
        
        Args:
            openrouter_client: OpenRouter client instance
            model_selector: Model selector instance
            cost_tracker: Cost tracker instance
            config: Configuration dictionary
        """
        self.client = openrouter_client
        self.model_selector = model_selector
        self.cost_tracker = cost_tracker
        self.config = config
        self.debater_configs = config.get("debaters", [])
        self.vote_threshold = config.get("vote_threshold", 0.67)
        self.min_debaters = config.get("min_debaters", 3)
        logger.info("DebateOrchestrator initialized")
    
    def validate_findings(
        self,
        candidate_findings: List[CandidateFinding]
    ) -> List[ValidatedFinding]:
        """
        Validate candidate findings through multi-model debate.
        
        Args:
            candidate_findings: List of candidate findings from Scan stage
            
        Returns:
            List of validated findings
        """
        validated_findings = []
        
        for finding in candidate_findings:
            # Check budget before debate
            if self.cost_tracker.is_budget_exceeded():
                logger.warning("Budget exceeded, skipping validation")
                break
            
            # Run debate for this finding
            debate_transcript = self._run_debate(finding)
            
            # Determine validation status based on debate result
            validation_status = self._determine_validation_status(debate_transcript)
            
            # Create validated finding
            validated_finding = ValidatedFinding(
                id=f"V-{finding.id}",
                original_candidate=finding,
                debate_transcript=debate_transcript,
                validation_status=validation_status,
                confidence=debate_transcript.confidence,
                grounding_type=GroundingType.SCORED_HYPOTHESIS
            )
            
            validated_findings.append(validated_finding)
            
            logger.info(
                f"Validated finding {finding.id}: {validation_status} "
                f"(confidence: {debate_transcript.confidence:.2f})"
            )
        
        logger.info(f"Validation complete: {len(validated_findings)} findings processed")
        return validated_findings
    
    def _run_debate(self, finding: CandidateFinding) -> DebateTranscript:
        """
        Run multi-model debate for a single finding.
        
        Args:
            finding: Candidate finding to debate
            
        Returns:
            Debate transcript with results
        """
        debaters = []
        votes = []
        transcript_lines = []
        
        # Build debate context
        context = self._build_debate_context(finding)
        
        # Select diverse models for debate
        debate_models = self.model_selector.select_multiple_for_validation(self.min_debaters)
        
        # Assign personas to models
        personas = ["pro-vulnerability", "anti-vulnerability", "arbiter"]
        
        for i, (model, persona) in enumerate(zip(debate_models, personas)):
            debater_config = next(
                (d for d in self.debater_configs if d.get("persona") == persona),
                {"model": model, "persona": persona, "temperature": 0.7 if persona != "arbiter" else 0.0}
            )
            
            # Run debater
            debater_response = self._run_debater(
                model=debater_config["model"],
                persona=debater_config["persona"],
                context=context,
                temperature=debater_config.get("temperature", 0.7)
            )
            
            # Track cost
            estimated_cost = self._estimate_debate_cost(debater_config["model"])
            self.cost_tracker.add_cost(debater_config["model"], estimated_cost, stage="validate")
            
            # Record debater
            debaters.append({
                "model": debater_config["model"],
                "persona": debater_config["persona"],
                "response": debater_response
            })
            
            # Extract vote from response
            vote = self._extract_vote(debater_response, persona)
            votes.append(vote)
            
            # Add to transcript
            transcript_lines.append(
                f"### {debater_config['persona'].upper()} ({debater_config['model']}):\n"
                f"{debater_response}\n"
            )
        
        # Calculate debate result
        result = self._calculate_debate_result(votes)
        confidence = self._calculate_confidence(votes, result)
        
        # Create debate transcript
        transcript = DebateTranscript(
            finding_id=finding.id,
            debaters=debaters,
            votes=votes,
            result=result,
            confidence=confidence,
            transcript="\n".join(transcript_lines)
        )
        
        return transcript
    
    def _build_debate_context(self, finding: CandidateFinding) -> str:
        """Build context for debate."""
        context = f"""You are participating in a security vulnerability debate. Analyze the following candidate finding and provide your assessment:

Finding Details:
- Bug Class: {finding.bug_class.value}
- Location: {finding.location}
- Precondition: {finding.precondition}
- Evidence: {finding.evidence}
- Hypothesis Score: {finding.hypothesis_score:.2f}
- CWE ID: {finding.cwe_id or 'N/A'}

Your task is to evaluate whether this represents a genuine security vulnerability or a false positive. Consider:
1. The technical feasibility of the precondition
2. The strength of the evidence provided
3. Common patterns in this bug class
4. Potential mitigating factors

Provide your assessment and conclude with either "TRUE: This is a genuine vulnerability" or "FALSE: This is a false positive" followed by your reasoning.
"""
        return context
    
    def _run_debater(
        self,
        model: str,
        persona: str,
        context: str,
        temperature: float
    ) -> str:
        """
        Run a single debater model.
        
        Args:
            model: Model identifier
            persona: Debate persona
            context: Debate context
            temperature: Sampling temperature
            
        Returns:
            Debater response
        """
        system_prompt = self._get_system_prompt(persona)
        
        try:
            response = self.client.chat(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": context}
                ],
                temperature=temperature,
                max_tokens=4096
            )
            
            return response["content"]
        
        except Exception as e:
            logger.error(f"Debater {model} ({persona}) failed: {e}")
            return f"ERROR: Failed to generate response: {str(e)}"
    
    def _get_system_prompt(self, persona: str) -> str:
        """Get system prompt for a debate persona."""
        prompts = {
            "pro-vulnerability": """You are a security advocate arguing that a candidate finding represents a genuine vulnerability. Your role is to:
1. Assume the finding is exploitable unless proven otherwise
2. Highlight the most severe interpretation of the evidence
3. Emphasize real-world attack scenarios
4. Point out any overlooked risk factors

Be thorough but fair - don't fabricate evidence, but do give the finding the benefit of the doubt.""",
            
            "anti-vulnerability": """You are a security skeptic arguing that a candidate finding is likely a false positive. Your role is to:
1. Challenge the feasibility of the precondition
2. Identify mitigating factors or defensive measures
3. Point out missing evidence or weak reasoning
4. Consider whether the issue is theoretical rather than practical

Be thorough but fair - don't dismiss genuine concerns, but do scrutinize the finding rigorously.""",
            
            "arbiter": """You are a neutral arbiter evaluating arguments from both sides. Your role is to:
1. Assess the strength of arguments on both sides
2. Identify which points are well-supported vs speculative
3. Weigh the evidence objectively
4. Provide a balanced final assessment

Consider technical accuracy, practical exploitability, and evidence quality. Be impartial and evidence-based."""
        }
        
        return prompts.get(persona, "You are a security expert evaluating a vulnerability finding.")
    
    def _extract_vote(self, response: str, persona: str) -> bool:
        """Extract vote (True = vulnerable, False = not vulnerable) from response."""
        response_upper = response.upper()
        
        # Look for explicit TRUE/FALSE indicators
        if "TRUE: THIS IS A GENUINE VULNERABILITY" in response_upper:
            return True
        if "FALSE: THIS IS A FALSE POSITIVE" in response_upper:
            return False
        
        # Fallback: look for keywords
        pro_keywords = ["genuine", "exploitable", "vulnerable", "confirmed"]
        anti_keywords = ["false positive", "not exploitable", "mitigated", "theoretical"]
        
        pro_count = sum(1 for kw in pro_keywords if kw in response_upper)
        anti_count = sum(1 for kw in anti_keywords if kw in response_upper)
        
        if persona == "arbiter":
            # Arbiter needs explicit conclusion
            return pro_count > anti_count
        elif persona == "pro-vulnerability":
            # Pro-vulnerability defaults to True unless explicitly False
            return anti_count == 0
        else:  # anti-vulnerability
            # Anti-vulnerability defaults to False unless explicitly True
            return pro_count > 0
    
    def _calculate_debate_result(self, votes: List[bool]) -> bool:
        """Calculate debate result from votes (2/3 majority)."""
        if not votes:
            return False
        
        true_votes = sum(1 for v in votes if v)
        total_votes = len(votes)
        
        return (true_votes / total_votes) >= self.vote_threshold
    
    def _calculate_confidence(self, votes: List[bool], result: bool) -> float:
        """Calculate confidence score from votes."""
        if not votes:
            return 0.0
        
        # Confidence is the proportion of votes that agree with the result
        agreeing_votes = sum(1 for v in votes if v == result)
        return agreeing_votes / len(votes)
    
    def _determine_validation_status(self, transcript: DebateTranscript) -> str:
        """Determine validation status based on debate transcript."""
        if transcript.result and transcript.confidence >= 0.67:
            return "validated"
        elif not transcript.result and transcript.confidence >= 0.67:
            return "false_positive"
        else:
            return "unconfirmed"
    
    def _estimate_debate_cost(self, model: str) -> float:
        """Estimate cost for a single debate turn."""
        # Rough estimation: 4K tokens * cost per 1K tokens
        cost_per_1k = 0.001
        return 4.0 * cost_per_1k
