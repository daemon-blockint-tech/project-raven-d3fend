"""
PoC generator for the Prove stage - generates proof-of-concept code.
"""
from typing import List, Dict, Any, Optional
import logging
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from openrouter_integration.client import OpenRouterClient
from openrouter_integration.model_selector import ModelSelector
from openrouter_integration.cost_tracker import CostTracker
from ..models import DeduplicatedFinding, PoCArtifact

logger = logging.getLogger(__name__)


class PoCGenerator:
    """Generate proof-of-concept code for vulnerabilities."""
    
    def __init__(
        self,
        openrouter_client: OpenRouterClient,
        model_selector: ModelSelector,
        cost_tracker: CostTracker,
        config: Dict[str, Any]
    ):
        """
        Initialize PoC generator.
        
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
        self.poc_model = config.get("poc_generator", "claude-3.5-sonnet")
        self.temperature = config.get("temperature", 0.0)
        self.max_tokens = config.get("max_tokens", 8192)
        logger.info(f"PoCGenerator initialized with model: {self.poc_model}")
    
    def generate_poc(
        self,
        finding: DeduplicatedFinding,
        language: str = "python"
    ) -> List[PoCArtifact]:
        """
        Generate PoC artifacts for a finding.
        
        Args:
            finding: Deduplicated finding to generate PoC for
            language: Programming language for PoC code
            
        Returns:
            List of PoC artifacts
        """
        artifacts = []
        
        # Check budget before generating PoC
        if self.cost_tracker.is_budget_exceeded():
            logger.warning("Budget exceeded, skipping PoC generation")
            return artifacts
        
        # Build PoC generation prompt
        prompt = self._build_poc_prompt(finding, language)
        
        # Select model for PoC generation
        model = self.model_selector.select_for_poc(language)
        
        try:
            # Generate PoC code
            response = self.client.chat(
                model=model,
                messages=[
                    {
                        "role": "system",
                        "content": f"You are a security researcher specializing in {language} vulnerability proof-of-concept development. Generate minimal, self-contained code that demonstrates the vulnerability without causing harm."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=self.temperature,
                max_tokens=self.max_tokens
            )
            
            # Track cost
            estimated_cost = self._estimate_poc_cost(len(response["content"]))
            self.cost_tracker.add_cost(model, estimated_cost, stage="prove")
            
            # Create PoC artifact
            poc_artifact = PoCArtifact(
                type="self_contained",
                content=response["content"],
                language=language
            )
            artifacts.append(poc_artifact)
            
            logger.info(f"Generated PoC for finding {finding.id}")
        
        except Exception as e:
            logger.error(f"Failed to generate PoC for finding {finding.id}: {e}")
        
        return artifacts
    
    def _build_poc_prompt(self, finding: DeduplicatedFinding, language: str) -> str:
        """Build prompt for PoC generation."""
        original = finding.representative_finding.original_candidate
        
        prompt = f"""Generate a minimal, self-contained proof-of-concept in {language} for the following vulnerability:

Vulnerability Details:
- Bug Class: {original.bug_class.value}
- Location: {original.location}
- Precondition: {original.precondition}
- Evidence: {original.evidence}
- CWE ID: {original.cwe_id or 'N/A'}

Requirements:
1. The code should be self-contained (no external dependencies beyond standard library)
2. Demonstrate the vulnerability conceptually without causing actual harm
3. Include comments explaining the vulnerability
4. Use defensive programming practices where appropriate
5. The code should be compilable/runnable in a standard {language} environment

Provide only the code with brief comments. Do not include exploit payloads or malicious code."""
        
        return prompt
    
    def _estimate_poc_cost(self, code_length: int) -> float:
        """Estimate cost for PoC generation."""
        # Rough estimation based on token count
        cost_per_1k_tokens = 0.002
        estimated_tokens = code_length / 4
        return (estimated_tokens / 1000) * cost_per_1k
