"""
Remediation engine for the pipeline - generates remediation suggestions.
"""
from typing import Dict, List, Any, Optional
import logging
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from openrouter_integration.client import OpenRouterClient
from openrouter_integration.model_selector import ModelSelector
from openrouter_integration.cost_tracker import CostTracker
from ..models import ProvenFinding, D3FENDTechnique

logger = logging.getLogger(__name__)


class RemediationEngine:
    """Generate remediation suggestions for findings."""
    
    def __init__(
        self,
        openrouter_client: OpenRouterClient,
        model_selector: ModelSelector,
        cost_tracker: CostTracker,
        config: Dict[str, Any]
    ):
        """
        Initialize remediation engine.
        
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
        logger.info("RemediationEngine initialized")
    
    def generate_remediation(
        self,
        proven_finding: ProvenFinding,
        d3fend_techniques: List[D3FENDTechnique]
    ) -> str:
        """
        Generate remediation suggestion for a finding.
        
        Args:
            proven_finding: Proven finding to generate remediation for
            d3fend_techniques: D3FEND techniques to apply
            
        Returns:
            Remediation suggestion string
        """
        original = proven_finding.deduplicated_finding.representative_finding.original_candidate
        
        # Build remediation prompt
        prompt = self._build_remediation_prompt(
            original,
            d3fend_techniques
        )
        
        # Check budget before generating remediation
        if self.cost_tracker.is_budget_exceeded():
            logger.warning("Budget exceeded, skipping remediation generation")
            return "Remediation skipped due to budget constraints"
        
        # Select model for remediation
        model = self.model_selector.select_for_poc("python")  # Use same model selection
        
        try:
            response = self.client.chat(
                model=model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a security remediation specialist. Generate practical, actionable remediation suggestions for vulnerabilities. Focus on defensive measures that align with D3FEND techniques."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.0,
                max_tokens=4096
            )
            
            # Track cost
            estimated_cost = self._estimate_remediation_cost(len(response["content"]))
            self.cost_tracker.add_cost(model, estimated_cost, stage="d3fend")
            
            return response["content"]
        
        except Exception as e:
            logger.error(f"Failed to generate remediation: {e}")
            return f"Remediation generation failed: {str(e)}"
    
    def _build_remediation_prompt(
        self,
        original,
        d3fend_techniques: List[D3FENDTechnique]
    ) -> str:
        """Build prompt for remediation generation."""
        technique_info = "\n".join([
            f"- {t.id} ({t.label} - {t.tactic} tactic)"
            for t in d3fend_techniques
        ])
        
        prompt = f"""Generate a remediation suggestion for the following vulnerability:

Vulnerability Details:
- Bug Class: {original.bug_class.value}
- Location: {original.location}
- Precondition: {original.precondition}
- Evidence: {original.evidence}
- CWE ID: {original.cwe_id or 'N/A'}

D3FEND Techniques to Apply:
{technique_info}

Requirements:
1. Provide specific code changes or configuration changes
2. Explain how the remediation addresses the vulnerability
3. Reference the applicable D3FEND techniques
4. Include testing recommendations to verify the fix
5. Consider defender-only measures (no offensive capabilities)
6. Be practical and implementable

Provide the remediation as a structured response with:
- Code changes (if applicable)
- Configuration changes (if applicable)
- Testing steps
- D3FEND technique mapping
"""
        return prompt
    
    def _estimate_remediation_cost(self, text_length: int) -> float:
        """Estimate cost for remediation generation."""
        cost_per_1k_tokens = 0.001
        estimated_tokens = text_length / 4
        return (estimated_tokens / 1000) * cost_per_1k_tokens
