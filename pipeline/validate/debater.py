"""
Debater class for the Validate stage - individual debate participant.
"""
from typing import Dict, Any, Optional
import logging
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from openrouter_integration.client import OpenRouterClient

logger = logging.getLogger(__name__)


class Debater:
    """Individual debater in multi-model validation debate."""
    
    def __init__(
        self,
        model: str,
        persona: str,
        openrouter_client: OpenRouterClient,
        temperature: float = 0.7,
        max_tokens: int = 4096
    ):
        """
        Initialize debater.
        
        Args:
            model: OpenRouter model identifier
            persona: Debate persona (pro-vulnerability, anti-vulnerability, arbiter)
            openrouter_client: OpenRouter client instance
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate
        """
        self.model = model
        self.persona = persona
        self.client = openrouter_client
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.system_prompt = self._get_system_prompt(persona)
        logger.info(f"Debater initialized: {model} ({persona})")
    
    def debate(self, context: str) -> Dict[str, Any]:
        """
        Participate in debate with given context.
        
        Args:
            context: Debate context with finding details
            
        Returns:
            Dictionary with debate response and vote
        """
        try:
            response = self.client.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": context}
                ],
                temperature=self.temperature,
                max_tokens=self.max_tokens
            )
            
            content = response["content"]
            vote = self._extract_vote(content)
            
            return {
                "model": self.model,
                "persona": self.persona,
                "response": content,
                "vote": vote,
                "usage": response.get("usage", {})
            }
        
        except Exception as e:
            logger.error(f"Debater {self.model} failed: {e}")
            return {
                "model": self.model,
                "persona": self.persona,
                "response": f"ERROR: {str(e)}",
                "vote": False,
                "usage": {}
            }
    
    def _get_system_prompt(self, persona: str) -> str:
        """Get system prompt for debate persona."""
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
    
    def _extract_vote(self, response: str) -> bool:
        """Extract vote (True = vulnerable, False = not vulnerable) from response."""
        response_upper = response.upper()
        
        # Look for explicit TRUE/FALSE indicators
        if "TRUE: THIS IS A GENUINE VULNERABILITY" in response_upper:
            return True
        if "FALSE: THIS IS A FALSE POSITIVE" in response_upper:
            return False
        
        # Fallback: look for keywords
        pro_keywords = ["genuine", "exploitable", "vulnerable", "confirmed", "valid"]
        anti_keywords = ["false positive", "not exploitable", "mitigated", "theoretical", "unlikely"]
        
        pro_count = sum(1 for kw in pro_keywords if kw in response_upper)
        anti_count = sum(1 for kw in anti_keywords if kw in response_upper)
        
        if self.persona == "arbiter":
            # Arbiter needs explicit conclusion
            return pro_count > anti_count
        elif self.persona == "pro-vulnerability":
            # Pro-vulnerability defaults to True unless explicitly False
            return anti_count == 0
        else:  # anti-vulnerability
            # Anti-vulnerability defaults to False unless explicitly True
            return pro_count > 0
