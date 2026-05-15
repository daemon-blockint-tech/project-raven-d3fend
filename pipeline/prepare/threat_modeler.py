"""
Threat modeler for the Prepare stage using OpenRouter models.
"""
from typing import Dict, List, Any, Optional
import logging
import sys
import os

# Add parent directory to path to import openrouter integration
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from openrouter_integration.client import OpenRouterClient
from openrouter_integration.model_selector import ModelSelector
from ..models import ThreatModel, SurfaceMap

logger = logging.getLogger(__name__)


class ThreatModeler:
    """Generate threat models using OpenRouter models."""
    
    def __init__(
        self,
        openrouter_client: OpenRouterClient,
        model_selector: ModelSelector,
        config: Dict[str, Any]
    ):
        """
        Initialize threat modeler.
        
        Args:
            openrouter_client: OpenRouter client instance
            model_selector: Model selector instance
            config: Configuration dictionary
        """
        self.client = openrouter_client
        self.model_selector = model_selector
        self.config = config
        self.temperature = config.get("temperature", 0.0)
        self.max_tokens = config.get("max_tokens", 4096)
        logger.info("ThreatModeler initialized")
    
    def generate_threat_model(
        self,
        surface_map: SurfaceMap,
        language_index: Dict[str, Any]
    ) -> ThreatModel:
        """
        Generate threat model using OpenRouter models.
        
        Args:
            surface_map: Surface map from indexing
            language_index: Language index data
            
        Returns:
            ThreatModel object
        """
        # Select model for threat modeling
        model = self.model_selector.select_for_threat_model()
        
        # Build prompt for threat modeling
        prompt = self._build_threat_model_prompt(surface_map, language_index)
        
        # Get threat model from multiple models for cross-validation
        threat_models = []
        models_to_use = self.config.get("models", [model])
        
        for model_name in models_to_use:
            try:
                response = self.client.chat(
                    model=model_name,
                    messages=[
                        {
                            "role": "system",
                            "content": "You are a security expert specializing in threat modeling and vulnerability analysis. Analyze the provided codebase and identify potential security threats and attack surfaces."
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    temperature=self.temperature,
                    max_tokens=self.max_tokens
                )
                
                # Parse response
                threat_analysis = self._parse_threat_response(response["content"])
                threat_models.append({
                    "model": model_name,
                    "analysis": threat_analysis,
                    "confidence": self._estimate_confidence(threat_analysis)
                })
                
            except Exception as e:
                logger.error(f"Failed to get threat model from {model_name}: {e}")
        
        # Select best threat model based on confidence
        best_model = max(threat_models, key=lambda x: x["confidence"], default=None)
        
        if not best_model:
            # Fallback to empty threat model
            return ThreatModel(
                target=surface_map.target,
                model_used="fallback",
                confidence=0.0
            )
        
        # Build ThreatModel object
        attack_surface = best_model["analysis"].get("attack_surface", [])
        high_risk_areas = best_model["analysis"].get("high_risk_areas", [])
        threat_hypotheses = best_model["analysis"].get("threat_hypotheses", [])
        
        return ThreatModel(
            target=surface_map.target,
            attack_surface=attack_surface,
            high_risk_areas=high_risk_areas,
            threat_hypotheses=threat_hypotheses,
            model_used=best_model["model"],
            confidence=best_model["confidence"]
        )
    
    def _build_threat_model_prompt(
        self,
        surface_map: SurfaceMap,
        language_index: Dict[str, Any]
    ) -> str:
        """Build prompt for threat modeling."""
        prompt = f"""Analyze the following codebase for security threats and attack surfaces:

Target: {surface_map.target}
Target Type: {surface_map.target_type}

Entry Points:
{self._format_list(surface_map.entry_points)}

Syscalls of Interest:
{self._format_list(surface_map.syscalls_of_interest)}

ABI Boundaries:
{self._format_list(surface_map.abi_boundaries)}

Languages Detected:
{', '.join(language_index.get('languages', {}).keys())}

Call Graph Summary:
- Total functions: {len(language_index.get('call_graph', {}))}
- Entry points identified: {len(surface_map.entry_points)}

Please provide:
1. Attack surface analysis - identify all external interfaces and inputs
2. High-risk areas - functions/modules that handle sensitive data or critical operations
3. Threat hypotheses - potential vulnerabilities based on the codebase structure

Format your response as JSON:
{{
    "attack_surface": [
        {{"location": "file:function", "type": "external_interface", "description": "..."}}
    ],
    "high_risk_areas": [
        {{"location": "file:function", "risk_type": "data_handling", "reason": "..."}}
    ],
    "threat_hypotheses": [
        {{"location": "file:function", "threat_type": "...", "precondition": "...", "likelihood": "high/medium/low"}}
    ]
}}
"""
        return prompt
    
    def _format_list(self, items: List[Any]) -> str:
        """Format list for prompt."""
        if not items:
            return "None"
        
        formatted = []
        for item in items[:20]:  # Limit to 20 items to avoid token overflow
            if isinstance(item, dict):
                formatted.append(f"- {item.get('location', str(item))}")
            else:
                formatted.append(f"- {str(item)}")
        
        if len(items) > 20:
            formatted.append(f"... and {len(items) - 20} more")
        
        return "\n".join(formatted)
    
    def _parse_threat_response(self, response: str) -> Dict[str, Any]:
        """Parse threat model response from LLM."""
        import json
        import re
        
        # Try to extract JSON from response
        json_match = re.search(r'\{[\s\S]*\}', response)
        
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                logger.warning("Failed to parse JSON from threat model response")
        
        # Fallback: parse text response
        return {
            "attack_surface": [],
            "high_risk_areas": [],
            "threat_hypotheses": []
        }
    
    def _estimate_confidence(self, analysis: Dict[str, Any]) -> float:
        """Estimate confidence of threat model analysis."""
        # Simple heuristic based on amount of data
        attack_surface_count = len(analysis.get("attack_surface", []))
        high_risk_count = len(analysis.get("high_risk_areas", []))
        threat_count = len(analysis.get("threat_hypotheses", []))
        
        total_items = attack_surface_count + high_risk_count + threat_count
        
        # Normalize confidence based on item count (max 10 items = 1.0 confidence)
        confidence = min(1.0, total_items / 10.0)
        
        return confidence
