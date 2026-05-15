"""
Model selection logic for the multi-model agentic security pipeline.
"""
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)


class ModelSelector:
    """Select appropriate OpenRouter models based on context and bug class."""
    
    # Default model mappings for different bug classes
    BUG_CLASS_MODELS = {
        "memory_corruption": ["claude-3.5-sonnet", "gpt-4"],
        "integer_overflow": ["claude-3.5-sonnet", "gpt-4"],
        "race_condition": ["gpt-4", "claude-3.5-sonnet"],
        "auth_bypass": ["gemini-pro", "gpt-4"],
        "deserialization": ["claude-3.5-sonnet", "gemini-pro"],
        "type_confusion": ["claude-3.5-sonnet", "gpt-4"],
        "signature_malleability": ["gemini-pro", "gpt-4"],
        "account_confusion": ["gpt-4", "claude-3.5-sonnet"],
        "oracle_manipulation": ["gemini-pro", "gpt-4"],
        "reentrancy": ["claude-3.5-sonnet", "gpt-4"],
        "logic_error": ["gpt-4", "claude-3.5-sonnet"]
    }
    
    # Debate persona models
    DEBATE_MODELS = {
        "pro-vulnerability": ["claude-3.5-sonnet", "gpt-4"],
        "anti-vulnerability": ["gpt-4", "claude-3.5-sonnet"],
        "arbiter": ["gemini-pro", "gpt-4"]
    }
    
    # Embedding models
    EMBEDDING_MODELS = [
        "text-embedding-3-small",
        "text-embedding-3-large"
    ]
    
    # PoC generation models
    POC_MODELS = ["claude-3.5-sonnet", "gpt-4"]
    
    # Threat modeling models
    THREAT_MODEL_MODELS = ["claude-3.5-sonnet", "gpt-4", "gemini-pro"]
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize model selector with optional configuration.
        
        Args:
            config: Configuration dictionary with model mappings
        """
        self.config = config or {}
        self.custom_mappings = self.config.get("model_mappings", {})
        
        # Override defaults with custom mappings if provided
        if self.custom_mappings:
            self._apply_custom_mappings()
    
    def _apply_custom_mappings(self):
        """Apply custom model mappings from configuration."""
        if "bug_class" in self.custom_mappings:
            self.BUG_CLASS_MODELS.update(self.custom_mappings["bug_class"])
        if "debate" in self.custom_mappings:
            self.DEBATE_MODELS.update(self.custom_mappings["debate"])
    
    def select_for_bug_class(
        self,
        bug_class: str,
        language: Optional[str] = None,
        complexity: Optional[str] = None
    ) -> str:
        """
        Select model for a specific bug class.
        
        Args:
            bug_class: Bug class identifier
            language: Programming language (optional, can influence model choice)
            complexity: Code complexity (simple, moderate, complex)
            
        Returns:
            Model identifier string
        """
        # Get base models for bug class
        models = self.BUG_CLASS_MODELS.get(bug_class, ["claude-3.5-sonnet"])
        
        # Adjust based on language
        if language:
            if language in ["solidity", "rust"]:
                # Prefer models with strong systems programming support
                models = [m for m in models if "gpt" in m or "claude" in m]
        
        # Adjust based on complexity
        if complexity == "complex":
            # Prefer more capable models for complex code
            models = [m for m in models if "gpt-4" in m or "claude-3.5" in m]
        
        # Return first available model
        return models[0] if models else "claude-3.5-sonnet"
    
    def select_for_debate(self, persona: str) -> str:
        """
        Select model for debate persona.
        
        Args:
            persona: Debate persona (pro-vulnerability, anti-vulnerability, arbiter)
            
        Returns:
            Model identifier string
        """
        models = self.DEBATE_MODELS.get(persona, ["claude-3.5-sonnet"])
        return models[0] if models else "claude-3.5-sonnet"
    
    def select_for_embedding(self) -> str:
        """
        Select embedding model.
        
        Returns:
            Model identifier string
        """
        return self.EMBEDDING_MODELS[0]
    
    def select_for_poc(self, language: str) -> str:
        """
        Select model for PoC generation.
        
        Args:
            language: Programming language for PoC
            
        Returns:
            Model identifier string
        """
        models = self.POC_MODELS.copy()
        
        # Adjust based on language
        if language in ["c", "cpp", "rust"]:
            # Prefer models with strong C/C++/Rust support
            models = [m for m in models if "gpt" in m or "claude" in m]
        
        return models[0] if models else "claude-3.5-sonnet"
    
    def select_for_threat_model(self) -> str:
        """
        Select model for threat modeling.
        
        Returns:
            Model identifier string
        """
        return self.THREAT_MODEL_MODELS[0]
    
    def select_multiple_for_validation(
        self,
        count: int = 3
    ) -> List[str]:
        """
        Select multiple diverse models for validation debate.
        
        Args:
            count: Number of models to select
            
        Returns:
            List of model identifiers
        """
        # Diverse model set for debate
        diverse_models = [
            "claude-3.5-sonnet",
            "gpt-4",
            "gemini-pro",
            "meta-llama/llama-3.1-70b-instruct",
            "mistralai/mistral-large"
        ]
        
        return diverse_models[:count]
    
    def get_model_capabilities(self, model: str) -> Dict[str, bool]:
        """
        Get capabilities of a specific model.
        
        Args:
            model: Model identifier
            
        Returns:
            Dictionary of capabilities
        """
        capabilities = {
            "streaming": True,
            "function_calling": True,
            "json_mode": True,
            "vision": False
        }
        
        # Model-specific capabilities
        if "claude" in model:
            capabilities.update({
                "vision": True,
                "large_context": True
            })
        elif "gpt-4" in model:
            capabilities.update({
                "vision": True,
                "large_context": True
            })
        elif "gemini" in model:
            capabilities.update({
                "vision": True,
                "large_context": True
            })
        
        return capabilities
