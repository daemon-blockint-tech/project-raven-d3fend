"""
Embedding generator for the Dedup stage - generates embeddings for semantic similarity.
"""
from typing import List, Dict, Any
import logging
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from openrouter_integration.client import OpenRouterClient
from openrouter_integration.model_selector import ModelSelector
from openrouter_integration.cost_tracker import CostTracker

logger = logging.getLogger(__name__)


class EmbeddingGenerator:
    """Generate embeddings for findings using OpenRouter embedding models."""
    
    def __init__(
        self,
        openrouter_client: OpenRouterClient,
        model_selector: ModelSelector,
        cost_tracker: CostTracker,
        config: Dict[str, Any]
    ):
        """
        Initialize embedding generator.
        
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
        self.embedding_model = config.get("embedding_model", "text-embedding-3-small")
        logger.info(f"EmbeddingGenerator initialized with model: {self.embedding_model}")
    
    def generate_finding_embedding(
        self,
        finding_text: str
    ) -> List[float]:
        """
        Generate embedding for a single finding.
        
        Args:
            finding_text: Text representation of the finding
            
        Returns:
            Embedding vector as list of floats
        """
        try:
            # Check budget before generating embedding
            if self.cost_tracker.is_budget_exceeded():
                logger.warning("Budget exceeded, skipping embedding generation")
                return []
            
            # Generate embedding
            embedding = self.client.embedding(
                model=self.embedding_model,
                input_text=finding_text
            )
            
            # Track cost
            estimated_cost = self._estimate_embedding_cost(len(finding_text))
            self.cost_tracker.add_cost(self.embedding_model, estimated_cost, stage="dedup")
            
            return embedding
        
        except Exception as e:
            logger.error(f"Failed to generate embedding: {e}")
            return []
    
    def generate_batch_embeddings(
        self,
        finding_texts: List[str]
    ) -> List[List[float]]:
        """
        Generate embeddings for multiple findings.
        
        Args:
            finding_texts: List of text representations of findings
            
        Returns:
            List of embedding vectors
        """
        embeddings = []
        
        for text in finding_texts:
            embedding = self.generate_finding_embedding(text)
            embeddings.append(embedding)
        
        logger.info(f"Generated {len(embeddings)} embeddings")
        return embeddings
    
    def _estimate_embedding_cost(self, text_length: int) -> float:
        """Estimate cost for embedding generation."""
        # Rough estimation: embeddings are cheaper than chat
        cost_per_1k_tokens = 0.0001
        estimated_tokens = text_length / 4  # Rough token estimate
        return (estimated_tokens / 1000) * cost_per_1k_tokens
