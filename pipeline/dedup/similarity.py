"""
Similarity calculator for the Dedup stage - computes semantic similarity between findings.
"""
from typing import List, Dict, Any
import logging
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity

logger = logging.getLogger(__name__)


class SimilarityCalculator:
    """Calculate semantic similarity between findings using embeddings."""
    
    def __init__(self, similarity_threshold: float = 0.85):
        """
        Initialize similarity calculator.
        
        Args:
            similarity_threshold: Threshold for considering findings similar
        """
        self.similarity_threshold = similarity_threshold
        logger.info(f"SimilarityCalculator initialized with threshold: {similarity_threshold}")
    
    def calculate_similarity_matrix(
        self,
        embeddings: List[List[float]]
    ) -> np.ndarray:
        """
        Calculate pairwise similarity matrix from embeddings.
        
        Args:
            embeddings: List of embedding vectors
            
        Returns:
            Similarity matrix (numpy array)
        """
        if not embeddings:
            return np.array([])
        
        # Convert to numpy array
        embeddings_array = np.array(embeddings)
        
        # Calculate cosine similarity
        similarity_matrix = cosine_similarity(embeddings_array)
        
        return similarity_matrix
    
    def find_similar_pairs(
        self,
        embeddings: List[List[float]],
        threshold: Optional[float] = None
    ) -> List[Dict[str, Any]]:
        """
        Find pairs of findings above similarity threshold.
        
        Args:
            embeddings: List of embedding vectors
            threshold: Similarity threshold (uses instance threshold if not provided)
            
        Returns:
            List of similar pair dictionaries
        """
        threshold = threshold or self.similarity_threshold
        similarity_matrix = self.calculate_similarity_matrix(embeddings)
        
        similar_pairs = []
        
        for i in range(len(similarity_matrix)):
            for j in range(i + 1, len(similarity_matrix)):
                similarity = similarity_matrix[i][j]
                
                if similarity >= threshold:
                    similar_pairs.append({
                        "index_i": i,
                        "index_j": j,
                        "similarity": similarity
                    })
        
        logger.info(f"Found {len(similar_pairs)} similar pairs above threshold {threshold}")
        return similar_pairs
    
    def calculate_text_similarity(
        self,
        text1: str,
        text2: str
    ) -> float:
        """
        Calculate similarity between two text strings using simple metrics.
        
        Args:
            text1: First text string
            text2: Second text string
            
        Returns:
            Similarity score (0-1)
        """
        # Jaccard similarity of words
        words1 = set(text1.lower().split())
        words2 = set(text2.lower().split())
        
        if not words1 and not words2:
            return 1.0
        if not words1 or not words2:
            return 0.0
        
        intersection = len(words1 & words2)
        union = len(words1 | words2)
        
        jaccard = intersection / union if union > 0 else 0.0
        
        return jaccard
