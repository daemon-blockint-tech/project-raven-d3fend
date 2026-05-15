"""
Confidence scorer for the Validate stage - calculates confidence scores from debate results.
"""
from typing import List, Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class ConfidenceScorer:
    """Calculate confidence scores from debate transcripts and votes."""
    
    def __init__(self):
        """Initialize confidence scorer."""
        logger.info("ConfidenceScorer initialized")
    
    def calculate_confidence(
        self,
        votes: List[bool],
        result: bool,
        debate_quality: Optional[float] = None
    ) -> float:
        """
        Calculate confidence score from votes and debate result.
        
        Args:
            votes: List of boolean votes
            result: Final debate result (True = vulnerable, False = not vulnerable)
            debate_quality: Optional quality score of the debate (0-1)
            
        Returns:
            Confidence score (0-1)
        """
        if not votes:
            return 0.0
        
        # Base confidence from vote agreement
        agreeing_votes = sum(1 for v in votes if v == result)
        base_confidence = agreeing_votes / len(votes)
        
        # Adjust by debate quality if provided
        if debate_quality is not None:
            # Weight base confidence by debate quality
            confidence = base_confidence * (0.7 + 0.3 * debate_quality)
        else:
            confidence = base_confidence
        
        return min(1.0, max(0.0, confidence))
    
    def calculate_debate_quality(
        self,
        debaters: List[Dict[str, Any]]
    ) -> float:
        """
        Calculate quality score of a debate based on response characteristics.
        
        Args:
            debaters: List of debater responses
            
        Returns:
            Quality score (0-1)
        """
        if not debaters:
            return 0.0
        
        quality_factors = []
        
        for debater in debaters:
            response = debater.get("response", "")
            
            # Factor 1: Response length (adequate detail)
            length_score = min(1.0, len(response) / 500)  # 500 chars = good length
            quality_factors.append(length_score)
            
            # Factor 2: Contains reasoning keywords
            reasoning_keywords = [
                "because", "since", "therefore", "however", "although",
                "evidence", "precondition", "feasible", "mitigating"
            ]
            response_lower = response.lower()
            reasoning_count = sum(1 for kw in reasoning_keywords if kw in response_lower)
            reasoning_score = min(1.0, reasoning_count / 3)  # 3+ keywords = good
            quality_factors.append(reasoning_score)
        
        # Average quality factors
        avg_quality = sum(quality_factors) / len(quality_factors) if quality_factors else 0.0
        
        return avg_quality
    
    def calculate_vote_consistency(
        self,
        votes: List[bool]
    ) -> float:
        """
        Calculate consistency of votes (how unanimous they are).
        
        Args:
            votes: List of boolean votes
            
        Returns:
            Consistency score (0-1, where 1 = unanimous)
        """
        if not votes:
            return 0.0
        
        true_count = sum(1 for v in votes if v)
        false_count = len(votes) - true_count
        
        # Consistency = proportion of majority vote
        majority = max(true_count, false_count)
        consistency = majority / len(votes)
        
        return consistency
    
    def get_confidence_breakdown(
        self,
        votes: List[bool],
        result: bool
    ) -> Dict[str, Any]:
        """
        Get detailed breakdown of confidence calculation.
        
        Args:
            votes: List of boolean votes
            result: Final debate result
            
        Returns:
            Dictionary with confidence breakdown
        """
        agreeing_votes = sum(1 for v in votes if v == result)
        total_votes = len(votes)
        vote_confidence = agreeing_votes / total_votes if total_votes else 0.0
        consistency = self.calculate_vote_consistency(votes)
        
        return {
            "vote_confidence": vote_confidence,
            "vote_consistency": consistency,
            "agreeing_votes": agreeing_votes,
            "total_votes": total_votes,
            "result": result
        }
