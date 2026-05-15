"""
Voting system for the Validate stage - aggregates debater votes.
"""
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)


class VotingSystem:
    """Aggregate and analyze votes from multiple debaters."""
    
    def __init__(self, vote_threshold: float = 0.67):
        """
        Initialize voting system.
        
        Args:
            vote_threshold: Threshold for majority vote (default 2/3)
        """
        self.vote_threshold = vote_threshold
        logger.info(f"VotingSystem initialized with threshold: {vote_threshold}")
    
    def aggregate_votes(self, votes: List[bool]) -> Dict[str, Any]:
        """
        Aggregate votes and calculate result.
        
        Args:
            votes: List of boolean votes (True = vulnerable, False = not vulnerable)
            
        Returns:
            Dictionary with voting results
        """
        if not votes:
            return {
                "total_votes": 0,
                "true_votes": 0,
                "false_votes": 0,
                "result": False,
                "confidence": 0.0,
                "meets_threshold": False
            }
        
        true_votes = sum(1 for v in votes if v)
        false_votes = len(votes) - true_votes
        total_votes = len(votes)
        
        # Calculate result (majority vote)
        result = true_votes > false_votes
        
        # Calculate confidence (proportion agreeing with result)
        if result:
            confidence = true_votes / total_votes
        else:
            confidence = false_votes / total_votes
        
        # Check if meets threshold
        meets_threshold = confidence >= self.vote_threshold
        
        return {
            "total_votes": total_votes,
            "true_votes": true_votes,
            "false_votes": false_votes,
            "result": result,
            "confidence": confidence,
            "meets_threshold": meets_threshold
        }
    
    def calculate_weighted_vote(
        self,
        votes: List[bool],
        weights: List[float]
    ) -> Dict[str, Any]:
        """
        Calculate weighted vote result.
        
        Args:
            votes: List of boolean votes
            weights: List of weights for each vote
            
        Returns:
            Dictionary with weighted voting results
        """
        if len(votes) != len(weights):
            raise ValueError("Votes and weights must have same length")
        
        if not votes:
            return {
                "total_votes": 0,
                "weighted_true": 0.0,
                "weighted_false": 0.0,
                "result": False,
                "confidence": 0.0
            }
        
        weighted_true = sum(w for v, w in zip(votes, weights) if v)
        weighted_false = sum(w for v, w in zip(votes, weights) if not v)
        total_weight = sum(weights)
        
        result = weighted_true > weighted_false
        
        if result:
            confidence = weighted_true / total_weight
        else:
            confidence = weighted_false / total_weight
        
        return {
            "total_votes": len(votes),
            "weighted_true": weighted_true,
            "weighted_false": weighted_false,
            "result": result,
            "confidence": confidence
        }
    
    def get_vote_breakdown(self, debaters: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Get vote breakdown by persona.
        
        Args:
            debaters: List of debater dictionaries with 'persona' and 'vote' keys
            
        Returns:
            Dictionary with vote breakdown by persona
        """
        breakdown = {
            "pro-vulnerability": {"total": 0, "true": 0, "false": 0},
            "anti-vulnerability": {"total": 0, "true": 0, "false": 0},
            "arbiter": {"total": 0, "true": 0, "false": 0}
        }
        
        for debater in debaters:
            persona = debater.get("persona", "unknown")
            vote = debater.get("vote", False)
            
            if persona in breakdown:
                breakdown[persona]["total"] += 1
                if vote:
                    breakdown[persona]["true"] += 1
                else:
                    breakdown[persona]["false"] += 1
        
        return breakdown
