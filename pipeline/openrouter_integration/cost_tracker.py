"""
Cost tracking and budget management for the multi-model agentic security pipeline.
"""
from typing import Dict, Optional
import logging
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class StageCost:
    """Cost tracking for a single pipeline stage."""
    stage_name: str
    cost_usd: float = 0.0
    request_count: int = 0
    start_time: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    end_time: Optional[str] = None
    model_costs: Dict[str, float] = field(default_factory=dict)
    
    def add_cost(self, model: str, cost: float):
        """Add cost for a specific model."""
        self.cost_usd += cost
        self.request_count += 1
        self.model_costs[model] = self.model_costs.get(model, 0.0) + cost
    
    def complete(self):
        """Mark stage as complete."""
        self.end_time = datetime.utcnow().isoformat()
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "stage_name": self.stage_name,
            "cost_usd": self.cost_usd,
            "request_count": self.request_count,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "model_costs": self.model_costs
        }


class CostTracker:
    """Track costs across pipeline stages with budget enforcement."""
    
    def __init__(self, budget_config: Dict):
        """
        Initialize cost tracker with budget configuration.
        
        Args:
            budget_config: Budget configuration dictionary with:
                - max_cost_usd: Maximum total cost
                - stage_limits: Per-stage cost limits
        """
        self.max_cost_usd = budget_config.get("max_cost_usd", 10.0)
        self.stage_limits = budget_config.get("stage_limits", {})
        self.cost_tracking_enabled = budget_config.get("cost_tracking", True)
        
        self.total_cost_usd = 0.0
        self.total_requests = 0
        self.stage_costs: Dict[str, StageCost] = {}
        self.current_stage: Optional[str] = None
        self.budget_exceeded = False
        
        logger.info(f"Cost tracker initialized with max budget: ${self.max_cost_usd:.2f}")
    
    def start_stage(self, stage_name: str):
        """
        Start tracking a new stage.
        
        Args:
            stage_name: Name of the stage
        """
        self.current_stage = stage_name
        self.stage_costs[stage_name] = StageCost(stage_name=stage_name)
        logger.info(f"Started tracking stage: {stage_name}")
    
    def end_stage(self, stage_name: str):
        """
        End tracking for a stage.
        
        Args:
            stage_name: Name of the stage
        """
        if stage_name in self.stage_costs:
            self.stage_costs[stage_name].complete()
            logger.info(
                f"Completed stage: {stage_name}, "
                f"cost: ${self.stage_costs[stage_name].cost_usd:.4f}, "
                f"requests: {self.stage_costs[stage_name].request_count}"
            )
    
    def add_cost(self, model: str, cost: float, stage: Optional[str] = None):
        """
        Add cost for a model request.
        
        Args:
            model: Model identifier
            cost: Cost in USD
            stage: Stage name (uses current stage if not provided)
            
        Returns:
            True if cost added, False if budget exceeded
        """
        if not self.cost_tracking_enabled:
            return True
        
        stage = stage or self.current_stage
        if not stage:
            logger.warning("No active stage for cost tracking")
            return True
        
        # Check total budget
        if self.total_cost_usd + cost > self.max_cost_usd:
            logger.warning(
                f"Budget exceeded: ${self.total_cost_usd + cost:.4f} > ${self.max_cost_usd:.2f}"
            )
            self.budget_exceeded = True
            return False
        
        # Check stage budget
        stage_limit = self.stage_limits.get(stage)
        if stage_limit:
            stage_cost = self.stage_costs.get(stage, StageCost(stage_name=stage))
            if stage_cost.cost_usd + cost > stage_limit:
                logger.warning(
                    f"Stage budget exceeded for {stage}: "
                    f"${stage_cost.cost_usd + cost:.4f} > ${stage_limit:.2f}"
                )
                return False
        
        # Add cost
        self.total_cost_usd += cost
        self.total_requests += 1
        
        if stage not in self.stage_costs:
            self.stage_costs[stage] = StageCost(stage_name=stage)
        self.stage_costs[stage].add_cost(model, cost)
        
        logger.debug(
            f"Added cost: ${cost:.6f} for {model} in stage {stage}, "
            f"total: ${self.total_cost_usd:.4f}"
        )
        
        return True
    
    def get_total_cost(self) -> float:
        """Get total cost incurred."""
        return self.total_cost_usd
    
    def get_stage_cost(self, stage_name: str) -> float:
        """Get cost for a specific stage."""
        if stage_name in self.stage_costs:
            return self.stage_costs[stage_name].cost_usd
        return 0.0
    
    def get_remaining_budget(self) -> float:
        """Get remaining budget."""
        return max(0.0, self.max_cost_usd - self.total_cost_usd)
    
    def is_budget_exceeded(self) -> bool:
        """Check if budget has been exceeded."""
        return self.budget_exceeded or self.total_cost_usd >= self.max_cost_usd
    
    def get_summary(self) -> Dict:
        """Get cost summary."""
        return {
            "total_cost_usd": self.total_cost_usd,
            "total_requests": self.total_requests,
            "max_budget_usd": self.max_cost_usd,
            "remaining_budget_usd": self.get_remaining_budget(),
            "budget_exceeded": self.is_budget_exceeded(),
            "stage_costs": {
                name: cost.to_dict()
                for name, cost in self.stage_costs.items()
            }
        }
    
    def reset(self):
        """Reset all cost tracking."""
        self.total_cost_usd = 0.0
        self.total_requests = 0
        self.stage_costs = {}
        self.current_stage = None
        self.budget_exceeded = False
        logger.info("Cost tracker reset")
