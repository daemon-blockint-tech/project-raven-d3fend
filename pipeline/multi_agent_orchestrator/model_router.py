"""
Model Router with dynamic model allocation by task complexity.

Uses the OpenRouter SDK to access 300+ models. Dynamically assigns
frontier models (GPT-4o, Claude 3.5) to complex tasks and distilled
cost-effective models to simple pattern matching.
"""
import asyncio
import logging
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass
from enum import Enum

# Try importing openrouter
try:
    from openrouter import OpenRouter
    OPENROUTER_AVAILABLE = True
except ImportError:
    OPENROUTER_AVAILABLE = False

logger = logging.getLogger(__name__)


class ModelTier(Enum):
    FRONTIER = "frontier"      # GPT-4o, Claude 3.5, Gemini Pro
    BALANCED = "balanced"      # GPT-4o-mini, Claude 3 Haiku
    DISTILLED = "distilled"    # Cost-effective models for high-volume tasks


@dataclass
class ModelConfig:
    model_id: str
    tier: ModelTier
    cost_per_1k_input: float
    cost_per_1k_output: float
    context_window: int
    capabilities: List[str]


class ModelRouter:
    """
    Routes tasks to the most appropriate model based on complexity,
    budget, and fallback chains.
    """

    # Default model registry
    DEFAULT_MODELS = {
        # Frontier tier
        "gpt-4o": ModelConfig("openai/gpt-4o", ModelTier.FRONTIER, 5.0, 15.0, 128000, ["reasoning", "code", "vision"]),
        "claude-3.5-sonnet": ModelConfig("anthropic/claude-3.5-sonnet", ModelTier.FRONTIER, 3.0, 15.0, 200000, ["reasoning", "code", "long-context"]),
        "gemini-pro": ModelConfig("google/gemini-pro", ModelTier.FRONTIER, 3.5, 10.5, 128000, ["reasoning", "vision", "multimodal"]),

        # Balanced tier
        "gpt-4o-mini": ModelConfig("openai/gpt-4o-mini", ModelTier.BALANCED, 0.15, 0.6, 128000, ["code", "fast"]),
        "claude-3-haiku": ModelConfig("anthropic/claude-3-haiku", ModelTier.BALANCED, 0.25, 1.25, 200000, ["code", "long-context"]),

        # Distilled tier
        "llama-3-8b": ModelConfig("meta-llama/llama-3-8b-instruct", ModelTier.DISTILLED, 0.05, 0.15, 8192, ["fast", "simple"]),
        "mistral-7b": ModelConfig("mistralai/mistral-7b-instruct", ModelTier.DISTILLED, 0.05, 0.15, 8192, ["fast", "simple"]),
    }

    def __init__(
        self,
        api_key: Optional[str] = None,
        models: Optional[Dict[str, ModelConfig]] = None,
        budget_usd: float = 10.0,
    ):
        if not OPENROUTER_AVAILABLE:
            logger.warning("openrouter package not installed. Install with: pip install openrouter")
            self._client = None
        else:
            self._client = OpenRouter(api_key=api_key)

        self.models = models or dict(self.DEFAULT_MODELS)
        self.budget_usd = budget_usd
        self.spent_usd = 0.0
        self.request_log: List[Dict] = []

        # Fallback chains per tier
        self.fallback_chains = {
            ModelTier.FRONTIER: ["gpt-4o", "claude-3.5-sonnet", "gemini-pro"],
            ModelTier.BALANCED: ["gpt-4o-mini", "claude-3-haiku", "llama-3-8b"],
            ModelTier.DISTILLED: ["llama-3-8b", "mistral-7b"],
        }

        logger.info(f"ModelRouter initialized with {len(self.models)} models, budget ${budget_usd}")

    def select_model(
        self,
        task_complexity: str,  # 'simple' | 'moderate' | 'complex' | 'deep-reasoning'
        required_capabilities: Optional[List[str]] = None,
        preferred_model: Optional[str] = None,
    ) -> str:
        """
        Select the best model for a task based on complexity and budget.

        Args:
            task_complexity: Complexity level of the task
            required_capabilities: List of required capabilities
            preferred_model: Optional preferred model ID

        Returns:
            Model ID string
        """
        # Map complexity to tier
        tier_map = {
            "simple": ModelTier.DISTILLED,
            "moderate": ModelTier.BALANCED,
            "complex": ModelTier.FRONTIER,
            "deep-reasoning": ModelTier.FRONTIER,
        }
        target_tier = tier_map.get(task_complexity, ModelTier.BALANCED)

        # If preferred model specified and available, use it
        if preferred_model and preferred_model in self.models:
            cfg = self.models[preferred_model]
            if self._can_afford(cfg):
                return preferred_model

        # Get fallback chain for tier
        chain = self.fallback_chains[target_tier]

        # Find first affordable model with required capabilities
        for model_id in chain:
            if model_id not in self.models:
                continue
            cfg = self.models[model_id]
            if not self._can_afford(cfg):
                continue
            if required_capabilities:
                if not all(cap in cfg.capabilities for cap in required_capabilities):
                    continue
            return model_id

        # Fallback to cheapest available
        logger.warning("Budget exhausted or no suitable model found. Falling back to cheapest.")
        cheapest = min(
            self.models.values(),
            key=lambda m: m.cost_per_1k_input + m.cost_per_1k_output
        )
        return cheapest.model_id

    def _can_afford(self, cfg: ModelConfig) -> bool:
        """Check if remaining budget can afford at least one request."""
        estimated_cost = (cfg.cost_per_1k_input + cfg.cost_per_1k_output) / 1000 * 4000  # estimate 4k tokens
        return (self.spent_usd + estimated_cost) <= self.budget_usd

    def track_cost(self, model_id: str, input_tokens: int, output_tokens: int):
        """Track cost for a request."""
        cfg = self.models.get(model_id)
        if not cfg:
            return
        cost = (input_tokens / 1000 * cfg.cost_per_1k_input +
                output_tokens / 1000 * cfg.cost_per_1k_output)
        self.spent_usd += cost
        self.request_log.append({
            "model": model_id,
            "tier": cfg.tier.value,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cost": cost,
        })
        logger.info(f"Tracked ${cost:.4f} for {model_id}. Total: ${self.spent_usd:.4f}")

    def get_budget_status(self) -> Dict[str, Any]:
        return {
            "budget_usd": self.budget_usd,
            "spent_usd": self.spent_usd,
            "remaining_usd": self.budget_usd - self.spent_usd,
            "utilization": self.spent_usd / self.budget_usd if self.budget_usd > 0 else 0,
            "request_count": len(self.request_log),
        }

    async def chat(
        self,
        model: str,
        messages: List[Dict[str, str]],
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> str:
        """
        Send a chat request to the selected model via OpenRouter.
        """
        if not self._client:
            raise RuntimeError("OpenRouter client not available. Install with: pip install openrouter")

        try:
            response = await asyncio.wait_for(
                asyncio.to_thread(
                    self._client.chat.completions.create,
                    model=model,
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                ),
                timeout=120
            )
            content = response.choices[0].message.content

            # Track cost
            usage = getattr(response, 'usage', None)
            if usage:
                self.track_cost(model, usage.prompt_tokens, usage.completion_tokens)

            return content
        except Exception as e:
            logger.error(f"Chat error with {model}: {e}")
            raise

    async def chat_with_fallback(
        self,
        messages: List[Dict[str, str]],
        complexity: str = "moderate",
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> str:
        """
        Select model dynamically and send chat request with automatic fallback.
        """
        model = self.select_model(complexity)
        try:
            return await self.chat(model, messages, temperature, max_tokens)
        except Exception as e:
            logger.warning(f"Primary model {model} failed: {e}. Attempting fallback.")
            # Try fallback chain
            cfg = self.models.get(model)
            if cfg:
                for fallback in self.fallback_chains.get(cfg.tier, []):
                    if fallback == model:
                        continue
                    try:
                        return await self.chat(fallback, messages, temperature, max_tokens)
                    except Exception as e2:
                        logger.warning(f"Fallback {fallback} also failed: {e2}")
            raise RuntimeError(f"All models failed for this request. Primary error: {e}")
