"""
Agent Pool — Manages 100+ distinct agents with spawn, route, balance, retire.

Spawn agents from config definitions, route tasks by bug class and stage,
balance load across models, and retire agents on budget exhaustion.
"""
import asyncio
import logging
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field

from .agent_core import Agent, AgentState
from .model_router import ModelRouter, ModelTier
from .config import ALL_AGENT_DEFINITIONS, AgentDefinition

logger = logging.getLogger(__name__)


@dataclass
class AgentInstance:
    """Runtime instance of a registered agent."""
    definition: AgentDefinition
    agent: Agent
    task_count: int = 0
    total_cost: float = 0.0
    active: bool = True
    last_used: float = 0.0


class AgentPool:
    """
    Pool of 100+ specialized agents.

    Responsibilities:
    - Spawn agents from AgentDefinition configs
    - Route tasks to the best agent by bug class / stage
    - Balance load across models (respect budget)
    - Retire agents when budget exhausted
    - Track agent metrics
    """

    def __init__(self, model_router: ModelRouter, max_concurrent: int = 50):
        self.model_router = model_router
        self.max_concurrent = max_concurrent
        self._agents: Dict[str, AgentInstance] = {}
        self._stage_index: Dict[str, List[str]] = {
            "prepare": [],
            "scan": [],
            "validate": [],
            "dedup": [],
            "prove": [],
            "enrich": [],
            "triage": [],
        }
        self._bug_class_index: Dict[str, List[str]] = {}
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._spawn_lock = asyncio.Lock()

        logger.info(f"AgentPool initialized (max_concurrent={max_concurrent})")

    async def spawn_all(self):
        """Spawn all agents from config definitions."""
        logger.info(f"Spawning {len(ALL_AGENT_DEFINITIONS)} agents...")
        tasks = []
        for defn in ALL_AGENT_DEFINITIONS.values():
            tasks.append(self._spawn_single(defn))
        await asyncio.gather(*tasks, return_exceptions=True)
        logger.info(f"Spawned {len(self._agents)} agents successfully")

    async def _spawn_single(self, defn: AgentDefinition):
        """Spawn a single agent from its definition."""
        async with self._spawn_lock:
            # Select model dynamically
            model_id = self.model_router.select_model(
                task_complexity=defn.complexity,
                required_capabilities=defn.capabilities,
                preferred_model=defn.model_preference,
            )

            agent = Agent(
                agent_id=defn.agent_id,
                name=defn.name,
                instructions=defn.instructions,
                model=model_id,
                tools=[{"name": t} for t in defn.tools],
                max_steps=defn.max_steps,
            )

            instance = AgentInstance(
                definition=defn,
                agent=agent,
            )

            self._agents[defn.agent_id] = instance
            self._stage_index.setdefault(defn.stage, []).append(defn.agent_id)

            for bc in defn.bug_classes:
                self._bug_class_index.setdefault(bc, []).append(defn.agent_id)

            logger.debug(f"Spawned {defn.agent_id}: {defn.name} (model={model_id})")

    def _has_budget(self, instance: AgentInstance) -> bool:
        """Check if an agent's model has remaining budget."""
        cfg = self.model_router.models.get(instance.agent.model)
        if not cfg:
            return True  # Unknown model, allow by default
        return self.model_router._can_afford(cfg)

    def get_agent(self, agent_id: str) -> Optional[AgentInstance]:
        """Get an agent instance by ID."""
        return self._agents.get(agent_id)

    def get_agents_by_stage(self, stage: str) -> List[AgentInstance]:
        """Get all agents for a pipeline stage."""
        ids = self._stage_index.get(stage, [])
        return [self._agents[i] for i in ids if i in self._agents]

    def get_agents_by_bug_class(self, bug_class: str) -> List[AgentInstance]:
        """Get all agents that handle a specific bug class."""
        ids = self._bug_class_index.get(bug_class, [])
        return [self._agents[i] for i in ids if i in self._agents]

    def route_task(
        self,
        task: Dict[str, Any],
        stage: Optional[str] = None,
        bug_class: Optional[str] = None,
    ) -> Optional[AgentInstance]:
        """
        Route a task to the best available agent.

        Priority:
        1. Exact bug class match
        2. Stage match
        3. Least loaded active agent
        """
        candidates = []

        if bug_class and bug_class in self._bug_class_index:
            candidates = self.get_agents_by_bug_class(bug_class)
        elif stage and stage in self._stage_index:
            candidates = self.get_agents_by_stage(stage)

        if not candidates:
            # Fallback: any active agent
            candidates = [a for a in self._agents.values() if a.active]

        # Filter active agents with budget remaining
        candidates = [
            c for c in candidates
            if c.active and self._has_budget(c)
        ]

        if not candidates:
            logger.warning("No available agents with budget remaining")
            return None

        # Select least loaded
        best = min(candidates, key=lambda a: a.task_count)
        return best

    async def execute_task(
        self,
        agent_id: str,
        task_input: str,
        timeout: float = 120.0,
    ) -> Dict[str, Any]:
        """
        Execute a task on a specific agent with concurrency control.
        """
        instance = self._agents.get(agent_id)
        if not instance:
            raise ValueError(f"Agent {agent_id} not found")

        if not instance.active:
            raise RuntimeError(f"Agent {agent_id} is retired")

        async with self._semaphore:
            instance.task_count += 1
            instance.last_used = asyncio.get_event_loop().time()

            try:
                result = await asyncio.wait_for(
                    instance.agent.run(task_input),
                    timeout=timeout,
                )

                # Track cost
                # (In real implementation, track from model response)
                instance.total_cost += 0.01  # placeholder

                return {
                    "agent_id": agent_id,
                    "agent_name": instance.agent.name,
                    "result": result,
                    "task_count": instance.task_count,
                    "state": instance.agent.state.value,
                }

            except asyncio.TimeoutError:
                logger.error(f"Agent {agent_id} timed out after {timeout}s")
                instance.agent._set_state(AgentState.ERROR)
                raise
            except Exception as e:
                logger.error(f"Agent {agent_id} error: {e}")
                instance.agent._set_state(AgentState.ERROR)
                raise

    def retire_agent(self, agent_id: str):
        """Retire an agent (budget exhausted or no longer needed)."""
        instance = self._agents.get(agent_id)
        if instance:
            instance.active = False
            instance.agent._set_state(AgentState.DONE)
            logger.info(f"Retired agent {agent_id}: {instance.agent.name}")

    def retire_by_budget(self):
        """Retire agents when pool budget is exhausted."""
        status = self.model_router.get_budget_status()
        if status["remaining_usd"] <= 0:
            logger.warning("Budget exhausted! Retiring non-critical agents.")
            for aid, inst in self._agents.items():
                if inst.definition.stage in ("scan", "dedup"):
                    self.retire_agent(aid)

    def get_metrics(self) -> Dict[str, Any]:
        """Get pool metrics."""
        active = sum(1 for a in self._agents.values() if a.active)
        total_tasks = sum(a.task_count for a in self._agents.values())
        total_cost = sum(a.total_cost for a in self._agents.values())

        stage_counts = {}
        for stage, ids in self._stage_index.items():
            stage_counts[stage] = sum(
                1 for i in ids
                if i in self._agents and self._agents[i].active
            )

        return {
            "total_agents": len(self._agents),
            "active_agents": active,
            "retired_agents": len(self._agents) - active,
            "total_tasks": total_tasks,
            "total_cost": total_cost,
            "budget_status": self.model_router.get_budget_status(),
            "stage_distribution": stage_counts,
        }

    def __len__(self):
        return len(self._agents)

    def __repr__(self):
        active = sum(1 for a in self._agents.values() if a.active)
        return f"<AgentPool {active}/{len(self._agents)} active>"
