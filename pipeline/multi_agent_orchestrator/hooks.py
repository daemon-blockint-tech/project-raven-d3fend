"""
Lifecycle hooks for observability, logging, metrics, and debugging.

Provides default hook implementations that can be attached to any Agent.
"""
import logging
import time
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

from .agent_core import Message, AgentState

logger = logging.getLogger(__name__)


@dataclass
class HookMetrics:
    """Metrics collected by hooks."""
    message_count: int = 0
    tool_call_count: int = 0
    tool_error_count: int = 0
    stream_deltas: int = 0
    total_stream_chars: int = 0
    thinking_time_ms: float = 0.0
    state_changes: List[Dict] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)

    @property
    def wall_time_ms(self) -> float:
        return (time.time() - self.start_time) * 1000


class DefaultHooks:
    """Default hook implementations for production observability."""

    @staticmethod
    def on_message_user(msg: Message):
        logger.info(f"[USER] {msg.content[:80]}...")

    @staticmethod
    def on_message_assistant(msg: Message):
        logger.info(f"[ASSISTANT] {msg.content[:80]}...")

    @staticmethod
    def on_stream_start():
        logger.debug("Stream started")

    @staticmethod
    def on_stream_delta(delta: str, accumulated: str):
        logger.debug(f"Stream delta: {len(delta)} chars (total: {len(accumulated)})")

    @staticmethod
    def on_stream_end(full_text: str):
        logger.info(f"Stream ended: {len(full_text)} chars")

    @staticmethod
    def on_tool_call(name: str, args: Any):
        logger.info(f"Tool call: {name}({args})")

    @staticmethod
    def on_tool_result(name: str, result: Any):
        logger.info(f"Tool result: {name} -> {str(result)[:80]}")

    @staticmethod
    def on_thinking_start():
        logger.debug("Thinking started")

    @staticmethod
    def on_thinking_end():
        logger.debug("Thinking ended")

    @staticmethod
    def on_reasoning_update(text: str):
        logger.debug(f"Reasoning: {text[:100]}...")

    @staticmethod
    def on_error(error: Exception):
        logger.error(f"Agent error: {error}", exc_info=True)

    @staticmethod
    def on_state_change(old: AgentState, new: AgentState):
        logger.debug(f"State: {old.value} -> {new.value}")


class MetricsCollector:
    """Collects detailed metrics from agent execution."""

    def __init__(self):
        self.metrics: Dict[str, HookMetrics] = {}

    def attach(self, agent_id: str, agent):
        """Attach metrics hooks to an agent."""
        self.metrics[agent_id] = HookMetrics()
        m = self.metrics[agent_id]

        def on_msg(msg: Message):
            m.message_count += 1

        def on_stream_delta(delta: str, accumulated: str):
            m.stream_deltas += 1
            m.total_stream_chars = len(accumulated)

        def on_tool_call(name: str, args: Any):
            m.tool_call_count += 1

        def on_tool_result(name: str, result: Any):
            if result is None:
                m.tool_error_count += 1

        def on_error(error: Exception):
            m.errors.append(str(error))

        def on_state_change(old: AgentState, new: AgentState):
            m.state_changes.append({
                "old": old.value,
                "new": new.value,
                "ts": time.time(),
            })

        agent.on("message:user", on_msg)
        agent.on("message:assistant", on_msg)
        agent.on("stream:delta", on_stream_delta)
        agent.on("tool:call", on_tool_call)
        agent.on("tool:result", on_tool_result)
        agent.on("error", on_error)
        agent.on("state:change", on_state_change)

    def get_metrics(self, agent_id: str) -> Optional[HookMetrics]:
        return self.metrics.get(agent_id)

    def get_all_metrics(self) -> Dict[str, Any]:
        return {
            aid: {
                "message_count": m.message_count,
                "tool_calls": m.tool_call_count,
                "tool_errors": m.tool_error_count,
                "stream_deltas": m.stream_deltas,
                "stream_chars": m.total_stream_chars,
                "wall_time_ms": m.wall_time_ms,
                "state_changes": len(m.state_changes),
                "errors": len(m.errors),
            }
            for aid, m in self.metrics.items()
        }


class PipelineLogger:
    """Structured logging for pipeline stages."""

    @staticmethod
    def log_stage_start(stage: str, finding_count: int = 0):
        logger.info(f"=== STAGE START: {stage} ({finding_count} findings) ===")

    @staticmethod
    def log_stage_end(stage: str, result_count: int, wall_time_ms: float):
        logger.info(f"=== STAGE END: {stage} ({result_count} results, {wall_time_ms:.0f}ms) ===")

    @staticmethod
    def log_agent_spawn(agent_id: str, name: str, model: str, stage: str):
        logger.info(f"AGENT SPAWN: {agent_id} | {name} | model={model} | stage={stage}")

    @staticmethod
    def log_agent_complete(agent_id: str, task_count: int, cost: float):
        logger.info(f"AGENT DONE: {agent_id} | tasks={task_count} | cost=${cost:.4f}")

    @staticmethod
    def log_finding(finding_id: str, bug_class: str, severity: str, confidence: float):
        logger.info(f"FINDING: {finding_id} | {bug_class} | {severity} | confidence={confidence:.2f}")

    @staticmethod
    def log_budget_warning(remaining: float, spent: float):
        logger.warning(f"BUDGET: ${spent:.2f} spent, ${remaining:.2f} remaining")


# Convenience function to attach all default hooks
def attach_default_hooks(agent):
    """Attach all default production hooks to an agent."""
    h = DefaultHooks
    agent.on("message:user", h.on_message_user)
    agent.on("message:assistant", h.on_message_assistant)
    agent.on("stream:start", h.on_stream_start)
    agent.on("stream:delta", h.on_stream_delta)
    agent.on("stream:end", h.on_stream_end)
    agent.on("tool:call", h.on_tool_call)
    agent.on("tool:result", h.on_tool_result)
    agent.on("thinking:start", h.on_thinking_start)
    agent.on("thinking:end", h.on_thinking_end)
    agent.on("reasoning:update", h.on_reasoning_update)
    agent.on("error", h.on_error)
    agent.on("state:change", h.on_state_change)
