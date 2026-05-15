"""
Agent Core with EventEmitter hooks.

Standalone agent class that can run anywhere, with lifecycle hooks for
observability, debugging, and extension. Pattern inspired by the OpenRouter
TypeScript agent skill, adapted to Python idioms.
"""
import asyncio
import logging
import time
from typing import Dict, Any, List, Optional, Callable, Coroutine
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class AgentState(Enum):
    IDLE = "idle"
    RUNNING = "running"
    THINKING = "thinking"
    TOOL_CALL = "tool_call"
    WAITING = "waiting"
    DONE = "done"
    ERROR = "error"


@dataclass
class Message:
    role: str  # 'user' | 'assistant' | 'system' | 'tool'
    content: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)


@dataclass
class ToolCall:
    name: str
    args: Dict[str, Any]
    result: Any = None
    error: Optional[str] = None
    start_ts: float = field(default_factory=time.time)
    end_ts: Optional[float] = None


class Agent:
    """
    Standalone agent core with EventEmitter-style hooks.

    Hooks available:
        - 'message:user'      (message: Message)
        - 'message:assistant' (message: Message)
        - 'stream:start'    ()
        - 'stream:delta'    (delta: str, accumulated: str)
        - 'stream:end'      (full_text: str)
        - 'tool:call'       (name: str, args: dict)
        - 'tool:result'     (name: str, result: any)
        - 'reasoning:update' (text: str)
        - 'thinking:start'  ()
        - 'thinking:end'    ()
        - 'error'           (error: Exception)
        - 'state:change'    (old: AgentState, new: AgentState)
    """

    def __init__(
        self,
        agent_id: str,
        name: str,
        instructions: str,
        model: str,
        tools: Optional[List[Dict]] = None,
        max_steps: int = 10,
        hooks: Optional[Dict[str, List[Callable]]] = None,
    ):
        self.agent_id = agent_id
        self.name = name
        self.instructions = instructions
        self.model = model
        self.tools = tools or []
        self.max_steps = max_steps
        self.messages: List[Message] = []
        self.state = AgentState.IDLE
        self._hooks: Dict[str, List[Callable]] = hooks or {}
        self._tool_registry: Dict[str, Callable] = {}
        self.total_cost_usd = 0.0
        self.step_count = 0

        logger.debug(f"Agent {agent_id} ({name}) initialized with model {model}")

    # -- Hook system --

    def on(self, event: str, callback: Callable):
        """Register a hook for an event."""
        self._hooks.setdefault(event, []).append(callback)
        return self

    def off(self, event: str, callback: Callable):
        """Unregister a hook."""
        if event in self._hooks:
            self._hooks[event] = [c for c in self._hooks[event] if c != callback]
        return self

    def emit(self, event: str, *args, **kwargs):
        """Emit an event to all registered hooks."""
        for cb in self._hooks.get(event, []):
            try:
                if asyncio.iscoroutinefunction(cb):
                    asyncio.create_task(cb(*args, **kwargs))
                else:
                    cb(*args, **kwargs)
            except Exception as e:
                logger.error(f"Hook error for {event}: {e}")

    # -- State management --

    def _set_state(self, new_state: AgentState):
        old = self.state
        self.state = new_state
        self.emit("state:change", old, new_state)

    # -- Conversation --

    def add_message(self, role: str, content: str, metadata: Optional[Dict] = None):
        msg = Message(role=role, content=content, metadata=metadata or {})
        self.messages.append(msg)
        self.emit(f"message:{role}", msg)
        return msg

    def clear_history(self):
        self.messages = []

    def get_messages(self) -> List[Message]:
        return list(self.messages)

    # -- Tool system --

    def register_tool(self, name: str, fn: Callable):
        self._tool_registry[name] = fn

    async def call_tool(self, name: str, args: Dict[str, Any]) -> Any:
        self._set_state(AgentState.TOOL_CALL)
        self.emit("tool:call", name, args)
        call = ToolCall(name=name, args=args)

        fn = self._tool_registry.get(name)
        if fn is None:
            call.error = f"Tool '{name}' not found"
            self.emit("tool:result", name, None)
            self.emit("error", RuntimeError(call.error))
            return None

        try:
            if asyncio.iscoroutinefunction(fn):
                result = await fn(**args)
            else:
                result = fn(**args)
            call.result = result
            call.end_ts = time.time()
            self.emit("tool:result", name, result)
            return result
        except Exception as e:
            call.error = str(e)
            call.end_ts = time.time()
            self.emit("tool:result", name, None)
            self.emit("error", e)
            raise

    # -- Streaming simulation --

    async def stream_response(self, chunks: List[str]):
        """Simulate streaming response from model."""
        self._set_state(AgentState.RUNNING)
        self.emit("stream:start")
        accumulated = ""
        for delta in chunks:
            accumulated += delta
            self.emit("stream:delta", delta, accumulated)
            await asyncio.sleep(0.01)  # simulate latency
        self.emit("stream:end", accumulated)
        self.add_message("assistant", accumulated)
        self._set_state(AgentState.DONE)
        return accumulated

    # -- Core run loop --

    async def run(self, user_input: str) -> str:
        """
        Main agent run loop.

        1. Add user message
        2. Stream assistant response
        3. Parse tool calls from response
        4. Execute tools
        5. Repeat until max_steps or no more tool calls
        """
        self.step_count = 0
        self.add_message("user", user_input)

        while self.step_count < self.max_steps:
            self.step_count += 1
            self._set_state(AgentState.THINKING)
            self.emit("thinking:start")

            # In a real implementation, this would call the model API
            # For now, we simulate a response
            response_text = f"[{self.name}] Processing: {user_input}"
            self.emit("thinking:end")

            # Simulate streaming
            chunks = [response_text[i:i+10] for i in range(0, len(response_text), 10)]
            full_response = await self.stream_response(chunks)

            # Check for tool calls in response (simple parsing)
            tool_calls = self._extract_tool_calls(full_response)
            if not tool_calls:
                break

            for tc in tool_calls:
                await self.call_tool(tc["name"], tc["args"])

        self._set_state(AgentState.DONE)
        return self.messages[-1].content if self.messages else ""

    def _extract_tool_calls(self, text: str) -> List[Dict]:
        """Extract tool calls from assistant response. Override in subclasses."""
        return []

    def __repr__(self):
        return f"<Agent {self.agent_id} {self.name} ({self.state.value})>"
