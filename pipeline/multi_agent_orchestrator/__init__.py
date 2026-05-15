"""
Multi-Agent Orchestrator for MDASH Pipeline.

Coordinates 100+ specialized agents across 7 pipeline stages using
multi-model ensemble with dynamic model allocation.

Exports:
    MultiAgentOrchestrator — Main pipeline orchestrator
    AgentPool — Manages 100+ agent instances
    Agent — Standalone agent core with hooks
    ModelRouter — Dynamic multi-model routing
    DebatePanel — Multi-model debate validation
    EnricherAgent — D3FEND + ATT&CK enrichment
    TriageAgent — DevSecOps triage and routing
    PipelineLogger — Structured logging
    MetricsCollector — Agent execution metrics
"""
from .agent_core import Agent, AgentState, Message, ToolCall
from .agent_pool import AgentPool, AgentInstance
from .model_router import ModelRouter, ModelTier, ModelConfig
from .debate_panel import DebatePanel, DebateResult, DebateVote
from .enricher_agent import EnricherAgent, EnrichmentResult
from .triage_agent import TriageAgent, TriageResult
from .orchestrator import MultiAgentOrchestrator, PipelineReport
from .hooks import PipelineLogger, MetricsCollector, attach_default_hooks, DefaultHooks
from .config import ALL_AGENT_DEFINITIONS, AgentDefinition, AGENT_COUNT, STAGE_COUNTS

__all__ = [
    # Core
    "Agent",
    "AgentState",
    "Message",
    "ToolCall",
    # Pool
    "AgentPool",
    "AgentInstance",
    # Routing
    "ModelRouter",
    "ModelTier",
    "ModelConfig",
    # Validation
    "DebatePanel",
    "DebateResult",
    "DebateVote",
    # Enrichment
    "EnricherAgent",
    "EnrichmentResult",
    # Triage
    "TriageAgent",
    "TriageResult",
    # Orchestration
    "MultiAgentOrchestrator",
    "PipelineReport",
    # Observability
    "PipelineLogger",
    "MetricsCollector",
    "attach_default_hooks",
    "DefaultHooks",
    # Config
    "ALL_AGENT_DEFINITIONS",
    "AgentDefinition",
    "AGENT_COUNT",
    "STAGE_COUNTS",
]

__version__ = "0.1.0"
