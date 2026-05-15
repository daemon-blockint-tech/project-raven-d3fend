"""
OpenAI Agents SDK adapter for the MDASH pipeline.

This module provides an optional integration layer between the MDASH pipeline
and the OpenAI Agents SDK, enabling:
- Production-grade agent orchestration with structured definitions
- Built-in tracing and session management
- Human-in-the-loop support
- Provider-agnostic LLM backends

Usage:
    from pipeline.openai_agents_adapter import MDASHAgentsRunner
    runner = MDASHAgentsRunner(config)
    findings = runner.run_pipeline(target="/path/to/code")
"""
from .auditor_agent import AuditorAgent
from .debater_agent import DebaterAgent
from .pipeline_runner import MDASHAgentsRunner, PipelineConfig

__all__ = [
    "AuditorAgent",
    "DebaterAgent",
    "MDASHAgentsRunner",
    "PipelineConfig",
]
