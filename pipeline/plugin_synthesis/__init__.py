"""
Plugin Synthesis Agent

Automatically extracts domain invariants from documentation, source history,
and commit messages to generate plugin specifications without manual encoding.
"""

from .plugin_synthesis_agent import (
    PluginSynthesisAgent,
    DomainInvariant,
    PluginSpecification,
    InvariantType,
    InvariantSource
)

__all__ = [
    'PluginSynthesisAgent',
    'DomainInvariant',
    'PluginSpecification',
    'InvariantType',
    'InvariantSource',
]
