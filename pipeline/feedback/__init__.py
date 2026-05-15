"""
Retrospective Feedback Agent for Self-Learning Pipeline

This module implements a feedback loop that learns from missed bugs by parsing CVE patches
and automatically updating agent context/examples for bug classes that were missed.
"""

from .feedback_agent import RetrospectiveFeedbackAgent
from .cve_parser import CVEPatchParser
from .context_updater import AgentContextUpdater
from .false_negative_tracker import FalseNegativeTracker

__all__ = [
    'RetrospectiveFeedbackAgent',
    'CVEPatchParser',
    'AgentContextUpdater',
    'FalseNegativeTracker'
]
