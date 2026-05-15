"""
Prepare stage: Ingest source target, build language-aware indices, generate threat models.
"""
from .ingester import CodebaseIngester
from .indexer import LanguageIndexer
from .threat_modeler import ThreatModeler
from .git_analyzer import GitAnalyzer

__all__ = [
    "CodebaseIngester",
    "LanguageIndexer",
    "ThreatModeler",
    "GitAnalyzer"
]
