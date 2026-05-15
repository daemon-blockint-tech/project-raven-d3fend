"""
Dedup stage: Collapse semantically equivalent findings.
"""
from .embedding_generator import EmbeddingGenerator
from .similarity import SimilarityCalculator
from .clustering import ClusteringEngine
from .merger import FindingMerger

__all__ = [
    "EmbeddingGenerator",
    "SimilarityCalculator",
    "ClusteringEngine",
    "FindingMerger"
]
