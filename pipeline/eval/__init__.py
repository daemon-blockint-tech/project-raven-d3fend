"""
Evaluation framework for the MDASH pipeline.

Measures true positives, false positives, and false negatives
against benchmark datasets with known ground-truth vulnerabilities.
"""
from .ground_truth_loader import GroundTruthLoader, BenchmarkDataset
from .evaluator import MDASHEvaluator, EvaluationResult
from .report_generator import EvaluationReportGenerator

__all__ = [
    "GroundTruthLoader",
    "BenchmarkDataset",
    "MDASHEvaluator",
    "EvaluationResult",
    "EvaluationReportGenerator",
]
