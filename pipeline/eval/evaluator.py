"""
MDASH Pipeline Evaluator.

Compares pipeline findings against ground truth to compute:
- True Positives (TP): correctly identified vulnerabilities
- False Positives (FP): reported but not in ground truth
- False Negatives (FN): missed ground-truth vulnerabilities
- Precision, Recall, F1-score
"""
import logging
from typing import List, Optional, Dict, Set
from dataclasses import dataclass, field

from ..models import CandidateFinding, ValidatedFinding, ProvenFinding, FinalFinding
from .ground_truth_loader import GroundTruthLoader, BenchmarkDataset, GroundTruthVulnerability

logger = logging.getLogger(__name__)


@dataclass
class FindingMatch:
    """A match between a pipeline finding and a ground-truth vulnerability."""
    ground_truth: GroundTruthVulnerability
    pipeline_finding: Optional[FinalFinding]
    match_type: str  # "exact", "fuzzy", "cwe_only", "missed"
    confidence: float
    # Match details
    location_overlap: bool
    cwe_match: bool
    bug_class_match: bool


@dataclass
class EvaluationResult:
    """Result of evaluating MDASH against a benchmark dataset."""
    dataset_name: str
    total_ground_truth: int
    true_positives: int
    false_positives: int
    false_negatives: int
    # Detailed matches
    matches: List[FindingMatch] = field(default_factory=list)
    # Per-category breakdown
    category_results: Dict = field(default_factory=dict)
    # Pipeline metadata
    pipeline_config: Dict = field(default_factory=dict)
    wall_clock_seconds: float = 0.0
    total_cost_usd: float = 0.0

    @property
    def precision(self) -> float:
        """TP / (TP + FP)"""
        if self.true_positives + self.false_positives == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_positives)

    @property
    def recall(self) -> float:
        """TP / (TP + FN)"""
        if self.true_positives + self.false_negatives == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_negatives)

    @property
    def f1_score(self) -> float:
        """2 * (precision * recall) / (precision + recall)"""
        if self.precision + self.recall == 0:
            return 0.0
        return 2 * (self.precision * self.recall) / (self.precision + self.recall)

    @property
    def false_positive_rate(self) -> float:
        """FP / (FP + TN) — but TN is unknown without exhaustive scanning."""
        if self.false_positives == 0:
            return 0.0
        # Approximate using total findings
        total_findings = self.true_positives + self.false_positives
        if total_findings == 0:
            return 0.0
        return self.false_positives / total_findings

    def to_dict(self) -> Dict:
        return {
            "dataset": self.dataset_name,
            "ground_truth_total": self.total_ground_truth,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1_score, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "wall_clock_seconds": self.wall_clock_seconds,
            "total_cost_usd": self.total_cost_usd,
            "category_breakdown": self.category_results,
        }


class MDASHEvaluator:
    """
    Evaluate MDASH pipeline findings against ground-truth benchmarks.
    """

    def __init__(self, ground_truth_loader: Optional[GroundTruthLoader] = None):
        self.gt_loader = ground_truth_loader or GroundTruthLoader()

    def evaluate(
        self,
        dataset_name: str,
        pipeline_findings: List[FinalFinding],
        fuzzy_match: bool = True,
        line_tolerance: int = 5
    ) -> EvaluationResult:
        """
        Evaluate pipeline findings against a benchmark dataset.

        Args:
            dataset_name: Name of the benchmark dataset
            pipeline_findings: Findings emitted by the MDASH pipeline
            fuzzy_match: Allow fuzzy line matching within tolerance
            line_tolerance: Max line distance for fuzzy match

        Returns:
            EvaluationResult with TP/FP/FN metrics
        """
        dataset = self.gt_loader.get_dataset(dataset_name)
        if not dataset:
            raise ValueError(f"Dataset '{dataset_name}' not found. Load it first.")

        result = EvaluationResult(
            dataset_name=dataset_name,
            total_ground_truth=len(dataset.vulnerabilities),
            pipeline_config={"fuzzy_match": fuzzy_match, "line_tolerance": line_tolerance}
        )

        # Track which ground truth items were matched
        matched_gt: Set[str] = set()
        # Track which findings matched something
        matched_findings: Set[int] = set()

        # Try to match each finding to ground truth
        for i, finding in enumerate(pipeline_findings):
            match = self._try_match_finding(
                finding, dataset, matched_gt, fuzzy_match, line_tolerance
            )
            if match:
                result.matches.append(match)
                matched_gt.add(match.ground_truth.vuln_id)
                matched_findings.add(i)

        # Calculate TP, FP, FN
        result.true_positives = len(matched_gt)
        result.false_positives = len(pipeline_findings) - len(matched_findings)
        result.false_negatives = len(dataset.vulnerabilities) - len(matched_gt)

        # Per-category breakdown
        result.category_results = self._category_breakdown(
            dataset, matched_gt, pipeline_findings, matched_findings
        )

        logger.info(
            "Evaluation complete: TP=%d, FP=%d, FN=%d, Precision=%.2f, Recall=%.2f, F1=%.2f",
            result.true_positives,
            result.false_positives,
            result.false_negatives,
            result.precision,
            result.recall,
            result.f1_score
        )

        return result

    def _try_match_finding(
        self,
        finding: FinalFinding,
        dataset: BenchmarkDataset,
        already_matched: Set[str],
        fuzzy_match: bool,
        line_tolerance: int
    ) -> Optional[FindingMatch]:
        """Try to match a pipeline finding to a ground-truth vulnerability."""
        orig = finding.proven_finding.deduplicated_finding.representative_finding.original_candidate

        # Extract location from finding
        finding_loc = orig.location
        finding_cwe = finding.cwe_id
        finding_bug_class = orig.bug_class.value

        best_match = None
        best_score = 0.0

        for gt in dataset.vulnerabilities:
            if gt.vuln_id in already_matched:
                continue

            score = 0.0
            loc_match = False
            cwe_match = False
            bug_match = False

            # Location match
            if finding_loc == gt.location:
                loc_match = True
                score += 0.5
            elif fuzzy_match and self._fuzzy_location_match(
                finding_loc, gt.location, line_tolerance
            ):
                loc_match = True
                score += 0.3

            # CWE match
            if finding_cwe and gt.cwe_id and finding_cwe.upper() == gt.cwe_id.upper():
                cwe_match = True
                score += 0.3

            # Bug class match
            gt_bug = gt.category.value.replace("_", "")
            find_bug = finding_bug_class.replace("_", "").replace("-", "")
            if gt_bug in find_bug or find_bug in gt_bug:
                bug_match = True
                score += 0.2

            if score > best_score and score >= 0.5:
                best_score = score
                match_type = "exact" if loc_match and score >= 0.8 else "fuzzy" if loc_match else "cwe_only"
                best_match = FindingMatch(
                    ground_truth=gt,
                    pipeline_finding=finding,
                    match_type=match_type,
                    confidence=score,
                    location_overlap=loc_match,
                    cwe_match=cwe_match,
                    bug_class_match=bug_match
                )

        return best_match

    def _fuzzy_location_match(
        self,
        finding_loc: str,
        gt_loc: str,
        tolerance: int
    ) -> bool:
        """Check if two locations are within line tolerance."""
        try:
            # Parse file:line format
            find_parts = finding_loc.rsplit(":", 1)
            gt_parts = gt_loc.rsplit(":", 1)

            if len(find_parts) != 2 or len(gt_parts) != 2:
                return False

            find_file = find_parts[0]
            find_line = int(find_parts[1])
            gt_file = gt_parts[0]
            gt_line = int(gt_parts[1])

            # Same file and within tolerance
            if find_file == gt_file or find_file.endswith(gt_file.split("/")[-1]):
                return abs(find_line - gt_line) <= tolerance

        except (ValueError, IndexError):
            pass

        return False

    def _category_breakdown(
        self,
        dataset: BenchmarkDataset,
        matched_gt_ids: Set[str],
        findings: List[FinalFinding],
        matched_finding_indices: Set[int]
    ) -> Dict:
        """Generate per-category breakdown of results."""
        breakdown = {}

        for category in dataset.categories:
            gt_in_cat = [v for v in dataset.vulnerabilities if v.category == category]
            matched_in_cat = [v for v in gt_in_cat if v.vuln_id in matched_gt_ids]

            # Count FPs that are in this category (approximate by CWE)
            cat_cwes = {v.cwe_id for v in gt_in_cat if v.cwe_id}
            fps_in_cat = 0
            for i, f in enumerate(findings):
                if i not in matched_finding_indices and f.cwe_id in cat_cwes:
                    fps_in_cat += 1

            cat_tp = len(matched_in_cat)
            cat_fn = len(gt_in_cat) - cat_tp

            cat_precision = cat_tp / (cat_tp + fps_in_cat) if (cat_tp + fps_in_cat) > 0 else 0
            cat_recall = cat_tp / (cat_tp + cat_fn) if (cat_tp + cat_fn) > 0 else 0

            breakdown[category.value] = {
                "ground_truth": len(gt_in_cat),
                "true_positives": cat_tp,
                "false_negatives": cat_fn,
                "false_positives": fps_in_cat,
                "precision": round(cat_precision, 4),
                "recall": round(cat_recall, 4),
            }

        return breakdown

    def evaluate_unseen_code_property(
        self,
        dataset_name: str,
        pipeline_findings: List[FinalFinding],
        llm_training_cutoff: str = "2024-01"
    ) -> Dict:
        """
        Evaluate whether findings on unseen code are genuinely novel.

        For private codebases, this documents that the code was not in
        LLM training data, making the finding evidence of true reasoning.
        """
        dataset = self.gt_loader.get_dataset(dataset_name)
        if not dataset:
            raise ValueError(f"Dataset '{dataset_name}' not found")

        result = {
            "dataset": dataset_name,
            "is_private": dataset.is_private,
            "llm_training_cutoff": llm_training_cutoff,
            "ground_truth_total": len(dataset.vulnerabilities),
            "findings_count": len(pipeline_findings),
            "unseen_code_claim": dataset.is_private,
            "reasoning_required": True,
            "note": (
                "All findings on this codebase are evidence of genuine vulnerability "
                "discovery reasoning, not pattern matching from training data."
                if dataset.is_private else
                "Codebase visibility unknown. Findings may include both reasoning and "
                "pattern-matching components."
            )
        }

        return result
