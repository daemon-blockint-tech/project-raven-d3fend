"""
Finding collector for the Scan stage - collects and deduplicates candidate findings.
"""
from typing import List, Dict, Any
import logging
import hashlib

from ..models import CandidateFinding

logger = logging.getLogger(__name__)


class FindingCollector:
    """Collect and manage candidate findings from specialized agents."""
    
    def __init__(self):
        """Initialize finding collector."""
        self.findings: List[CandidateFinding] = []
        logger.info("FindingCollector initialized")
    
    def add_finding(self, finding: CandidateFinding):
        """
        Add a candidate finding.
        
        Args:
            finding: CandidateFinding object
        """
        self.findings.append(finding)
        logger.debug(f"Added finding: {finding.id} ({finding.bug_class.value})")
    
    def add_findings(self, findings: List[CandidateFinding]):
        """
        Add multiple candidate findings.
        
        Args:
            findings: List of CandidateFinding objects
        """
        self.findings.extend(findings)
        logger.info(f"Added {len(findings)} findings")
    
    def get_findings(self) -> List[CandidateFinding]:
        """Get all collected findings."""
        return self.findings
    
    def get_findings_by_bug_class(self, bug_class: str) -> List[CandidateFinding]:
        """
        Get findings filtered by bug class.
        
        Args:
            bug_class: Bug class name
            
        Returns:
            Filtered list of findings
        """
        return [f for f in self.findings if f.bug_class.value == bug_class]
    
    def get_findings_by_location(self, location: str) -> List[CandidateFinding]:
        """
        Get findings filtered by location.
        
        Args:
            location: Location string
            
        Returns:
            Filtered list of findings
        """
        return [f for f in self.findings if f.location == location]
    
    def deduplicate_by_location(self) -> List[CandidateFinding]:
        """
        Deduplicate findings by location (keep highest confidence).
        
        Returns:
            Deduplicated list of findings
        """
        location_map: Dict[str, CandidateFinding] = {}
        
        for finding in self.findings:
            if finding.location not in location_map:
                location_map[finding.location] = finding
            else:
                # Keep finding with higher hypothesis score
                if finding.hypothesis_score > location_map[finding.location].hypothesis_score:
                    location_map[finding.location] = finding
        
        deduplicated = list(location_map.values())
        logger.info(f"Deduplicated {len(self.findings)} findings to {len(deduplicated)}")
        
        return deduplicated
    
    def filter_by_score_threshold(self, threshold: float = 0.5) -> List[CandidateFinding]:
        """
        Filter findings by hypothesis score threshold.
        
        Args:
            threshold: Minimum score threshold
            
        Returns:
            Filtered list of findings
        """
        filtered = [f for f in self.findings if f.hypothesis_score >= threshold]
        logger.info(f"Filtered {len(self.findings)} findings to {len(filtered)} with score >= {threshold}")
        
        return filtered
    
    def sort_by_score(self, descending: bool = True) -> List[CandidateFinding]:
        """
        Sort findings by hypothesis score.
        
        Args:
            descending: Sort in descending order (highest first)
            
        Returns:
            Sorted list of findings
        """
        return sorted(
            self.findings,
            key=lambda f: f.hypothesis_score,
            reverse=descending
        )
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get summary statistics of collected findings.
        
        Returns:
            Dictionary with summary statistics
        """
        bug_class_counts: Dict[str, int] = {}
        
        for finding in self.findings:
            bug_class = finding.bug_class.value
            bug_class_counts[bug_class] = bug_class_counts.get(bug_class, 0) + 1
        
        avg_score = sum(f.hypothesis_score for f in self.findings) / len(self.findings) if self.findings else 0.0
        
        return {
            "total_findings": len(self.findings),
            "bug_class_distribution": bug_class_counts,
            "average_score": avg_score,
            "highest_score": max((f.hypothesis_score for f in self.findings), default=0.0),
            "lowest_score": min((f.hypothesis_score for f in self.findings), default=0.0)
        }
    
    def clear(self):
        """Clear all findings."""
        self.findings = []
        logger.info("Findings cleared")
