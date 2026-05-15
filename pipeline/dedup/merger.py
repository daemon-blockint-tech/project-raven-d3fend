"""
Finding merger for the Dedup stage - merges semantically equivalent findings.
"""
from typing import List, Dict, Any
import logging
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ..models import ValidatedFinding, DeduplicatedFinding

logger = logging.getLogger(__name__)


class FindingMerger:
    """Merge semantically equivalent findings into deduplicated findings."""
    
    def __init__(self):
        """Initialize finding merger."""
        logger.info("FindingMerger initialized")
    
    def merge_findings(
        self,
        validated_findings: List[ValidatedFinding],
        cluster_labels: List[int],
        cluster_representatives: Dict[str, Any]
    ) -> List[DeduplicatedFinding]:
        """
        Merge findings based on clustering results.
        
        Args:
            validated_findings: List of validated findings
            cluster_labels: Cluster labels for each finding
            cluster_representatives: Representative info for each cluster
            
        Returns:
            List of deduplicated findings
        """
        deduplicated_findings = []
        
        for cluster_id, rep_info in cluster_representatives.items():
            rep_index = rep_info["index"]
            cluster_indices = rep_info["cluster_indices"]
            
            # Get representative finding
            representative = validated_findings[rep_index]
            
            # Get merged finding IDs
            merged_ids = [
                validated_findings[i].id
                for i in cluster_indices
            ]
            
            # Calculate similarity scores (use confidence as proxy)
            similarity_scores = [
                validated_findings[i].confidence
                for i in cluster_indices
            ]
            
            # Create deduplicated finding
            dedup_finding = DeduplicatedFinding(
                id=f"D-{representative.id}",
                cluster_id=cluster_id,
                cluster_size=len(cluster_indices),
                representative_finding=representative,
                merged_findings=merged_ids,
                similarity_scores=similarity_scores,
                embedding_model="text-embedding-3-small"
            )
            
            deduplicated_findings.append(dedup_finding)
        
        # Handle noise points (findings not in any cluster)
        noise_indices = [i for i, label in enumerate(cluster_labels) if label == -1]
        for index in noise_indices:
            finding = validated_findings[index]
            # Create singleton cluster for noise points
            dedup_finding = DeduplicatedFinding(
                id=f"D-{finding.id}",
                cluster_id=f"noise-{index}",
                cluster_size=1,
                representative_finding=finding,
                merged_findings=[finding.id],
                similarity_scores=[finding.confidence],
                embedding_model="text-embedding-3-small"
            )
            deduplicated_findings.append(dedup_finding)
        
        logger.info(f"Merged {len(validated_findings)} findings into {len(deduplicated_findings)} deduplicated findings")
        return deduplicated_findings
    
    def merge_by_location(
        self,
        validated_findings: List[ValidatedFinding]
    ) -> List[DeduplicatedFinding]:
        """
        Merge findings by location (simple deduplication strategy).
        
        Args:
            validated_findings: List of validated findings
            
        Returns:
            List of deduplicated findings
        """
        location_map: Dict[str, List[ValidatedFinding]] = {}
        
        # Group by location
        for finding in validated_findings:
            location = finding.original_candidate.location
            if location not in location_map:
                location_map[location] = []
            location_map[location].append(finding)
        
        deduplicated_findings = []
        
        for cluster_id, (location, findings) in enumerate(location_map.items()):
            # Select representative (highest confidence)
            representative = max(findings, key=lambda f: f.confidence)
            
            merged_ids = [f.id for f in findings]
            similarity_scores = [f.confidence for f in findings]
            
            dedup_finding = DeduplicatedFinding(
                id=f"D-{representative.id}",
                cluster_id=str(cluster_id),
                cluster_size=len(findings),
                representative_finding=representative,
                merged_findings=merged_ids,
                similarity_scores=similarity_scores,
                embedding_model="location-based"
            )
            
            deduplicated_findings.append(dedup_finding)
        
        logger.info(f"Merged {len(validated_findings)} findings by location into {len(deduplicated_findings)} deduplicated findings")
        return deduplicated_findings
