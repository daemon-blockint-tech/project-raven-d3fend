"""
Clustering engine for the Dedup stage - clusters similar findings together.
"""
from typing import List, Dict, Any, Optional
import logging
import numpy as np
from sklearn.cluster import DBSCAN, AgglomerativeClustering
from sklearn.metrics import silhouette_score

logger = logging.getLogger(__name__)


class ClusteringEngine:
    """Cluster findings based on semantic similarity."""
    
    def __init__(
        self,
        algorithm: str = "dbscan",
        eps: float = 0.5,
        min_samples: int = 2,
        similarity_threshold: float = 0.85
    ):
        """
        Initialize clustering engine.
        
        Args:
            algorithm: Clustering algorithm (dbscan, agglomerative)
            eps: Epsilon parameter for DBSCAN
            min_samples: Minimum samples for DBSCAN
            similarity_threshold: Threshold for considering findings in same cluster
        """
        self.algorithm = algorithm
        self.eps = eps
        self.min_samples = min_samples
        self.similarity_threshold = similarity_threshold
        logger.info(f"ClusteringEngine initialized with {algorithm} algorithm")
    
    def cluster_findings(
        self,
        embeddings: List[List[float]],
        similarity_matrix: Optional[np.ndarray] = None
    ) -> Dict[str, Any]:
        """
        Cluster findings based on embeddings or similarity matrix.
        
        Args:
            embeddings: List of embedding vectors
            similarity_matrix: Optional pre-computed similarity matrix
            
        Returns:
            Dictionary with clustering results
        """
        if not embeddings:
            return {
                "cluster_labels": [],
                "n_clusters": 0,
                "cluster_sizes": {}
            }
        
        # Convert to distance matrix (1 - similarity)
        if similarity_matrix is None:
            from sklearn.metrics.pairwise import cosine_similarity
            embeddings_array = np.array(embeddings)
            similarity_matrix = cosine_similarity(embeddings_array)
        
        distance_matrix = 1 - similarity_matrix
        
        # Apply clustering algorithm
        if self.algorithm == "dbscan":
            labels = self._dbscan_cluster(distance_matrix)
        elif self.algorithm == "agglomerative":
            labels = self._agglomerative_cluster(distance_matrix)
        else:
            logger.warning(f"Unknown algorithm {self.algorithm}, using DBSCAN")
            labels = self._dbscan_cluster(distance_matrix)
        
        # Analyze clusters
        unique_labels = set(labels)
        n_clusters = len(unique_labels) - (1 if -1 in labels else 0)
        
        cluster_sizes = {}
        for label in unique_labels:
            if label != -1:  # Ignore noise points
                cluster_sizes[str(label)] = list(labels).count(label)
        
        logger.info(f"Clustering complete: {n_clusters} clusters identified")
        
        return {
            "cluster_labels": labels,
            "n_clusters": n_clusters,
            "cluster_sizes": cluster_sizes,
            "noise_points": list(labels).count(-1)
        }
    
    def _dbscan_cluster(self, distance_matrix: np.ndarray) -> List[int]:
        """Perform DBSCAN clustering on distance matrix."""
        clustering = DBSCAN(
            eps=self.eps,
            min_samples=self.min_samples,
            metric="precomputed"
        )
        
        labels = clustering.fit_predict(distance_matrix)
        return labels.tolist()
    
    def _agglomerative_cluster(self, distance_matrix: np.ndarray) -> List[int]:
        """Perform agglomerative clustering on distance matrix."""
        # Estimate number of clusters from similarity threshold
        n_samples = len(distance_matrix)
        n_clusters = max(1, int(n_samples * (1 - self.similarity_threshold)))
        
        clustering = AgglomerativeClustering(
            n_clusters=n_clusters,
            affinity="precomputed",
            linkage="average"
        )
        
        labels = clustering.fit_predict(distance_matrix)
        return labels.tolist()
    
    def get_cluster_representatives(
        self,
        labels: List[int],
        embeddings: List[List[float]],
        original_findings: List[Any]
    ) -> Dict[str, Any]:
        """
        Get representative finding for each cluster.
        
        Args:
            labels: Cluster labels
            embeddings: Embedding vectors
            original_findings: Original finding objects
            
        Returns:
            Dictionary mapping cluster IDs to representative findings
        """
        representatives = {}
        unique_labels = set(labels)
        
        for label in unique_labels:
            if label == -1:
                continue  # Skip noise points
            
            # Get indices of findings in this cluster
            cluster_indices = [i for i, l in enumerate(labels) if l == label]
            
            if not cluster_indices:
                continue
            
            # Select representative (first finding in cluster)
            rep_index = cluster_indices[0]
            representatives[str(label)] = {
                "index": rep_index,
                "cluster_size": len(cluster_indices),
                "finding": original_findings[rep_index],
                "cluster_indices": cluster_indices
            }
        
        return representatives
