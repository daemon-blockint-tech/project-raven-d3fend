"""
D3FEND ontology client for the pipeline - queries D3FEND OWL ontology.
"""
from typing import Dict, List, Any, Optional
import logging
import json
from pathlib import Path

logger = logging.getLogger(__name__)


class D3FENDOntologyClient:
    """Client for querying D3FEND OWL ontology."""
    
    def __init__(self, owl_file_path: Optional[str] = None):
        """
        Initialize D3FEND ontology client.
        
        Args:
            owl_file_path: Path to D3FEND OWL ontology file (optional)
        """
        self.owl_file_path = owl_file_path
        self.ontology_data = {}
        
        if owl_file_path and Path(owl_file_path).exists():
            self._load_ontology(owl_file_path)
        else:
            logger.warning("D3FEND OWL ontology file not found, using fallback data")
            self._load_fallback_data()
        
        logger.info("D3FENDOntologyClient initialized")
    
    def _load_ontology(self, owl_file_path: str):
        """Load D3FEND OWL ontology from file."""
        try:
            # In production, this would use an actual SPARQL endpoint (Oxigraph)
            # For now, load simplified JSON representation
            json_path = Path(owl_file_path).with_suffix(".json")
            
            if json_path.exists():
                with open(json_path, 'r') as f:
                    self.ontology_data = json.load(f)
                logger.info(f"Loaded D3FEND ontology from {json_path}")
            else:
                self._load_fallback_data()
        
        except Exception as e:
            logger.error(f"Failed to load D3FEND ontology: {e}")
            self._load_fallback_data()
    
    def _load_fallback_data(self):
        """Load fallback D3FEND data."""
        # Simplified D3FEND data structure
        self.ontology_data = {
            "techniques": {
                "D3-ATA": {
                    "label": "Attack Surface Reduction",
                    "tactic": "Detect",
                    "description": "Reduce the attack surface by minimizing exposed interfaces"
                },
                "D3-ATP": {
                    "label": "Attack Technical Prevention",
                    "tactic": "Detect",
                    "description": "Prevent attacks through technical controls"
                },
                "D3-AIP": {
                    "label": "Attack Isolation and Preparation",
                    "tactic": "Detect",
                    "description": "Isolate attack vectors and prepare defenses"
                },
                "D3-MSA": {
                    "label": "Malicious Software Analysis",
                    "tactic": "Detect",
                    "description": "Analyze malicious software for indicators"
                },
                "D3-MSI": {
                    "label": "Malicious Software Investigation",
                    "tactic": "Detect",
                    "description": "Investigate malicious software incidents"
                },
                "D3-DCR": {
                    "label": "Decoy Corruption",
                    "tactic": "Deceive",
                    "description": "Corrupt decoy resources to detect attacker interaction"
                },
                "D3-DCS": {
                    "label": "Decoy Compromise",
                    "tactic": "Deceive",
                    "description": "Compromise decoy resources to detect attacker interaction"
                },
                "D3-RC": {
                    "label": "Restore Components",
                    "tactic": "Restore",
                    "description": "Restore compromised components from backups"
                },
                "D3-RF": {
                    "label": "Restore Functions",
                    "tactic": "Restore",
                    "description": "Restore compromised functions to operational state"
                },
                "D3-RA": {
                    "label": "Restore Access",
                    "tactic": "Restore",
                    "description": "Restore access to compromised accounts"
                },
                "D3-RD": {
                    "label": "Restore Data",
                    "tactic": "Restore",
                    "description": "Restore corrupted data from backups"
                },
                "D3-RDI": {
                    "label": "Restore Data Integrity",
                    "tactic": "Restore",
                    "description": "Verify and restore data integrity"
                },
                "D3-RNA": {
                    "label": "Restore Network Access",
                    "tactic": "Restore",
                    "description": "Restore network access after incident"
                },
                "D3-RO": {
                    "label": "Restore Operations",
                    "tactic": "Restore",
                    "description": "Restore operational capabilities"
                },
                "D3-RS": {
                    "label": "Restore Services",
                    "tactic": "Restore",
                    "description": "Restore affected services to normal operation"
                },
                "D3-RUAA": {
                    "label": "Restore User Account Access",
                    "tactic": "Restore",
                    "description": "Restore user account access after incident"
                },
                "D3-ULA": {
                    "label": "Use Limiting Authentication",
                    "tactic": "Detect",
                    "description": "Limit authentication attempts to prevent brute force"
                },
                "D3-RIC": {
                    "label": "Restore Incident Containment",
                    "tactic": "Restore",
                    "description": "Contain incident and prevent spread"
                },
                "D3-CRO": {
                    "label": "Containment Response Orchestration",
                    "tactic": "Restore",
                    "description": "Orchestrate containment response"
                },
                "D3-CERO": {
                    "label": "Containment Eradication and Remediation",
                    "tactic": "Restore",
                    "description": "Eradicate threat and remediate affected systems"
                }
            },
            "cwe_mappings": {
                "CWE-119": ["D3-ATA", "D3-ATP", "D3-AIP"],
                "CWE-120": ["D3-MSA", "D3-MSI"],
                "CWE-125": ["D3-MSI", "D3-MSA"],
                "CWE-787": ["D3-MSI", "D3-MSA"],
                "CWE-190": ["D3-MSI", "D3-MSA"],
                "CWE-362": ["D3-ATA", "D3-ATP"],
                "CWE-367": ["D3-ATA", "D3-ATP"],
                "CWE-20": ["D3-ATA", "D3-ATP"],
                "CWE-79": ["D3-ATA", "D3-ATP"],
                "CWE-89": ["D3-ATA", "D3-ATP"],
                "CWE-352": ["D3-ATA", "D-ATP"],
                "CWE-400": ["D-ATA", "D-ATP"],
                "CWE-502": ["D-ATA", "D-ATP"],
                "CWE-287": ["D-ATA", "D-ATP"],
                "CWE-476": ["D3-DCR", "D3-DCS"],
                "CWE-502": ["D3-DCR", "D-DCS"],
                "CWE-522": ["D3-DCR", "D3-DCS"],
            }
        }
    
    def query_technique(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """
        Query a specific D3FEND technique.
        
        Args:
            technique_id: D3FEND technique ID (e.g., "D3-ATA")
            
        Returns:
            Technique dictionary or None if not found
        """
        return self.ontology_data.get("techniques", {}).get(technique_id)
    
    def query_cwe_techniques(self, cwe_id: str) -> List[Dict[str, Any]]:
        """
        Query D3FEND techniques for a CWE.
        
        Args:
            cwe_id: CWE identifier
            
        Returns:
            List of technique dictionaries
        """
        technique_ids = self.ontology_data.get("cwe_mappings", {}).get(cwe_id, [])
        
        techniques = []
        for tech_id in technique_ids:
            technique = self.query_technique(tech_id)
            if technique:
                techniques.append(technique)
        
        return techniques
    
    def get_all_techniques(self) -> List[Dict[str, Any]]:
        """
        Get all D3FEND techniques.
        
        Returns:
            List of all technique dictionaries
        """
        return [
            {"id": tech_id, **tech_data}
            for tech_id, tech_data in self.ontology_data.get("techniques", {}).items()
        ]
    
    def get_coverage_summary(self) -> Dict[str, Any]:
        """
        Get summary of D3FEND coverage.
        
        Returns:
            Dictionary with coverage statistics
        """
        techniques = self.ontology_data.get("techniques", {})
        cwe_mappings = self.ontology_data.get("cwe_mappings", {})
        
        tactic_counts = {}
        for tech_id, tech_data in techniques.items():
            tactic = tech_data.get("tactic", "unknown")
            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
        
        return {
            "total_techniques": len(techniques),
            "cwe_coverage": len(cwe_mappings),
            "tactic_distribution": tactic_counts
        }
