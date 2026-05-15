"""
CWE to D3FEND mapper for the pipeline - maps CWE IDs to D3FEND techniques.
"""
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)


class CWEMapper:
    """Map CWE IDs to D3FEND techniques."""
    
    def __init__(self):
        """Initialize CWE to D3FEND mapper."""
        # Simplified CWE to D3FEND mapping
        # In production, this would query the actual D3FEND OWL ontology
        self.cwe_to_d3fend = {
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
            "CWE-352": ["D3-ATA", "D3-ATP"],
            "CWE-400": ["D3-ATA", "D3-ATP"],
            "CWE-502": ["D3-ATA", "D3-ATP"],
            "CWE-287": ["D3-ATA", "D3-ATP"],
            "CWE-190": ["D3-MSI", "D3-MSA"],
            "CWE-476": ["D3-DCR", "D3-DCS"],
            "CWE-502": ["D3-DCR", "D3-DCS"],
            "CWE-522": ["D3-DCR", "D3-DCS"],
            "CWE-400": ["D3-DCR", "D3-DCS"],
            "CWE-89": ["D3-DCR", "D3-DCS"],
            "CWE-20": ["D3-DCR", "D3-DCS"],
            "CWE-352": ["D3-DCR", "D3-DCS"],
            "CWE-400": ["D3-DCR", "D3-DCS"],
            "CWE-787": ["D3-MSI", "D3-MSA"],
            "CWE-125": ["D3-MSI", "D3-MSA"],
            "CWE-119": ["D3-MSI", "D3-MSA"],
            "CWE-190": ["D3-MSI", "D3-MSA"],
            "CWE-362": ["D3-MSI", "D3-MSA"],
            "CWE-367": ["D3-MSI", "D3-MSA"],
            "CWE-787": ["D3-MSI", "D3-MSA"],
            "CWE-190": ["D3-MSI", "DMSA"],
            "CWE-125": ["D3-MSI", "DMSA"],
            "CWE-787": ["D3-MSI", "DMSA"],
            "CWE-119": ["D3-MSI", "DMSA"],
            "CWE-20": ["D3-MSI", "DMSA"],
            "CWE-79": ["D3-MSI", "DMSA"],
            "CWE-89": ["D3-MSI", "DMSA"],
            "CWE-190": ["D3-MSI", "DMSA"],
            "CWE-362": ["D3-MSI", "DMSA"],
            "CWE-367": ["D3-MSI", "DMSA"],
            "CWE-352": ["D3-MSI", "DMSA"],
            "CWE-400": ["D3-MSI", "DMSA"],
            "CWE-502": ["D3-MSI", "DMSA"],
            "CWE-287": ["D-MSI", "DMSA"],
            "CWE-476": ["D3-MSI", "DMSA"],
            "CWE-502": ["D3-MSI", "DMSA"],
            "CWE-522": ["D3-MSI", "DMSA"],
            "CWE-89": ["D-MSI", "DMSA"],
            "CWE-20": ["D-MSI", "DMSA"],
            "CWE-352": ["D-MSI", "DMSA"],
            "CWE-400": ["D-MSI", "DMSA"],
        }
        
        # D3FEND technique labels
        self.d3fend_labels = {
            "D3-ATA": "Attack Surface Reduction",
            "D3-ATP": "Attack Technical Prevention",
            "D3-AIP": "Attack Isolation and Preparation",
            "D3-MSA": "Malicious Software Analysis",
            "D3-MSI": "Malicious Software Investigation",
            "D3-DCR": "Decoy Corruption",
            "D3-DCS": "Decoy Compromise",
            "D3-DTA": "Decoy Timing and Activation",
            "D3-DII": "Decoy Isolation and Identification",
            "D3-DIT": "Decoy Injection and Trigger",
            "D3-DCE": "Decoy Content Elicitation",
            "D3-DCR": "Decoy Corruption",
            "D3-DCS": "Decoy Compromise",
            "D3-RC": "Restore Components",
            "D3-RF": "Restore Functions",
            "D3-RA": "Restore Access",
            "D3-RD": "Restore Data",
            "D3-RDI": "Restore Data Integrity",
            "D3-RNA": "Restore Network Access",
            "D3-RO": "Restore Operations",
            "D3-RS": "Restore Services",
            "D3-RUAA": "Restore User Account Access",
            "D3-ULA": "Use Limiting Authentication",
            "D3-RIC": "Restore Incident Containment",
            "D3-CRO": "Containment Response Orchestration",
            "D3-CERO": "Containment Eradication and Remediation",
        }
        
        logger.info("CWEMapper initialized")
    
    def map_cwe_to_d3fend(self, cwe_id: str) -> List[Dict[str, Any]]:
        """
        Map a CWE ID to D3FEND techniques.
        
        Args:
            cwe_id: CWE identifier (e.g., "CWE-119")
            
        Returns:
            List of D3FEND technique dictionaries
        """
        techniques = self.cwe_to_d3fend.get(cwe_id, [])
        
        result = []
        for technique_id in techniques:
            label = self.d3fend_labels.get(technique_id, technique_id)
            tactic = technique_id.split("-")[1] if "-" in technique_id else "unknown"
            
            result.append({
                "id": technique_id,
                "label": label,
                "tactic": tactic
            })
        
        logger.debug(f"Mapped {cwe_id} to {len(result)} D3FEND techniques")
        return result
    
    def get_d3fend_coverage(self, cwe_ids: List[str]) -> Dict[str, List[str]]:
        """
        Get D3FEND coverage for multiple CWEs.
        
        Args:
            cwe_ids: List of CWE identifiers
            
        Returns:
            Dictionary mapping CWE IDs to D3FEND technique lists
        """
        coverage = {}
        
        for cwe_id in cwe_ids:
            techniques = self.map_cwe_to_d3fend(cwe_id)
            coverage[cwe_id] = [t["id"] for t in techniques]
        
        return coverage
