"""
D3FEND integration for the pipeline - binds findings to D3FEND countermeasures.
"""
from .cwe_mapper import CWEMapper
from .ontology_client import D3FENDOntologyClient
from .remediation import RemediationEngine
from .attack_mapper import ATTACKMapper
from .d3fend_catalog_loader import D3FENDCatalogLoader
from .cci_loader import CCILoader
from .enrichment_engine import D3FENDEnrichmentEngine, EnrichmentResult

__all__ = [
    "CWEMapper",
    "D3FENDOntologyClient",
    "RemediationEngine",
    "ATTACKMapper",
    "D3FENDCatalogLoader",
    "CCILoader",
    "D3FENDEnrichmentEngine",
    "EnrichmentResult"
]
