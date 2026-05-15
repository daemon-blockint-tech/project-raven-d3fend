"""
CCI (Control Correlation Identifier) Loader — parses D3FEND CCI mappings.

CCI provides NIST SP 800-53 control mappings to D3FEND defensive techniques,
enabling compliance-aware security analysis.
"""
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class CCIEntry:
    """A single CCI control to D3FEND technique mapping."""

    def __init__(
        self,
        cci_id: str,
        relation: str,
        d3fend_uri: str,
        technique_name: str,
        definition: str,
    ):
        self.cci_id = cci_id
        self.relation = relation
        self.d3fend_uri = d3fend_uri
        self.technique_name = technique_name
        self.definition = definition

    @property
    def d3fend_id(self) -> str:
        """Extract D3FEND technique ID from the URI."""
        # URI like http://d3fend.mitre.org/ontologies/d3fend.owl#AccountLocking
        fragment = urlparse(self.d3fend_uri).fragment
        return fragment or self.d3fend_uri.split("#")[-1]

    def to_dict(self) -> Dict:
        return {
            "cci_id": self.cci_id,
            "relation": self.relation,
            "d3fend_uri": self.d3fend_uri,
            "d3fend_id": self.d3fend_id,
            "technique_name": self.technique_name,
            "definition": self.definition,
        }


class CCILoader:
    """
    Loads and indexes CCI-to-D3FEND mappings from the D3FEND API JSON.
    Provides lookups by CCI control ID and by D3FEND technique.
    """

    def __init__(self, json_path: Optional[str] = None):
        self.entries: List[CCIEntry] = []
        self.by_cci: Dict[str, List[CCIEntry]] = {}
        self.by_d3fend_id: Dict[str, List[CCIEntry]] = {}
        self.by_technique_name: Dict[str, List[CCIEntry]] = {}
        self.cci_definitions: Dict[str, str] = {}

        if json_path and Path(json_path).exists():
            self.load(json_path)
        else:
            logger.warning("CCI JSON not found at %s", json_path)

    def load(self, json_path: str) -> None:
        """Parse the CCI SPARQL JSON results."""
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        bindings = data.get("results", {}).get("bindings", [])
        logger.info("Parsing %d CCI bindings", len(bindings))

        for binding in bindings:
            cci_id = binding.get("Control", {}).get("value", "").strip()
            relation = binding.get("Relation", {}).get("value", "").strip()
            d3fend_uri = binding.get("Defensive_Technique", {}).get("value", "").strip()
            technique_name = binding.get("Technique", {}).get("value", "").strip()
            definition = binding.get("CCI_Definition", {}).get("value", "").strip()

            if not cci_id or not d3fend_uri:
                continue

            entry = CCIEntry(
                cci_id=cci_id,
                relation=relation,
                d3fend_uri=d3fend_uri,
                technique_name=technique_name,
                definition=definition,
            )
            self.entries.append(entry)

            # Index by CCI
            self.by_cci.setdefault(cci_id, []).append(entry)

            # Index by D3FEND ID
            d3fend_id = entry.d3fend_id
            self.by_d3fend_id.setdefault(d3fend_id, []).append(entry)

            # Index by technique name
            self.by_technique_name.setdefault(technique_name, []).append(entry)

            # Store CCI definition (same for all entries with same CCI)
            if definition and cci_id not in self.cci_definitions:
                self.cci_definitions[cci_id] = definition

        logger.info(
            "Loaded CCI mappings: %d entries, %d unique CCI controls, %d unique D3FEND techniques",
            len(self.entries),
            len(self.by_cci),
            len(self.by_d3fend_id),
        )

    def get_by_cci(self, cci_id: str) -> List[CCIEntry]:
        """Get all D3FEND mappings for a CCI control."""
        return self.by_cci.get(cci_id, [])

    def get_by_d3fend_id(self, d3fend_id: str) -> List[CCIEntry]:
        """Get all CCI controls mapped to a D3FEND technique."""
        return self.by_d3fend_id.get(d3fend_id, [])

    def get_by_technique_name(self, name: str) -> List[CCIEntry]:
        """Get CCI mappings by technique name."""
        return self.by_technique_name.get(name, [])

    def get_cci_definition(self, cci_id: str) -> Optional[str]:
        """Get the definition for a CCI control."""
        return self.cci_definitions.get(cci_id)

    def get_related_cci_controls(self, d3fend_id: str) -> List[str]:
        """Get CCI control IDs related to a D3FEND technique."""
        entries = self.by_d3fend_id.get(d3fend_id, [])
        return sorted({e.cci_id for e in entries})

    def get_compliance_context(self, d3fend_id: str) -> Dict:
        """
        Get compliance context for a D3FEND technique:
        which NIST controls require it.
        """
        entries = self.by_d3fend_id.get(d3fend_id, [])
        if not entries:
            return {}

        cci_ids = sorted({e.cci_id for e in entries})
        definitions = {}
        for cci_id in cci_ids:
            defn = self.cci_definitions.get(cci_id)
            if defn:
                definitions[cci_id] = defn

        return {
            "d3fend_id": d3fend_id,
            "cci_controls": cci_ids,
            "control_count": len(cci_ids),
            "definitions": definitions,
            "compliance_frameworks": ["NIST SP 800-53"],
        }

    def search_cci(self, query: str) -> List[CCIEntry]:
        """Search CCI mappings by control ID or technique name."""
        query = query.lower()
        results = []
        for entry in self.entries:
            if (query in entry.cci_id.lower() or
                query in entry.technique_name.lower()):
                results.append(entry)
        return results

    def get_coverage_stats(self) -> Dict:
        """Get coverage statistics for the CCI mappings."""
        relations = {}
        for entry in self.entries:
            relations[entry.relation] = relations.get(entry.relation, 0) + 1

        return {
            "total_mappings": len(self.entries),
            "unique_cci_controls": len(self.by_cci),
            "unique_d3fend_techniques": len(self.by_d3fend_id),
            "relation_distribution": relations,
            "cci_with_definitions": len(self.cci_definitions),
        }

    def suggest_d3fend_for_requirement(self, requirement_text: str) -> List[str]:
        """
        Suggest D3FEND techniques for a compliance requirement text.
        Best-effort keyword matching against CCI definitions and technique names.
        """
        requirement_lower = requirement_text.lower()
        matched_d3fend_ids: Set[str] = set()

        # Search CCI definitions
        for cci_id, definition in self.cci_definitions.items():
            if any(word in definition.lower() for word in requirement_lower.split() if len(word) > 5):
                entries = self.by_cci.get(cci_id, [])
                for e in entries:
                    matched_d3fend_ids.add(e.d3fend_id)

        # Search technique names
        for name, entries in self.by_technique_name.items():
            if any(word in name.lower() for word in requirement_lower.split() if len(word) > 4):
                for e in entries:
                    matched_d3fend_ids.add(e.d3fend_id)

        return sorted(matched_d3fend_ids)
