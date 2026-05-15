"""
D3FEND Catalog Loader — parses the official D3FEND CSV into an indexed catalog.
"""
import csv
import logging
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class D3FENDCatalogEntry:
    """A single D3FEND technique entry from the catalog."""

    def __init__(
        self,
        technique_id: str,
        tactic: str,
        technique: str,
        level_0: str,
        level_1: str,
        definition: str
    ):
        self.technique_id = technique_id
        self.tactic = tactic
        self.technique = technique
        self.level_0 = level_0
        self.level_1 = level_1
        self.definition = definition

    @property
    def label(self) -> str:
        """Best available human-readable label."""
        return self.level_1 or self.level_0 or self.technique or self.technique_id

    @property
    def display_name(self) -> str:
        """Full display name with hierarchy."""
        parts = [p for p in [self.technique, self.level_0, self.level_1] if p]
        return " → ".join(parts) if parts else self.technique_id

    def to_dict(self) -> Dict:
        return {
            "id": self.technique_id,
            "tactic": self.tactic,
            "technique": self.technique,
            "level_0": self.level_0,
            "level_1": self.level_1,
            "label": self.label,
            "display_name": self.display_name,
            "definition": self.definition,
        }


class D3FENDCatalogLoader:
    """
    Loads and indexes the D3FEND technique catalog CSV.
    Provides fast lookups by ID, tactic, and keyword.
    """

    def __init__(self, csv_path: Optional[str] = None):
        self.entries: Dict[str, D3FENDCatalogEntry] = {}
        self.by_tactic: Dict[str, List[str]] = {}
        self.by_keyword: Dict[str, List[str]] = {}

        if csv_path and Path(csv_path).exists():
            self.load(csv_path)
        else:
            logger.warning("D3FEND catalog CSV not found at %s", csv_path)

    def load(self, csv_path: str) -> None:
        """Load the D3FEND catalog from CSV."""
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                entry = D3FENDCatalogEntry(
                    technique_id=row.get("ID", "").strip(),
                    tactic=row.get("D3FEND Tactic", "").strip(),
                    technique=row.get("D3FEND Technique", "").strip(),
                    level_0=row.get("D3FEND Technique Level 0", "").strip(),
                    level_1=row.get("D3FEND Technique Level 1", "").strip(),
                    definition=row.get("Definition", "").strip(),
                )
                if not entry.technique_id:
                    continue

                self.entries[entry.technique_id] = entry

                # Index by tactic
                if entry.tactic:
                    self.by_tactic.setdefault(entry.tactic, []).append(entry.technique_id)

                # Index by keywords in label/definition
                keywords = self._extract_keywords(entry)
                for kw in keywords:
                    self.by_keyword.setdefault(kw, []).append(entry.technique_id)

        logger.info(
            "Loaded D3FEND catalog: %d entries, %d tactics",
            len(self.entries),
            len(self.by_tactic),
        )

    def _extract_keywords(self, entry: D3FENDCatalogEntry) -> List[str]:
        """Extract indexable keywords from an entry."""
        text = " ".join([
            entry.technique_id.lower(),
            entry.tactic.lower(),
            entry.technique.lower(),
            entry.level_0.lower(),
            entry.level_1.lower(),
            entry.definition.lower(),
        ])
        # Simple keyword extraction
        words = set()
        for word in text.split():
            word = word.strip(".,;:\"'")
            if len(word) >= 4:
                words.add(word)
        return list(words)

    def get_by_id(self, technique_id: str) -> Optional[D3FENDCatalogEntry]:
        """Lookup a technique by its D3FEND ID."""
        return self.entries.get(technique_id)

    def get_by_tactic(self, tactic: str) -> List[D3FENDCatalogEntry]:
        """Get all techniques for a given tactic."""
        ids = self.by_tactic.get(tactic, [])
        return [self.entries[i] for i in ids if i in self.entries]

    def search(self, query: str) -> List[D3FENDCatalogEntry]:
        """Search catalog by keyword."""
        query = query.lower()
        matched_ids = set()
        for kw, ids in self.by_keyword.items():
            if query in kw or kw in query:
                matched_ids.update(ids)
        return [self.entries[i] for i in matched_ids if i in self.entries]

    def get_all_entries(self) -> List[D3FENDCatalogEntry]:
        """Return all catalog entries."""
        return list(self.entries.values())

    def get_tactic_distribution(self) -> Dict[str, int]:
        """Count techniques per tactic."""
        return {tactic: len(ids) for tactic, ids in self.by_tactic.items()}

    def suggest_for_cwe(self, cwe_id: str) -> List[D3FENDCatalogEntry]:
        """
        Suggest D3FEND techniques for a CWE using keyword matching.
        Falls back to tactic-based heuristics.
        """
        cwe_keywords = self._cwe_to_keywords(cwe_id)
        matched = set()
        for kw in cwe_keywords:
            matched.update(self.by_keyword.get(kw, []))

        results = [self.entries[i] for i in matched if i in self.entries]

        # If no keyword matches, use heuristic tactic mapping
        if not results:
            tactic_hints = self._cwe_to_tactics(cwe_id)
            for tactic in tactic_hints:
                results.extend(self.get_by_tactic(tactic))

        # Deduplicate
        seen = set()
        unique = []
        for r in results:
            if r.technique_id not in seen:
                seen.add(r.technique_id)
                unique.append(r)
        return unique

    @staticmethod
    def _cwe_to_keywords(cwe_id: str) -> List[str]:
        """Map CWE IDs to likely D3FEND keywords."""
        mapping = {
            "CWE-119": ["buffer", "bounds", "memory", "validate"],
            "CWE-120": ["buffer", "overflow", "memory", "validate"],
            "CWE-121": ["stack", "buffer", "overflow"],
            "CWE-122": ["heap", "buffer", "overflow"],
            "CWE-125": ["out-of-bounds", "memory", "read"],
            "CWE-190": ["integer", "overflow", "wrap", "validate"],
            "CWE-191": ["integer", "underflow", "wrap"],
            "CWE-362": ["race", "condition", "concurrency", "thread"],
            "CWE-367": ["time-of-check", "time-of-use", "race"],
            "CWE-20": ["input", "validation", "sanitize"],
            "CWE-78": ["command", "injection", "shell", "os"],
            "CWE-79": ["cross-site", "xss", "scripting", "sanitize"],
            "CWE-89": ["sql", "injection", "query", "parameterize"],
            "CWE-94": ["code", "injection", "eval", "dynamic"],
            "CWE-287": ["authentication", "credential", "identity"],
            "CWE-306": ["authentication", "missing", "credential"],
            "CWE-352": ["cross-site", "forgery", "csrf", "token"],
            "CWE-400": ["resource", "exhaustion", "denial", "rate"],
            "CWE-502": ["deserialization", "untrusted", "marshal"],
            "CWE-522": ["credential", "password", "storage", "hash"],
            "CWE-732": ["permission", "authorization", "access"],
            "CWE-798": ["hardcoded", "credential", "password"],
            "CWE-918": ["server-side", "request", "ssrf", "forgery"],
            "CWE-476": ["null", "pointer", "dereference", "reference"],
            "CWE-416": ["use-after-free", "memory", "dangling"],
            "CWE-772": ["resource", "leak", "memory", "unreachable"],
            "CWE-835": ["infinite", "loop", "resource", "exhaustion"],
            "CWE-295": ["certificate", "validation", "trust", "identity", "authentication"],
            "CWE-296": ["certificate", "authentication", "identity", "bypass"],
            "CWE-297": ["certificate", "validation", "spoofing", "man-in-middle"],
            "CWE-326": ["encryption", "key", "strength", "cryptography", "weak"],
            "CWE-523": ["certificate", "transmission", "exposure", "credential"],
            "CWE-649": ["reliance", "obfuscation", "authentication", "crypto"],
        }
        return mapping.get(cwe_id.upper(), [])

    @staticmethod
    def _cwe_to_tactics(cwe_id: str) -> List[str]:
        """Map CWE IDs to likely D3FEND tactics."""
        mapping = {
            "CWE-119": ["Harden"],
            "CWE-120": ["Harden"],
            "CWE-125": ["Harden"],
            "CWE-190": ["Harden"],
            "CWE-362": ["Harden", "Isolate"],
            "CWE-20": ["Harden", "Detect"],
            "CWE-78": ["Harden", "Detect"],
            "CWE-79": ["Harden", "Detect"],
            "CWE-89": ["Harden", "Detect"],
            "CWE-287": ["Harden"],
            "CWE-306": ["Harden"],
            "CWE-400": ["Harden", "Detect"],
            "CWE-502": ["Harden", "Detect"],
            "CWE-522": ["Harden"],
            "CWE-476": ["Harden"],
            "CWE-416": ["Harden"],
            "CWE-295": ["Harden", "Detect"],
            "CWE-296": ["Harden"],
            "CWE-297": ["Harden", "Detect"],
            "CWE-326": ["Harden"],
            "CWE-523": ["Harden", "Isolate"],
            "CWE-649": ["Harden"],
        }
        return mapping.get(cwe_id.upper(), ["Harden", "Detect"])
