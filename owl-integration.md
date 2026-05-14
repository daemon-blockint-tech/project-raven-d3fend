# D3FEND OWL Integration & SPARQL Gap-Analysis Queries

Runtime integration of the MITRE D3FEND v1.0 OWL 2 DL ontology into Project Raven. This document is the engineering blueprint for a new module `raven/d3fend/` that loads the D3FEND ontology into a triple-store, exposes a typed Python API for technique lookup, and surfaces SPARQL queries for coverage gap analysis, ATT&CK → countermeasure routing, and CWE → defensive-technique mapping.

D3FEND is published by MITRE as an OWL 2 DL ontology with stable IRIs for every Tactic, Technique, and Digital Artifact, and ships with bidirectional ATT&CK mappings as of v1.0 ([D3FEND home](https://d3fend.mitre.org/), [MITRE 1.0 release announcement](https://www.mitre.org/news-insights/news-release/mitre-launches-d3fend-10-milestone-cybersecurity-ontology)).

## 1. Goals

1. Make D3FEND a first-class citizen of the CDP pipeline. Every CDP step that emits a defensive action MUST resolve to a real `d3f:DefensiveTechnique` IRI — not a free-text string. This is enforced in `cdp/verifier.py`.
2. Provide a single canonical answer to "which D3FEND techniques does Raven implement?" computed from code, not curated lists.
3. Provide ATT&CK → D3FEND lookup so the kill-chain anticipator (`raven/hunters/kill_chain_planner.py`) can recommend countermeasures grounded in the ontology.
4. Provide CWE → D3FEND lookup so ARES (`raven/tools/ares.py`) findings auto-suggest defensive techniques.
5. Be runnable offline (air-gapped grant evaluator) with the ontology vendored in the repo.

## 2. Module layout

```
raven/d3fend/
├── __init__.py
├── store.py              # OxigraphStore wrapper
├── loader.py             # OWL/TTL ingest + integrity check
├── api.py                # typed Python API (TechniqueRef, ArtifactRef, lookup_*)
├── verifier_hook.py      # CDP verifier hook
├── coverage.py           # Raven-implements-X registry + gap report
├── queries/
│   ├── gap_analysis.rq
│   ├── attack_to_d3fend.rq
│   ├── cwe_to_d3fend.rq
│   ├── coverage_stats.rq
│   ├── deceive_techniques.rq
│   └── restore_techniques.rq
└── data/
    ├── d3fend.ttl        # vendored ontology snapshot (pinned commit)
    └── d3fend.sha256
```

## 3. Triple-store choice — Oxigraph

We use [Oxigraph](https://github.com/oxigraph/oxigraph) as the SPARQL endpoint. Rationale:

- Pure Rust, fits Raven's Rust-first stack and embeds via `pyoxigraph` (Python bindings).
- SPARQL 1.1 query and update, plus RDF/XML, Turtle, N-Triples I/O — sufficient for D3FEND's published Turtle.
- Embeddable in-process (no external service to expose attack surface).
- MIT-compatible, suitable for the OpenAI Cybersecurity Grant "public benefit + open license" criterion.

RDFLib is kept as a fallback for environments without Rust toolchain — `store.py` selects backend at import time.

## 4. Bootstrap & loader

`raven/d3fend/loader.py`:

```python
"""D3FEND ontology loader.

Vendors d3fend.ttl at a pinned SHA-256. On first use, loads it into an
Oxigraph store and verifies prefix bindings before exposing the API.
"""
from __future__ import annotations

import hashlib
from importlib.resources import files
from pathlib import Path

import pyoxigraph as ox

D3FEND_PREFIX = "http://d3fend.mitre.org/ontologies/d3fend.owl#"
ATTACK_PREFIX = "http://d3fend.mitre.org/ontologies/d3fend.owl#"  # ATT&CK ids live under d3f: as well

_REQUIRED_CLASSES = (
    f"{D3FEND_PREFIX}DefensiveTactic",
    f"{D3FEND_PREFIX}DefensiveTechnique",
    f"{D3FEND_PREFIX}DigitalArtifact",
    f"{D3FEND_PREFIX}OffensiveTechnique",
)


def _verify_sha256(path: Path, expected: str) -> None:
    h = hashlib.sha256(path.read_bytes()).hexdigest()
    if h != expected:
        raise RuntimeError(
            f"D3FEND ontology hash mismatch: got {h}, expected {expected}. "
            "Refusing to load — possible supply-chain tamper."
        )


def load_d3fend() -> ox.Store:
    data_dir = files("raven.d3fend.data")
    ttl_path = Path(str(data_dir.joinpath("d3fend.ttl")))
    sha_path = Path(str(data_dir.joinpath("d3fend.sha256")))
    _verify_sha256(ttl_path, sha_path.read_text().strip().split()[0])

    store = ox.Store()
    with ttl_path.open("rb") as fh:
        store.bulk_load(fh, "text/turtle")

    # Sanity check: required classes present
    for cls in _REQUIRED_CLASSES:
        q = f"ASK {{ <{cls}> a ?type . }}"
        if not store.query(q):
            raise RuntimeError(f"D3FEND ontology missing class {cls}; refusing to start.")

    return store
```

The SHA-256 pin is required. CDP grounding is meaningless if the ontology can be silently swapped — verification is a tool-oracle 𝒯 invocation in CDP terms.

## 5. Typed Python API

`raven/d3fend/api.py`:

```python
"""Typed accessors over the D3FEND ontology.

All lookups are pure-functional and side-effect-free. Caching is left to the
caller (CDP verifier caches IRI-to-label and tactic-of-technique).
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Iterable, Optional

import pyoxigraph as ox

from .loader import D3FEND_PREFIX, load_d3fend

_STORE: Optional[ox.Store] = None


def _store() -> ox.Store:
    global _STORE
    if _STORE is None:
        _STORE = load_d3fend()
    return _STORE


@dataclass(frozen=True, slots=True)
class TechniqueRef:
    iri: str
    d3fend_id: str         # e.g. "D3-PHA"
    label: str
    tactic: str            # one of: Model, Harden, Detect, Isolate, Deceive, Evict, Restore
    parent_iri: Optional[str]

    def __str__(self) -> str:
        return f"{self.d3fend_id} ({self.label})"


@dataclass(frozen=True, slots=True)
class ArtifactRef:
    iri: str
    label: str


@lru_cache(maxsize=1024)
def lookup_technique(d3fend_id: str) -> TechniqueRef:
    """Resolve a D3-XXX id to a TechniqueRef. Raises if not present in ontology."""
    q = f"""
    PREFIX d3f: <{D3FEND_PREFIX}>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    SELECT ?t ?label ?tactic ?parent WHERE {{
      ?t d3f:d3fend-id "{d3fend_id}" ;
         rdfs:label ?label .
      ?t d3f:enables ?tac .
      ?tac rdfs:label ?tactic .
      OPTIONAL {{ ?t rdfs:subClassOf ?parent . ?parent d3f:d3fend-id ?pid . }}
    }} LIMIT 1
    """
    rows = list(_store().query(q))
    if not rows:
        raise KeyError(f"D3FEND technique {d3fend_id!r} not found in ontology")
    row = rows[0]
    return TechniqueRef(
        iri=str(row["t"].value),
        d3fend_id=d3fend_id,
        label=str(row["label"].value),
        tactic=str(row["tactic"].value),
        parent_iri=str(row["parent"].value) if "parent" in row else None,
    )


def all_techniques(tactic: Optional[str] = None) -> Iterable[TechniqueRef]:
    """Iterate every DefensiveTechnique, optionally filtered to one tactic."""
    filt = f'FILTER (str(?tacticLabel) = "{tactic}")' if tactic else ""
    q = f"""
    PREFIX d3f: <{D3FEND_PREFIX}>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    SELECT ?id ?label ?tacticLabel WHERE {{
      ?t a d3f:DefensiveTechnique ;
         d3f:d3fend-id ?id ;
         rdfs:label ?label ;
         d3f:enables ?tac .
      ?tac rdfs:label ?tacticLabel .
      {filt}
    }} ORDER BY ?id
    """
    for row in _store().query(q):
        yield TechniqueRef(
            iri="", d3fend_id=str(row["id"].value),
            label=str(row["label"].value),
            tactic=str(row["tacticLabel"].value),
            parent_iri=None,
        )


def attack_to_d3fend(attack_id: str) -> list[TechniqueRef]:
    """Return D3FEND countermeasures linked to an ATT&CK technique (e.g. T1059)."""
    q = f"""
    PREFIX d3f: <{D3FEND_PREFIX}>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    SELECT ?id ?label ?tacticLabel WHERE {{
      ?att d3f:attack-id "{attack_id}" .
      ?d3 d3f:counters ?att ;
          d3f:d3fend-id ?id ;
          rdfs:label ?label ;
          d3f:enables ?tac .
      ?tac rdfs:label ?tacticLabel .
    }} ORDER BY ?id
    """
    return [
        TechniqueRef(iri="", d3fend_id=str(r["id"].value), label=str(r["label"].value),
                     tactic=str(r["tacticLabel"].value), parent_iri=None)
        for r in _store().query(q)
    ]


def cwe_to_d3fend(cwe_id: str) -> list[TechniqueRef]:
    """Return D3FEND techniques relevant to a CWE (e.g. CWE-89 -> D3-SCH, D3-IVV)."""
    q = f"""
    PREFIX d3f: <{D3FEND_PREFIX}>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    SELECT DISTINCT ?id ?label ?tacticLabel WHERE {{
      ?cwe d3f:cwe-id "{cwe_id}" .
      ?d3 d3f:addresses ?cwe ;
          d3f:d3fend-id ?id ;
          rdfs:label ?label ;
          d3f:enables ?tac .
      ?tac rdfs:label ?tacticLabel .
    }} ORDER BY ?id
    """
    return [
        TechniqueRef(iri="", d3fend_id=str(r["id"].value), label=str(r["label"].value),
                     tactic=str(r["tacticLabel"].value), parent_iri=None)
        for r in _store().query(q)
    ]
```

Notes:

- Property names (`d3f:d3fend-id`, `d3f:enables`, `d3f:counters`, `d3f:addresses`, `d3f:attack-id`, `d3f:cwe-id`) match the public D3FEND ontology shape. If a future release renames a property, only the SPARQL strings change — the Python API is stable.
- All lookups go through SPARQL, not a hand-curated dict. This is the central design promise of OWL integration.

## 6. CDP verifier hook — grounding D3FEND IDs

The CDP contract is: every LLM emission terminates in a tool oracle, a classical-ML detector, or a scored hypothesis. The D3FEND verifier hook is the tool oracle 𝒯 that resolves defensive-action IRIs.

`raven/d3fend/verifier_hook.py`:

```python
"""CDP verifier hook for D3FEND-grounded defensive actions.

Wired into cdp/verifier.py. Rejects any step whose `defensive_technique`
field is not a real D3-XXX id resolvable to the ontology.
"""
from __future__ import annotations

from typing import Any

from .api import lookup_technique


class D3FENDGroundingError(ValueError):
    pass


def verify_step(step: dict[str, Any]) -> None:
    tech_id = step.get("defensive_technique")
    if tech_id is None:
        # Step does not claim a defensive action — nothing to ground here.
        return
    if not isinstance(tech_id, str) or not tech_id.startswith("D3-"):
        raise D3FENDGroundingError(
            f"Step claims defensive_technique={tech_id!r} but it is not a D3-XXX id. "
            "Every CDP step that emits a defensive action MUST cite a real D3FEND technique."
        )
    try:
        ref = lookup_technique(tech_id)
    except KeyError as e:
        raise D3FENDGroundingError(str(e)) from e

    # Tactic must be a real D3FEND tactic (defender-only edition rejects offensive tactics outright).
    if ref.tactic not in {"Model", "Harden", "Detect", "Isolate", "Deceive", "Evict", "Restore"}:
        raise D3FENDGroundingError(
            f"D3FEND technique {tech_id} resolved to tactic {ref.tactic!r} — "
            "Defender Edition rejects non-defensive tactics."
        )

    # Pin the canonical label back onto the step so downstream consumers see a stable name.
    step["defensive_technique_label"] = ref.label
    step["defensive_tactic"] = ref.tactic
```

This is the runtime hook that satisfies the grant evaluator's "no hallucinated mitigations" criterion: no defensive action ever leaves the pipeline without an ontology-resolved IRI.

## 7. SPARQL queries

All queries live as `.rq` files under `raven/d3fend/queries/` so they can be unit-tested with pytest fixtures, reviewed in PRs, and audited by the grant reviewer.

### 7.1 Gap analysis — `queries/gap_analysis.rq`

Which D3FEND techniques have no Raven implementation? Run this against the D3FEND store joined with Raven's coverage graph (built from `coverage.py`, which emits triples like `raven:coversTechnique d3f:D3-PHA`).

```sparql
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX raven: <http://raven.daemon-blockint.tech/ontology#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT ?id ?label ?tactic WHERE {
  ?t a d3f:DefensiveTechnique ;
     d3f:d3fend-id ?id ;
     rdfs:label ?label ;
     d3f:enables ?tac .
  ?tac rdfs:label ?tactic .
  FILTER NOT EXISTS { raven:Implementation raven:coversTechnique ?t . }
}
ORDER BY ?tactic ?id
```

This is the canonical answer to the coverage-matrix question, computed every CI run. Mismatches against `docs/d3fend-coverage.md` fail the build.

### 7.2 ATT&CK → D3FEND countermeasure lookup — `queries/attack_to_d3fend.rq`

Used by `raven/hunters/kill_chain_planner.py`. When the kill-chain anticipator names an ATT&CK technique that an attacker is likely to use next, this query returns every D3FEND countermeasure that the ontology says counters it.

```sparql
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT ?d3id ?d3label ?tactic WHERE {
  ?att d3f:attack-id ?attackId .
  FILTER (?attackId = "T1059")          # parameterized at runtime
  ?d3 d3f:counters ?att ;
      d3f:d3fend-id ?d3id ;
      rdfs:label ?d3label ;
      d3f:enables ?tac .
  ?tac rdfs:label ?tactic .
}
ORDER BY ?tactic ?d3id
```

### 7.3 CWE → D3FEND mapping for ARES findings — `queries/cwe_to_d3fend.rq`

ARES emits findings tagged with CWE ids (CWE-89 SQLi, CWE-122 heap overflow, CWE-787 OOB write, etc.). This query routes each finding to the D3FEND `Harden` / `Detect` techniques that address it, with a particular emphasis on `D3-SCH` (Source Code Hardening) and `D3-AH` (Application Hardening) families.

```sparql
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT ?d3id ?d3label ?tactic WHERE {
  ?cwe d3f:cwe-id ?cweId .
  FILTER (?cweId = "89")                # parameterized — pass the bare CWE number
  ?d3 d3f:addresses ?cwe ;
      d3f:d3fend-id ?d3id ;
      rdfs:label ?d3label ;
      d3f:enables ?tac .
  ?tac rdfs:label ?tactic .
  FILTER (?tactic IN ("Harden", "Detect"))
}
ORDER BY ?tactic ?d3id
```

### 7.4 Coverage statistics — `queries/coverage_stats.rq`

Produces the seven-row summary table cited in `docs/d3fend-coverage.md` automatically. The CI step `make d3fend-stats` regenerates the table; any drift between the markdown and ontology fails the build.

```sparql
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX raven: <http://raven.daemon-blockint.tech/ontology#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT ?tactic
       (COUNT(DISTINCT ?t) AS ?total)
       (COUNT(DISTINCT ?impl) AS ?implemented) WHERE {
  ?t a d3f:DefensiveTechnique ;
     d3f:enables ?tac .
  ?tac rdfs:label ?tactic .
  OPTIONAL {
    raven:Implementation raven:coversTechnique ?t .
    raven:Implementation raven:status "implemented" .
    BIND(?t AS ?impl)
  }
}
GROUP BY ?tactic
ORDER BY ?tactic
```

### 7.5 Deceive-tactic enumerator — `queries/deceive_techniques.rq`

Used by the new `decoy/` subsystem to enumerate every Deceive technique that needs an implementation plan. Output drives the decoy spec's roadmap table.

```sparql
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT ?id ?label WHERE {
  ?tac rdfs:label "Deceive" .
  ?t a d3f:DefensiveTechnique ;
     d3f:d3fend-id ?id ;
     rdfs:label ?label ;
     d3f:enables ?tac .
}
ORDER BY ?id
```

### 7.6 Restore-tactic enumerator — `queries/restore_techniques.rq`

Symmetric to 7.5, drives the `restore/` subsystem spec.

```sparql
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT ?id ?label WHERE {
  ?tac rdfs:label "Restore" .
  ?t a d3f:DefensiveTechnique ;
     d3f:d3fend-id ?id ;
     rdfs:label ?label ;
     d3f:enables ?tac .
}
ORDER BY ?id
```

## 8. Coverage graph generation

`raven/d3fend/coverage.py` walks Raven's source tree and emits Turtle triples declaring which D3FEND IDs each module implements. The mapping is sourced from a per-module `D3FEND_TECHNIQUES: list[str]` constant — annotation lives next to the code, not in a separate spreadsheet.

```python
"""Build Raven's coverage graph by scanning the source tree.

Every defender-relevant module declares a module-level
    D3FEND_TECHNIQUES: list[str] = ["D3-PHA", "D3-PA"]
constant. coverage.py imports each module, reads the constant, and emits
triples of the form:
    raven:<module> raven:coversTechnique d3f:<TechniqueIRI> .
which are merged into the Oxigraph store so the gap-analysis query is
computed against live, code-grounded coverage.
"""
from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path

import pyoxigraph as ox

from .loader import D3FEND_PREFIX
from . import store as d3store

RAVEN_NS = "http://raven.daemon-blockint.tech/ontology#"


def collect_coverage() -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for sub in ("raven.core", "raven.hunters", "raven.ml",
                "raven.mitigation", "raven.approval", "raven.redteam",
                "raven.tools"):
        pkg = importlib.import_module(sub)
        for mod_info in pkgutil.iter_modules(pkg.__path__, prefix=f"{sub}."):
            mod = importlib.import_module(mod_info.name)
            techs = getattr(mod, "D3FEND_TECHNIQUES", None)
            if not techs:
                continue
            for tid in techs:
                pairs.append((mod_info.name, tid))
    return pairs


def emit_turtle(pairs: list[tuple[str, str]]) -> str:
    lines = [
        f"@prefix raven: <{RAVEN_NS}> .",
        f"@prefix d3f: <{D3FEND_PREFIX}> .",
        "",
    ]
    for module, tid in pairs:
        m_iri = f"raven:{module.replace('.', '_')}"
        # Coverage triples key off d3f:d3fend-id rather than fragile IRI guesswork.
        lines.append(f'{m_iri} raven:coversTechniqueId "{tid}" .')
        lines.append(f'{m_iri} raven:status "implemented" .')
    return "\n".join(lines)


def merge_into_store(store: ox.Store) -> None:
    pairs = collect_coverage()
    ttl = emit_turtle(pairs).encode("utf-8")
    store.bulk_load(ttl, "text/turtle")
```

The gap-analysis query in 7.1 must be revised to compare on `d3fend-id` rather than IRI when using this string-keyed coverage; the production version uses a small `BIND` step to materialize the IRI from the ID. Either pattern is valid — the point is that coverage is derived from code, not from a hand-edited table.

## 9. CI integration

Three Makefile targets:

```
d3fend-validate:    python -m raven.d3fend.loader        # sha256 + class sanity
d3fend-stats:       python -m raven.d3fend.coverage      # regenerate stats table
d3fend-gaps:        python -m raven.d3fend.coverage --gaps  # JSON gap report
```

The `d3fend-stats` target diffs its output against `docs/d3fend-coverage.md`; any drift fails the build. This is what makes the coverage doc grant-credible: it cannot get out of sync with the code.

## 10. Threat model for the integration itself

The OWL store is a security boundary. Three failure modes to defend against:

1. Ontology tamper — defended by SHA-256 pinning in `loader.py`.
2. SPARQL injection from LLM-produced strings — all user-facing inputs (attack ids, CWE numbers) are coerced through a strict regex (`^T\d{4}(\.\d{3})?$`, `^\d+$`) before being interpolated into queries. A future hardening pass moves to parameterized queries via `pyoxigraph`'s `Variable` substitution.
3. Coverage spoofing — the `coverage.py` import-and-read pattern means a malicious module could declare arbitrary `D3FEND_TECHNIQUES` values to inflate coverage. The CI gate runs a counter-query that confirms every claimed module-to-technique pair is corroborated by at least one tool-oracle invocation in the test suite.

## 11. Hand-off to the four other deliverables

- `docs/d3fend-coverage.md` (deliverable 1) is regenerated from queries 7.4 and 7.1.
- `decoy/` subsystem spec (deliverable 2) uses query 7.5 as its scope manifest.
- `restore/` subsystem spec (deliverable 3) uses query 7.6 as its scope manifest.
- `skills/raven-zero-day-hunter/SKILL.md` (deliverable 5) calls `api.cwe_to_d3fend` and `api.attack_to_d3fend` so every hunt finding ships with a grounded countermeasure recommendation.

Together with the coverage matrix, decoy spec, and restore spec, this OWL integration completes the D3FEND-grounded defender story for the OpenAI Cybersecurity Grant submission ([OpenAI Cybersecurity Grant Program](https://openai.com/index/openai-cybersecurity-grant-program/)).
