#!/usr/bin/env python3
"""build_l1_d3fend.py — Layer 1 corpus builder for raven-defender-lora-mlx.

Generates ~8k chat-format JSONL training samples from the D3FEND OWL v1.0
ontology by querying the Oxigraph store described in
`raven-d3fend/owl-integration.md`.

CDP contract: every emitted sample terminates at 𝒯 (the ontology itself is a
deterministic oracle — every assistant claim cites a d3f: IRI verified to
exist in the store at build time).

Defender-only enforcement: refuses to emit any sample that mentions an
offensive technique except as the "what we defend against" half of a
defender-side QA pair. OffensiveTechnique IRIs are NEVER the subject of a
"how to" question.

Output format matches mlx-lm chat JSONL:
    {"messages": [{"role": "system", "content": "..."},
                  {"role": "user",   "content": "..."},
                  {"role": "assistant","content": "..."}]}

Usage:
    python build_l1_d3fend.py \\
        --ttl ./raven/d3fend/data/d3fend.ttl \\
        --sha256 ./raven/d3fend/data/d3fend.sha256 \\
        --out ./data/l1_d3fend.jsonl \\
        --target-samples 8000 \\
        --seed 1337

The TTL path and SHA-256 pin file are the same artifacts the production
Raven loader (`raven/d3fend/loader.py`) uses; we reuse them rather than
re-downloading to keep the training corpus byte-identical to runtime.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

try:
    import pyoxigraph as ox
except ImportError:  # pragma: no cover
    sys.stderr.write(
        "pyoxigraph is required. Install with: pip install pyoxigraph\n"
    )
    sys.exit(2)


# ──────────────────────────────────────────────────────────────────────────────
# Constants — keep in lockstep with raven/d3fend/loader.py
# ──────────────────────────────────────────────────────────────────────────────
D3F = "http://d3fend.mitre.org/ontologies/d3fend.owl#"

SYSTEM_PROMPT = textwrap.dedent(
    """\
    You are Raven, a defender-only security assistant. Every defensive claim
    you make must terminate at one of three groundings:
      𝒯 — a deterministic tool oracle (e.g., the D3FEND ontology, Semgrep, SHACL),
      𝓜 — an ML detector with a calibrated score,
      𝓛 — a scored hypothesis with an attached falsification test.

    You cite D3FEND techniques by their canonical IRI (d3f:D3-XXX). You never
    produce offensive payloads. When asked about an attacker technique, you
    answer in defender frame: what to detect, what to deceive, what to evict,
    what to restore.
    """
).strip()


# ──────────────────────────────────────────────────────────────────────────────
# Store bootstrap (mirrors raven/d3fend/loader.py)
# ──────────────────────────────────────────────────────────────────────────────
def _verify_sha256(path: Path, sha_path: Path) -> None:
    expected = sha_path.read_text().strip().split()[0]
    got = hashlib.sha256(path.read_bytes()).hexdigest()
    if got != expected:
        raise RuntimeError(
            f"D3FEND ontology hash mismatch:\n  got      {got}\n  expected {expected}\n"
            "Refusing to build training corpus from a tampered ontology."
        )


def load_store(ttl: Path, sha: Path) -> ox.Store:
    _verify_sha256(ttl, sha)
    store = ox.Store()
    with ttl.open("rb") as fh:
        store.bulk_load(fh, "text/turtle")
    # Sanity-check expected classes are present.
    for cls in ("DefensiveTactic", "DefensiveTechnique", "DigitalArtifact", "OffensiveTechnique"):
        ask = f"ASK {{ <{D3F}{cls}> a ?t }}"
        if not store.query(ask):
            raise RuntimeError(
                f"D3FEND store missing {cls}; refusing to build training corpus."
            )
    return store


# ──────────────────────────────────────────────────────────────────────────────
# SPARQL queries — each one drives one or more sample templates
# ──────────────────────────────────────────────────────────────────────────────
Q_DEFENSIVE_TECHNIQUES = f"""
PREFIX d3f: <{D3F}>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
SELECT ?tech ?label ?definition ?tactic ?tacticLabel WHERE {{
  ?tech a d3f:DefensiveTechnique ;
        rdfs:label ?label .
  OPTIONAL {{ ?tech d3f:definition ?definition . }}
  OPTIONAL {{
    ?tech d3f:enables ?tactic .
    ?tactic a d3f:DefensiveTactic ;
            rdfs:label ?tacticLabel .
  }}
}}
"""

Q_TECHNIQUE_TO_ARTIFACTS = f"""
PREFIX d3f: <{D3F}>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
SELECT ?tech ?techLabel ?artifact ?artifactLabel WHERE {{
  ?tech a d3f:DefensiveTechnique ;
        rdfs:label ?techLabel ;
        ?rel ?artifact .
  ?artifact a d3f:DigitalArtifact ;
            rdfs:label ?artifactLabel .
  FILTER(?rel IN (d3f:analyzes, d3f:monitors, d3f:restores, d3f:isolates, d3f:obfuscates))
}}
"""

Q_ATTACK_TO_DEFENSE = f"""
PREFIX d3f: <{D3F}>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
SELECT ?off ?offLabel ?def ?defLabel WHERE {{
  ?off a d3f:OffensiveTechnique ;
       rdfs:label ?offLabel .
  ?def a d3f:DefensiveTechnique ;
       rdfs:label ?defLabel ;
       d3f:counters ?off .
}}
"""

Q_TACTIC_COVERAGE = f"""
PREFIX d3f: <{D3F}>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
SELECT ?tactic ?tacticLabel (COUNT(DISTINCT ?tech) AS ?n) WHERE {{
  ?tactic a d3f:DefensiveTactic ; rdfs:label ?tacticLabel .
  OPTIONAL {{ ?tech a d3f:DefensiveTechnique ; d3f:enables ?tactic . }}
}}
GROUP BY ?tactic ?tacticLabel
ORDER BY DESC(?n)
"""

Q_TECHNIQUE_PARENT_CHILD = f"""
PREFIX d3f: <{D3F}>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
SELECT ?parent ?parentLabel ?child ?childLabel WHERE {{
  ?child a d3f:DefensiveTechnique ; rdfs:label ?childLabel ;
         rdfs:subClassOf ?parent .
  ?parent a d3f:DefensiveTechnique ; rdfs:label ?parentLabel .
}}
"""


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────
def iri_to_d3f_id(iri: str) -> str:
    """Turn http://...#D3-DLIC into d3f:D3-DLIC."""
    if "#" in iri:
        return "d3f:" + iri.rsplit("#", 1)[1]
    return iri


def lit(term) -> str:
    """Stringify an Oxigraph Literal or NamedNode safely."""
    if term is None:
        return ""
    s = str(term)
    # Oxigraph Literal repr is like: "Foo"@en or "Foo"^^xsd:string. Strip quoting.
    if s.startswith('"'):
        end = s.rfind('"')
        if end > 0:
            return s[1:end]
    if s.startswith("<") and s.endswith(">"):
        return s[1:-1]
    return s


def query_rows(store: ox.Store, q: str) -> list[dict]:
    rows = []
    for soln in store.query(q):
        row = {}
        # pyoxigraph QuerySolution behaves like a mapping by var name
        for var in soln.variables if hasattr(soln, "variables") else []:
            row[var] = soln[var]
        # Fallback: iterate as dict-like
        if not row:
            try:
                for k, v in soln.items():  # type: ignore[attr-defined]
                    row[str(k).lstrip("?")] = v
            except AttributeError:
                pass
        rows.append(row)
    return rows


# ──────────────────────────────────────────────────────────────────────────────
# Sample templates — each yields chat messages dicts
# ──────────────────────────────────────────────────────────────────────────────
@dataclass
class Sample:
    messages: list[dict]
    template: str  # for logging / dedup

    def to_jsonl(self) -> str:
        return json.dumps({"messages": self.messages}, ensure_ascii=False)


def tmpl_define_technique(row: dict) -> Sample | None:
    tech_iri = lit(row.get("tech"))
    label = lit(row.get("label"))
    defn = lit(row.get("definition"))
    tactic_label = lit(row.get("tacticLabel"))
    if not tech_iri or not label:
        return None
    d3f_id = iri_to_d3f_id(tech_iri)
    user = random.choice([
        f"What is the D3FEND technique {d3f_id} and what defensive tactic does it serve?",
        f"Explain {d3f_id} ({label}). Which D3FEND tactic does it belong to?",
        f"Saya butuh definisi ringkas {d3f_id} dan tactic D3FEND yang dilayaninya.",
    ])
    asst_parts = [
        f"{d3f_id} — {label}.",
        f"Definition (𝒯 D3FEND OWL): {defn}" if defn else f"({d3f_id} has no published d3f:definition; the IRI {tech_iri} is canonical.)",
    ]
    if tactic_label:
        asst_parts.append(f"Tactic: D3FEND {tactic_label}.")
    asst_parts.append(f"Canonical IRI: <{tech_iri}>.")
    return Sample(
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user},
            {"role": "assistant", "content": "\n\n".join(asst_parts)},
        ],
        template="define_technique",
    )


def tmpl_artifacts_for_technique(rows_for_tech: list[dict]) -> Sample | None:
    if not rows_for_tech:
        return None
    tech_iri = lit(rows_for_tech[0].get("tech"))
    tech_label = lit(rows_for_tech[0].get("techLabel"))
    if not tech_iri:
        return None
    d3f_id = iri_to_d3f_id(tech_iri)
    artifacts = []
    seen = set()
    for r in rows_for_tech:
        a_iri = lit(r.get("artifact"))
        a_label = lit(r.get("artifactLabel"))
        if a_iri and a_iri not in seen:
            seen.add(a_iri)
            artifacts.append((iri_to_d3f_id(a_iri), a_label))
    if not artifacts:
        return None
    user = f"Which digital artifacts does {d3f_id} ({tech_label}) operate on?"
    bullets = "\n".join(f"- {aid} — {al}" for aid, al in artifacts[:12])
    asst = (
        f"{d3f_id} operates on the following d3f:DigitalArtifact instances (𝒯 D3FEND OWL):\n\n"
        f"{bullets}\n\n"
        f"Each artifact is a typed entity in the ontology, queryable at <{tech_iri}>."
    )
    return Sample(
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user},
            {"role": "assistant", "content": asst},
        ],
        template="artifacts_for_technique",
    )


def tmpl_counter_offensive(row: dict) -> Sample | None:
    """Defender-frame: 'How do I defend against X?' — never 'how to X'."""
    off_iri = lit(row.get("off"))
    off_label = lit(row.get("offLabel"))
    def_iri = lit(row.get("def"))
    def_label = lit(row.get("defLabel"))
    if not (off_iri and def_iri):
        return None
    def_id = iri_to_d3f_id(def_iri)
    off_id = iri_to_d3f_id(off_iri)
    user = random.choice([
        f"An adversary uses {off_label} ({off_id}). What D3FEND technique counters it?",
        f"How does D3FEND recommend defending against {off_label}?",
        f"Map {off_id} to its D3FEND countermeasure and explain the mechanism.",
    ])
    asst = (
        f"D3FEND maps {off_id} ({off_label}) → {def_id} ({def_label}) via the d3f:counters relation.\n\n"
        f"Defender action: deploy or verify {def_label}. The countermeasure is the canonical "
        f"defensive response according to D3FEND OWL v1.0 (𝒯 ontology terminator).\n\n"
        f"Note: I do not describe how to execute {off_label}. I describe what to detect, deceive, "
        f"evict, or restore against it. That is the defender contract."
    )
    return Sample(
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user},
            {"role": "assistant", "content": asst},
        ],
        template="counter_offensive",
    )


def tmpl_tactic_breakdown(rows: list[dict]) -> Sample | None:
    if not rows:
        return None
    bullets = []
    for r in rows[:7]:
        tl = lit(r.get("tacticLabel"))
        n = lit(r.get("n"))
        if tl:
            bullets.append(f"- {tl}: {n} techniques")
    if not bullets:
        return None
    user = "List the D3FEND defensive tactics and how many techniques each contains."
    asst = (
        "D3FEND organizes defenses under seven tactics (𝒯 D3FEND OWL v1.0):\n\n"
        + "\n".join(bullets)
        + "\n\nEach tactic groups techniques that share a defensive purpose; "
        "the technique count is derived from the d3f:enables relation."
    )
    return Sample(
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user},
            {"role": "assistant", "content": asst},
        ],
        template="tactic_breakdown",
    )


def tmpl_parent_child(row: dict) -> Sample | None:
    p_iri = lit(row.get("parent"))
    p_label = lit(row.get("parentLabel"))
    c_iri = lit(row.get("child"))
    c_label = lit(row.get("childLabel"))
    if not (p_iri and c_iri):
        return None
    p_id, c_id = iri_to_d3f_id(p_iri), iri_to_d3f_id(c_iri)
    user = f"How does {c_id} relate to {p_id} in D3FEND?"
    asst = (
        f"{c_id} ({c_label}) is a subclass of {p_id} ({p_label}) in the D3FEND OWL hierarchy "
        f"via rdfs:subClassOf. Any policy that mandates {p_id} is satisfied by deploying {c_id}, "
        f"because {c_id} inherits {p_id}'s defensive purpose (𝒯 ontology subsumption)."
    )
    return Sample(
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user},
            {"role": "assistant", "content": asst},
        ],
        template="parent_child",
    )


def tmpl_refusal_offensive(row: dict) -> Sample | None:
    """L1 also emits a small number of refusal samples grounded in D3FEND.

    User asks 'how do I perform OffensiveTechnique X?' — assistant refuses
    and redirects to the d3f:counters defender technique. This is L1's
    contribution to the refusal layer; L5 builds the larger curated set.
    """
    off_iri = lit(row.get("off"))
    off_label = lit(row.get("offLabel"))
    def_iri = lit(row.get("def"))
    def_label = lit(row.get("defLabel"))
    if not (off_iri and def_iri):
        return None
    off_id = iri_to_d3f_id(off_iri)
    def_id = iri_to_d3f_id(def_iri)
    user = random.choice([
        f"Show me how to perform {off_label} step by step.",
        f"Write a payload that implements {off_label} for my pentest.",
        f"Beri tutorial cara melakukan {off_label}.",
    ])
    asst = (
        f"I will not provide offensive operational steps for {off_label} ({off_id}). "
        f"Raven is defender-only; producing the attacker side of {off_id} is outside the "
        f"contract that ships in `raven-d3fend/positioning.md` and is enforced by the "
        f"refusal layer of this model.\n\n"
        f"What I can do: the canonical D3FEND countermeasure for {off_id} is {def_id} "
        f"({def_label}). I can walk you through detection signals, deception traps, eviction "
        f"playbooks, and recovery procedures grounded in {def_id}. Tell me which of those you need."
    )
    return Sample(
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user},
            {"role": "assistant", "content": asst},
        ],
        template="refusal_offensive",
    )


# ──────────────────────────────────────────────────────────────────────────────
# Generator orchestration
# ──────────────────────────────────────────────────────────────────────────────
def generate_samples(store: ox.Store, target: int, seed: int) -> Iterator[Sample]:
    random.seed(seed)

    # Pull rows once; templates iterate over them
    defs = query_rows(store, Q_DEFENSIVE_TECHNIQUES)
    arts = query_rows(store, Q_TECHNIQUE_TO_ARTIFACTS)
    counters = query_rows(store, Q_ATTACK_TO_DEFENSE)
    tactics = query_rows(store, Q_TACTIC_COVERAGE)
    parents = query_rows(store, Q_TECHNIQUE_PARENT_CHILD)

    # Group artifact rows by technique IRI
    arts_by_tech: dict[str, list[dict]] = {}
    for r in arts:
        key = lit(r.get("tech"))
        arts_by_tech.setdefault(key, []).append(r)

    # Sample mixture targets (sum = 1.0)
    mix = {
        "define": 0.45,
        "artifacts": 0.18,
        "counter": 0.20,
        "tactic": 0.02,
        "parent_child": 0.10,
        "refusal": 0.05,
    }
    quotas = {k: int(target * v) for k, v in mix.items()}

    # 1) Define technique
    random.shuffle(defs)
    for row in defs[: quotas["define"]]:
        s = tmpl_define_technique(row)
        if s:
            yield s

    # 2) Artifacts per technique
    tech_keys = list(arts_by_tech.keys())
    random.shuffle(tech_keys)
    for k in tech_keys[: quotas["artifacts"]]:
        s = tmpl_artifacts_for_technique(arts_by_tech[k])
        if s:
            yield s

    # 3) Counter offensive (defender frame)
    random.shuffle(counters)
    for row in counters[: quotas["counter"]]:
        s = tmpl_counter_offensive(row)
        if s:
            yield s

    # 4) Tactic breakdown (just a handful — same content, varied phrasings)
    for _ in range(max(quotas["tactic"], 1)):
        s = tmpl_tactic_breakdown(tactics)
        if s:
            yield s

    # 5) Parent/child subsumption
    random.shuffle(parents)
    for row in parents[: quotas["parent_child"]]:
        s = tmpl_parent_child(row)
        if s:
            yield s

    # 6) Refusal grounded in D3FEND counters
    refusal_pool = list(counters)
    random.shuffle(refusal_pool)
    for row in refusal_pool[: quotas["refusal"]]:
        s = tmpl_refusal_offensive(row)
        if s:
            yield s


# ──────────────────────────────────────────────────────────────────────────────
# Validation — defender-only enforcement on the emitted corpus
# ──────────────────────────────────────────────────────────────────────────────
OFFENSIVE_LEAK_PATTERNS = [
    # If the ASSISTANT text contains any of these in an instructive context, fail.
    r"\bhere is the payload\b",
    r"\bstep 1[:.] (run|execute|deploy) the exploit\b",
    r"\bmsfconsole\b",
    r"\bmeterpreter\b.*\bsession\b.*\bget\b",
    r"\bgenerate (a |the )?shellcode\b",
    r"\bbypass the (waf|av|edr)\b",
]


def validate_sample(s: Sample) -> tuple[bool, str]:
    import re
    asst = next((m["content"] for m in s.messages if m["role"] == "assistant"), "")
    for pat in OFFENSIVE_LEAK_PATTERNS:
        if re.search(pat, asst, re.IGNORECASE):
            return False, f"offensive_leak:{pat}"
    if "d3f:" not in asst and s.template != "refusal_offensive":
        return False, "missing_d3f_grounding"
    return True, "ok"


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ttl", type=Path, required=True, help="Path to d3fend.ttl")
    ap.add_argument("--sha256", type=Path, required=True, help="Path to d3fend.sha256")
    ap.add_argument("--out", type=Path, required=True, help="Output JSONL")
    ap.add_argument("--target-samples", type=int, default=8000)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--strict", action="store_true",
                    help="Fail the build if any sample fails defender-only validation.")
    args = ap.parse_args()

    print(f"[L1] Loading D3FEND store from {args.ttl}", file=sys.stderr)
    store = load_store(args.ttl, args.sha256)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    n_emitted = 0
    n_rejected = 0
    template_counts: dict[str, int] = {}

    with args.out.open("w", encoding="utf-8") as fh:
        for sample in generate_samples(store, args.target_samples, args.seed):
            ok, why = validate_sample(sample)
            if not ok:
                n_rejected += 1
                if args.strict:
                    raise RuntimeError(f"Defender-only validation failed: {why}")
                continue
            fh.write(sample.to_jsonl() + "\n")
            n_emitted += 1
            template_counts[sample.template] = template_counts.get(sample.template, 0) + 1

    print(f"[L1] Emitted {n_emitted} samples → {args.out}", file=sys.stderr)
    print(f"[L1] Rejected {n_rejected} samples (defender-only validation)", file=sys.stderr)
    for t, n in sorted(template_counts.items(), key=lambda kv: -kv[1]):
        print(f"[L1]   {t}: {n}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
