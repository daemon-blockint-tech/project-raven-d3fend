---
name: raven-zero-day-threat-patterns
description: Curate, query, and emit Raven's catalog of 0-day threat patterns. Use when the user says "0-day pattern", "exploit pattern library", "threat fingerprint", "variant template", "bug-class taxonomy", "match this finding against known patterns", or asks to extend the YARA / Semgrep / ARES rule packs with a new 0-day archetype. Every pattern record terminates at a tool oracle (𝒯) or a classical-ML detector (𝓜) — never raw LLM speculation — and ships with the CWE plus D3FEND Harden / Detect technique ids it counters.
---

# Raven — 0-Day Threat Patterns

This skill is the curator of Raven's pattern library. It does not hunt and it does not fix — it owns the catalog that the hunting, detection, investigator, prevention, and fixing skills all read from. Treat patterns as durable assets: every pattern in the library MUST be reproducible, machine-checkable, and bound to a CWE plus one or more D3FEND techniques.

## When to use

Trigger when the user asks any of:

- "Show me Raven's 0-day patterns for `<bug class>`"
- "Add a new pattern for CVE-YYYY-NNNNN"
- "Match this finding against the pattern library"
- "Promote this hypothesis into a permanent pattern"
- "Export the pattern pack for ARES / Semgrep / YARA"
- "What patterns cover CWE-`<id>`?"

Do not trigger for: running a hunt (use `raven-zero-day-hunter`), validating a single finding (use `raven-zero-day-investigator`), or generating mitigations (use `raven-zero-day-fixing`).

## Inputs

Required:

1. Mode — one of: `list`, `query`, `add`, `match`, `export`
2. Filter (for `list` / `query`) — any of: `bug_class`, `cwe`, `d3fend_id`, `target_type`, `seed_cve`

For `add`:

- `seed_cve` (optional) — CVE to derive the pattern from
- `bug_class` — must be one of the canonical classes (memory-corruption, integer-overflow, race-condition, auth-bypass, deserialization, type-confusion, signature-malleability, account-confusion, oracle-manipulation, deserialization, ssrf, prompt-injection)
- `target_type` — `solana-program`, `evm-contract`, `c-cpp-source`, `rust-source`, `binary-elf`, `binary-pe`, `android-apk`, `linux-kernel-module`, `web-app`, `llm-service`
- `detector` — at least one tool-oracle rule (ARES / Semgrep / YARA / Nuclei template / IsolationForest feature vector) — patterns without detectors are rejected

## Pattern record schema

Every entry in the library is a JSON record with these fields. Records live under `raven/patterns/<bug_class>/<pattern_id>.json` plus a denormalized `raven/patterns/index.parquet` for fast queries.

```json
{
  "pattern_id": "P-2026-0042",
  "title": "Solana CPI privilege escalation via missing owner check",
  "bug_class": "auth-bypass",
  "cwe": "CWE-862",
  "target_type": "solana-program",
  "seed_cves": ["CVE-2024-XXXXX", "CVE-2024-YYYYY"],
  "preconditions": [
    "Program performs CPI to caller-controlled account",
    "No assert_eq!(account.owner, expected_program_id)"
  ],
  "detectors": [
    {
      "kind": "ares",
      "rule_id": "ares.solana.owner_check_missing",
      "evidence_kind": "static-AST"
    },
    {
      "kind": "semgrep",
      "rule_id": "raven.solana.cpi.missing_owner_check",
      "evidence_kind": "static-text"
    }
  ],
  "d3fend_countermeasures": ["D3-SCH", "D3-IVV", "D3-AH"],
  "false_positive_rate_observed": 0.07,
  "true_positive_rate_observed": 0.91,
  "last_validated_at": "2026-05-12T00:00:00Z",
  "validator_runs": 312,
  "provenance": {
    "added_by": "raven-zero-day-hunter",
    "added_at": "2026-04-30T00:00:00Z",
    "promoted_from_hypothesis_id": "H-2026-0987"
  }
}
```

Records that lack `detectors` or `d3fend_countermeasures` are invalid and MUST be rejected at write time.

## Pipeline — mode-specific

### Mode `list` and `query`

1. Load `raven/patterns/index.parquet`.
2. Apply filters (DuckDB query inline — no full-table scan).
3. Return matching `pattern_id` + `title` + `bug_class` + `cwe` + `d3fend_countermeasures` + `true_positive_rate_observed`.

Limit default 50, configurable up to 500.

### Mode `add`

1. Validate `bug_class` is in the canonical list.
2. Validate every `detector.rule_id` exists in the corresponding tool pack (call into `raven/tools/ares.py`, `raven/tools/yara_scanner.py`, etc. to confirm the rule loads).
3. Run `raven.d3fend.api.lookup_technique` on every entry in `d3fend_countermeasures` — reject if any id is not in the ontology.
4. Run `raven.d3fend.api.cwe_to_d3fend(record.cwe)` — at least one returned technique MUST overlap with `d3fend_countermeasures`. This is the cross-check that prevents arbitrary D3FEND IDs from being attached.
5. Persist as JSON, regenerate `index.parquet`, commit with a structured message: `pattern: add P-YYYY-NNNN <title>`.

### Mode `match`

1. Accept a finding (from `raven-zero-day-investigator`) as input.
2. Cross-reference its `cwe`, `target_type`, and `evidence_features` against the library.
3. Score each candidate pattern with cosine similarity of the evidence feature vector against the pattern's exemplar vector (`raven/ml/zero_day_detector.py` provides the embedding).
4. Return top-K patterns with score ≥ 0.65 and never return a match below 0.50 — below that, emit `no_match` rather than a noisy false positive.

### Mode `export`

Exports a deterministic, version-tagged pack:

- `pack/ares/` — ARES rules
- `pack/semgrep/` — Semgrep rules
- `pack/yara/` — YARA rules
- `pack/nuclei/` — Nuclei templates (own-asset use only — defender edition)
- `pack/manifest.json` — pin SHAs, pattern ids, D3FEND coverage delta

Pack version is the git short-SHA of the patterns directory at export time.

## CDP grounding — non-negotiable

Patterns are static, but the skill's emissions are not. Every `match` result and every `add` validation MUST be grounded:

- 𝒯 — the actual ARES / Semgrep / YARA rule must compile and load. The skill verifies by invoking the tool oracle on a known-good fixture and a known-bad fixture before accepting the pattern.
- 𝓜 — `raven/ml/zero_day_detector.py` provides the feature embedding used for similarity scoring. Embeddings produced from LLM-only output are rejected — the embedding pipeline must read the actual source artifact.
- 𝓛 — when promoting a hypothesis to a pattern, the hypothesis must carry validator evidence from at least three independent hunts (`validator_runs ≥ 3`). Single-shot hypotheses do not become patterns.

## Defender-only enforcement

The skill MUST NOT accept patterns whose `detectors` reference excluded modules: `raven/redteam/offensive.py`, `raven/tools/metasploit_integration.py`, `raven/tools/empire_client.py`, `raven/tools/exploitdb*.py`. Any such reference fails validation. The skill MUST NOT export an "exploit recipe" form — the pack format is detector-only.

## Output contract

For `list` / `query` / `match`:

```markdown
# Pattern query — <filter summary>

| Pattern | Title | CWE | D3FEND | TPR | FPR | Last validated |
|---------|-------|-----|--------|-----|-----|----------------|
| P-2026-0042 | Solana CPI missing owner check | CWE-862 | D3-SCH, D3-IVV, D3-AH | 0.91 | 0.07 | 2026-05-12 |
| ... |
```

For `add`:

```markdown
# Pattern added — P-YYYY-NNNN

- Title: <title>
- CWE: <cwe>
- D3FEND: <id list>
- Detectors loaded: <n>
- Cross-check D3FEND ⇄ CWE: PASS (overlap on <id>)
- Index regenerated: <row count>
- Commit: <sha>
```

For `export`:

```markdown
# Pattern pack exported — v<git-short-sha>

- Patterns: <n>
- ARES rules: <n> / Semgrep: <n> / YARA: <n> / Nuclei: <n>
- D3FEND coverage delta vs previous pack: +<n> -<n>
- Manifest: pack/manifest.json
- SHA-256: <hash>
```

## Refusal rules

1. Refuse to add a pattern without at least one working detector.
2. Refuse to add a pattern without at least one D3FEND countermeasure id.
3. Refuse to add a pattern whose D3FEND ids do not cross-check against the CWE.
4. Refuse to export an "exploit pack" — defender edition is detector-only.
5. Refuse to promote a hypothesis with `validator_runs < 3`.

## Related skills

- `raven-zero-day-hunter` — produces hypotheses; this skill curates which ones become permanent patterns.
- `raven-zero-day-investigator` — consumes pattern library via `match` mode.
- `raven-zero-day-detection` — consumes the exported pack as its runtime ruleset.
- `raven-zero-day-fixing` — reads `d3fend_countermeasures` to drive remediation.
- D3FEND OWL integration (`raven/d3fend/`) — source of truth for the technique ids that every pattern must bind to ([D3FEND home](https://d3fend.mitre.org/)).
