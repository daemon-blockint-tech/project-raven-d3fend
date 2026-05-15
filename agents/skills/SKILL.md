---
name: raven-zero-day-hunter
description: Run Project Raven's MDASH (Multi-Model Agentic Security Harness) pipeline against a target codebase or runtime. Use when the user says "hunt 0-days", "look for zero-days", "ARES scan", "variant analysis", "memory corruption hunt", "kernel/driver hunt", "smart-contract 0-day", or asks Raven to anticipate kill chains, generate exploit hypotheses, or validate LLM-claimed vulnerabilities. Every finding ends in a tool-oracle (𝒯), classical-ML detector (𝓜), or scored hypothesis (𝓛) — never raw LLM speculation — and ships with D3FEND defensive techniques, ATT&CK offensive context, and real-world exposure scoring.
---

# Raven — 0-Day Threat Hunter

This skill drives Project Raven's MDASH (Multi-Model Agentic Security Harness) pipeline. It composes modules from `pipeline/` into a single end-to-end flow:

```
target ─► prepare ─► scan ─► validate ─► dedup ─► prove ─► enrich ─► report
         │           │          │          │        │         │
         │           │          │          │        │         └─ D3FEND + ATT&CK + threat intel
         │           │          │          │        └─ symbolic execution / formal verification
         │           │          │          └─ semantic clustering
         │           │          └─ multi-model debate
         │           └─ 100+ specialized auditor agents
         └─ surface map + threat model + cross-language taint
```

Every emission terminates at a tool oracle, a classical-ML detector, or a scored hypothesis. This is the CDP (Compositional Defense Pipelines) contract — the skill MUST NOT print a free-text "this looks vulnerable" verdict that is not backed by one of those three terminators.

The skill is defender-first. It MUST NOT load `raven/redteam/offensive.py`, `raven/tools/metasploit_integration.py`, `raven/tools/empire_client.py`, `raven/tools/exploitdb*.py`, or any other excluded-from-Defender-Edition module listed in `raven-modules.md`.

## When to use

Trigger when the user asks any of:

- "Hunt 0-days in `<repo>` / `<binary>` / `<program>`"
- "Run ARES on this Solana program"
- "Variant analysis for CVE-YYYY-NNNNN"
- "Find memory corruption in this binary"
- "Kernel / driver / firmware 0-day hunt"
- "Anticipate the kill chain for this incident"
- "Validate this LLM-claimed bug"
- "Score the exploitability of `<finding>`"

Do not trigger for: routine SAST runs, dependency-CVE lookups, or generic "audit my code" requests that should go through ARES directly.

## Inputs

Required from the user (ask if missing):

1. Target type — one of: `solana-program`, `evm-contract`, `c-cpp-source`, `rust-source`, `android-apk`, `binary-elf`, `binary-pe`, `linux-kernel-module`, `live-host`, `network-range-own-assets`
2. Target locator — repo URL, file path, or host. Must be an asset the user owns or is authorized to test. Refuse otherwise.
3. Trial budget — Cybergym-style. Default `(trials=10, cost_cap_usd=2.00)`. Confirm with user for budgets >$10.

Optional:

- Prior CVE family for variant analysis (`cve_seed=CVE-2024-XXXXX`)
- Kill-chain anticipation flag (`anticipate=True` runs `raven/hunters/kill_chain_planner.py` after the validation pass)
- Approval mode (`smart` default, `manual` for any action with destructive blast radius)

## Pipeline — five mandatory stages

### Stage 1 — Surface mapping (𝒯-grounded)

Pick the right tool oracle by target type. Do not skip — this is the grounding step that makes every later claim auditable.

| Target | Pipeline modules |
|--------|------------------|
| `solana-program` | `pipeline/prepare/ingester.py` + `pipeline/cross_language/solidity_analyzer.py` |
| `evm-contract` | `pipeline/prepare/ingester.py` + `pipeline/cross_language/solidity_analyzer.py` |
| `c-cpp-source` / `rust-source` | `pipeline/prepare/indexer.py` + `pipeline/cross_language/ffi_analyzer.py` + `pipeline/cross_language/taint_tracker.py` |
| `android-apk` | `pipeline/prepare/ingester.py` + `pipeline/cross_language/wasm_analyzer.py` |
| `binary-elf` / `binary-pe` | `pipeline/prepare/indexer.py` |
| `linux-kernel-module` | `pipeline/prepare/indexer.py` + `pipeline/cross_language/ffi_analyzer.py` |
| `live-host` | `pipeline/prepare/threat_modeler.py` |
| `network-range-own-assets` | `pipeline/prepare/threat_modeler.py` |

Output: a structured `SurfaceMap` JSON listing entry points, syscalls/instructions of interest, ABI boundaries, and known-good baselines.

### Stage 2 — Scan / Hypothesis generation (𝓛-scored)

Invoke `pipeline/scan/agent_router.py` with the `SurfaceMap` and `ThreatModel`. The router dispatches to specialized auditor agents (100+ agents by bug class) from `pipeline/scan/`. Cross-language targets also receive taint analysis from `pipeline/cross_language/taint_tracker.py` to flag data flows across language boundaries.

Each agent emits `CandidateFinding` objects with:

- A `bug_class` (one of: memory-corruption, integer-overflow, race-condition, auth-bypass, deserialization, type-confusion, signature-malleability, account-confusion, oracle-manipulation, etc.)
- A `location` (file + line range, or function symbol, or instruction address)
- A `precondition` (what attacker control is required)
- A `hypothesis_score` in `[0, 1]` — the LLM's confidence, NOT the verdict
- A linked CWE id (used in Stage 6 for D3FEND routing)

Hypotheses are scored objects; they are NEVER the final verdict. Print them as "candidates", not "findings".

### Stage 3 — Variant analysis branch (optional, 𝓜-detected)

If `cve_seed` is set, run `raven/ml/variant_analyzer.py` against the seed CVE's pattern. This is the ZeroDayBench-style branch: it surfaces near-clones of the seed bug elsewhere in the target. Output is a `VariantCandidate` list — also scored objects, also routed to Stage 4.

### Stage 4 — Validate / Multi-model debate (� → 𝒯)

For each candidate from Stage 2 or Stage 3, invoke `pipeline/validate/debate_orchestrator.py`. This runs a cohort of debater agents (different models arguing for/against exploitability) from `pipeline/validate/`. No claim escapes this stage without passing debate.

Validation paths by `bug_class`:

| `bug_class` | Pipeline validators |
|-------------|---------------------|
| memory-corruption | `pipeline/prove/sanitizer_runner.py` (ASan/MSan) + `pipeline/prove_extension/formal_verification.py` |
| race-condition | `pipeline/prove/sanitizer_runner.py` (TSan) + `pipeline/prove_extension/formal_verification.py` |
| auth-bypass | `pipeline/prove/sandbox.py` + `pipeline/prove_extension/formal_verification.py` |
| signature-malleability / account-confusion / oracle-manipulation | `pipeline/cross_language/solidity_analyzer.py` + `pipeline/cross_language/taint_tracker.py` |
| deserialization | `pipeline/prove/harness_builder.py` + `pipeline/prove/fuzzer.py` |
| every class | `pipeline/scan/finding_collector.py` cross-reference against NVD/OSV to filter known issues |

A candidate emerges from Stage 4 as either:

- `ValidatedFinding` — debate confirmed with confidence ≥ threshold
- `unconfirmed` — no debate consensus; downgraded back to a low-prior hypothesis
- `false_positive` — explicit refutation by debaters or tool oracle

Only `ValidatedFinding` records advance to Stage 5.

### Stage 5 — Dedup (𝓜)

Run `pipeline/dedup/clustering.py` to collapse semantically equivalent findings. Uses embeddings from `pipeline/dedup/embedding_generator.py` and merges via `pipeline/dedup/merger.py`.

### Stage 6 — Prove (𝒯-grounded)

For each deduplicated finding, invoke `pipeline/prove/poc_generator.py` and `pipeline/prove/harness_builder.py`. For cryptographic properties, also invoke `pipeline/prove_extension/formal_verification.py`.

Proof stages:
- Self-contained claim (minimal code snippet)
- Reachability harness (instrumented trigger)
- Fuzzing / symbolic execution (`pipeline/prove/fuzzer.py`, `pipeline/prove/sandbox.py`)

Output: `ProvenFinding` with PoC artifacts and sanitizer results.

### Stage 7 — Enrich (𝒯 + 𝓜)

For every `ProvenFinding`, invoke `pipeline/d3fend/enrichment_engine.py` to bind:

1. **D3FEND defensive techniques** — from `pipeline/d3fend/d3fend_catalog_loader.py` (real 271-entry catalog) + `pipeline/d3fend/ontology_client.py`
2. **ATT&CK offensive techniques** — from `pipeline/d3fend/attack_mapper.py` for threat actor context
3. **Exposure scoring** — from `pipeline/threat_intel/onchain_threat_intel.py` for real-world impact
4. **Compliance mapping** — from `pipeline/d3fend/cci_loader.py` (CCI-to-D3FEND NIST SP 800-53 mappings)

Every finding shipped in the final report has:

- `cwe` — the CWE id
- `d3fend_techniques` — list of `D3FENDTechnique` (id, label, tactic, definition)
- `attack_techniques` — list of `ATTACKTechnique` (id, name, tactic) for threat context
- `exposure_score` — real-world exposure 0-100
- `threat_narrative` — human-readable exploitation scenario
- `recommended_remediation` — from `pipeline/d3fend/remediation.py`, gated by approval

A finding without `d3fend_techniques` or `attack_techniques` is a bug in this skill, not a feature.

## Approval gate (Hermes-style, mandatory)

Before any action with destructive blast radius (process kill, network isolation, account disable, patch apply, host quarantine), route through `raven/approval/gate.py`. Default mode is `smart` (auxiliary LLM auto-approves benign read-only actions) but anything matched by `raven/approval/patterns.py:UNRECOVERABLE_BLOCKLIST` (rm -rf /, fork bombs, mkfs /dev/sd*) is hard-rejected even in `smart` mode and requires explicit user override.

The skill MUST NOT bypass the gate by invoking containment / remediation modules directly. Always call `raven.mitigation.response_orchestrator.execute(...)` which wires the gate in.

## Trial budget protocol — Cybergym-aligned

The skill implements the Anthropic Cybergym evaluation pattern referenced in the [Anthropic AI for Cyber Defenders post](https://red.anthropic.com/2025/ai-for-cyber-defenders/): repeated trials with a hard cost cap.

- `trials=1` — fast smoke pass, returns top-prior candidate only
- `trials=10` — default; spreads across hypotheses to surface long-tail bugs
- `trials=30` — deep mode; only run if `cost_cap_usd >= $5.00`

Hard cap: skill aborts the loop the instant cumulative cost reaches `cost_cap_usd`. Partial findings are reported with a `truncated_by_budget=True` flag.

## Output contract

The skill emits exactly one Markdown report with this skeleton:

```markdown
# Raven 0-Day Hunt — <target>

## Run metadata
- Target: <locator>
- Trials: <n> / cost: $<spend>
- Approval mode: <smart|manual>
- Pipeline stages completed: prepare, scan, [variants], validate, dedup, prove, enrich

## Findings (<count>)

### Finding F-<n>: <one-line summary>
- Bug class: <class>
- Location: <file:lines or symbol or address>
- CWE: CWE-<id>
- Stage 2 score: <hypothesis_score>
- Stage 3 debate: <models> → <vote> (confidence: <conf>)
- Stage 4 cluster: <cluster_id> (<cluster_size> findings merged)
- Stage 5 proof: <status> (PoC: <has_poc>)
- D3FEND countermeasures: <id1> (<tactic1>), <id2> (<tactic2>), ...
- ATT&CK techniques: <id1> (<name1>), <id2> (<name2>), ...
- Exposure score: <score>/100 (threat actor likelihood: <HIGH|MEDIUM|LOW>)
- Threat narrative: <narrative>
- Remediation: <remediation_engine output, awaiting approval / approved / applied>
- Confidence: <validated|high|medium>  ← never "low"; low-confidence items are unconfirmed, not findings

(repeat per finding)

## Unconfirmed hypotheses (<count>)
| Candidate | Prior | Why unconfirmed |
|-----------|-------|-----------------|

## False positives suppressed (<count>)
| Candidate | Reason |
|-----------|--------|

## Kill-chain anticipation (if anticipate=True)
- Next ATT&CK technique most likely: <T-id> (<label>)
- D3FEND countermeasures to deploy now: <id list>

## Reproducibility kit
- Commit: <git sha>
- Datasets: <hashes>
- Random seeds: <values>
- Scoring rubric: <path>
```

## Refusal rules

The skill MUST refuse, with a one-line reason, when:

1. The target is not owned or authorized by the user. Ask for written attestation or refuse outright.
2. The user asks for an exploit payload, weaponized PoC, or ATT&CK technique execution. Raven is defender-only — point at D3FEND instead.
3. The user asks to disable the approval gate. Hard rejection.
4. The user asks to skip the Validate stage. The CDP contract is non-negotiable.
5. The user asks to mark unvalidated hypotheses as findings. Hypotheses are not findings.

## Reproducibility — grant-credible kit

Every run writes a `reproducibility/<run-id>/` directory containing:

- `manifest.json` — target hash, tool versions, model id, model temperature (always `0` for validators), random seed, trial budget, wall-clock and cost ledger
- `hypotheses.jsonl` — every Stage 2 emission
- `validation_traces/` — raw tool-oracle outputs (ARES rule hits, Ghidra decompilation snippets, code-flow taint traces, etc.)
- `findings.json` — final validated set with D3FEND bindings
- `d3fend-coverage-delta.md` — which D3FEND techniques this run exercised, regenerated from the `raven.d3fend.coverage` graph

This kit is what makes the OpenAI grant evaluator's "no human guided the scan" claim verifiable ([OpenAI Cybersecurity Grant Program](https://openai.com/index/openai-cybersecurity-grant-program/)).

## CDP contract — quick check before returning

Before returning the report, the skill walks every finding and asserts:

```
assert finding.validator_oracle is not None        # 𝒯
   or finding.ml_detector is not None              # 𝓜
   or finding.scored_hypothesis is not None        # 𝓛
assert finding.d3fend_techniques                   # at least one defensive technique
assert finding.attack_techniques                   # at least one offensive technique
assert finding.exposure_score is not None          # real-world exposure calculated
assert finding.confidence != "low"                 # low ⇒ unconfirmed bucket
```

Any failed assertion is a skill bug. Drop the finding into the unconfirmed bucket with an explicit reason rather than shipping it.

## Related skills and modules

- `pipeline/` — the source-of-truth implementation of all MDASH stages
- `pipeline/d3fend/` — D3FEND + ATT&CK enrichment engine with real MITRE catalog data
- `pipeline/threat_intel/` — on-chain exposure scoring for prioritization
- `pipeline/cross_language/` — cross-language taint tracking for multi-language targets
- `pipeline/plugin_synthesis/` — domain invariant extraction from source history
- `pipeline/prove_extension/` — symbolic execution and formal verification
- `pipeline/feedback/` — retrospective feedback loop for continuous improvement
- `pipeline/openai_agents_adapter/` — optional OpenAI Agents SDK backend for production-grade agent orchestration, tracing, and human-in-the-loop
- `pipeline/multi_agent_orchestrator/` — 100+ agent multi-model orchestration with dynamic model allocation and parallel async execution
- `agents/skills/multi-agent-orchestrator/` — skill definition for the multi-agent orchestrator
- `decoy/` subsystem — pair with this skill when the user wants to deploy tripwires alongside the hunt.
- `restore/` subsystem — invoked after a validated finding when the user asks for rollback / recovery, not just patching.
