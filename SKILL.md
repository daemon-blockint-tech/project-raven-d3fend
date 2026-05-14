---
name: raven-zero-day-hunter
description: Run Project Raven's 0-day threat hunting loop against a target codebase or runtime. Use when the user says "hunt 0-days", "look for zero-days", "ARES scan", "variant analysis", "memory corruption hunt", "kernel/driver hunt", "smart-contract 0-day", or asks Raven to anticipate kill chains, generate exploit hypotheses, or validate LLM-claimed vulnerabilities. Every finding ends in a tool-oracle (𝒯), classical-ML detector (𝓜), or scored hypothesis (𝓛) — never raw LLM speculation — and ships with a D3FEND countermeasure id.
---

# Raven — 0-Day Threat Hunter

This skill drives Project Raven's hypothesis-driven hunting loop. It composes the existing modules listed in `raven-modules.md` into a single end-to-end pipeline:

```
target ─► surface mapper ─► hypothesis generator ─► tool-oracle validator ─► scorer ─► D3FEND countermeasure ─► report
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

| Target | Tool oracle |
|--------|-------------|
| `solana-program` | `raven/tools/ares.py` + `raven/tools/ebpf_ghidra.py` |
| `evm-contract` | `raven/tools/ares.py` (EVM mode) |
| `c-cpp-source` / `rust-source` | `raven/ml/code_flow_scanner.py` |
| `android-apk` | `raven/tools/jadx_analyzer.py` + `raven/tools/frida_hook.py` (instrument-only, no exploit payloads) |
| `binary-elf` / `binary-pe` | `raven/tools/ghidra_analyzer.py` + `raven/tools/radare2.py` |
| `linux-kernel-module` | `raven/tools/ghidra_analyzer.py` + `raven/ml/memory_analyzer.py` |
| `live-host` | `raven/tools/nmap_scanner.py` + `raven/tools/nuclei_scanner.py` (own-asset only) |
| `network-range-own-assets` | `raven/tools/projectdiscovery.py` (subfinder/naabu/httpx) |

Output: a structured `SurfaceMap` JSON listing entry points, syscalls/instructions of interest, ABI boundaries, and known-good baselines.

### Stage 2 — Hypothesis generation (𝓛-scored)

Invoke `raven/hunters/hypothesis_generator.py` with the `SurfaceMap`. The LLM proposes a ranked list of candidate 0-day hypotheses. Each hypothesis MUST have:

- A `bug_class` (one of: memory-corruption, integer-overflow, race-condition, auth-bypass, deserialization, type-confusion, signature-malleability, account-confusion, oracle-manipulation, etc.)
- A `location` (file + line range, or function symbol, or instruction address)
- A `precondition` (what attacker control is required)
- A `prior` score in `[0, 1]` — the LLM's confidence, NOT the verdict
- A linked CWE id (used in Stage 5 for D3FEND routing)

Hypotheses are scored objects; they are NEVER the final verdict. Print them as "candidates", not "findings".

### Stage 3 — Variant analysis branch (optional, 𝓜-detected)

If `cve_seed` is set, run `raven/ml/variant_analyzer.py` against the seed CVE's pattern. This is the ZeroDayBench-style branch: it surfaces near-clones of the seed bug elsewhere in the target. Output is a `VariantCandidate` list — also scored objects, also routed to Stage 4.

### Stage 4 — Tool-oracle validation (𝒯, mandatory)

For each candidate from Stage 2 or Stage 3, invoke `raven/ml/vulnerability_validator.py`. This is the G-Bind grounding step — no claim escapes this stage unsupported.

Validation paths by `bug_class`:

| `bug_class` | Validator tool oracles |
|-------------|------------------------|
| memory-corruption | `raven/ml/memory_analyzer.py` + ASan-style synthetic trigger in a sandbox (no exploit payload) |
| race-condition | `raven/ml/sequence_analyzer.py` + ThreadSanitizer-style trace |
| auth-bypass | symbolic execution stub via `raven/ml/code_flow_scanner.py` |
| signature-malleability / account-confusion / oracle-manipulation | `raven/tools/ares.py` (Solana / EVM rule pack) |
| deserialization | `raven/tools/yara_scanner.py` over the deserialization sinks + `raven/ml/code_flow_scanner.py` taint trace |
| every class | `raven/ml/cve_matcher.py` cross-reference against NVD/OSV to filter known issues |

A candidate emerges from Stage 4 as either:

- `validated_finding` — at least one tool oracle confirmed exploitability or strong indicators
- `unconfirmed` — no oracle confirmation; downgraded back to a low-prior hypothesis
- `false_positive` — explicit refutation by an oracle (e.g. cve_matcher matched a since-patched CVE)

Only `validated_finding` records advance to Stage 5.

### Stage 5 — D3FEND countermeasure binding (𝒯-grounded)

For every `validated_finding`, call `raven.d3fend.api.cwe_to_d3fend(finding.cwe)` and attach the returned D3FEND techniques to the finding. If `anticipate=True`, also call `attack_to_d3fend(predicted_attack_id)` from the kill-chain anticipator and append those Harden / Isolate / Detect techniques as defender next-steps.

Every finding shipped in the final report has:

- `cwe` — the CWE id (string)
- `d3fend_techniques` — list of `TechniqueRef` (id, label, tactic)
- `recommended_remediation` — joined from `raven/mitigation/remediation_engine.py` patch suggestions, gated by `raven/approval/gate.py`

A finding without `d3fend_techniques` is a bug in this skill, not a feature.

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
- Pipeline stages completed: surface, hypotheses, [variants], validated, d3fend

## Findings (<count>)

### Finding F-<n>: <one-line summary>
- Bug class: <class>
- Location: <file:lines or symbol or address>
- CWE: CWE-<id>
- Validator evidence: <which tool oracle, what it returned>
- D3FEND countermeasures: <id1> (<tactic1>), <id2> (<tactic2>), ...
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
4. The user asks to skip Stage 4 (validation). The CDP contract is non-negotiable.
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
assert finding.d3fend_techniques                   # at least one
assert finding.confidence != "low"                 # low ⇒ unconfirmed bucket
```

Any failed assertion is a skill bug. Drop the finding into the unconfirmed bucket with an explicit reason rather than shipping it.

## Related skills and modules

- `raven-modules.md` — the source-of-truth list of defender modules this skill is allowed to import.
- `docs/d3fend-coverage.md` — coverage matrix the skill cross-references in Stage 5.
- `decoy/` subsystem — pair with this skill when the user wants to deploy tripwires alongside the hunt.
- `restore/` subsystem — invoked after a validated finding when the user asks for rollback / recovery, not just patching.
- D3FEND OWL integration (`raven/d3fend/`) — the source of every countermeasure binding in Stage 5.
