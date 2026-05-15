---
name: raven-zero-day-investigator
description: Investigate a single 0-day alert or finding end-to-end and produce a grounded incident report. Use when the user says "investigate this alert", "triage this finding", "deep-dive this anomaly", "root-cause this 0-day candidate", "build a timeline for this incident", or hands over an alert from `raven-zero-day-detection`. Every conclusion terminates at a tool oracle (𝒯), classical-ML detector (𝓜), or scored hypothesis (𝓛) and ships with D3FEND Detect / Isolate / Evict technique ids, ATT&CK offensive context, and exposure scoring. Built for production DevSecOps: every finding has an owner, triage process, and Patch Tuesday deadline.
---

# Raven — 0-Day Investigator

This skill is Raven's depth-of-evidence layer in the MDASH (Multi-Model Agentic Security Harness) pipeline. Detection skills emit alerts; this skill turns one alert into a defensible incident record: timeline, root cause, blast radius, attribution-grade evidence, and recommended D3FEND next steps with ATT&CK threat context.

This skill is built for production DevSecOps at enterprise scale:
- Every finding has an owner, a triage process, and a Patch Tuesday deadline
- All reasoning occurs on private codebases (Windows, Hyper-V, Azure, drivers) that are not in any LLM training corpus
- The pipeline is the result of collaboration between ACS (Autonomous Code Security), MORSE (Offensive Research & Security Engineering), and WARP (Windows Attack Research and Protection)

It does NOT scan broadly (use `raven-zero-day-hunter`), does NOT enact defense (use `raven-zero-day-defend`), and does NOT patch (use `raven-zero-day-fixing`).

## When to use

Trigger when the user provides one (and only one) alert / finding and asks for:

- "Investigate / triage / deep-dive / root-cause this"
- "Build a timeline for this"
- "Was this a real 0-day or a false positive?"
- "How far did this go? What's the blast radius?"
- "What should I do next about this specific alert?"

Do not trigger for: broad scans, multi-incident campaigns (treat each alert separately), or pre-alert hunting (use `raven-zero-day-hunter`).

## Inputs

Required:

1. Alert record — JSON from `raven-zero-day-detection` OR a `ValidatedFinding` from `raven-zero-day-hunter` OR a free-form analyst description that includes target locator and observed indicators. Must include `finding_owner` for DevSecOps routing.
2. Investigation depth — `quick` (≤ 5 min, surface evidence only), `standard` (≤ 30 min, full timeline), `deep` (≤ 2 hours, includes binary RE / memory forensics)

Optional:

- Approval mode — `smart` default, `manual` for any sample collection that touches production data
- Cost cap — default $5 for `standard`, $20 for `deep`

## Pipeline — six mandatory stages

### Stage 1 — Alert validation (𝒯-grounded)

1. Reload the artifact named in the alert (file hash, binary path, host id, flow tuple).
2. Re-run the original detector(s) listed in `alert.detector_hits` using `pipeline/scan/agent_router.py` and `pipeline/scan/finding_collector.py`. If the rerun does not reproduce the hit, mark `reproducible=false` and continue — this is forensically important.
3. Re-extract features via `pipeline/prepare/indexer.py` and diff against the alert's stored feature vector. Significant drift triggers a `tampering_suspected` flag.
4. Route the validated alert to the assigned `finding_owner` per DevSecOps routing rules.

If `reproducible=false`, the investigation continues but the final report's `confidence` cannot exceed `medium`. The finding is still triaged because at Microsoft scale there is no quiet drawer for speculative findings.

### Stage 2 — Timeline reconstruction (𝒯-grounded)

Map the alert to a timeline using the appropriate pipeline modules by alert mode:

| Alert origin mode | Timeline source |
|-------------------|-----------------|
| `scan-file` / `scan-binary` | File metadata + `pipeline/prepare/ingester.py` + `pipeline/cross_language/wasm_analyzer.py` |
| `scan-memory` | `pipeline/prepare/indexer.py` process and network trees |
| `scan-flows` | Flow log replay via `pipeline/scan/finding_collector.py` |
| `monitor-host` | `pipeline/cross_language/taint_tracker.py` syscall trace replay |
| `scan-source` | `git blame` + `pipeline/prepare/indexer.py` |

Output is a list of `TimelineEvent` records with `ts`, `actor`, `action`, `evidence_source`, `evidence_path`. Events without an `evidence_source` are dropped — speculation does not enter the timeline.

### Stage 3 — Root-cause hypothesis (𝓛-scored)

Invoke `pipeline/scan/agent_router.py` with the timeline as context. Specialized auditor agents propose up to five ranked root-cause hypotheses. Each hypothesis must include:

- `bug_class`, `cwe`, `location`, `precondition`, `hypothesis_score` (LLM confidence)
- An explicit `falsification_test` — a concrete tool-oracle invocation that would refute the hypothesis
- Cross-file pattern references for private-codebase reasoning (kernel conventions, IRP invariants, IPC trust boundaries)

Hypotheses without a falsification test are rejected at this stage. The pipeline handles private Microsoft codebases that do not yield to pattern matching — a model has to actually reason about kernel calling conventions and component-internal idioms.

### Stage 4 — Falsification pass (𝒯-grounded, mandatory)

For each hypothesis from Stage 3, run its `falsification_test`. Use `pipeline/validate/debate_orchestrator.py` for code-level debate validation, and the specific pipeline module named in the test (`pipeline/prove/sandbox.py`, `pipeline/prove_extension/formal_verification.py`, `pipeline/cross_language/solidity_analyzer.py`, `pipeline/prove/harness_builder.py`) for the others.

Outcomes:

- `confirmed` — oracle reproduces the hypothesized condition
- `refuted` — oracle returns evidence inconsistent with the hypothesis
- `inconclusive` — oracle could not run or returned mixed signal

Only `confirmed` hypotheses become the report's root cause. Multiple confirmed hypotheses become an explicit list — the skill MUST NOT pick one arbitrarily.

### Stage 5 — Blast radius (𝒯-grounded)

For each `confirmed` root cause, enumerate exposure:

- Source-level: variant search via `pipeline/scan/agent_router.py` variant analysis branch against the confirmed pattern
- Host-level: `pipeline/threat_intel/onchain_threat_intel.py` exposure scoring for real-world impact assessment
- Identity-level: shared credential / token reuse via `pipeline/d3fend/enrichment_engine.py` compliance mapping
- Asset-level: cross-reference with `pipeline/prepare/threat_modeler.py` own-asset inventory
- **Exposure score**: `pipeline/threat_intel/onchain_threat_intel.py` calculates real-world exposure 0-100 and threat actor likelihood

Blast-radius items are returned as a structured list, not a prose paragraph.

### Stage 6 — Enrich / D3FEND + ATT&CK binding (𝒯-grounded)

For each confirmed root cause and each blast-radius item, invoke `pipeline/d3fend/enrichment_engine.py` to bind:

1. **D3FEND defensive techniques** — from `pipeline/d3fend/d3fend_catalog_loader.py` (real 271-entry catalog) + `pipeline/d3fend/ontology_client.py`
2. **ATT&CK offensive techniques** — from `pipeline/d3fend/attack_mapper.py` for threat actor context
3. **Exposure scoring** — from `pipeline/threat_intel/onchain_threat_intel.py` for real-world impact
4. **Compliance mapping** — from `pipeline/d3fend/cci_loader.py` (CCI-to-D3FEND NIST SP 800-53 mappings)

Bucket recommendations by tactic and rank by overlap count. Techniques returned by both D3FEND and ATT&CK queries rank higher.

Output is a `RecommendedActions` block in the report — these are recommendations only; this skill does not enact them.

## CDP contract — quick check before returning

```
assert every TimelineEvent.evidence_source is not None
assert every confirmed_hypothesis has at least one validator oracle hit (𝒯) or debate confirmation (𝓛)
assert every d3fend_id resolves through pipeline.d3fend.enrichment_engine
assert every attack_technique is populated from pipeline.d3fend.attack_mapper
assert report.exposure_score is not None from pipeline.threat_intel.onchain_threat_intel
assert report.confidence == "high" only if reproducible=true AND at least two confirmed hypotheses agree on the bug_class
assert report.finding_owner is assigned for DevSecOps routing
```

A failed assertion downgrades the report's `confidence` field — it does NOT crash the skill. The investigator's job is to ship the best honest answer, not the most confident one.

## Output contract

```markdown
# Raven 0-Day Investigation — <alert_id>

## Summary
- Verdict: <true-positive|false-positive|inconclusive>
- Confidence: <high|medium|low>
- Reproducible: <yes|no>
- Root-cause bug class: <class>
- CWE: <id>
- ATT&CK observed: <T-id list>

## Timeline
| ts | actor | action | evidence source | path |
|----|-------|--------|-----------------|------|
| ... |

## Confirmed root causes (<count>)

### Root cause R-<n>
- bug_class: <class>
- Location: <file:lines or symbol or address>
- CWE: <id>
- Falsification test: <test description>
- Oracle outcome: confirmed by <tool> at <evidence_path>
- Prior: <value>  →  Posterior (after oracle): <value>

(repeat)

## Refuted / inconclusive hypotheses (<count>)
| Hypothesis | Outcome | Why |
|------------|---------|-----|

## Blast radius
| Scope | Item | Source |
|-------|------|--------|
| source | <file:lines> | variant_analyzer |
| host | <hostname / pid> | behavioral_profiler |
| identity | <principal> | response_orchestrator |
| asset | <fqdn / cidr> | projectdiscovery |

## Recommended D3FEND actions
| Tactic | D3FEND id | Rationale |
|--------|-----------|-----------|
| Harden | D3-SCH | from CWE→D3FEND |
| Isolate | D3-NI | from ATT&CK→D3FEND |
| Detect | D3-PA | from CWE→D3FEND ∩ ATT&CK→D3FEND |
| Evict | D3-PE (Process Eviction) | from ATT&CK→D3FEND |

## Reproducibility kit
- Alert id: <id>
- Commit: <sha>
- Tool versions: <list>
- Random seeds: <list>
- Validator traces: <path>
```

## Refusal rules

1. Refuse to emit a `high` confidence verdict without reproducibility.
2. Refuse to enact any recommended action — this is a read-only skill.
3. Refuse to treat the alert as ground truth — Stage 1 reproduction is mandatory.
4. Refuse to ship a hypothesis as a root cause without a passing falsification test.
5. Refuse to skip blast radius for `deep` investigations.

## Related skills and modules

- `raven-zero-day-detection` — upstream producer of alerts.
- `raven-zero-day-hunter` — upstream for full pipeline hunts.
- `raven-zero-day-defend` — downstream consumer of `RecommendedActions`.
- `raven-zero-day-fixing` — downstream when the recommended action is patch / rollback.
- `pipeline/` — source-of-truth implementation of all MDASH stages
- `pipeline/d3fend/` — D3FEND + ATT&CK enrichment with real MITRE catalog data
- `pipeline/threat_intel/` — on-chain exposure scoring for prioritization
- `pipeline/validate/` — multi-model debate orchestration
- `pipeline/prove_extension/` — symbolic execution and formal verification
- `pipeline/eval/` — benchmark evaluation framework for measuring recall and precision
