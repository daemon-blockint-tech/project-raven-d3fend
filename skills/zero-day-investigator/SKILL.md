---
name: raven-zero-day-investigator
description: Investigate a single 0-day alert or finding end-to-end and produce a grounded incident report. Use when the user says "investigate this alert", "triage this finding", "deep-dive this anomaly", "root-cause this 0-day candidate", "build a timeline for this incident", or hands over an alert from `raven-zero-day-detection`. Every conclusion terminates at a tool oracle (𝒯), classical-ML detector (𝓜), or scored hypothesis (𝓛) and ships with D3FEND Detect / Isolate / Evict technique ids for next-step recommendation.
---

# Raven — 0-Day Investigator

This skill is Raven's depth-of-evidence layer. Detection skills emit alerts; this skill turns one alert into a defensible incident record: timeline, root cause, blast radius, attribution-grade evidence, and recommended D3FEND next steps. It does NOT scan broadly (use `raven-zero-day-detection`), does NOT enact defense (use `raven-zero-day-defend` or `raven-zero-day-auto-prevent`), and does NOT patch (use `raven-zero-day-fixing`).

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

1. Alert record — JSON from `raven-zero-day-detection` OR a `validated_finding` from `raven-zero-day-hunter` OR a free-form analyst description that includes target locator and observed indicators
2. Investigation depth — `quick` (≤ 5 min, surface evidence only), `standard` (≤ 30 min, full timeline), `deep` (≤ 2 hours, includes binary RE / memory forensics)

Optional:

- Approval mode — `smart` default, `manual` for any sample collection that touches production data
- Cost cap — default $5 for `standard`, $20 for `deep`

## Pipeline — six mandatory stages

### Stage 1 — Alert validation (𝒯-grounded)

1. Reload the artifact named in the alert (file hash, binary path, host id, flow tuple).
2. Re-run the original detector(s) listed in `alert.detector_hits`. If the rerun does not reproduce the hit, mark `reproducible=false` and continue — this is forensically important.
3. Re-extract features and diff against the alert's stored feature vector. Significant drift triggers a `tampering_suspected` flag.

If `reproducible=false`, the investigation continues but the final report's `confidence` cannot exceed `medium`.

### Stage 2 — Timeline reconstruction (𝒯-grounded)

Map the alert to a timeline using the appropriate tool oracles by alert mode:

| Alert origin mode | Timeline source |
|-------------------|-----------------|
| `scan-file` / `scan-binary` | File metadata + `raven/tools/volatility_analyzer.py` if host context available |
| `scan-memory` | `raven/tools/volatility_analyzer.py` process and network trees |
| `scan-flows` | Flow log replay via `raven/core/threat_detector.py` |
| `monitor-host` | `raven/ml/sequence_analyzer.py` syscall trace replay |
| `scan-source` | `git blame` + `raven/ml/code_flow_scanner.py` |

Output is a list of `TimelineEvent` records with `ts`, `actor`, `action`, `evidence_source`, `evidence_path`. Events without an `evidence_source` are dropped — speculation does not enter the timeline.

### Stage 3 — Root-cause hypothesis (𝓛-scored)

Invoke `raven/hunters/hypothesis_generator.py` with the timeline as context. The LLM proposes up to five ranked root-cause hypotheses. Each hypothesis must include:

- `bug_class`, `cwe`, `location`, `precondition`, `prior` (LLM confidence)
- An explicit `falsification_test` — a concrete tool-oracle invocation that would refute the hypothesis

Hypotheses without a falsification test are rejected at this stage.

### Stage 4 — Falsification pass (𝒯-grounded, mandatory)

For each hypothesis from Stage 3, run its `falsification_test`. Use `raven/ml/vulnerability_validator.py` for code-level tests, and the specific tool oracle named in the test (`ares.py`, `ghidra_analyzer.py`, `radare2.py`, `frida.py` defensive mode, `volatility_analyzer.py`) for the others.

Outcomes:

- `confirmed` — oracle reproduces the hypothesized condition
- `refuted` — oracle returns evidence inconsistent with the hypothesis
- `inconclusive` — oracle could not run or returned mixed signal

Only `confirmed` hypotheses become the report's root cause. Multiple confirmed hypotheses become an explicit list — the skill MUST NOT pick one arbitrarily.

### Stage 5 — Blast radius (𝒯-grounded)

For each `confirmed` root cause, enumerate exposure:

- Source-level: variant search via `raven/ml/variant_analyzer.py` against the confirmed pattern
- Host-level: `raven/core/behavioral_profiler.py` baseline comparison to find lateral movement candidates
- Identity-level: shared credential / token reuse via `raven/mitigation/response_orchestrator.py` lookup
- Asset-level: cross-reference with `raven/tools/projectdiscovery.py` own-asset inventory

Blast-radius items are returned as a structured list, not a prose paragraph.

### Stage 6 — D3FEND next-step binding (𝒯-grounded)

For each confirmed root cause and each blast-radius item:

1. Call `raven.d3fend.api.cwe_to_d3fend(cwe)` to get Harden / Detect techniques.
2. Call `raven.d3fend.api.attack_to_d3fend(observed_attack_id)` for Isolate / Evict techniques tied to the observed ATT&CK technique.
3. Bucket recommendations by tactic and rank by overlap count (techniques returned by both queries rank higher).

Output is a `RecommendedActions` block in the report — these are recommendations only; this skill does not enact them.

## CDP contract — quick check before returning

```
assert every TimelineEvent.evidence_source is not None
assert every confirmed_hypothesis has at least one validator oracle hit (𝒯)
assert every d3fend_id resolves through raven.d3fend.api.lookup_technique
assert report.confidence == "high" only if reproducible=true AND at least two confirmed hypotheses agree on the bug_class
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

## Related skills

- `raven-zero-day-detection` — upstream producer of alerts.
- `raven-zero-day-threat-patterns` — consulted in Stage 5 for variant analysis.
- `raven-zero-day-defend` — downstream consumer of `RecommendedActions`.
- `raven-zero-day-auto-prevent` — downstream when policy authorizes automatic action.
- `raven-zero-day-fixing` — downstream when the recommended action is patch / rollback.
- D3FEND OWL integration (`raven/d3fend/`) — source of every recommended action id ([D3FEND home](https://d3fend.mitre.org/)).
