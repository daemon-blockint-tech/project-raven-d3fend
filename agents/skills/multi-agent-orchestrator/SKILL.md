---
name: raven-multi-agent-orchestrator
description: Orchestrate 100+ specialized AI agents across an ensemble of frontier and distilled models to discover, debate, validate, prove, enrich, and triage exploitable bugs end-to-end. Use when the user wants to run the full MDASH pipeline with multi-model ensemble, dynamic agent spawning, or production-scale vulnerability discovery. Every finding terminates at a tool oracle (𝒯), classical-ML detector (𝓜), or scored hypothesis (𝓛), and ships with D3FEND defensive techniques, ATT&CK offensive context, exposure scoring, and DevSecOps routing.
---

# Raven — Multi-Agent Orchestrator

This skill is the master conductor of the MDASH (Multi-Model Agentic Security Harness) pipeline. It spawns, routes, and manages 100+ specialized agents across 7 pipeline stages, dynamically allocating frontier models (GPT-4o, Claude 3.5) for complex reasoning and distilled models for high-volume tasks.

Built for production DevSecOps at enterprise scale:
- Every finding has an owner, a triage process, and a Patch Tuesday deadline
- 100+ distinct agent classes for maximum type safety and explicit behavior
- Dynamic model allocation by task complexity — no waste, no compromise
- Parallel async execution with built-in rate limiting
- Collaboration between ACS (Autonomous Code Security), MORSE (Offensive Research & Security Engineering), and WARP (Windows Attack Research and Protection)

## When to use

Trigger when the user asks any of:

- "Run the full MDASH pipeline"
- "Orchestrate multi-agent security scanning"
- "Discover vulnerabilities at scale"
- "Run 100+ agents on this codebase"
- "Multi-model debate and validation"
- "Production vulnerability discovery"
- "Enterprise-scale security audit"

Do not trigger for: single-agent tasks (use individual auditor agents), defensive actions only (use `raven-zero-day-defend`), or incident response (use `raven-zero-day-investigator`).

## Inputs

Required:

1. Target path — path to codebase or repository
2. Target type — `c-cpp-source`, `solana-program`, `evm-contract`, `rust-source`, `windows-kernel`, `hyper-v`, `azure-service`
3. Budget — max USD spend (default $10.00)

Optional:

- Stages — subset of stages to run (default: all 7)
- Debate panel size — 3-7 debaters (default 3)
- Vote threshold — 0.0-1.0 for validation (default 0.67)
- Max concurrent — parallel agent limit (default 50)

## Pipeline — seven mandatory stages

### Stage 1 — PREPARE (𝒯-grounded)

Spawn prepare agents (`CodebaseIngesterAgent`, `ThreatModelerAgent`, `LanguageIndexerAgent`) to:

1. Ingest and parse the target codebase
2. Build a `ThreatModel` identifying high-risk areas and trust boundaries
3. Index languages and build cross-reference maps
4. Output: `SurfaceMap` with annotated risk areas

### Stage 2 — SCAN (𝒯 + 𝓜 + 𝓛)

Spawn 40+ auditor agents by bug class. Each agent is a **distinct class** with domain-specific instructions:

- `MemoryCorruptionAuditor` — buffer overflows, UAF, double-free
- `HeapExploitationAuditor` — heap spray, chunk manipulation
- `StackCorruptionAuditor` — stack canary bypass, ROP gadgets
- `RaceConditionAuditor` — TOCTOU, double-fetch, synchronization errors
- `AuthBypassAuditor` — missing checks, privilege escalation
- `WindowsKernelAuditor` — IRP flaws, lock invariants (private codebase reasoning)
- `HyperVAuditor` — VM escape, hypercall flaws
- `EVMReentrancyAuditor` — Solidity reentrancy, CEI pattern violations
- `SolanaAccountConfusionAuditor` — missing signer, PDA validation
- ... (40+ more distinct auditors)

Dynamic model allocation: frontier models for complex kernel/driver analysis, distilled models for simple pattern matching.

Output: `CandidateFinding` records with bug_class, location, precondition, severity, and falsification test.

### Stage 3 — VALIDATE (𝓛-scored, multi-model debate)

For each candidate finding, spawn a debate panel of 3-7 debater agents with **different models and personas**:

- `ProVulnerabilityDebater` — argues FOR exploitability
- `AntiVulnerabilityDebater` — argues AGAINST (challenges evidence)
- `ArbiterDebater` — neutral evaluation and confidence scoring
- `TechnicalDebater` — focuses on technical feasibility
- `ImpactDebater` — evaluates real-world impact

Each debater uses a different model (Claude 3.5, GPT-4o, Gemini) to maximize independent reasoning. Votes are aggregated with configurable threshold (default 67% FOR to validate).

Output: `ValidatedFinding` with debate transcript, confidence score, and validation status.

### Stage 4 — DEDUP (𝓜)

Spawn dedup agents (`EmbeddingGeneratorAgent`, `ClusteringEngineAgent`) to:

1. Generate embeddings for validated findings
2. Cluster by semantic similarity (DBSCAN)
3. Merge duplicate findings, preserving highest confidence variant

Output: `DeduplicatedFinding` records with cluster size and merge history.

### Stage 5 — PROVE (𝒯-grounded)

Spawn prover agents to generate and validate proof-of-concepts:

- `PoCGeneratorAgent` — constructs triggering inputs
- `HarnessBuilderAgent` — builds libFuzzer/AFL++/honggfuzz harnesses
- `SanitizerRunnerAgent` — runs ASan/TSan/UBSan
- `FormalVerificationProverAgent` — SMT solver + symbolic execution

Output: `ProvenFinding` with sanitizer reports, harness paths, and proof status.

### Stage 6 — ENRICH (𝒯-grounded)

Spawn enricher agents to bind full threat context:

- `D3FENDEnricherAgent` — maps CWE to real 271-entry MITRE D3FEND catalog
- `ATTACKMapperAgent` — binds offensive ATT&CK techniques
- `ExposureScorerAgent` — calculates real-world exposure 0-100
- `ComplianceMapperAgent` — CCI-to-NIST SP 800-53 mappings

Output: Enriched findings with `d3fend_techniques`, `attack_techniques`, `exposure_score`, `compliance_controls`, and `threat_narrative`.

### Stage 7 — TRIAGE (𝒯-grounded)

Spawn triage agents for DevSecOps routing:

- `SeverityTriage` — CVSS-based severity scoring
- `OwnerAssignment` — assigns finding owner by component responsibility
- `PatchTuesdayScheduler` — schedules fix deadlines
- `FalsePositiveFilter` — filters probable FPs before human review

Output: Final report with `finding_owner`, `team`, `patch_tuesday_target`, `sla_hours`, and `recommended_action`.

## CDP contract — quick check before returning

```
assert every finding terminates at 𝒯 or 𝓜 or 𝓛
assert every finding has d3fend_techniques from pipeline.d3fend.enrichment_engine
assert every finding has attack_techniques from pipeline.d3fend.attack_mapper
assert every finding has exposure_score from pipeline.threat_intel.onchain_threat_intel
assert every finding has finding_owner for DevSecOps routing
assert every finding has patch_tuesday_target
assert every finding has sla_hours
assert report.confidence == "high" only if debate confidence >= 0.67 AND reproducible=true
assert no stage silently skipped without gap_warning
```

## Output contract

```markdown
# MDASH Multi-Agent Report — <target>

## Summary
- Target: <path> (<type>)
- Wall time: <s>
- Total cost: $<usd>
- Findings: <n>
- Agents spawned: <n>
- Models used: <list>

## Findings

### Finding F-<n>
- ID: <id>
- Bug class: <class>
- Location: <file:line>
- Severity: <critical|high|medium|low>
- Confidence: <float>
- Validated: <yes|no>
- Proven: <yes|no>
- D3FEND: <technique list>
- ATT&CK: <technique list>
- Exposure: <score>/100
- Owner: <email>
- Patch Tuesday: <date>
- SLA: <hours>
- Recommended action: <route-to-investigator|route-to-defend>
- Threat narrative: <paragraph>
- Debate transcript: <link>
- Proof of concept: <path>

(repeat)

## Stage metrics
| Stage | Agents | Findings | Wall time | Cost |
|-------|--------|----------|-----------|------|
| prepare | <n> | <n> | <ms> | $<usd> |
| scan | <n> | <n> | <ms> | $<usd> |
| validate | <n> | <n> | <ms> | $<usd> |
| dedup | <n> | <n> | <ms> | $<usd> |
| prove | <n> | <n> | <ms> | $<usd> |
| enrich | <n> | <n> | <ms> | $<usd> |
| triage | <n> | <n> | <ms> | $<usd> |

## Agent metrics
| Agent | Tasks | Cost | State |
|-------|-------|------|-------|
| ... |

## Budget status
- Budget: $<usd>
- Spent: $<usd>
- Remaining: $<usd>
- Utilization: <percent>%

## Reproducibility kit
- Commit: <sha>
- Config: <path>
- Agent definitions: <count>
- Model mappings: <path>
```

## Refusal rules

1. Refuse to run without budget cap configured.
2. Refuse to skip validation stage — every finding must pass debate.
3. Refuse to emit findings without D3FEND + ATT&CK enrichment.
4. Refuse to bypass triage — every finding must have an owner.
5. Refuse to run on unauthorized targets.
6. Refuse to exceed max concurrent agents without explicit override.

## Related skills and modules

- `raven-zero-day-hunter` — upstream skill for initiating hunts
- `raven-zero-day-detection` — downstream alert producer
- `raven-zero-day-investigator` — downstream for alert investigation
- `raven-zero-day-defend` — downstream for defensive action
- `pipeline/multi_agent_orchestrator/` — source-of-truth implementation
- `pipeline/openai_agents_adapter/` — optional OpenAI Agents SDK backend
- `pipeline/eval/` — benchmark evaluation framework
- `pipeline/d3fend/` — D3FEND + ATT&CK enrichment engine
- `pipeline/threat_intel/` — on-chain exposure scoring
