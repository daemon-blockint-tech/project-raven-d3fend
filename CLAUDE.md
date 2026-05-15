# Project Raven D3FEND — AI Assistant Context

> **Token-reduction strategy**: This file compresses the full project architecture, source-of-truth files, editing rules, agent definitions, the CDP contract, and key concepts into a single document. Read this once before exploring the codebase.

---

## 1. Project Overview

**MDASH** (Multi-Model Agentic Security Harness) is a 7-stage pipeline that hunts 0-day vulnerabilities in source code, binaries, and smart contracts. Every finding terminates at a deterministic oracle — never raw LLM speculation.

### Key Concepts (one-liners)

| Symbol | Meaning |
|--------|---------|
| **𝒯** | Tool oracle — deterministic output (sanitizer, formal verifier, symbolic executor) |
| **𝓜** | ML detector — classical model with calibrated score (clustering, anomaly detection) |
| **𝓛** | Scored hypothesis — LLM-generated but with falsification test and confidence interval |
| **CDP** | Contract for Defensible Predictions — every finding must terminate at 𝒯, 𝓜, or 𝓛 |
| **D3FEND** | MITRE D3FEND defensive-technique ontology (271 techniques) mapped to every finding |
| **ATT&CK** | MITRE ATT&CK offensive techniques mapped for threat-actor context |
| **ACF** | D3FEND Analytic Characterization Framework — taxonomy of analytic techniques (pattern matching, ML, formal methods) used to implement defenses |
| **PR-Reviewer** | PR Security Reviewer agent — inspects diffs for medium+ vulnerabilities with attack paths |
| **AppSec** | Application Security Scanner — full-repo scan with persistent finding memory (JSON-based) |
| **Test-Coverage** | Test Coverage Agent — adds missing tests for merged code, prevents regressions |
| **Invariant-Monitor** | Invariant Monitor — detects drift from engineering and security invariants (secrets logging, permission checks, cross-surface consistency, safety controls) |
| **OS-Hardening** | OS Security Mapper — maps Windows Registry, Linux file structure, process monitors, and hardware architecture to D3FEND techniques |
| **Infra-Mapper** | Infrastructure Mapper — maps serverless, virtualization (Type I/II), and containerization (Docker) to D3FEND techniques |
| **IAM-Mapper** | IAM Mapper — maps MFA, SSO, Federation, PAM, Passwordless, CASB to D3FEND techniques |
| **Crypto-Mapper** | Crypto Mapper — maps PKI (CA/RA/VA), certificate trust models, and SSL inspection to D3FEND techniques |
| **Data-Protection** | Data Protection Mapper — maps DLP, PII, CHD, PHI, credentials, and IP to D3FEND techniques with code-level secret detection |
| **OWASP** | OWASP Cheat Sheet Mapper — maps OWASP Cheat Sheets (30+ topics) to D3FEND techniques, bug classes, and CWEs |

### Pipeline Stages

```
Target → PREPARE → SCAN → VALIDATE → DEDUP → PROVE → ENRICH → TRIAGE → Report
```

1. **PREPARE** — Ingest codebase, build threat model, index languages, analyze git history
2. **SCAN** — 40+ specialized auditor agents emit candidate findings (𝓛-scored hypotheses)
3. **VALIDATE** — Multi-model debate panel (3-7 debaters) filters false positives
4. **DEDUP** — Semantic clustering (DBSCAN) collapses equivalent findings
5. **PROVE** — PoC generation, harness building, fuzzing, sandboxed execution with sanitizers
6. **ENRICH** — Bind D3FEND + ATT&CK techniques, exposure scoring, compliance mapping
7. **TRIAGE** — DevSecOps routing: owner assignment, Patch Tuesday scheduling, SLA calculation

---

## 2. What Lives Where

```
project-raven-d3fend/
├── CLAUDE.md                  # ← You are here
├── README.md                  # User-facing overview & usage examples
├── pipeline-architecture.md   # Detailed architecture & data models
├── pipeline/
│   ├── config.yaml            # Model mappings, budget, stage settings
│   ├── orchestrator.py        # Legacy 5-stage orchestrator (OpenRouter)
│   ├── models/                # Data models: SurfaceMap, CandidateFinding, etc.
│   ├── multi_agent_orchestrator/  # ← 100+ agent system (NEW)
│   │   ├── agent_core.py      # EventEmitter agent with lifecycle hooks
│   │   ├── agent_pool.py      # Spawn, route, balance 100+ agents
│   │   ├── model_router.py    # Dynamic multi-model allocation
│   │   ├── debate_panel.py    # Multi-model debate validation
│   │   ├── enricher_agent.py  # D3FEND + ATT&CK enrichment
│   │   ├── triage_agent.py    # DevSecOps routing & Patch Tuesday
│   │   ├── hooks.py           # Lifecycle hooks & metrics
│   │   ├── config.py          # 100+ agent definitions
│   │   └── orchestrator.py    # Multi-agent pipeline coordinator
│   ├── openrouter_integration/    # OpenRouter SDK wrapper
│   │   ├── client.py
│   │   ├── model_selector.py
│   │   └── cost_tracker.py
│   ├── prepare/               # Stage 1: Ingestion, indexing, threat modeling
│   ├── scan/                  # Stage 2: Agent routing, finding collection
│   ├── validate/              # Stage 3: Debate orchestration, voting, confidence
│   ├── dedup/                 # Stage 4: Embeddings, similarity, clustering, merging
│   ├── prove/                 # Stage 5: PoC, harness, fuzzer, sandbox, sanitizer
│   ├── d3fend/                # D3FEND + ATT&CK enrichment engine
│   ├── threat_intel/          # On-chain exposure scoring
│   ├── cross_language/        # FFI, Solidity, WASM, taint tracking
│   ├── plugin_synthesis/      # Domain invariant extraction
│   ├── prove_extension/       # Symbolic execution & formal verification
│   ├── eval/                  # Benchmark evaluation framework
│   ├── feedback/              # Retrospective learning loop
│   └── openai_agents_adapter/ # Optional OpenAI Agents SDK backend
├── agents/skills/
│   ├── SKILL.md               # Master skill definition (raven-zero-day-hunter)
│   ├── multi-agent-orchestrator/SKILL.md  # Multi-agent orchestrator skill
│   ├── devsec-mythos-class/SKILL.md
│   ├── zero-day-threat-patterns/SKILL.md
│   ├── zero-day-auto-prevent/SKILL.md
│   ├── zero-day-fixing/SKILL.md
│   ├── zero-day-defend/SKILL.md
│   ├── zero-day-detection/SKILL.md
│   ├── zero-day-investigator/SKILL.md
│   └── research-looped-reasoning-eval/SKILL.md
├── docs/
│   └── benchmark-results.md   # Evaluation results & failure analysis
└── tools/
    ├── d3fend.csv             # Real 271-entry D3FEND catalog
    └── cci.2022-04-05.json  # CCI-to-D3FEND NIST SP 800-53 mappings
```

---

## 3. Single Source of Truth Files

These files are canonical. Edit them directly; do not duplicate their content elsewhere.

| File | Purpose | What to Edit |
|------|---------|--------------|
| `pipeline/config.yaml` | Pipeline configuration | Model selections, budget limits, debate thresholds, target types |
| `pipeline/models/__init__.py` | Data models | BugClass enum, all dataclasses (SurfaceMap, CandidateFinding, etc.) |
| `pipeline/logging_utils.py` | Structured logging | Log levels, JSON SIEM output, pipeline context, time sync |
| `pipeline/os_security/hardening_mapper.py` | OS security concepts | Windows Registry, Linux file structure, process monitors, hardware architecture → D3FEND |
| `pipeline/os_security/infrastructure_mapper.py` | Infrastructure security | Serverless, virtualization, containerization → D3FEND |
| `pipeline/os_security/iam_mapper.py` | IAM security | MFA, SSO, Federation, PAM, Passwordless, CASB → D3FEND |
| `pipeline/os_security/crypto_mapper.py` | Cryptography & PKI | PKI components, certificate trust, SSL inspection → D3FEND |
| `pipeline/os_security/data_protection_mapper.py` | Data protection | DLP, PII, CHD, PHI, credentials, IP → D3FEND |
| `pipeline/multi_agent_orchestrator/config.py` | 100+ agent definitions | Agent instructions, model preferences, bug class mappings |
| `pipeline/d3fend/cwe_mapper.py` | CWE→D3FEND mappings | Add new CWE mappings |
| `pipeline/d3fend/acf_loader.py` | D3FEND ACF taxonomy | Add new analytic technique mappings |
| `pipeline/d3fend/compliance_reporter.py` | CySA+ aligned compliance reporting | Add new framework mappings |
| `pipeline/d3fend/owasp_cheatsheet_mapper.py` | OWASP Cheat Sheets | OWASP topics → D3FEND, bug classes, CWEs |
| `pipeline/d3fend/d3fend_catalog_loader.py` | D3FEND CSV parser | Catalog loading logic |
| `agents/skills/SKILL.md` | Master skill contract | Pipeline stages, refusal rules, output format |
| `agents/skills/multi-agent-orchestrator/SKILL.md` | Multi-agent skill | Orchestrator-specific contract |
| `README.md` | User-facing docs | Usage examples, installation, target types |
| `pipeline-architecture.md` | Architecture docs | Design principles, data flow, CDP compliance |

---

## 4. Editing Rules

### Before You Edit Checklist

- [ ] Are you editing a **source-of-truth file** from Section 3? If not, reconsider.
- [ ] Does your change preserve the **CDP contract** (every finding must terminate at 𝒯, 𝓜, or 𝓛)?
- [ ] Does your change preserve **defender-only enforcement** (no offensive tooling)?
- [ ] If adding a new agent, did you add it to `config.py` and update `AGENT_COUNT`?
- [ ] If changing model mappings, did you update `config.yaml`?

### Conventions

- **Never modify sub-skills unless requested.** The `agents/skills/*/` directory contains skill definitions that are loaded by the orchestrator. Each skill has its own `SKILL.md` that defines its contract.
- **Never bypass the approval gate.** Any destructive action (patch apply, network isolation, process kill) must route through `raven/approval/gate.py`.
- **Never emit unvalidated hypotheses as findings.** Hypotheses are candidates until they pass the Validate stage.
- **Never skip the Validate stage.** The CDP contract is non-negotiable.
- **Preserve enum values.** `BugClass` and `GroundingType` enums in `pipeline/models/__init__.py` are referenced by string values in configs and skills.
- **Agent IDs are permanent.** Once assigned in `config.py`, do not change agent IDs to preserve metrics continuity.
- **Model tier mapping:** `simple` → distilled, `moderate` → balanced, `complex`/`deep-reasoning` → frontier.

---

## 5. Agent Architecture

### Core Components

| Component | File | Responsibility |
|-----------|------|----------------|
| `Agent` | `agent_core.py` | EventEmitter agent with hooks: message, stream, tool call, reasoning, state change |
| `AgentPool` | `agent_pool.py` | Spawn 100+ agents from config, route by bug class/stage, load balance, budget-aware retirement |
| `ModelRouter` | `model_router.py` | Dynamic model selection by complexity; fallback chains; cost tracking |
| `DebatePanel` | `debate_panel.py` | 3-7 debaters per finding, multi-model, vote aggregation, confidence scoring |
| `EnricherAgent` | `enricher_agent.py` | Bind D3FEND + ATT&CK + exposure + compliance |
| `TriageAgent` | `triage_agent.py` | Severity, owner, Patch Tuesday, SLA, false positive risk |
| `MultiAgentOrchestrator` | `orchestrator.py` | Coordinate all 7 stages, parallel async execution |

### Agent Lifecycle Hooks

```python
agent.on("message:user", callback)
agent.on("message:assistant", callback)
agent.on("stream:start", callback)
agent.on("stream:delta", callback)      # delta: str, accumulated: str
agent.on("stream:end", callback)
agent.on("tool:call", callback)         # name: str, args: dict
agent.on("tool:result", callback)
agent.on("reasoning:update", callback)  # text: str
agent.on("thinking:start", callback)
agent.on("thinking:end", callback)
agent.on("error", callback)
agent.on("state:change", callback)      # old: AgentState, new: AgentState
```

### Model Tiers

| Tier | Models | Use Case |
|------|--------|----------|
| **Frontier** | GPT-4o, Claude 3.5 Sonnet, Gemini Pro | Complex reasoning, kernel/driver analysis, debate |
| **Balanced** | GPT-4o-mini, Claude 3 Haiku | Moderate complexity, code analysis |
| **Distilled** | Llama 3 8B, Mistral 7B | High-volume pattern matching, simple audits |

### Stage → Agent Mapping

| Stage | Agent Types | Count |
|-------|-------------|-------|
| PREPARE | CodebaseIngester, ThreatModeler, LanguageIndexer | 3+ |
| SCAN | MemoryCorruptionAuditor, RaceConditionAuditor, AuthBypassAuditor, SolanaAccountConfusionAuditor, EVMReentrancyAuditor, WindowsKernelAuditor, HyperVAuditor, etc. | 40+ |
| VALIDATE | ProVulnerabilityDebater, AntiVulnerabilityDebater, ArbiterDebater, TechnicalDebater, ImpactDebater | 5+ |
| DEDUP | EmbeddingGenerator, ClusteringEngine | 2+ |
| PROVE | PoCGenerator, HarnessBuilder, SanitizerRunner, FormalVerificationProver | 4+ |
| ENRICH | D3FENDEnricher, ATTACKMapper, ExposureScorer, ComplianceMapper | 4+ |
| TRIAGE | SeverityTriage, OwnerAssignment, PatchTuesdayScheduler, FalsePositiveFilter | 4+ |

---

## 6. CDP Contract (Raven's Contract for Defensible Predictions)

### The Three Terminators

Every finding MUST terminate at one of:

1. **𝒯 — Tool Oracle**: Deterministic output from a tool (AddressSanitizer, ThreadSanitizer, symbolic executor, formal verifier)
2. **𝓜 — ML Detector**: Classical ML model with calibrated score (semantic clustering, anomaly detection)
3. **𝓛 — Scored Hypothesis**: LLM-generated with falsification test and confidence in [0, 1]

### Quick Check (run before returning any report)

```python
assert finding.validator_oracle is not None        # 𝒯
   or finding.ml_detector is not None              # 𝓜
   or finding.scored_hypothesis is not None        # 𝓛
assert finding.d3fend_techniques                   # at least one defensive technique
assert finding.attack_techniques                   # at least one offensive technique
assert finding.exposure_score is not None          # real-world exposure calculated
assert finding.confidence != "low"                 # low → unconfirmed bucket
```

### Validation Rules

| Rule | Enforcement |
|------|-------------|
| No raw LLM speculation as findings | 𝓛 must have falsification test |
| Every finding has D3FEND binding | Enrich stage mandatory |
| Every finding has ATT&CK context | Enrich stage mandatory |
| Low-confidence items are unconfirmed | Not findings; bucket separately |
| Budget hard cap | Abort pipeline when exceeded |
| Approval gate for destructive actions | `raven/approval/gate.py` |

### Refusal Rules (the skill MUST refuse)

1. Target not owned/authorized by user
2. Request for exploit payload or weaponized PoC
3. Request to disable approval gate
4. Request to skip Validate stage
5. Request to mark unvalidated hypotheses as findings
6. Request to run without budget cap

---

## 7. Key Concepts

### D3FEND + ACF Technique Binding

Every finding maps to:
- **MITRE D3FEND** defensive techniques via:
  - `pipeline/d3fend/cwe_mapper.py` — CWE → D3FEND technique IDs
  - `pipeline/d3fend/ontology_client.py` — D3FEND OWL ontology queries
  - `pipeline/d3fend/d3fend_catalog_loader.py` — Real 271-entry CSV catalog
  - `pipeline/d3fend/cci_loader.py` — CCI-to-D3FEND NIST SP 800-53 mappings
- **D3FEND ACF** (Analytic Characterization Framework) via:
  - `pipeline/d3fend/acf_loader.py` — ACF taxonomy and technique mappings
  - Each D3FEND technique is characterized by the analytic methods used to implement it (pattern matching, statistical inference, formal verification, deep learning, etc.)
  - Each bug class maps to recommended ACF techniques for detection
- **Compliance Reporting** (CySA+ Domain 4 aligned) via:
  - `pipeline/d3fend/compliance_reporter.py` — Maps findings to ISO 27001, HIPAA, PCI-DSS, GDPR, SOC 2, NIST 800-53
  - Generates executive summaries, action plans, KPIs, and stakeholder recommendations
  - Tracks compliance status per framework control
  - Produces auditable compliance reports with evidence and remediation guidance
- **OWASP Cheat Sheet references** via:
  - `pipeline/d3fend/owasp_cheatsheet_mapper.py` — Maps 30+ OWASP Cheat Sheets to D3FEND techniques, bug classes, and CWEs
  - Enriched findings include direct links to relevant OWASP guidance
  - Coverage: Authentication, Authorization, Cryptography, Input Validation, APIs, Mobile, AI/ML, IaC scenarios

### Exposure Score Calculation

- Base: severity (critical=90, high=70, medium=50, low=30)
- Boost: kernel/driver (+15), hypervisor (+20)
- Cap: 100
- Threat actor likelihood: HIGH if exposure > 50

### Multi-Model Debate

- Panel size: 3-7 debaters (configurable)
- Each debater uses a different model for independent reasoning
- Vote threshold: 67% FOR to validate (configurable)
- Debaters: Pro, Anti, Arbiter, Technical, Impact

### DevSecOps Triage

| Severity | SLA | Patch Tuesday |
|----------|-----|---------------|
| Critical | 24h | Out-of-band (7 days) |
| High | 72h | Next Patch Tuesday |
| Medium | 1 week | Next Patch Tuesday |
| Low | 30 days | Next Patch Tuesday |

---

## 8. Usage Patterns

### Quick Start

```python
from pipeline.multi_agent_orchestrator import MultiAgentOrchestrator

orchestrator = MultiAgentOrchestrator(
    api_key="$OPENROUTER_API_KEY",
    budget_usd=50.0,
    max_concurrent=50,
    debate_panel_size=5,
    debate_threshold=0.67,
)

report = await orchestrator.run_pipeline(
    target="/path/to/codebase",
    target_type="c-cpp-source",
)
```

### Legacy Pipeline

```python
from pipeline.orchestrator import PipelineOrchestrator

pipeline = PipelineOrchestrator()
report = pipeline.run_pipeline(
    target="https://github.com/example/repo.git",
    target_type="c-cpp-source",
    trials=10
)
```

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `OPENROUTER_API_KEY` | Yes | OpenRouter API key |
| `OPENROUTER_DEBUG` | No | Enable debug logging |

---

## 9. Target Types Supported

| Type | Pipeline Modules |
|------|----------------|
| `solana-program` | `prepare/ingester.py` + `cross_language/solidity_analyzer.py` |
| `evm-contract` | `prepare/ingester.py` + `cross_language/solidity_analyzer.py` |
| `c-cpp-source` / `rust-source` | `prepare/indexer.py` + `cross_language/ffi_analyzer.py` + `cross_language/taint_tracker.py` |
| `android-apk` | `prepare/ingester.py` + `cross_language/wasm_analyzer.py` |
| `binary-elf` / `binary-pe` | `prepare/indexer.py` |
| `linux-kernel-module` | `prepare/indexer.py` + `cross_language/ffi_analyzer.py` |
| `live-host` | `prepare/threat_modeler.py` |
| `network-range-own-assets` | `prepare/threat_modeler.py` |

---

## 10. Integration Points

| Module | Integrates With |
|--------|----------------|
| `pipeline/multi_agent_orchestrator/` | Deep integration with existing `pipeline/` stages |
| `pipeline/openai_agents_adapter/` | Optional OpenAI Agents SDK backend |
| `pipeline/openrouter_integration/` | OpenRouter SDK for 300+ models |
| `pipeline/d3fend/` | Real MITRE D3FEND catalog (`tools/d3fend.csv`) |
| `pipeline/threat_intel/` | On-chain threat intel + Shodan external exposure scoring |
| `pipeline/cross_language/` | Multi-language taint tracking |
| `pipeline/feedback/` | Retrospective learning from missed bugs |
| `pipeline/eval/` | Benchmark evaluation against ground truth |

---

*End of CLAUDE.md. For detailed skill contracts, see `agents/skills/*/SKILL.md`. For architecture details, see `pipeline-architecture.md`.*
