# Multi-Model Agentic Security Pipeline (MDASH) Architecture

## Overview

MDASH is a structured pipeline that takes a codebase and emits validated, proven findings. It operates in five stages — Prepare, Scan, Validate, Dedup, and Prove — each handled by a cohort of specialized AI agents. The pipeline is model-agnostic by construction: targeting, validation, deduplication, and proving are decoupled from any specific model, so when a new model lands, A/B testing it against the current panel is one configuration flip.

## Design Principles

1. **CDP Grounding**: Every finding terminates at 𝒯 (tool oracle), 𝓜 (ML detector), or 𝓛 (scored hypothesis)
2. **Multi-Model Ensemble**: No single model is best at every stage. The harness runs a configurable panel of models — SOTA heavy reasoners, distilled cost-effective debaters, and independent counterpoints. Disagreement between models is itself a signal.
3. **Specialized Agents**: An auditor does not reason like a debater, which does not reason like a prover. Each stage has its own role, prompt regime, tools, and stop criteria. MDASH fields more than 100 specialized agents constructed through deep research with past CVEs and their patches.
4. **Extensible Plugins**: Domain experts inject context the foundation models cannot see on their own — kernel calling conventions, IRP rules, lock invariants, IPC trust boundaries, codec state machines. The pipeline is opinionated but not closed.
5. **D3FEND Integration**: Maintain MITRE D3FEND v1.0 OWL ontology grounding
6. **Defender-Only**: No offensive capabilities, all modules defender-focused
7. **Model Portability**: Prior investment — scope files, plugins, configurations, calibrations — all carry over across model generations, allowing customers to ride the frontier of security value.

## Why This Works

Three properties make the pipeline practical at scale:

### 1. Multi-Model Ensemble (MDASH)

No single model is best at every stage. The harness runs a configurable panel:
- **SOTA heavy reasoners** for deep auditing passes
- **Distilled models** as cost-effective debaters for high-volume validation
- **Independent counterpoint models** to surface disagreement

When an auditor flags something as suspect and the debater cannot refute it, that finding's posterior credibility goes up. Disagreement between models is itself a signal.

### 2. Specialized Agents

An auditor does not reason like a debater, which does not reason like a prover. Each pipeline stage has its own role, prompt regime, tools, and stop criteria:
- **Auditors** discover vulnerabilities through targeted code analysis
- **Debaters** argue for and against reachability / exploitability
- **Provers** construct triggering inputs and validate pre-conditions dynamically

We do not expect one prompt to do everything; we do not expect one agent to recognize, validate, and exploit a bug in a single pass. MDASH fields more than 100 specialized agents, constructed through deep research with past CVEs and their patches, working independently. Their auditing results are ensembled as a single report.

### 3. Extensible Plugins

The pipeline is opinionated, but it is not closed. Plugins let domain experts inject context the foundation models cannot see on their own:
- Kernel calling conventions
- IRP rules and lock invariants
- IPC trust boundaries
- Codec state machines
- Custom code analysis databases (e.g., CodeQL)

A plugin knows how to construct a triggering input given a candidate finding — for example, a CLFS proving plugin that knows how to build a triggering log file. When a new model lands, A/B testing it against the current panel is one configuration flip. When a model improves, the customer's prior investment — scope files, plugins, configurations, calibrations — all carry over, allowing customers to ride the frontier of security value.

## Pipeline Stages

### Stage 1: Prepare (Recon)

**Purpose**: Ingest source target, build language-aware indices, generate threat models

**Inputs**:
- Target repository URL or file path
- Target type (solana-program, evm-contract, c-cpp-source, rust-source, etc.)
- Git history (for CVE patch analysis)

**Process**:
1. Clone/ingest target codebase
2. Build language-aware indices (AST, call graph, control flow)
3. Analyze past commits for CVE patches
4. Generate attack surface map
5. Create threat model using OpenRouter models (multiple models for cross-validation)

**Outputs**:
- `SurfaceMap` JSON (entry points, syscalls, ABI boundaries)
- `ThreatModel` JSON (attack surface, high-risk areas)
- `LanguageIndex` (AST, call graph, data flow)

**OpenRouter Integration**:
- Use multiple models (e.g., claude-3.5-sonnet, gpt-4, gemini-pro) for threat modeling
- Cross-validate threat models across models
- Select highest-confidence threat model

**CDP Grounding**: 𝒯 (git history analysis, static analysis tools)

### Stage 2: Scan (Discovery)

**Purpose**: Run specialized auditor agents over candidate code paths

**Inputs**:
- `SurfaceMap` from Stage 1
- `ThreatModel` from Stage 1
- `LanguageIndex` from Stage 1

**Process**:
1. Select relevant code paths based on threat model
2. Route to specialized auditor agents (100+ agents by bug type)
3. Each agent emits candidate findings with:
   - Bug class
   - Location
   - Precondition
   - Evidence
   - Hypothesis score (𝓛)

**Specialized Agents** (examples):
- Memory corruption auditor
- Integer overflow auditor
- Race condition auditor
- Auth bypass auditor
- Deserialization auditor
- Type confusion auditor
- Signature malleability auditor
- Account confusion auditor
- Oracle manipulation auditor

**OpenRouter Integration**:
- Each auditor agent uses specialized model selection
- Memory corruption: claude-3.5-sonnet (strong code analysis)
- Race condition: gpt-4 (complex reasoning)
- Auth bypass: gemini-pro (security-focused)
- Model routing based on bug class and code complexity

**Outputs**:
- `CandidateFindings` list (hypotheses with scores)

**CDP Grounding**: 𝓛 (scored hypotheses from LLM agents)

### Stage 3: Validate (Bug Triage)

**Purpose**: Multi-model debate to filter false positives

**Inputs**:
- `CandidateFindings` from Stage 2

**Process**:
1. For each candidate finding, run debate with 3-5 different OpenRouter models
2. Each model acts as a debater with persona:
   - Model A: Pro-vulnerability (argues for exploitability)
   - Model B: Anti-vulnerability (argues for false positive)
   - Model C: Neutral arbiter (evaluates arguments)
3. Vote mechanism: 2/3 majority for True/False
4. Confidence scoring based on debate quality

**Debate Protocol**:
```
Finding: <candidate>
Model A (Pro): "This is exploitable because..."
Model B (Anti): "This is a false positive because..."
Model C (Arbiter): "Evaluating arguments..."
Vote: [True, False, True] → Result: True (confidence: 0.67)
```

**OpenRouter Integration**:
- Use diverse models for debate (claude, gpt, gemini, llama, mistral)
- Configure different temperatures for different personas
- Stream debate outputs for transparency

**Outputs**:
- `ValidatedFindings` (with debate transcripts and confidence scores)

**CDP Grounding**: 𝓛 (multi-model debate with scored outcomes)

### Stage 4: Dedup (Semantic Collapse)

**Purpose**: Collapse semantically equivalent findings

**Inputs**:
- `ValidatedFindings` from Stage 3

**Process**:
1. Semantic similarity analysis using embeddings
2. Patch-based grouping (if findings share same root cause patch)
3. Location-based clustering (same function/region)
4. Deduplication rules:
   - Same bug class + same function = merge
   - Same CWE + similar code pattern = merge
   - Different bug class + same location = keep separate

**Dedup Strategy**:
- Use OpenRouter embeddings for semantic similarity
- Apply clustering algorithm (DBSCAN or hierarchical)
- Generate representative finding for each cluster

**OpenRouter Integration**:
- Use embedding models (text-embedding-3-small, etc.)
- Multi-model embedding for robustness

**Outputs**:
- `DeduplicatedFindings` (unique findings with cluster info)

**CDP Grounding**: 𝓜 (ML-based similarity and clustering)

### Stage 5: Prove (PoC Generation)

**Purpose**: Construct and execute triggering inputs to prove vulnerability

**Inputs**:
- `DeduplicatedFindings` from Stage 4

**Process**:
1. For each finding, construct proof-of-concept:
   - Self-contained claim
   - Reachability harness
   - Fuzzing inputs
2. Execute in sandboxed environment:
   - Docker build with sanitizers (ASan, TSan, UBSan)
   - Dynamic validation
   - Crash/trigger detection
3. Validate pre-conditions dynamically
4. Formulate bug-triggering inputs

**Proof Stages**:
```
Stage 5.1: Self-contained claim
  - Minimal code snippet demonstrating vulnerability
  - No external dependencies

Stage 5.2: Reachability harness
  - Instrumented code to trigger vulnerability
  - Control flow verification

Stage 5.3: Fuzzing
  - Automated input generation
  - Crash detection
  - Sanitizer output analysis
```

**OpenRouter Integration**:
- Use models to generate PoC code
- Model selection based on language (C/C++, Rust, Solidity, etc.)
- Code validation using models

**Outputs**:
- `ProvenFindings` (with PoC code and execution results)
- `PoCArtifacts` (Dockerfiles, harnesses, fuzzing inputs)

**CDP Grounding**: 𝒯 (dynamic execution, sanitizers, crash detection)

## Post-Pipeline: D3FEND Binding

**Purpose**: Attach D3FEND countermeasures to proven findings

**Process**:
1. For each proven finding, map CWE to D3FEND techniques
2. Query D3FEND OWL ontology via SPARQL
3. Attach Harden/Isolate/Detect techniques
4. Generate remediation suggestions

**Outputs**:
- Final report with D3FEND techniques
- Remediation recommendations

**CDP Grounding**: 𝒯 (D3FEND ontology queries)

## Architecture Components

### Core Modules

```
pipeline/
├── prepare/
│   ├── ingester.py          # Codebase ingestion
│   ├── indexer.py           # Language-aware indexing
│   ├── threat_modeler.py    # Threat model generation
│   └── git_analyzer.py      # CVE patch analysis
├── scan/
│   ├── agent_router.py      # Route to specialized agents
│   ├── agents/              # 100+ specialized auditors
│   │   ├── memory_corruption.py
│   │   ├── integer_overflow.py
│   │   ├── race_condition.py
│   │   └── ...
│   └── finding_collector.py  # Collect candidate findings
├── validate/
│   ├── debate_orchestrator.py  # Multi-model debate
│   ├── debater.py            # Individual debater
│   ├── voting.py             # Vote aggregation
│   └── confidence_scorer.py  # Confidence calculation
├── dedup/
│   ├── embedding_generator.py  # Generate embeddings
│   ├── similarity.py          # Semantic similarity
│   ├── clustering.py          # Clustering algorithm
│   └── merger.py              # Merge findings
├── prove/
│   ├── poc_generator.py     # PoC code generation
│   ├── harness_builder.py   # Reachability harness
│   ├── fuzzer.py            # Fuzzing orchestration
│   ├── sandbox.py           # Docker sandbox
│   └── sanitizer_runner.py   # ASan/TSan/UBSan execution
├── d3fend/
│   ├── cwe_mapper.py           # CWE to D3FEND mapping
│   ├── ontology_client.py      # SPARQL queries
│   ├── remediation.py          # Remediation generation
│   ├── attack_mapper.py        # ATT&CK technique mapping
│   ├── d3fend_catalog_loader.py # D3FEND catalog CSV loader
│   ├── cci_loader.py           # CCI compliance mappings
│   └── enrichment_engine.py    # Unified D3FEND + ATT&CK enrichment
├── cross_language/
│   ├── ffi_analyzer.py         # Rust FFI boundary analysis
│   ├── solidity_analyzer.py    # Solidity-to-native call analysis
│   ├── wasm_analyzer.py        # WASM runtime boundary analysis
│   └── taint_tracker.py        # Cross-language taint tracking
├── plugin_synthesis/
│   └── plugin_synthesis_agent.py  # Domain invariant extraction
├── threat_intel/
│   └── onchain_threat_intel.py # On-chain exposure scoring
├── prove_extension/
│   └── formal_verification.py  # Symbolic execution + formal verification
├── feedback/
│   ├── false_negative_tracker.py
│   ├── cve_parser.py
│   ├── context_updater.py
│   └── feedback_agent.py
├── eval/
│   ├── ground_truth_loader.py   # Benchmark dataset parsing
│   ├── evaluator.py             # TP/FP/FN metrics + F1 scoring
│   └── report_generator.py      # Markdown/JSON/grant reports
├── openai_agents_adapter/       # Optional OpenAI Agents SDK Backend
│   ├── auditor_agent.py         # Bug-class specialist agents
│   ├── debater_agent.py         # Multi-model debate panel
│   └── pipeline_runner.py       # Full MDASH pipeline orchestration
└── multi_agent_orchestrator/    # 100+ Agent Multi-Model Orchestration
    ├── __init__.py              # Module exports
    ├── agent_core.py            # EventEmitter agent with lifecycle hooks
    ├── agent_pool.py            # Spawn, route, balance, retire 100+ agents
    ├── model_router.py          # Dynamic multi-model allocation by complexity
    ├── debate_panel.py          # 3-7 debater multi-model debate
    ├── enricher_agent.py        # D3FEND + ATT&CK + exposure enrichment
    ├── triage_agent.py          # DevSecOps routing & Patch Tuesday
    ├── hooks.py                 # Lifecycle hooks, metrics, logging
    ├── config.py                # 100+ agent definitions & model mappings
    └── orchestrator.py          # 7-stage pipeline coordinator
```

### OpenRouter Integration Layer

```
openrouter_integration/
├── client.py               # OpenRouter SDK client wrapper
├── model_selector.py       # Model selection logic
├── debate_config.py        # Debate persona configurations
├── embedding_client.py     # Embedding API wrapper
└── cost_tracker.py        # Cost tracking and budgeting
```

### Data Models

```
models/
├── surface_map.py          # SurfaceMap data structure
├── threat_model.py         # ThreatModel data structure
├── candidate_finding.py    # CandidateFinding data structure
├── validated_finding.py    # ValidatedFinding data structure
├── deduplicated_finding.py # DeduplicatedFinding data structure
├── proven_finding.py       # ProvenFinding data structure
└── report.py               # Final report structure
```

## Optional Backends

### OpenAI Agents SDK Integration

The pipeline includes an optional adapter layer (`pipeline/openai_agents_adapter/`) that replaces the custom agent orchestration with the [OpenAI Agents SDK](https://github.com/openai/openai-agents-python). This provides:

- **Production-grade agent orchestration** — structured agent definitions with instructions, tools, and handoffs
- **Built-in tracing** — full visibility into every agent run, tool call, and handoff
- **Session management** — automatic conversation history across multi-turn analyses
- **Human-in-the-loop** — built-in mechanisms for human approval of destructive actions
- **Provider-agnostic** — works with OpenAI, Anthropic, Google, and 100+ other LLMs

**When to use the OpenAI Agents SDK backend:**
- You need production observability and debugging capabilities
- You want structured agent definitions with guardrails
- You need human-in-the-loop support for approval gates
- You want to leverage the SDK's tracing and session management

**When to use the native backend:**
- You want full control over the orchestration logic
- You need custom debate configurations not supported by the SDK
- You want to minimize external dependencies
- You are running in an air-gapped environment

```python
from pipeline.openai_agents_adapter import MDASHAgentsRunner, PipelineConfig

config = PipelineConfig(
    auditor_models=["gpt-4o", "claude-3-5-sonnet-20241022"],
    debater_models=["gpt-4o", "gpt-4o-mini", "claude-3-5-sonnet-20241022"],
    enable_tracing=True,
)

runner = MDASHAgentsRunner(config)
report = runner.run_pipeline(target_path="/path/to/code", target_type="c-cpp-source")
```

## Configuration

### Pipeline Config

```yaml
pipeline:
  stages:
    prepare:
      models:
        - claude-3.5-sonnet
        - gpt-4
        - gemini-pro
      temperature: 0.0
    scan:
      agent_routing:
        memory_corruption: claude-3.5-sonnet
        race_condition: gpt-4
        auth_bypass: gemini-pro
      agents_per_function: 5
    validate:
      debaters:
        - model: claude-3.5-sonnet
          persona: pro-vulnerability
          temperature: 0.7
        - model: gpt-4
          persona: anti-vulnerability
          temperature: 0.7
        - model: gemini-pro
          persona: arbiter
          temperature: 0.0
      vote_threshold: 0.67
    dedup:
      embedding_model: text-embedding-3-small
      similarity_threshold: 0.85
      clustering_algorithm: dbscan
    prove:
      poc_generator: claude-3.5-sonnet
      sanitizers:
        - address
        - thread
        - undefined
      sandbox: docker
```

### Cost Budget

```yaml
budget:
  max_cost_usd: 10.00
  stage_limits:
    prepare: 1.00
    scan: 5.00
    validate: 2.00
    dedup: 0.50
    prove: 1.50
```

## Integration with Existing Raven

### CDP Contract Compliance

Every finding must satisfy:
```python
assert finding.validator_oracle is not None        # 𝒯
   or finding.ml_detector is not None              # 𝓜
   or finding.scored_hypothesis is not None        # 𝓛
assert finding.d3fend_techniques                   # at least one
assert finding.confidence != "low"                 # low ⇒ unconfirmed
```

### D3FEND Integration

- Use existing `raven/d3fend/` module
- SPARQL queries via Oxigraph
- Coverage matrix tracking
- Technique binding

### Module Reuse

- `raven/tools/ares.py` for Solana/EVM analysis
- `raven/ml/code_flow_scanner.py` for taint analysis
- `raven/ml/vulnerability_validator.py` for validation
- `raven/approval/gate.py` for approval gating

## Execution Flow

```
1. User provides target (repo URL, file path, etc.)
2. Pipeline runs Stage 1 (Prepare)
3. Pipeline runs Stage 2 (Scan)
4. Pipeline runs Stage 3 (Validate)
5. Pipeline runs Stage 4 (Dedup)
6. Pipeline runs Stage 5 (Prove)
7. D3FEND binding
8. Generate final report
9. Approval gate for destructive actions
```

## Output Format

```markdown
# Multi-Model Agentic Security Scan — <target>

## Pipeline Execution
- Target: <locator>
- Target type: <type>
- Stages completed: prepare, scan, validate, dedup, prove
- Total cost: $<spend>
- Trial budget: <trials> / $<cap>

## Findings (<count>)

### Finding F-<n>: <summary>
- Bug class: <class>
- Location: <file:lines>
- CWE: CWE-<id>
- Stage 2 score: <score>
- Stage 3 debate: <models> → <vote> (confidence: <conf>)
- Stage 4 cluster: <cluster_id> (<cluster_size> findings merged)
- Stage 5 proof: <status> (PoC: <has_poc>)
- D3FEND techniques: <id1> (<tactic1>), <id2> (<tactic2>)
- ATT&CK techniques: <id1> (<tactic1>), <id2> (<tactic2>)
- Exposure score: <score>/100 (threat actor likelihood: <HIGH|MEDIUM|LOW>)
- Threat narrative: <narrative>
- Confidence: <validated|high>

## Debate Transcripts (sample)
<transcript for finding F-1>

## PoC Artifacts
<links to Dockerfiles, harnesses, fuzzing inputs>

## D3FEND Coverage
<techniques exercised in this scan>
```

## Next Steps

- [x] Create pipeline directory structure
- [x] Implement OpenRouter integration layer
- [x] Implement Stage 1 (Prepare)
- [x] Implement Stage 2 (Scan)
- [x] Implement Stage 3 (Validate)
- [x] Implement Stage 4 (Dedup)
- [x] Implement Stage 5 (Prove)
- [x] Integrate D3FEND binding + ATT&CK enrichment
- [x] Cross-language taint tracking (`cross_language/`)
- [x] Plugin synthesis agent (`plugin_synthesis/`)
- [x] On-chain threat intel layer (`threat_intel/`)
- [x] Symbolic execution + formal verification (`prove_extension/`)
- [x] Feedback loop (`feedback/`)
- [x] Real MITRE D3FEND catalog + CCI mappings
- [ ] **Pre-processing agent for task descriptions** — CyberGym failure analysis shows 82% of wrong-code-area findings come from vague descriptions lacking function/file identifiers. Build a pre-processor that parses vague task descriptions, queries the code index for candidate files/functions, and injects identifiers before the scan stage.
- [ ] **Harness format detector before prove stage** — CyberGym failures include otherwise-sound reproductions failing because libFuzzer inputs were submitted for honggfuzz-format tasks. Build a format fingerprinting step that identifies required fuzzer format (libFuzzer, honggfuzz, AFL++, etc.) before PoC construction.
- [ ] **Cross-task pattern memory for CyberGym** — Store solved patterns from previous CyberGym tasks as few-shot context for similar tasks, improving success rate on the remaining ~12%.
- [ ] Add approval gate
- [ ] Write tests and documentation
