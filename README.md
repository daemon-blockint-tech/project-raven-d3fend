# Multi-Model Agentic Cyber Defense

<p align="center">
<svg width="480" height="168" viewBox="0 0 4677 2240" fill="none" xmlns="http://www.w3.org/2000/svg">
<path d="M1055.29 745V278.8H1234.44C1327.68 278.8 1388.95 334.744 1388.95 421.99C1388.95 509.236 1327.68 565.846 1234.44 565.846H1113.23V745H1055.29ZM1229.78 332.08H1113.23V512.566H1229.11C1290.39 512.566 1329.68 477.268 1329.68 421.99C1329.68 366.712 1291.05 332.08 1229.78 332.08ZM1457.39 745V278.8H1635.87C1729.11 278.8 1791.05 334.744 1791.05 421.99C1791.05 487.258 1751.76 537.874 1691.82 554.524L1796.38 745H1731.11L1632.54 565.846H1515.33V745H1457.39ZM1631.88 332.08H1515.33V512.566H1631.21C1692.48 512.566 1731.78 476.602 1731.78 421.99C1731.78 367.378 1692.48 332.08 1631.88 332.08ZM2293.56 511.9C2293.56 649.096 2202.32 748.996 2071.11 748.996C1939.91 748.996 1848.67 649.096 1848.67 511.9C1848.67 374.704 1939.91 274.804 2071.11 274.804C2202.32 274.804 2293.56 374.704 2293.56 511.9ZM1907.94 511.9C1907.94 619.126 1973.88 695.716 2071.11 695.716C2168.35 695.716 2234.28 619.126 2234.28 511.9C2234.28 404.674 2168.35 328.084 2071.11 328.084C1973.88 328.084 1907.94 404.674 1907.94 511.9ZM2427.46 630.448V278.8H2485.4V635.11C2485.4 707.038 2447.44 745 2375.51 745H2314.91V691.72H2368.19C2410.15 691.72 2427.46 672.406 2427.46 630.448ZM2582.38 745V278.8H2879.42V332.08H2640.32V481.264H2839.46V534.544H2640.32V691.72H2888.07V745H2582.38ZM3144.62 748.996C3010.75 748.996 2926.84 654.424 2926.84 511.9C2926.84 370.708 3014.08 274.804 3149.28 274.804C3252.51 274.804 3327.77 334.744 3345.08 431.314H3283.81C3265.83 366.712 3216.55 328.084 3146.62 328.084C3048.71 328.084 2986.11 404.008 2986.11 511.9C2986.11 619.126 3046.05 695.716 3143.95 695.716C3215.88 695.716 3265.83 657.754 3283.15 592.486H3344.42C3327.1 689.056 3249.85 748.996 3144.62 748.996ZM3361.76 332.08V278.8H3722.07V332.08H3570.88V745H3512.94V332.08H3361.76Z" fill="white"/>
<path d="M1724 1441V741H1992C2132 741 2225 825 2225 956C2225 1054 2166 1130 2076 1155L2233 1441H2135L1987 1172H1811V1441H1724ZM1986 821H1811V1092H1985C2077 1092 2136 1038 2136 956C2136 874 2077 821 1986 821ZM2354.66 1441H2264.66L2531.66 741H2634.66L2900.66 1441H2807.66L2733.66 1252H2428.66L2354.66 1441ZM2580.66 836L2454.66 1173H2707.66L2580.66 836ZM3077.16 1441L2825.16 741H2917.16L3131.16 1338L3344.16 741H3434.16L3182.16 1441H3077.16ZM3511.11 1441V741H3957.11V821H3598.11V1045H3897.11V1125H3598.11V1361H3970.11V1441H3511.11ZM4152.75 1441H4067.75V741H4147.75L4523.75 1281V741H4608.75V1441H4528.75L4152.75 901V1441Z" fill="white"/>
<path d="M427 21.5L136 258.5L185 277L37.5 554L103 502.5L56 716V782L0 875.5V1026L173.5 1331L497.5 1610.5V1577.5L530.5 1598.5L715.5 1835.5L516 2084.5H338L286 2164.5L640.5 2152.5L669 2084.5H654.5L640.5 2061L856.5 1812L838 1725.5L953 1770L1007 1861.5L882.5 2084.5H715.5L669 2164.5H1154.5L1091.5 2084.5H1007L990.5 2061L1154.5 1812V1753.5L1349.5 1835.5L1596 2103.5L2293 2239.5L1983 1965V1936.5L2293 2061L1802.5 1610.5L1833 1563.5L1783.5 1413L1377.5 988.5L1091.5 674L838 566L772 420.5L859 305.5C899.667 302.333 989 295.5 1021 293.5C1053 291.5 1117.33 269.333 1145.5 258.5L1187.5 275C1169.5 243.667 1125.1 173.5 1091.5 143.5C1057.9 113.5 864.5 85.6667 772 75.5L758 56.5L600.5 0L427 21.5Z" fill="white"/>
<circle cx="588" cy="152" r="48" fill="#FF0000"/>
</svg>
</p>

## Overview

This pipeline implements a Microsoft-style multi-model agentic security system in Project Raven, leveraging the OpenRouter SDK for access to 300+ AI models. The pipeline follows a 5-stage architecture:

## Design Principles (Kelly's 14 Rules)

Raven is built on principles proven by Lockheed Martin's Skunk Works under Kelly Johnson—the legendary innovation unit that delivered breakthrough aircraft like the SR-71 Blackbird in record time with minimal bureaucracy.

> **"Be quick, be quiet, and be on time."** — Kelly Johnson

| Rule | Principle | Raven Application |
|------|-----------|-------------------|
| **1** | **Complete control** | `PipelineOrchestrator` has end-to-end autonomy; no micromanagement between stages |
| **2** | **Small project offices** | 11 specialized auditors, not 100+ generalists—small, elite agents |
| **3** | **Restrict viciously** | Agentic system augments small teams; 10% of traditional AppSec headcount |
| **4** | **Simple, flexible drawings** | Modular Python modules; swap auditors without rearchitecting |
| **5** | **Minimum reports** | Findings are the product—not process docs; D3FEND bindings provide traceability |
| **6** | **Monthly cost review** | Real-time cost tracking via OpenRouter; $10 trial budget with stage-level limits |
| **7** | **Contractor responsibility** | Agents own their bug-class domains; no handoffs between teams |
| **8** | **Streamlined inspection** | Multi-model debate (3-5 models) replaces manual code review cycles |
| **9** | **Authority to test** | Prove stage generates PoCs; agents "fly" their own findings |
| **10** | **Clear specs upfront** | CDP contract—every finding terminates at 𝒯/𝓜/𝓛; D3FEND mappings agreed in advance |
| **11** | **Timely funding** | Per-request billing via OpenRouter; no running to finance for every scan |
| **12** | **Mutual trust** | Feedback loop (thumbs up/down) + human-in-the-loop for edge cases |
| **13** | **Controlled access** | Defender-only enforcement; no offensive tooling in pipeline |
| **14** | **Reward performance** | Agent effectiveness measured by true positive rate, not tokens consumed |

**The 15th Rule for Raven:**

> *"Starve before building another static rule engine. They don't know what vulnerabilities look like in 2025 and will drown you in false positives before they break your security budget."*

These principles validate Raven's approach: **small, autonomous, empowered agents operating with clear contracts, minimal bureaucracy, and direct accountability for results.**

## Architecture


1. **Prepare** - Ingest codebase, build language-aware indices, generate threat models
2. **Scan** - Run specialized auditor agents to discover vulnerabilities
3. **Validate** - Multi-model debate to filter false positives
4. **Dedup** - Collapse semantically equivalent findings
5. **Prove** - Generate and execute PoCs to prove vulnerabilities
6. **D3FEND Binding** - Map findings to D3DEND countermeasures

## Architecture

```
project-raven-d3fend/pipeline/
├── config.yaml                 # Pipeline configuration
├── orchestrator.py             # Main pipeline orchestrator
├── multi_agent_orchestrator/  # 100+ Agent Multi-Model Orchestration
│   ├── agent_core.py          # EventEmitter agent with hooks
│   ├── agent_pool.py          # Spawn, route, balance 100+ agents
│   ├── model_router.py        # Dynamic multi-model allocation
│   ├── debate_panel.py        # Multi-model debate validation
│   ├── enricher_agent.py      # D3FEND + ATT&CK enrichment
│   ├── triage_agent.py        # DevSecOps routing & Patch Tuesday
│   ├── hooks.py               # Lifecycle hooks & metrics
│   ├── config.py              # 100+ agent definitions
│   └── orchestrator.py        # Multi-agent pipeline coordinator
├── models/                    # Data models for all stages
├── openrouter_integration/    # OpenRouter SDK wrapper
│   ├── client.py
│   ├── model_selector.py
│   └── cost_tracker.py
├── prepare/                   # Stage 1: Prepare
│   ├── ingester.py
│   ├── indexer.py
│   ├── threat_modeler.py
│   └── git_analyzer.py
├── scan/                      # Stage 2: Scan
│   ├── agent_router.py
│   └── finding_collector.py
├── validate/                  # Stage 3: Validate
│   ├── debate_orchestrator.py
│   ├── debater.py
│   ├── voting.py
│   └── confidence_scorer.py
├── dedup/                     # Stage 4: Dedup
│   ├── embedding_generator.py
│   ├── similarity.py
│   ├── clustering.py
│   └── merger.py
├── prove/                      # Stage 5: Prove
│   ├── poc_generator.py
│   ├── harness_builder.py
│   ├── fuzzer.py
│   ├── sandbox.py
│   └── sanitizer_runner.py
├── d3fend/                    # D3FEND + ATT&CK Enrichment
│   ├── cwe_mapper.py
│   ├── ontology_client.py
│   ├── remediation.py
│   ├── attack_mapper.py
│   ├── d3fend_catalog_loader.py
│   ├── cci_loader.py
│   └── enrichment_engine.py
├── threat_intel/              # On-Chain Threat Intel
│   └── onchain_threat_intel.py
├── cross_language/            # Cross-Language Analysis
│   ├── ffi_analyzer.py
│   ├── solidity_analyzer.py
│   ├── wasm_analyzer.py
│   └── taint_tracker.py
├── plugin_synthesis/          # Domain Invariant Extraction
│   └── plugin_synthesis_agent.py
├── prove_extension/           # Symbolic Execution & Formal Verification
│   └── formal_verification.py
├── eval/                      # Benchmark Evaluation Framework
│   ├── ground_truth_loader.py
│   ├── evaluator.py
│   └── report_generator.py
├── feedback/                  # Retrospective Feedback Loop
│   ├── false_negative_tracker.py
│   ├── cve_parser.py
│   ├── context_updater.py
│   └── feedback_agent.py
└── openai_agents_adapter/     # Optional OpenAI Agents SDK Backend
    ├── auditor_agent.py       # Bug-class specialist agents
    ├── debater_agent.py       # Multi-model debate panel
    └── pipeline_runner.py     # Full MDASH pipeline orchestration
```

## Installation

### Requirements

- Python 3.9+
- OpenRouter API key (set `OPENROUTER_API_KEY` environment variable)
- Docker (optional, for Prove stage sandboxing)

### Dependencies

Install the OpenRouter SDK:

```bash
pip install openrouter
```

Optional: Install the OpenAI Agents SDK for production-grade agent orchestration, tracing, and session management:

```bash
pip install openai-agents
```

Additional Python dependencies:
- pyyaml
- scikit-learn (for clustering)
- numpy (for similarity calculations)

## Configuration

Edit `pipeline/config.yaml` to customize:
- Model selections for each stage
- Budget limits
- Debate configuration
- Deduplication thresholds

## Usage

### Basic Usage

```python
from pipeline.orchestrator import PipelineOrchestrator

# Initialize pipeline
pipeline = PipelineOrchestrator()

# Run pipeline on a target
report = pipeline.run_pipeline(
    target="https://github.com/example/repo.git",
    target_type="c-cpp-source",
    trials=10
)

# Print report
print(report.to_markdown())
```

### Using the OpenAI Agents SDK Backend (Optional)

The pipeline includes an optional adapter for the [OpenAI Agents SDK](https://github.com/openai/openai-agents-python), providing production-grade agent orchestration, built-in tracing, session management, and human-in-the-loop support.

```python
from pipeline.openai_agents_adapter import MDASHAgentsRunner, PipelineConfig

# Configure with diverse models for debate
config = PipelineConfig(
    auditor_models=["gpt-4o", "claude-3-5-sonnet-20241022"],
    debater_models=["gpt-4o", "gpt-4o-mini", "claude-3-5-sonnet-20241022"],
    enable_tracing=True,
    max_cost_usd=10.0
)

# Run the full MDASH pipeline
runner = MDASHAgentsRunner(config)
report = runner.run_pipeline(
    target_path="/path/to/codebase",
    target_type="c-cpp-source"
)

print(f"Found {report['findings_count']} findings")
for finding in report['findings']:
    print(f"- {finding['bug_class']} at {finding['location']}")
```

### Using the Multi-Agent Orchestrator (100+ Agents)

The pipeline includes a production-grade multi-agent orchestrator that spawns, routes, and manages 100+ specialized agents across 7 pipeline stages with dynamic model allocation.

```python
import asyncio
from pipeline.multi_agent_orchestrator import MultiAgentOrchestrator

async def run():
    # Initialize with dynamic model allocation
    orchestrator = MultiAgentOrchestrator(
        api_key="$OPENROUTER_API_KEY",
        budget_usd=50.0,
        max_concurrent=50,
        debate_panel_size=5,
        debate_threshold=0.67,
    )

    # Run the full 7-stage pipeline
    report = await orchestrator.run_pipeline(
        target="/path/to/codebase",
        target_type="c-cpp-source",
    )

    print(f"Found {len(report.findings)} findings")
    print(f"Wall time: {report.wall_time_seconds:.1f}s")
    print(f"Total cost: ${report.total_cost_usd:.2f}")
    print(f"Agents spawned: {report.metrics['total_agents']}")

    for f in report.findings:
        print(f"- {f['bug_class']} at {f['location']} | "
              f"owner={f['finding_owner']} | "
              f"patch_tuesday={f['patch_tuesday_target']}")

asyncio.run(run())
```

**Features:**
- **100+ distinct agent classes** — each bug class has its own specialized auditor
- **Dynamic model allocation** — frontier models (GPT-4o, Claude 3.5) for complex reasoning, distilled models for high-volume scanning
- **Parallel async execution** — all agents run concurrently with built-in rate limiting
- **Multi-model debate** — 3-7 debaters per finding using different models for independent reasoning
- **DevSecOps integration** — every finding gets an owner, Patch Tuesday deadline, and SLA

### Supported Target Types

- `solana-program`
- `evm-contract`
- `c-cpp-source`
- `rust-source`
- `android-apk`
- `binary-elf`
- `binary-pe`
- `linux-kernel-module`
- `live-host`
- `network-range-own-assets`

### Environment Variables

Required:
- `OPENROUTER_API_KEY` - OpenRouter API key

Optional:
- `OPENROUTER_DEBUG` - Enable debug logging (set to `true`)

## CDP Compliance

The pipeline enforces Raven's Contract for Defensible Predictions (CDP):

- Every finding terminates at:
  - **𝒯** - Tool oracle (e.g., sanitizer results)
  - **𝓜** - ML detector with calibrated score
  - **𝓛** - Scored hypothesis with falsification test

- Every finding includes D3FEND technique bindings
- Low-confidence items are marked as "unconfirmed", not findings

## D3FEND + ATT&CK Enrichment

The pipeline enriches every finding with both defensive and offensive threat intelligence context:

### D3FEND Technique Mapping
- Every finding is automatically mapped to relevant D3FEND defensive techniques via `D3FENDEnrichmentEngine`
- CWE-to-D3FEND mappings drawn from the D3FEND ontology (`ontology_client.py`)
- Produces defensive recommendations aligned to MITRE D3FEND tactics

### ATT&CK Technique Enrichment
- `ATTACKMapper` maps bug classes and CWEs to relevant MITRE ATT&CK offensive techniques
- Provides threat actor context: which tactics would exploit this vulnerability
- Generates a threat narrative explaining real-world exploitation scenarios

### Exposure Score Adjustment
- Findings with HIGH threat-actor likelihood get a 1.15x priority boost
- Strong D3FEND defensive coverage can slightly reduce exposure
- Integrated into `OnChainThreatIntelLayer` for unified prioritization

### Real Data Sources

The enrichment engine loads real MITRE data when available:

- **D3FEND Catalog CSV** (`tools/d3fend.csv`) — 270+ D3FEND techniques with tactics, hierarchy levels, and definitions. Loaded via `D3FENDCatalogLoader`.
- **CCI Mappings JSON** (`tools/cci.2022-04-05.json`) — CCI-to-D3FEND mappings from the D3FEND SPARQL endpoint, linking NIST SP 800-53 controls to defensive techniques. Loaded via `CCILoader`.

```python
from pipeline.d3fend import D3FENDEnrichmentEngine

# With real data files
engine = D3FENDEnrichmentEngine(
    catalog_path="tools/d3fend.csv",
    cci_path="tools/cci.2022-04-05.json"
)
```

### Usage

```python
from pipeline.d3fend import D3FENDEnrichmentEngine
from pipeline.models import CandidateFinding, BugClass

engine = D3FENDEnrichmentEngine()

# Enrich a candidate finding
result = engine.enrich_candidate(candidate)
print(result.threat_narrative)
print([t.id for t in result.d3fend_techniques])
print([t.id for t in result.attack_techniques])
```

## Cost Management

The pipeline includes cost tracking and budget enforcement:
- Per-stage cost limits
- Total budget cap
- Automatic termination when budget exceeded

Default budget: $10.00 USD

## Next Steps

To run the pipeline:

1. Set `OPENROUTER_API_KEY` environment variable
2. Install dependencies
3. Run the orchestrator with your target

Example:

```bash
export OPENROUTER_API_KEY="your-api-key-here"
python pipeline/orchestrator.py
```

## Integration with Existing Raven

The pipeline is designed to integrate with existing Raven modules:
- Uses existing D3FEND OWL ontology (`raven/d3fend/`)
- Compatible with Raven skills structure
- Follows Raven's defender-only enforcement policies
