---
name: raven-zero-day-detection
description: Run Raven's online 0-day detection stack against live telemetry, files, binaries, or network flows. Use when the user says "detect 0-days", "scan for novel threats", "run anomaly detection", "screen this artifact for unknown malware", "novelty detection", or asks for a continuous monitor against unknown-bad. Every detection terminates at a classical-ML detector (𝓜) or a tool-oracle rule (𝒯) — LLM verdicts alone are never accepted — and every alert ships with a D3FEND Detect-tactic technique id, ATT&CK offensive context, and exposure scoring. Built for production DevSecOps at enterprise scale on private codebases.
---

# Raven — 0-Day Detection

This skill is Raven's detection front-end in the MDASH (Multi-Model Agentic Security Harness) pipeline. It composes ML detectors and tool-oracle rule packs into one streaming or batch pipeline that emits novelty alerts with D3FEND, ATT&CK, and exposure context.

This skill is built for production DevSecOps at enterprise scale:
- Every finding has an owner, a triage process, and a Patch Tuesday deadline
- Operates on private codebases (Windows, Hyper-V, Azure, drivers) not in any LLM training corpus
- Collaboration between ACS (Autonomous Code Security), MORSE (Offensive Research & Security Engineering), and WARP (Windows Attack Research and Protection)
- At Microsoft scale, if a tool produces noise, the noise is everyone's problem — precision is paramount

It does NOT investigate alerts (use `raven-zero-day-investigator`), and it does NOT take containment action (use `raven-zero-day-defend`).

The skill enforces Raven's CDP rule strictly: a detection without a 𝓜 score or a 𝒯 rule hit is not a detection — it is a hypothesis, and must be routed to `raven-zero-day-hunter` instead.

## When to use

Trigger when the user asks any of:

- "Scan `<artifact>` for novel / 0-day patterns"
- "Run anomaly detection on `<telemetry>`"
- "Continuously monitor `<host / endpoint / cluster>`"
- "Score this binary's exploit-likelihood"
- "Novelty detection on these syscall traces"
- "Is this file unknown-bad?"

Do not trigger for: full hunts (use `raven-zero-day-hunter`), pattern library queries (use `raven-zero-day-threat-patterns`), or post-detection response.

## Inputs

Required:

1. Mode — one of: `scan-file`, `scan-binary`, `scan-source`, `scan-memory`, `scan-flows`, `monitor-host`, `monitor-endpoint-batch`
2. Target locator — file path, host, batch manifest, or live-stream endpoint
3. Sensitivity — `low` (high precision, low recall), `medium` (default), `high` (high recall, accept FPR ~10%)

Optional:

- Pattern pack version — pinned to a `raven-zero-day-threat-patterns` export SHA; default is `latest`
- Alert sink — `stdout`, `file`, `kafka`, `prometheus`; default `file` plus `prometheus`

## Pipeline — four mandatory stages

### Stage 1 — Detector selection by mode

| Mode | 𝓜 detectors | 𝒯 rule packs |
|------|-------------|--------------|
| `scan-file` | `pipeline/scan/agent_router.py` (IsolationForest + RandomForest ensemble) | `pipeline/scan/finding_collector.py` |
| `scan-binary` | `pipeline/scan/agent_router.py`, `pipeline/cross_language/wasm_analyzer.py` | `pipeline/scan/finding_collector.py`, `pipeline/prepare/indexer.py` |
| `scan-source` | `pipeline/scan/agent_router.py`, `pipeline/cross_language/taint_tracker.py` | `pipeline/cross_language/solidity_analyzer.py`, `pipeline/prepare/indexer.py` |
| `scan-memory` | `pipeline/cross_language/wasm_analyzer.py`, `pipeline/cross_language/ffi_analyzer.py` | `pipeline/prepare/indexer.py` |
| `scan-flows` | `pipeline/scan/agent_router.py` (IsolationForest on flow features) | `pipeline/scan/finding_collector.py` |
| `monitor-host` | `pipeline/cross_language/taint_tracker.py` + `pipeline/cross_language/ffi_analyzer.py` | `pipeline/scan/finding_collector.py` |
| `monitor-endpoint-batch` | Same as `monitor-host`, distributed | Same |

The skill MUST run the 𝒯 packs in parallel with the 𝓜 detectors — neither alone is sufficient. Detection rule: an alert fires when EITHER 𝓜 anomaly score crosses the sensitivity threshold OR a 𝒯 rule hits, NOT both.

### Stage 2 — Feature extraction (𝒯-grounded)

Every detection must derive features from the actual artifact, not from LLM-generated paraphrase:

- Files / binaries → entropy, PE/ELF header anomalies, import table, embedded strings via `pipeline/prepare/ingester.py`
- Source → AST features via `pipeline/prepare/indexer.py`
- Memory → process tree, suspicious mappings via `pipeline/prepare/indexer.py`
- Flows → per-flow stats (bytes, packets, IAT, port entropy)
- Hosts → syscall sequences via `pipeline/cross_language/taint_tracker.py`

Feature vectors are persisted to the alert record so investigators can recompute.

### Stage 3 — Scoring (𝓜)

The IsolationForest + RandomForest ensemble in `pipeline/scan/agent_router.py` returns:

- `anomaly_score` ∈ [-1, 1], lower is more anomalous
- `novelty_class` — one of: `seen`, `near-variant`, `novel`
- `confidence` — model-reported

Thresholds by sensitivity:

| Sensitivity | anomaly_score cutoff | novelty class accepted |
|-------------|----------------------|------------------------|
| low | < -0.6 | `novel` only |
| medium | < -0.4 | `near-variant` or `novel` |
| high | < -0.2 | any |

If a sample's `novelty_class` is `near-variant`, the skill MUST also run `pipeline/scan/agent_router.py` variant analysis branch against the matched seed CVE — this is the ZeroDayBench-style branch.

### Stage 4 — Enrich / D3FEND + ATT&CK binding (𝒯-grounded)

Every alert that survives Stage 3 gets enriched via `pipeline/d3fend/enrichment_engine.py` to attach:

1. **D3FEND Detect-tactic techniques** — from `pipeline/d3fend/d3fend_catalog_loader.py` (real 271-entry MITRE catalog):
   - File / binary scan → D3-FA (File Analysis)
   - Memory scan → D3-PA (Process Analysis)
   - Flow scan → D3-NTA (Network Traffic Analysis)
   - Syscall sequence → D3-PA + D3-IPCTA (IPC Traffic Analysis)
   - Source AST → D3-SCA (Source Code Analysis)
2. **ATT&CK offensive techniques** — from `pipeline/d3fend/attack_mapper.py` for threat actor context
3. **Exposure scoring** — from `pipeline/threat_intel/onchain_threat_intel.py` for real-world impact
4. Cross-checking via `pipeline/d3fend/ontology_client.py` — the alert is dropped if the id is not in the ontology (defensive consistency check, not a logic shortcut).

## Alert record schema

```json
{
  "alert_id": "A-2026-04-30-00001234",
  "ts": "2026-04-30T07:14:00Z",
  "mode": "scan-binary",
  "target": "<locator>",
  "detector_hits": [
    {"kind": "ml", "name": "zero_day_detector", "anomaly_score": -0.71, "novelty_class": "novel"},
    {"kind": "yara", "rule_id": "raven.binary.suspicious_packer_v3", "rule_pack_sha": "<sha>"}
  ],
  "features_path": "alerts/A-...-features.parquet",
  "d3fend_techniques": ["D3-FA", "D3-PA"],
  "attack_techniques": ["T1190", "T1071"],
  "exposure_score": 75,
  "severity": "high",
  "next_action": "route-to-investigator",
  "finding_owner": "security-team@microsoft.com",
  "cdp_grounding": {"M": true, "T": true, "L": false}
}
```

`cdp_grounding` MUST have at least one of `M` or `T` set to true. The skill MUST drop any alert where both are false — that is an LLM speculation and does not belong on this surface.

## Continuous-monitor mode

For `monitor-host` and `monitor-endpoint-batch`:

- Run as a long-lived loop with a per-iteration budget (default 5 seconds wall-clock).
- Push alerts to the configured sink at most once per `alert_id` (dedupe on a 24-hour sliding window).
- Emit a Prometheus `raven_detection_alert_total{mode,severity,d3fend_id}` counter for every alert.
- Emit a heartbeat `raven_detection_heartbeat_seconds{mode}` every iteration so downstream knows the loop is alive.

If the iteration budget is exceeded for 3 iterations in a row, the skill MUST self-throttle (drop sensitivity by one level) rather than fall behind silently.

## Output contract — single-shot mode

```markdown
# Raven 0-Day Detection — <mode> on <target>

## Run metadata
- Sensitivity: <low|medium|high>
- Pattern pack: <sha>
- Wall-clock: <s> / processed: <n> samples

## Alerts (<count>)

### Alert A-<id>
- Detector hits: <list>
- Anomaly score: <value>
- Novelty class: <seen|near-variant|novel>
- D3FEND: <id list>
- Severity: <low|medium|high|critical>
- Next action: <route-to-investigator|route-to-defender|route-to-auto-prevent>
- Features: <path>

(repeat per alert)

## No-alert samples (<count>)
| Sample | Reason |
|--------|--------|

## CDP audit
- Alerts grounded in 𝓜 only: <n>
- Alerts grounded in 𝒯 only: <n>
- Alerts grounded in both: <n>
- Alerts dropped for ungrounded: <n>
```

## Refusal rules

1. Refuse to emit an alert without 𝓜 or 𝒯 grounding.
2. Refuse to run `monitor-host` on hosts the user does not own or has not authorized.
3. Refuse to use a pattern pack SHA that fails its `raven.d3fend.coverage.verify_pack(sha)` integrity check.
4. Refuse to silently throttle without emitting a Prometheus `raven_detection_self_throttle_total` increment.
5. Refuse to mark an alert `critical` without at least two detector hits (one 𝓜 and one 𝒯) — single-source criticals are forbidden.

## Related skills and modules

- `raven-zero-day-hunter` — upstream for full pipeline hunts and deeper analysis.
- `raven-zero-day-investigator` — destination for every `route-to-investigator` alert.
- `raven-zero-day-defend` — destination when severity is high and a known D3FEND plan exists.
- `pipeline/` — source-of-truth implementation of all MDASH stages
- `pipeline/d3fend/` — D3FEND + ATT&CK enrichment with real MITRE catalog data
- `pipeline/threat_intel/` — on-chain exposure scoring for prioritization
- `pipeline/scan/` — agent routing and finding collection
- `pipeline/eval/` — benchmark evaluation framework (CyberGym, StorageDrive, MSRC)
