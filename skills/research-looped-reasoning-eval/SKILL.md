---
name: raven-research-looped-reasoning-eval
description: Scaffold a research-grade experiment that tests whether a Looped / Recurrent-Depth Transformer (RDT) is better than a parameter-matched vanilla transformer at vulnerability discovery, when both are continued-pretrained on a security corpus. Use when the user says "test the looped-transformer hypothesis", "run the OpenMythos RDT experiment", "compare loop count to trial budget", "does inference-time loops help security reasoning", or asks for a reproducible research pipeline around the Mythos architecture hypothesis. The skill scaffolds the experiment — it does NOT make claims about Mythos itself, and it explicitly bins OpenMythos as a community speculative reconstruction, not Anthropic's actual model.
---

# Raven — Looped-Reasoning Vulnerability-Discovery Research Eval

This skill is a research scaffold, not a production capability. It exists to answer one question, honestly:

> Does inference-time recurrence in a Recurrent-Depth Transformer (RDT) improve vulnerability-discovery quality over a parameter-matched fixed-depth transformer, when both are continued-pretrained on the same security corpus?

The answer matters because the OpenMythos community speculation ([kyegomez/OpenMythos](https://github.com/kyegomez/OpenMythos)) and the Mythos Preview public record both suggest depth-via-looping as a likely contributor to Mythos's strong code-reading. If the hypothesis holds at small scale on a defender-relevant benchmark, Raven gets a defensible architectural bet. If it fails, Raven has a publishable negative result and stops chasing the wrong rabbit.

This skill is honest about three boundaries:

1. OpenMythos is an independent reconstruction ([its own README disclaimer](https://github.com/kyegomez/OpenMythos)). The experiment does not validate Mythos. It validates a property the reconstruction predicts.
2. The experiment runs at small scale (3B params). Negative results at small scale do not refute large-scale claims. Positive results at small scale do not prove them either — they are evidence of a trend.
3. No checkpoint is publicly trained yet. The skill scaffolds pretraining, continued pretraining, and evaluation from scratch.

## When to use

Trigger when the user asks any of:

- "Run the looped-transformer research experiment"
- "Test OpenMythos at 3B on a security corpus"
- "Does loop count behave like a trial budget"
- "Compare RDT vs vanilla on vulnerability-discovery quality"
- "Scaffold the architecture-bet experiment for Raven"

Do not trigger for: production runs (this is research-only), grant deliverables (use `raven-d3fend/positioning.md` instead), or claims that imply Raven actually uses a Mythos-class model.

## Honest framing — what this experiment can and cannot tell you

| Question | Can this experiment answer? |
|----------|----------------------------|
| Does more inference-time loops help vulnerability reasoning at 3B scale? | Yes |
| Does the loop-count budget behave like a trial budget (Cybergym pattern)? | Yes |
| Is RDT-3B better than vanilla-3B at the same FLOPs per forward? | Yes |
| Does this prove Mythos uses looped reasoning? | No — it is consistent evidence, not proof |
| Does this scale to 100B+? | Unknown — Parcae paper provides scaling laws, but does not prove them at frontier |
| Does this make Raven Mythos-class? | No — Raven is the harness, the model is one component |

## Inputs

Required:

1. Compute budget — `gpu_hours` (default 200 H100-hours for full experiment), `max_train_tokens` (default 30B per model)
2. Security corpus paths — must point at workspace files; the skill validates corpus integrity before training
3. Output dir — where checkpoints, eval logs, and the final research report land

Optional:

- Model variant — `open_mythos_3b` (default), `open_mythos_1b` (smoke test), `open_mythos_10b` (if compute permits)
- Vanilla baseline — `llama_3b` or `qwen_3b` parameter-matched architecture
- Loop counts to evaluate — default `[1, 2, 4, 8, 16, 32]`
- Random seeds — default `[42, 1337, 2026]` for replication

## Phase 0 — Reproducibility & honest-bookkeeping setup (mandatory)

Before any training, the skill writes a `manifest.json` to the output dir containing:

- Git commit SHAs of: this skill, OpenMythos (pinned), the corpus build scripts
- SHA-256 of every corpus file
- GPU hardware (model + driver version + CUDA + PyTorch versions)
- Random seeds
- All hyperparameters (read directly from `MythosConfig`)
- Expected wall-clock and compute cost
- Explicit statement: "This experiment does not validate Claude Mythos Preview. It tests a property predicted by the OpenMythos community reconstruction."

A run without manifest is invalid. The skill refuses to start training if the manifest cannot be written or if any corpus file's SHA does not match the pre-registered value.

## Phase 1 — Security corpus assembly

The corpus is what makes the result defender-relevant. FineWeb-Edu (OpenMythos's default training set) is generic web text — useless for security reasoning. The skill assembles a layered security corpus:

| Layer | Source | Approximate tokens | License |
|-------|--------|--------------------|---------|
| L1 — Base | FineWeb-Edu `sample-10BT` | 10B | ODC-BY |
| L2 — Code | The Stack v2 (filtered to C, C++, Rust, Solidity, Python, Go) | 8B | Various — verify per-language |
| L3 — Vuln narratives | NVD CVE descriptions + linked references + advisory text 2010–2026 | 0.5B | CC-BY / NIST public |
| L4 — Security commits | Linux kernel + OpenSSL + curl + sqlite + nginx security-tagged commit messages + diffs | 1.5B | GPL / various — research use |
| L5 — Smart-contract audits | Public Solana / EVM audit reports (Trail of Bits, OpenZeppelin, etc.) | 0.3B | Per-publisher CC-BY where stated; skip otherwise |
| L6 — Detector rules | YARA, Semgrep, ARES, Sigma rule packs as plain text | 0.1B | Various FOSS |

The skill enforces:

- Per-source license check; entries without verifiable license are dropped, not used.
- Deduplication via SimHash at 64-bit threshold 4.
- Per-layer SHA-256 manifest.
- No CTF writeups, no exploit-code-with-shellcode (Raven defender edition). Filter via regex blocklist and a 𝓜 classifier from `raven/ml/zero_day_detector.py` running in inverse mode (block exploit-content).

Total ~20B tokens at first build. Optionally extend to 50B by widening L2.

## Phase 2 — Pretrain / continued-pretrain matrix

Three model configurations, all parameter-matched at 3B active params:

| Config | Architecture | Loop iterations (train) | Loop iterations (eval) |
|--------|--------------|-------------------------|------------------------|
| A — RDT-mythos | OpenMythos 3B (`mythos_3b()` config) | mean 8, sampled per Parcae | swept `[1, 2, 4, 8, 16, 32]` |
| B — RDT-static | Same OpenMythos 3B, ACT halting disabled, fixed loops | fixed 8 | swept `[1, 2, 4, 8, 16, 32]` |
| C — Vanilla | LLaMA-3 / Qwen-3 architecture, 3B params, depth tuned for FLOP parity per forward at loop=8 | n/a (fixed depth) | n/a |

Why three configs:

- A vs C — does looped beat vanilla at all?
- A vs B — does Parcae adaptive halting help over fixed loops?
- B vs C — does looping itself help, even without ACT?

Train each config on the assembled corpus for 30B tokens, 3 seeds each. Total 9 runs. Use the `training/3b_fine_web_edu.py` script from OpenMythos as a starting point and modify the dataset loader to consume the layered security corpus.

Mandatory training-time invariants:

- Log spectral radius ρ(A) every 100 steps for configs A and B. Run is invalidated if ρ(A) ≥ 1 at any point — this is the Parcae stability constraint the OpenMythos README emphasizes.
- Log loss every 10 steps; the skill auto-detects loss spikes (>3σ above rolling mean) and saves checkpoints around them for forensic analysis.
- Save checkpoints at 1B, 5B, 10B, 20B, 30B tokens for every run.

## Phase 3 — Evaluation suite

Five defender-relevant evals. The skill explicitly does NOT include offensive evals — no CTF execution, no exploit construction. Defender edition.

### Eval 3.1 — CVE-aware code completion accuracy (𝓜-graded)

Hold-out 500 NVD entries with linked patches from 2025–2026 (not in training). For each:

- Show the model the pre-patch code
- Ask: "Identify the vulnerability class (CWE) and the location"
- Grade with a 𝓜 classifier that compares model output to ground truth CWE + line range

Metric: accuracy at CWE-class + within-10-line localization. Compute curve over loop count for A and B.

### Eval 3.2 — Variant analysis recall (𝒯-graded)

500 pairs of (seed CVE, target codebase containing a variant). The model is asked to identify the variant. Grade with `raven/ml/variant_analyzer.py` as the tool oracle.

Metric: recall@k for k ∈ {1, 5, 10}. Curve over loop count.

### Eval 3.3 — Threat-model spirit-vs-letter recovery (𝓛-graded with falsification)

100 hand-crafted PR diffs that pass naive lint but violate an explicit threat-model invariant. The model gets the diff + the THREAT_MODEL.yaml. Grade by whether it surfaces a `letter_to_spirit_recovery` finding as defined in `raven-devsec-mythos-class`.

Metric: recovery rate. This is the key defender-relevant test — it directly measures the XBOW-documented Mythos weakness ([XBOW Mythos evaluation](https://xbow.com/blog/mythos-offensive-security-xbow-evaluation)) and whether loops help mitigate it.

### Eval 3.4 — Cost vs accuracy frontier (Cybergym-aligned)

Following the [Anthropic AI for Cyber Defenders post](https://red.anthropic.com/2025/ai-for-cyber-defenders/) Cybergym methodology: pick a fixed accuracy target, ask each (config, loop_count) pair what it costs to reach it. Plot pareto frontier.

The hypothesis to test: loop count behaves like trial count — i.e., the curve for config A at loop=8 should look like the curve for config C at trials=8. If it does, Raven gets a unified budget abstraction.

### Eval 3.5 — Severity-agreement against human experts

A small held-out set of 50 findings with senior-security-engineer severity labels. Each config's top-1 verdict is compared against expert label. Match the [Anthropic red team writeup](https://red.anthropic.com/2026/mythos-preview/)'s 89%/98% metric format.

## Phase 4 — Statistical analysis

For every metric:

- Compute mean ± 1.96 × stderr across 3 seeds.
- Run paired bootstrap (10k resamples) for every config-pair comparison.
- Apply Benjamini–Hochberg correction across the 5 evals × 3 config-pair comparisons = 15 hypotheses (FDR=0.05).
- Report effect sizes (Cohen's d), not just p-values.

A "positive" result requires: BH-corrected significance AND effect size d ≥ 0.5 AND the loop-count curve is monotonically improving up to the saturation point predicted by Parcae.

Anything less is reported as "consistent with no effect" — the skill REFUSES to spin marginal results as positive.

## Phase 5 — Honest-report generation

Auto-generate `report.md` with:

```markdown
# Looped-Reasoning Vulnerability-Discovery Eval — <date>

## Headline result
- Verdict: <SUPPORTS_HYPOTHESIS | INCONCLUSIVE | REFUTES_HYPOTHESIS>
- Confidence: <high | medium | low>
- One-line summary: <verbatim from the analyst>

## Honest disclaimers (mandatory)
1. OpenMythos is a community reconstruction, not Anthropic's Claude Mythos Preview.
2. This experiment was run at 3B scale. Results do not necessarily generalize to frontier scale.
3. We do not claim Raven is "Mythos-class" based on this result. Raven is a defender harness; the model is one component.

## Compute & reproducibility
- Total GPU-hours: <n>
- Wall clock: <h>
- Random seeds: [42, 1337, 2026]
- Commit SHAs: <list>
- Corpus SHA: <hash>
- All checkpoints: <s3 path / disk path>

## Eval results
<5 sections, one per eval, with table + curve description>

## Statistical defense
<bootstrap CI, effect sizes, BH-corrected p-values>

## What this means for Raven
- If SUPPORTS: candidate integration into CDP — loop count becomes a unified budget primitive across `raven-zero-day-hunter` trial count, `raven-devsec-mythos-class` verification depth, and `raven-zero-day-detection` sensitivity.
- If INCONCLUSIVE: park architecture bet; revisit at 10B scale or with larger corpus.
- If REFUTES: publish negative result, drop looped-reasoning from Raven's roadmap.

## What this means for the OpenAI grant submission
The grant submission does NOT depend on this result. Per raven-d3fend/positioning.md, Raven's grant pitch is CDP grounding + D3FEND OWL + defender-first — architectural choices are research-track, not pitch-track.
```

The skill refuses to ship a report that omits the "Honest disclaimers" section.

## Phase 6 — Publishable artifact

If the result is publishable (SUPPORTS or REFUTES with high confidence), the skill scaffolds:

- An arXiv-ready LaTeX file with the eval methodology and results
- The full corpus manifest (SHA-256 + license per file)
- A reproducibility kit: dockerfile + requirements pin + a single `make all` to re-run the experiment
- An OpenReview submission template targeting a security venue (USENIX Security, NDSS, IEEE S&P) with a defender-applications track

The skill explicitly does NOT scaffold a "Raven is Mythos-class" marketing piece. That would be dishonest.

## Refusal rules

1. Refuse to start training without a complete manifest + corpus SHA verification.
2. Refuse to ship a report without the Honest disclaimers section verbatim.
3. Refuse to claim the experiment validates Claude Mythos Preview itself.
4. Refuse to include CTF/exploit-construction evals. Defender edition.
5. Refuse to spin marginal results as positive — INCONCLUSIVE is a valid honest verdict.
6. Refuse to gate any Raven production behavior on this experiment until it has been independently replicated at ≥ 10B scale.
7. Refuse to skip Eval 3.3 (spirit-vs-letter) — it is the defender-relevant test, and the experiment is meaningless without it.

## Compute budget reference

A rough estimate for the full 9-run experiment at 3B × 30B tokens:

| Item | Cost |
|------|------|
| Training (9 runs × 30B tokens × 3B params) | ~150 H100-hours |
| Evaluation (5 evals × 3 configs × 6 loop counts × 3 seeds) | ~30 H100-hours |
| Buffer for restarts, corpus rebuild, debugging | ~20 H100-hours |
| **Total** | **~200 H100-hours** |

At commercial rates (Lambda, Voltage Park, etc., May 2026) this is in the low-thousands-USD range. The skill calls this out explicitly so the user can decide whether the architectural bet is worth that spend.

## Related skills & docs

- `raven-devsec-mythos-class` — production skill that the spirit-vs-letter eval (3.3) targets. Improvements there are the practical payoff if the experiment supports the hypothesis.
- `hermes-mythos-persona.md` — persona overlay that uses the *behavioral* properties of Mythos at the prompt level, independent of architecture. Always available, no experiment required.
- `raven-d3fend/positioning.md` — companion grant-positioning document; explicitly chooses Opsi C (skip OpenMythos from grant submission) and explains why this experiment is research-track only.
- OpenMythos repo — [kyegomez/OpenMythos](https://github.com/kyegomez/OpenMythos), MIT, ~12.7K stars as of May 14 2026, community speculative reconstruction.

## Provenance — sources this skill is built on

- [kyegomez/OpenMythos repo + README](https://github.com/kyegomez/OpenMythos) — architecture being tested
- [Parcae paper — Scaling Laws for Stable Looped Language Models](https://arxiv.org/abs/2604.12946) — stability via ρ(A) < 1, scaling laws
- [Saunshi et al. 2025 — Reasoning with Latent Thoughts on the Power of Looped Transformers](https://arxiv.org/abs/2502.17416) — theoretical basis for loop-as-CoT
- [Anthropic red team Mythos writeup](https://red.anthropic.com/2026/mythos-preview/) — methodology to match in evals 3.5
- [Anthropic AI for Cyber Defenders / Cybergym](https://red.anthropic.com/2025/ai-for-cyber-defenders/) — trial-budget methodology for eval 3.4
- [XBOW Mythos evaluation](https://xbow.com/blog/mythos-offensive-security-xbow-evaluation) — letter-vs-spirit weakness; defines eval 3.3
- [imiel.dev system card breakdown](https://imiel.dev/blog/claude-mythos-preview-system-card) — Mythos's 89%/98% severity-agreement format
