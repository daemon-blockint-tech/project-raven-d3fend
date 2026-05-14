# Benchmarks for Raven Defender LoRA

This document integrates five user-supplied benchmark sources into the Raven defender LoRA pipeline. Each benchmark is classified by what it is *good at measuring*, what it is *bad at measuring* for our defender-only mandate, and how it plugs into the training corpus (Layers L1–L6 in `SKILL.md` §3) or the eval harness (E1–E5 in `SKILL.md` §5).

CDP contract reminder: every benchmark we admit must terminate at 𝒯 (deterministic oracle), 𝓜 (calibrated detector), or 𝓛 (falsifiable hypothesis). Benchmarks that only produce free-text grades are downgraded to qualitative signals, not training labels.

## 0. TL;DR mapping

| Benchmark | License | Defender-aligned? | Use for training? | Use for eval? | CDP terminator |
|---|---|---|---|---|---|
| [OSSF CVE Benchmark](https://github.com/wunderalbert/ossf-cve-benchmark) | MIT | Yes — SAST evaluator over 200+ real CVEs | L2 + L4 (vulnerable/patched pairs) | E2 (Semgrep clean rate proxy) | 𝒯 SAST tools |
| [CyberGym](https://github.com/sunblaze-ucb/cybergym) | Apache 2.0 | Mixed — designed for offense (PoC generation), but the validator is defender-grade | L2 (vul descriptions) and L4 (fix diffs) ONLY | E2 patch verification, NOT PoC generation | 𝒯 ASan/UBSan |
| [Trident Arena Benchmarks](https://github.com/Ackee-Blockchain/trident-arena-benchmarks) | Unspecified — audit reports inside | Yes — Solana smart contract audits | Not used in main pipeline — separate Solana sub-skill | E6 (new — Solana audit recall) | 𝒯 professional audit gold |
| [Wake Arena Benchmarks](https://github.com/Ackee-Blockchain/wake-arena-benchmarks) | Unspecified | Yes — Solidity audit findings | Not used in main pipeline — separate Solidity sub-skill | E6 (new — Solidity audit recall) | 𝒯 Code4rena/Sherlock judging |
| [Awesome AI Security Benchmarks](https://github.com/EvanThomasLuke/Awesome-AI-Security-Benchmarks) | List (no license) | Index, not a benchmark | Discovery only — pick further benchmarks | Reference for adding more evals | n/a |

## 1. OSSF CVE Benchmark — primary L2/L4 grounding

[wunderalbert/ossf-cve-benchmark](https://github.com/wunderalbert/ossf-cve-benchmark) (MIT) ships ~200 real CVEs with both vulnerable and patched commits plus tool drivers for ESLint, NodeJSScan, and CodeQL.

### Why it fits the Raven defender pipeline

1. Pairs of (vulnerable, patched) commits are **exactly** the supervision signal L4 (secure code rewrite) needs — the patch is the ground-truth defender output for a given vulnerability.
2. The MITRE CWE Top 25 selector (`bin/cli report ... mitre-cwe-top:25:2020`) is a built-in stratifier so we can balance L4 by CWE class.
3. Tool driver SARIF outputs are deterministic 𝒯 oracles — they pass/fail per CVE, which is the signal shape DPO needs in §4.3.

### What we extract

- For each CVE: `(cve_id, vulnerable_diff, patched_diff, cwe_id, project, language)`.
- Built into L4 chat samples with the schema:

```json
{"messages":[
  {"role":"system","content":"You are Raven, a defender-only assistant ..."},
  {"role":"user","content":"This function from <project> is reported as <CVE-id> (<CWE>). Rewrite it so SAST (Semgrep / CodeQL / ESLint security plugins) reports clean while preserving behavior."},
  {"role":"assistant","content":"<patched_diff>\n\n(𝒯 SAST: this corresponds to the upstream-accepted fix; behavior preserved per the project's test suite.)"}
]}
```

### Caveats

- Stack is JS/TS-heavy. For C/C++ coverage we lean on CyberGym (next section) and ARVO.
- The MITRE CWE Top 25 list referenced in the README is 2020 vintage. Re-stratify against the [latest CWE Top 25](https://cwe.mitre.org/top25/) when building L4.
- The benchmark's own metric is tool-vs-CVE detection. We use it for *training supervision*, not as a leaderboard. Different goal.

### Builder

`scripts/data/build_l4_ossf.py` — clones the benchmark, walks the CVE metadata, materializes (vulnerable, patched) pairs into L4 JSONL with Semgrep clean-on-patched as a hard filter.

## 2. CyberGym — careful integration with strict defender-only fence

[sunblaze-ucb/cybergym](https://github.com/sunblaze-ucb/cybergym) (Apache 2.0) is the same benchmark Anthropic's red team used in [AI for Cyber Defenders](https://red.anthropic.com/2025/ai-for-cyber-defenders/). 1,507 real vulnerability instances from 188 OSS projects with ASan/UBSan validation. Paper: [arXiv:2506.02548](https://arxiv.org/abs/2506.02548). Dataset card: [sunblaze-ucb/cybergym on HuggingFace](https://huggingface.co/datasets/sunblaze-ucb/cybergym).

### Why we have to be careful

CyberGym's primary task design is **PoC generation** — the agent produces an input that crashes the vulnerable binary under sanitizer. That is offensive task framing, even though the artifact is a defender's sanitizer report. The `level3` difficulty even ships `patch.diff` to the agent.

If we train Raven to generate PoCs, we violate the defender-only contract in `positioning.md`. So we use CyberGym with two surgical restrictions:

**Rule A — never train on the "produce a crashing input" task formulation.** No PoC bytes in training data. No `submit.sh` scripts in training data.

**Rule B — use only the four asymmetric defender-side projections of each task:**

1. **Vulnerability description → CWE classification** (L2 supervision). Sample: `description.txt` → `cwe_id`.
2. **Vulnerability description → D3FEND defensive technique mapping** (L2 supervision). Sample: `description.txt` → ranked `d3f:D3-XXX` IRIs.
3. **Vulnerable code + sanitizer error → root-cause hypothesis** (L4 supervision, defender frame). Sample: `(repo-vul.tar.gz, error.txt)` → human-written root-cause-analysis paragraph + suggested fix area. NEVER a working exploit.
4. **Patch diff → "why this patch works" explanation** (L4 supervision). Sample: `patch.diff` → defender-style explanation grounded in CWE.

### Eval use — E2 patch verification, NOT PoC generation

For E2 we hand the model the vulnerable repo and ask: "Generate a patch that makes ASan report clean while preserving the test suite." We use CyberGym's submission server with a **patch-mode wrapper** that:

1. Applies the model's proposed patch to `repo-vul`.
2. Re-compiles.
3. Runs the original ASan-positive input.
4. Pass iff ASan reports clean AND the upstream test suite still passes.

This is the same eval shape as [AutoPatchBench](https://engineering.fb.com/2025/04/29/ai-research/autopatchbench-benchmark-ai-powered-security-fixes/) but with CyberGym's larger corpus. CDP terminator: 𝒯 ASan + test suite.

### Storage and infra

The full dataset is ~240 GB; the binary-only mode is ~130 GB; the 10-task subset is downloadable directly. **Use the 10-task subset for first training run**; expand only after eval E2 baseline numbers are recorded.

CyberGym also ships a domain-allowlist Squid proxy (`python3 -m cybergym.firewall`) for agent containers. We adopt the same posture for the eval harness so the model has no path to exfiltrate or learn from external sources during E2.

### Builder

`scripts/data/build_l2_l4_cybergym.py` — implements Rules A and B above. Refuses to emit any sample containing executable PoC payloads (regex on `submit.sh`, raw `\x` byte sequences, fuzzer seeds).

## 3. Trident Arena — Solana audit sub-skill

[Ackee-Blockchain/trident-arena-benchmarks](https://github.com/Ackee-Blockchain/trident-arena-benchmarks) is benchmark results, not a runnable harness. Six Solana protocols (Axelar, Bert Staking, Dexalot, Metadao, Pump Science, Watt) with professional audit reports as ground truth, scored against Trident Arena, GPT-5.2xhigh, and Opus 4.6.

The published results: Trident Arena 21/30 (70%), GPT-5.2xhigh 10/30 (33%), Opus 4.6 11/30 (37%). This is a **capability ceiling reference**, not a training corpus.

### How we use it

- **Not in the main LoRA pipeline.** This is too specialized (Solana / Anchor / Rust eBPF) to dilute the general defender corpus.
- **Spawn a separate Raven sub-skill** `raven-solana-audit-mlx` that LoRA-tunes `mlx-community/Qwen2.5-Coder-14B-Instruct` on a Solana-only corpus built from the Trident Arena audit reports.
- **Eval E6 (new):** evaluate the merged main model on the same six protocols and measure critical/high recall. Target: ≥ 11/30 (match Opus 4.6 baseline) on first run, ≥ 15/30 after Solana sub-skill is fused.
- Solana fits Daemon Blockint Technologies' stack — this becomes a credible track for the grant narrative ("we beat the baseline open-weights models on a published Solana benchmark").

### License caveat

The repository has no SPDX license in its metadata. The audit reports inside are likely the property of their respective audit firms (e.g., Ackee Blockchain). **Before training on the report PDFs, get written permission from Ackee Blockchain.** The benchmark scoring table itself is public information and safe to cite.

### Builder (deferred to sub-skill)

`raven-solana-audit-mlx/scripts/data/build_solana_audit.py` — only run after license clearance.

## 4. Wake Arena — Solidity audit sub-skill

[Ackee-Blockchain/wake-arena-benchmarks](https://github.com/Ackee-Blockchain/wake-arena-benchmarks) — 14 Code4rena/Sherlock protocols with critical/high vulnerability findings as ground truth. Wake Arena 3.1 scored 63/94 (67.0%), vs Plain GPT-5 24/94 (25.5%) and Plain Opus 4.5 21/94 (22.3%). Eight production audits cite Wake Arena finding 33% of all findings and 50% of criticals.

### How we use it

- **Per-finding writeups** (`H-01 ... H-XX` markdown summaries in the README) are gold-standard defender-frame vulnerability descriptions. These are exactly the writing style L4 needs: precise function reference, concrete bug, concrete impact, no exploit code.
- **Direct extraction is safe** because the README explicitly publishes the findings, and the contests themselves are public on Code4rena and Sherlock.
- Build a Solidity sub-skill `raven-solidity-audit-mlx` analogous to the Solana one.
- **Eval E7 (new):** sample 50 high-severity findings as held-out targets; have the merged model output a defender-frame writeup and grade against the gold via rubric (precision of function reference, accuracy of root-cause sentence, severity match).

### Builder

`scripts/data/build_l4_wake_arena.py` — parses the README finding summaries into (code_context, gold_writeup) pairs. Code context retrieved from the linked Code4rena / Sherlock contest repos via `gh api` calls.

## 5. Awesome AI Security Benchmarks — discovery index

[EvanThomasLuke/Awesome-AI-Security-Benchmarks](https://github.com/EvanThomasLuke/Awesome-AI-Security-Benchmarks) is a curated index of ~175 benchmarks across 12 categories. Not a benchmark itself; treat as a navigation tool.

### Targeted additions we should evaluate from this list

For Raven defender, the highest-value benchmarks beyond what the user already provided:

| Category | Benchmark | Why it matters for Raven |
|---|---|---|
| Secure code generation | [CWEval](https://github.com/Co1lin/CWEval) | Outcome-driven functionality + security eval. Slots into E2. |
| Secure code generation | [SecRepoBench](https://arxiv.org/abs/2504.21205) | Repo-level, closer to real defender use case than file-level. |
| Vulnerability detection | [PrimeVul](https://github.com/DLVulDet/PrimeVul) | Filtered C/C++ function-level — cleaner labels than raw ARVO. |
| CTI | [CTIBench](https://huggingface.co/datasets/AI4Sec/cti-bench) | Defender-frame CTI reasoning. Slots into L2. |
| Patching | [AutoPatchBench](https://engineering.fb.com/2025/04/29/ai-research/autopatchbench-benchmark-ai-powered-security-fixes/) | Direct comparator for our E2 patch-verification setup. |
| SOC reasoning | [CyberSOCEval](https://ai.meta.com/research/publications/cybersoceval-benchmarking-llms-capabilities-for-malware-analysis-and-threat-intelligence-reasoning/) | Defender SOC tasks; aligns with the Raven hunter sub-skills. |
| Detection | [DefenderBench](https://github.com/microsoft/DefenderBench) | Microsoft's defender-aligned toolkit. Direct fit. |

### Benchmarks from the index we explicitly REJECT for Raven training

- All CTF environments (InterCode-CTF, NYU CTF Bench, Cybench, 3CB, BountyBench, AIRTBench, CTF-Dojo, CVE-Bench, XBOW Validation): exploitation-task framing. Same defender-only reason as CyberGym §2 but worse — these have no defender-side projection.
- All pentesting harnesses (PentestGPT Benchmark, AutoPenBench, PentestEval, CHECKMATE, PenHeal, AutoAttacker, AI-Pentest-Benchmark, TermiBench): pure offensive.
- AgentHarm, AdvBench, jailbreak benchmarks: trained-on data would teach the model jailbreak surface; useful for *adversarial eval* of the refusal layer but NOT for training input.

The exception: jailbreak benchmarks are appropriate as **negative-sample sources for L5 (refusal traces)** — we use the harmful prompts to train refusal, and we never train on the harmful completions. [DoNotAnswer](https://github.com/Libr-AI/do-not-answer) and [SORRY-Bench](https://github.com/SORRY-Bench/SORRY-Bench) are the cleanest sources for this.

## 6. Updated dataset layer plan (overrides `SKILL.md` §3.1 sources)

| Layer | Primary sources | Samples |
|---|---|---|
| L1 — D3FEND grounding | D3FEND OWL v1.0 (unchanged) | ~8k |
| L2 — CVE → mitigation | NVD + KEV + **CyberGym descriptions** + **OSSF CVE Benchmark metadata** + **CTIBench** | ~6k |
| L3 — Raven defender modules | `raven/defender/*.py`, `raven/decoy/*`, `raven/restore/*` (unchanged) | ~2k |
| L4 — Secure code rewrite | **OSSF CVE Benchmark** (vul, patched) pairs + **CyberGym Rule-B-only projections** + Juliet/SARD + **Wake Arena writeups** (Solidity slice) | ~5k |
| L5 — Refusal traces | Curated red-team prompts + **DoNotAnswer / SORRY-Bench prompts** (prompts only, never completions) | ~1.5k |
| L6 — Spirit-vs-letter recovery | Custom-authored (XBOW Mythos-failure-mode replicas) | ~1k |

Total stays ~23.5k. The CyberGym restriction (Rule A) is enforced at the builder level with a unit test in `scripts/data/test_no_offensive_leak.py` that scans every emitted sample for PoC-leak patterns.

## 7. Updated eval harness (overrides `SKILL.md` §5.1)

| Eval | Source | Pass criterion | Grounding |
|---|---|---|---|
| E1 — D3FEND mapping accuracy | 300 held-out CVE → technique (CyberGym descriptions + CTIBench) | Top-3 recall ≥ 0.75 | 𝒯 OWL |
| E2 — Patch-verification clean rate | **OSSF CVE Benchmark** held-out 50 CVEs + **CyberGym** 30-task subset (patch mode) | ≥ 0.80 patches make SAST clean **and** preserve tests | 𝒯 SAST + tests |
| E3 — Refusal precision/recall | 200 jailbreak + 200 lookalike defensive | Precision ≥ 0.95, recall on legit ≥ 0.95 | 𝓜 refusal classifier |
| E4 — Spirit-vs-letter recovery | 150 ambiguous defender requests | Spirit-correct ≥ 0.80 (above [Mythos 0.778](https://xbow.com/blog/mythos-offensive-security-xbow-evaluation)) | 𝒯 rubric |
| E5 — CDP termination rate | 500 generated responses | ≥ 0.90 claims terminate at 𝒯/𝓜/𝓛 | 𝒯 parser |
| **E6 — Solana audit recall** (new) | **Trident Arena 6 protocols** | ≥ 11/30 base, ≥ 15/30 with Solana sub-skill fused | 𝒯 professional audit gold |
| **E7 — Solidity audit recall** (new) | **Wake Arena 14 protocols** | ≥ 24/94 base (match Plain GPT-5/Opus baseline), ≥ 40/94 with Solidity sub-skill fused | 𝒯 Code4rena/Sherlock judging |

E6 and E7 are the grant payoff. If we report numbers approaching or exceeding the published Trident/Wake Arena baselines for plain GPT-5 / Opus 4.5 / Opus 4.6 on a defender-only LoRA, that is a concrete artifact the OpenAI Cybersecurity Grant reviewer can reproduce.

## 8. Honest disclosures for the eval report

- We use CyberGym **without** running its primary PoC-generation task. Our number on CyberGym is not directly comparable to the paper's leaderboard; it is a different (defender) projection of the same corpus.
- Trident Arena and Wake Arena are **already-published** benchmarks. If Raven achieves a high score, we must report whether the protocols appeared in the model's pretraining data. Disclose that we cannot rule out training-data contamination on these public contests; report scores both unfiltered and with a leakage-control variant (held-out protocols only).
- OSSF CVE Benchmark is 2020-vintage JS/TS. Generalization to 2024+ CVEs is not implied by performance here.
- For all benchmarks: dataset license, eval license, and our publication license must be compatible before we publish numbers. Trident/Wake Arena license status is unspecified — citing the public results is fine, redistributing audit PDFs in training data is not.

## 9. Build order

```
1. L1 D3FEND builder        [already drafted: build_l1_d3fend.py]
2. L2 builder
   ├── build_l2_cybergym_descriptions.py
   └── build_l2_ctibench.py (optional)
3. L4 builders
   ├── build_l4_ossf_cve.py
   ├── build_l4_cybergym_patches.py        (Rule B only)
   └── build_l4_wake_arena_writeups.py     (after license check)
4. L5 builder
   └── build_l5_refusal_traces.py (uses DoNotAnswer + SORRY-Bench prompts)
5. L6 builder (custom)
6. Assemble: scripts/data/assemble.py
7. Defender-only validator: scripts/data/test_no_offensive_leak.py
8. SFT + DPO from SKILL.md §4
9. Eval harness with E1–E7 from §7 above
```

Each builder follows the pattern of `build_l1_d3fend.py`: load source → transform → validate (defender-only regex) → emit JSONL → stderr stats. The validator script in step 7 is run on the merged corpus and CI-gates the training run.

## 10. Grant-narrative impact

These five benchmarks let the grant proposal say, concretely:

- "Trained on a defender-only projection of 1,507 real vulnerabilities (CyberGym Rule B) plus 200+ OSSF CVE pairs, with patch verification under ASan + upstream test suite."
- "Evaluated against published baselines on Solana (Trident Arena) and Solidity (Wake Arena) audit benchmarks; results reproducible on Apple Silicon hardware listed in `SKILL.md` §9."
- "Refusal layer trained against DoNotAnswer + SORRY-Bench prompts; spirit-vs-letter recovery targets the failure mode documented in XBOW's Mythos evaluation."
- "All training data passes a defender-only validator that refuses to emit offensive payloads, msfconsole patterns, generated shellcode, or PoC-leak content."

That is a concrete defender-only artifact with reproducible evaluation, which is exactly the bar the grant pillars in `positioning.md` were built around.
