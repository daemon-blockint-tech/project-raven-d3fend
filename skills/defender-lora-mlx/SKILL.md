---
name: raven-defender-lora-mlx
description: Fine-tune a clean open base model (Qwen2.5 / Llama-3.x) on Apple Silicon with mlx-lm LoRA for the Raven defender domain — D3FEND OWL reasoning, CVE→D3FEND mapping, secure code rewriting, and CDP-grounded triage. Defender-only. Compatible with OpenAI Cybersecurity Grant positioning.
when_to_use: User wants a local fine-tuned model for Raven that runs in LM Studio / MLX on Apple Silicon and stays consistent with `positioning.md` (CDP grounding + D3FEND OWL + defender-only). Do NOT use this skill to train abliterated, "uncensored", or safety-stripped variants.
---

# Raven Defender LoRA — MLX Fine-Tuning Skill

## 0. Why this skill exists

Two facts shape every decision below.

1. Raven's grant positioning (`raven-d3fend/positioning.md`) is built on three pillars: CDP grounding (𝒯 / 𝓜 / 𝓛), D3FEND OWL v1.0 as the canonical defensive ontology ([MITRE D3FEND v1.0 release](https://www.mitre.org/news-insights/news-release/mitre-launches-d3fend-10-milestone-cybersecurity-ontology)), and defender-only enforcement. Any model artifact we train inherits those pillars or it does not ship.
2. CISA Secure-by-Design ([CISA, NSA, FBI et al., 2023](https://www.cisa.gov/sites/default/files/2023-10/SecureByDesign_1025_508c.pdf)) requires that security is a core business goal, not a feature, and that products be safe out of the box. A LoRA adapter we train and distribute IS a product. Defender-only is the secure-by-default posture.

This skill produces:

- A **base-model selection** that is provably clean (no abliteration ancestry).
- A **dataset assembly pipeline** from D3FEND OWL, Raven defender modules, CVE → mitigation mappings, and refusal traces.
- A **LoRA training recipe** (mlx-lm-lora) with a stable hyperparameter set proven for security-domain tuning.
- An **optional DPO preference-tuning stage** (defender-preferred vs offensive-leak completions).
- An **eval harness** including spirit-vs-letter recovery (the XBOW-identified Mythos weakness) so we do not regress defender judgment.
- A **packaging step** producing both an MLX-native adapter and a GGUF export for portability.
- A **deployment recipe** to LM Studio.

This skill explicitly refuses to scaffold:

- Training of any "uncensored", "heretic", "abliterated", or safety-stripped variant.
- Training on a base whose ancestry includes such variants (e.g. `DavidAU/Qwen3.5-9B-Claude-4.6-OS-HERETIC-UNCENSORED-INSTRUCT` and its MLX conversions). The HERETIC lineage strips refusal direction and trains adversarial content; downstream LoRA on it inherits that posture and is incompatible with the Raven grant pillars.
- Training on data scraped from offensive Raven modules (`offensive.py`, `metasploit_integration.py`, `empire_client.py`, `exploitdb*.py`).
- Distillation from any model whose name claims to be a closed-weights vendor model (no "Claude-X" bases — Anthropic does not release weights).

## 1. CDP contract for the training pipeline

Every stage of the pipeline must terminate at one of:

- 𝒯 — tool oracle (deterministic check that passes or fails). Example: AddressSanitizer / Semgrep / D3FEND OWL SHACL validator.
- 𝓜 — ML detector with calibrated score (logged with confidence). Example: defender-vs-offensive classifier on training samples.
- 𝓛 — scored hypothesis with a falsification test attached. Example: a generated mitigation hypothesis with a unit test that fails if the mitigation is wrong.

No stage may produce a free-text claim without one of these three groundings. This is the same rule the rest of Raven enforces; the training pipeline is not exempt.

## 2. Base model selection (defender-clean tier)

### 2.1 Hard requirements

A candidate base passes only if **all** are true:

1. Open weights released by the original lab (not a community re-upload).
2. License permits commercial fine-tuning and redistribution of adapters (Apache 2.0, Llama Community License, Qwen License — read each, do not assume).
3. No ancestry that contains the strings `heretic`, `abliterated`, `uncensored`, `dolphin-uncensored`, `lewd`, `roleplay-jailbreak`, `dpo-jailbreak` in the HuggingFace model tree.
4. Has an MLX conversion in `mlx-community/` or can be converted with `mlx_lm.convert` without errors.
5. Has a published instruction-tuned variant (we LoRA on the instruct, not the base, for chat-style defender prompts).

### 2.2 Recommended bases

| Model | Params | MLX repo | License | Use case |
|---|---|---|---|---|
| `Qwen/Qwen2.5-7B-Instruct` | 7B | `mlx-community/Qwen2.5-7B-Instruct-4bit` | Qwen License | Default. Fits 32 GB unified memory comfortably. |
| `Qwen/Qwen2.5-14B-Instruct` | 14B | `mlx-community/Qwen2.5-14B-Instruct-4bit` | Qwen License | If ≥48 GB unified memory; stronger reasoning. |
| `Qwen/Qwen2.5-Coder-14B-Instruct` | 14B | `mlx-community/Qwen2.5-Coder-14B-Instruct-4bit` | Qwen License | Best for the secure-code-rewrite sub-domain. |
| `meta-llama/Llama-3.1-8B-Instruct` | 8B | `mlx-community/Meta-Llama-3.1-8B-Instruct-4bit` | Llama 3.1 License | Alternative if Qwen license is a concern. |

### 2.3 Bases this skill rejects

- Anything matching the patterns in §2.1 ancestry blocklist.
- Any model card claiming "Claude" / "GPT-4" / "Gemini" in the name with no proof of distillation methodology.
- `DavidAU/*` HERETIC line and all MLX conversions of it (including `enet45/Qwen3.5-9B-Claude-4.6-OS-HERETIC-UNCENSORED-INSTRUCT-mlx-8Bit`).

### 2.4 Quantization rule for training

**Train on the unquantized BF16 weights.** LoRA on 8-bit / 4-bit weights is supported by mlx-lm-lora but the gradient signal is degraded and DPO becomes unstable. Quantize **after** training, for inference distribution only.

```bash
# Download unquantized for training
huggingface-cli download Qwen/Qwen2.5-7B-Instruct --local-dir ./bases/qwen25-7b-instruct

# Quantize the merged-adapter checkpoint after training
mlx_lm.convert --hf-path ./out/raven-defender-merged \
               --mlx-path ./out/raven-defender-mlx-q8 \
               --quantize --q-bits 8
```

## 3. Dataset assembly

### 3.1 Six layers, all defender-side

| Layer | Source | Format | Approx samples | CDP terminator |
|---|---|---|---|---|
| L1 — D3FEND grounding | D3FEND OWL v1.0 ([d3fend.mitre.org/resources/ontology](https://d3fend.mitre.org/resources/ontology/)) | Triples → Q/A | 8k | 𝒯 SHACL validator |
| L2 — CVE → mitigation | NVD + D3FEND mappings + KEV catalog | CVE description → ranked D3FEND techniques | 6k | 𝒯 mapping table |
| L3 — Raven defender modules | `raven/defender/*.py`, `raven/decoy/*`, `raven/restore/*` | Code → docstring → triage walkthrough | 2k | 𝒯 unit tests pass |
| L4 — Secure code rewrite | OWASP Top 10 + CWE Top 25 patterns | (insecure_code, secure_code, semgrep_diff) pairs | 5k | 𝒯 Semgrep clean |
| L5 — Refusal traces (defender-only) | Curated red-team prompts asking for offensive ops | (prompt, refusal_with_redirect_to_defensive_alternative) | 1.5k | 𝓜 refusal classifier |
| L6 — Spirit-vs-letter recovery | Mythos failure mode replicas (XBOW [letter-over-spirit 77.8%](https://xbow.com/blog/mythos-offensive-security-xbow-evaluation)) | (ambiguous_request, literal_interpretation, spirit_interpretation, justification) | 1k | 𝒯 rubric grader |

Total: ~23.5k high-quality samples. Quality beats quantity at this scale.

### 3.2 Format — mlx-lm chat JSONL

mlx-lm's LoRA trainer accepts a `messages` field per line (chat template will be applied from the tokenizer). Example:

```json
{"messages":[
  {"role":"system","content":"You are Raven, a defender-only security assistant. Every claim terminates at a tool oracle, an ML detector, or a falsifiable hypothesis. You never produce offensive payloads."},
  {"role":"user","content":"CVE-2024-3094 affected xz-utils. Map it to D3FEND techniques and propose three layered mitigations."},
  {"role":"assistant","content":"## Mapping\n- D3-SBOM (Software Bill of Materials Detection): detect xz-utils 5.6.0/5.6.1 in deployed images.\n- D3-FCR (File Content Rules): YARA on the malicious m4 build helper.\n- D3-EI (Executable Inspection): runtime check on liblzma symbol resolution path.\n\n## Mitigation hypotheses (𝓛)\nH1: Pin xz-utils ≤ 5.4.6 in base images. Falsifier: SBOM scan after rebuild shows no 5.6.x. (𝒯 syft SBOM)\nH2: Add liblzma symbol allow-list check at sshd start. Falsifier: process trace shows no unexpected resolution. (𝒯 strace + ldd)\nH3: Rotate any SSH host keys from machines that ran xz 5.6.0/5.6.1 between Feb–Mar 2024. Falsifier: key fingerprint changed in known_hosts diff. (𝒯 git diff of ansible inventory)"}
]}
```

Files: `data/train.jsonl`, `data/valid.jsonl`, `data/test.jsonl` (80 / 10 / 10 split, stratified by layer).

### 3.3 Layer assembly scripts

Each layer has a builder under `scripts/data/`:

```
scripts/data/
├── build_l1_d3fend.py      # SPARQL over Oxigraph store from raven-d3fend/owl-integration.md
├── build_l2_cve_mapping.py # NVD JSON feed + D3FEND mapping table → Q/A pairs
├── build_l3_raven_modules.py # AST walk of raven/defender/, docstring → walkthrough
├── build_l4_secure_rewrite.py # juliet / sard / owasp benchmark → semgrep-validated pairs
├── build_l5_refusal_traces.py # curated, hand-reviewed; defender-only redirects
├── build_l6_spirit_letter.py  # ambiguous-request templates with held-out rubric
└── assemble.py # shuffle + stratify + write train/valid/test
```

L5 is the load-bearing layer for grant positioning. Every refusal trace must:
- Refuse the offensive path.
- Cite the specific Raven defender-only rule.
- Redirect to the closest defensive D3FEND technique.
- Never include the offensive payload, even as a "for educational reference" footnote.

L6 is the load-bearing layer for defender judgment quality. It directly addresses the XBOW finding that Mythos was strong at letter-following but weaker at spirit-recovery (77.8% command-safety). Hermes-class behavior is conferred by this layer.

## 4. LoRA training recipe (mlx-lm-lora)

### 4.1 Install

```bash
# On macOS, Apple Silicon, Python 3.11+
python -m venv .venv && source .venv/bin/activate
pip install --upgrade pip
pip install "mlx-lm>=0.20" "mlx-lm-lora>=0.4" "datasets" "huggingface_hub" "semgrep"

# Verify Metal is visible
python -c "import mlx.core as mx; print('Metal:', mx.metal.is_available())"
```

[mlx-lm-lora](https://github.com/Goekdeniz-Guelmez/mlx-lm-lora) supports Qwen 2/2.5/3, Llama 3/4, Phi 2/3, Mistral, Mixtral, Gemma 1/2/3, OLMo, MiniCPM. It implements SFT, DPO, ORPO, KTO, GRPO, and SimPO loss heads on top of mlx-lm.

### 4.2 Stage 1 — SFT with LoRA

`configs/sft.yaml`:

```yaml
model: "./bases/qwen25-7b-instruct"
train: true
data: "./data"
adapter_path: "./out/adapters/raven-defender-sft"

# Stable strategy from the cybersecurity assistant fine-tune study
# (cosine + warmup > aggressive linear; r=32 covering all 7 linear layers > lightweight r=8)
lora_parameters:
  rank: 32
  alpha: 64
  dropout: 0.05
  scale: 10.0
  keys: ["self_attn.q_proj","self_attn.k_proj","self_attn.v_proj","self_attn.o_proj","mlp.gate_proj","mlp.up_proj","mlp.down_proj"]

num_layers: -1   # apply to all transformer blocks
batch_size: 4
iters: 3000
max_seq_length: 4096
learning_rate: 1.0e-4
lr_schedule:
  name: cosine_decay
  warmup: 200
  arguments: [1.0e-4, 3000, 1.0e-6]
weight_decay: 0.01
grad_checkpoint: true
seed: 1337
steps_per_report: 25
steps_per_eval: 200
save_every: 400
test: true
```

Run:

```bash
mlx_lm.lora --config configs/sft.yaml 2>&1 | tee logs/sft.log
```

Expected wall-clock on M3 Max 128 GB: ~6–9 hours for 3000 iters at 7B BF16.

### 4.3 Stage 2 — DPO preference tuning (defender vs offensive-leak)

Build `data/dpo/{train,valid}.jsonl` with the schema:

```json
{"prompt":"<chat-formatted prompt>","chosen":"<defender-grounded response>","rejected":"<offensive-leak or letter-only response>"}
```

Sources for preference pairs:
- 600 pairs from L5 (refusal-correct vs offensive-leak).
- 400 pairs from L6 (spirit-recovery vs letter-only).
- 500 pairs from L1/L4 (CDP-grounded vs ungrounded plausible).
- 500 pairs from a Semgrep-judged rewrite (clean vs still-vulnerable). This is the same self-supervised pattern used in [codelion/Qwen2.5-Coder-0.5B-Instruct-security-grpo-lora](https://huggingface.co/codelion/Qwen2.5-Coder-0.5B-Instruct-security-grpo-lora) but with DPO loss instead of GRPO.

`configs/dpo.yaml`:

```yaml
model: "./bases/qwen25-7b-instruct"
adapter_path: "./out/adapters/raven-defender-sft"  # start from SFT adapter
train: true
data: "./data/dpo"
output_adapter_path: "./out/adapters/raven-defender-dpo"

train_mode: "dpo"
dpo:
  beta: 0.1          # standard range 0.1–0.5; 0.1 conservative
  label_smoothing: 0.0
  loss_type: "sigmoid"   # sigmoid | hinge | ipo
  reference_model_path: "./bases/qwen25-7b-instruct"  # frozen ref

lora_parameters:
  rank: 32
  alpha: 64
  dropout: 0.05
  keys: ["self_attn.q_proj","self_attn.v_proj","mlp.down_proj"]

batch_size: 2
iters: 1000
max_seq_length: 4096
learning_rate: 5.0e-6  # DPO needs ~10x lower LR than SFT
lr_schedule: { name: cosine_decay, warmup: 50, arguments: [5.0e-6, 1000, 1.0e-7] }
grad_checkpoint: true
```

Run:

```bash
mlx_lm.lora --config configs/dpo.yaml 2>&1 | tee logs/dpo.log
```

DPO loss formula and stable-range reference: [DPO MLX implementation thread](https://github.com/ml-explore/mlx-examples/issues/513), grounding paper [Rafailov et al., 2023](https://arxiv.org/abs/2305.18290).

### 4.4 Stage 3 — Merge adapter into base

```bash
mlx_lm.fuse \
  --model ./bases/qwen25-7b-instruct \
  --adapter-path ./out/adapters/raven-defender-dpo \
  --save-path ./out/raven-defender-merged \
  --de-quantize
```

## 5. Evaluation harness

### 5.1 Five evals (all defender-relevant; none capability-uplift)

| Eval | Method | Pass criterion | Grounding |
|---|---|---|---|
| E1 — D3FEND mapping accuracy | 300 held-out CVE → technique ranking | Top-3 recall ≥ 0.75 vs analyst gold | 𝒯 |
| E2 — Secure-rewrite Semgrep clean rate | 300 vulnerable snippets, model rewrites | ≥ 80% Semgrep clean **and** functional unit test pass | 𝒯 |
| E3 — Refusal precision | 200 offensive prompts + 200 lookalike defensive prompts | Refusal precision ≥ 0.95, recall on legitimate ≥ 0.95 | 𝓜 |
| E4 — Spirit-vs-letter recovery | 150 ambiguous defender requests, rubric-graded | Spirit-correct ≥ 0.80 (XBOW reported Mythos at 0.778; we target above) | 𝒯 rubric |
| E5 — CDP termination rate | 500 generated responses scanned for 𝒯/𝓜/𝓛 grounding tokens | ≥ 0.90 of factual claims terminate at one of the three | 𝒯 regex+parser |

Compare three models: base instruct, SFT-only, SFT+DPO. Bonferroni-correct across 5 comparisons.

### 5.2 Eval runner

```bash
python scripts/eval/run_all.py \
  --model ./out/raven-defender-merged \
  --baseline ./bases/qwen25-7b-instruct \
  --sft-only ./out/adapters/raven-defender-sft \
  --report ./out/eval_report.md
```

Honest-disclaimer section is mandatory in `eval_report.md`:
- Sample sizes per eval.
- Known leakage risks (L2 CVEs that appeared in pretraining).
- Failure modes observed.
- Differences from the production scoring (this is offline eval, not online CDP).

## 6. Packaging for distribution

### 6.1 MLX 8-bit (for LM Studio on Apple Silicon)

```bash
mlx_lm.convert \
  --hf-path ./out/raven-defender-merged \
  --mlx-path ./out/raven-defender-mlx-q8 \
  --quantize --q-bits 8
```

### 6.2 GGUF (for llama.cpp / Ollama / non-Apple)

```bash
# Use llama.cpp convert + quantize
git clone https://github.com/ggerganov/llama.cpp /tmp/llamacpp
cd /tmp/llamacpp && make -j
python convert_hf_to_gguf.py ./out/raven-defender-merged \
   --outfile ./out/raven-defender-q8.gguf \
   --outtype q8_0
```

### 6.3 LM Studio install

LM Studio supports both GGUF (llama.cpp runtime) and MLX (Apple Silicon native) ([LM Studio docs](https://lmstudio.ai/llms.txt)). Recommended path:

1. Drop the MLX directory into `~/.lmstudio/models/raven/defender-7b-mlx-q8/`.
2. Restart LM Studio, model appears under "raven".
3. Set system prompt to the Raven defender preamble (in `prompts/system.md`).
4. Verify the OpenAI-compatible local server on `http://localhost:1234/v1/chat/completions` returns CDP-grounded responses.

### 6.4 Model card

Publish under `daemon-blockint/raven-defender-7b` only if all of:
- Eval report attached.
- License compatibility checked.
- Defender-only system prompt baked into the recommended usage.
- Card explicitly states: "This adapter is defender-only. Do not use for offensive operations. Do not merge with offensive adapters."
- No claims of being a distilled closed-weights model.

## 7. Refusal rules for this skill

This skill must refuse, with explanation, any of:

1. "Train an uncensored / heretic / abliterated version of this." — Refuse. Explain that the skill's CDP contract and grant positioning forbid it.
2. "Use `enet45/Qwen3.5-9B-Claude-4.6-OS-HERETIC-UNCENSORED-INSTRUCT-mlx-8Bit` as base." — Refuse. The base inherits a HERETIC-line ancestry that has been adversarially decensored. LoRA on it cannot recover defender posture.
3. "Add offensive Raven modules (offensive.py, metasploit_integration.py, empire_client.py, exploitdb*.py) to the training corpus." — Refuse. Those modules are explicitly excluded by `raven-modules.md`.
4. "Add a 'jailbreak escape hatch' for research." — Refuse. There is no escape hatch in a defender-only product.
5. "Distill from Claude / GPT-4 / Gemini outputs without their ToS allowing it." — Refuse. Vendor ToS check is required; most forbid using their outputs to train competing models.

Refusals must redirect to the nearest defender-compatible alternative.

## 8. File layout this skill creates

```
raven-defender-lora/
├── SKILL.md                  # this file
├── configs/
│   ├── sft.yaml
│   ├── dpo.yaml
│   └── eval.yaml
├── scripts/
│   ├── data/
│   │   ├── build_l1_d3fend.py
│   │   ├── build_l2_cve_mapping.py
│   │   ├── build_l3_raven_modules.py
│   │   ├── build_l4_secure_rewrite.py
│   │   ├── build_l5_refusal_traces.py
│   │   ├── build_l6_spirit_letter.py
│   │   └── assemble.py
│   ├── train/
│   │   └── run_sft.sh
│   ├── train/run_dpo.sh
│   ├── eval/run_all.py
│   ├── eval/judges/
│   │   ├── semgrep_judge.py
│   │   ├── d3fend_judge.py
│   │   └── cdp_termination_judge.py
│   └── package/
│       ├── merge_and_convert.sh
│       └── make_gguf.sh
├── data/                      # gitignored; rebuilt from sources
├── bases/                     # gitignored; downloaded base weights
├── out/                       # gitignored; adapters and merged models
├── prompts/
│   └── system.md              # Raven defender preamble
├── logs/                      # gitignored
└── docs/
    ├── eval_report_template.md
    └── model_card_template.md
```

## 9. Hardware budget

| Stage | Memory peak | Wall-clock (M3 Max 128 GB) | Wall-clock (M2 Max 64 GB) |
|---|---|---|---|
| SFT 7B BF16 LoRA r=32, ctx 4096, bs=4 | ~52 GB | 6–9 h for 3000 iters | 10–14 h, bs=2 |
| DPO 7B with frozen ref | ~78 GB | 3–5 h for 1000 iters | 7–9 h, bs=1 |
| Merge + quantize Q8 | ~30 GB | 15 min | 15 min |
| Convert to GGUF Q8 | ~16 GB CPU | 30 min | 30 min |
| Eval (5 evals, 1450 samples) | ~30 GB | 1 h | 1.5 h |

If memory pressure: drop `num_layers` to 12 (top half only), reduce `max_seq_length` to 2048, or use the 4-bit MLX base for training (accepting the gradient-quality cost).

## 10. Grant narrative payoff

This skill produces a defender-only model artifact that:
- Is grounded in D3FEND OWL v1.0 (Pillar 2 of the grant pillars).
- Enforces CDP termination at 𝒯 / 𝓜 / 𝓛 (Pillar 1).
- Includes a load-bearing refusal layer trained with DPO (Pillar 3).
- Has an evaluation harness with spirit-vs-letter recovery that directly addresses a documented capability-tier weakness ([XBOW Mythos evaluation](https://xbow.com/blog/mythos-offensive-security-xbow-evaluation)).
- Is reproducible on consumer Apple Silicon (does not require a hyperscaler).
- Has a clean license chain and no offensive ancestry.

This is the kind of artifact the grant reviewer can run themselves and verify. That is the bar.

## 11. Open questions to resolve before first training run

- [ ] Confirm license posture for redistributing a Qwen-derived adapter under Daemon Blockint Technologies (read [Qwen License](https://huggingface.co/Qwen/Qwen2.5-7B-Instruct/blob/main/LICENSE)).
- [ ] Get an Oxigraph dump of the D3FEND OWL store from `raven-d3fend/owl-integration.md` for L1 builder.
- [ ] Decide whether to include the Indonesian-language defender subset (recommended: yes, ~10% of L4–L6, to match operator profile).
- [ ] Decide whether to publish the adapter publicly on HuggingFace under `daemon-blockint/` or keep it grant-internal until grant decision.
