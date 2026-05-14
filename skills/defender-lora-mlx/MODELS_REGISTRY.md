# Model Registry: Raven Defender Positioning in models.dev

This document tracks Project Raven's position in the open-source AI model ecosystem, specifically the [models.dev](https://models.dev/) registry maintained at [anomalyco/models.dev](https://github.com/anomalyco/models.dev) (MIT, 3.7k stars as of May 2026).

## Why models.dev matters

models.dev is the de-facto open registry of LLM provider catalogs covering 50+ providers (OpenAI, Anthropic, Google, xAI, Mistral, DeepSeek, Qwen/Alibaba, Llama, OpenRouter, LMStudio, Hugging Face, Apple/MLX-via-LMStudio, Vercel AI Gateway, Cerebras, Groq, Together, Fireworks, Cloudflare Workers AI, and more). Each entry carries: provider id, model id, capabilities (tool calling, reasoning), pricing (input/output/cache/audio), context and output limits, temperature support, weights status (open or closed), knowledge cutoff, release date, and last-updated date.

For Project Raven we use models.dev for three purposes:

1. **Base model selection** — Raven trains on Qwen2.5-7B-Instruct (open weights, BF16, released by Alibaba). models.dev exposes the Qwen catalog and its context limit (32k-128k depending on variant), which we use to bound `max_seq_length` in the training notebook (we picked 4096 to keep memory tractable on Apple Silicon M3 Max).

2. **Adapter target positioning** — After SFT + DPO + fuse + MLX 8-bit + GGUF Q8_0 export, the merged Raven model is intended to be served via LMStudio. models.dev has an `lmstudio` provider entry that documents the deploy path. Raven's positioning in the registry is: open-weights defender-only LoRA on a Qwen2.5-7B-Instruct base, MLX 8-bit + GGUF Q8_0, knowledge cutoff May 2026, license AGPL-3.0.

3. **Honest competitive context** — When the grant reviewer asks "how does Raven compare to closed-weights vendors?", we have a single authoritative source (models.dev) for pricing and capability of the comparator models. We do not claim Raven matches closed-weights frontier models on raw capability; we claim it occupies a distinct category (defender-only, open-weights, locally deployable, AGPL-3.0).

## Raven registry entry (proposed)

When Raven v1 model release lands, the proposed models.dev entry is:

```yaml
provider: lmstudio
model_id: raven-d3fend-defender-7b-v1
display_name: Project Raven D3FEND Defender 7B v1
weights: open
license: AGPL-3.0
base_model: qwen/qwen2.5-7b-instruct
adapter_type: LoRA r=32 alpha=64
quantization: MLX 8-bit + GGUF Q8_0
context_limit: 4096
output_limit: 2048
capabilities:
  tool_call: yes
  reasoning: limited (7B parameter ceiling)
training:
  sft_iters: 3000
  dpo_iters: 1000
  dataset_layers: 6 (L1-L6, ~23.5k samples total)
  hardware: Apple Silicon M3 Max 128GB (~10-15 hours total)
evaluation:
  E1_d3fend_mapping_recall@3: ">= 0.75 (target)"
  E2_patch_clean_rate: ">= 0.80 (target, AutoPatchBench baseline)"
  E3_refusal_precision_recall: ">= 0.95 (target)"
  E4_spirit_vs_letter: ">= 0.80 (target, above XBOW Mythos 0.778 baseline)"
  E5_cdp_termination: ">= 0.90 (target)"
  E6_solana_audit_recall: ">= 11/30 base (target, matches Opus 4.6 baseline)"
  E7_solidity_audit_recall: ">= 24/94 base (target, matches Plain GPT-5/Opus 4.5 baselines)"
  E8_opencode_bench: "TBD (target after fine-tuning, see Section 4)"
positioning: defender-only, CDP-grounded, D3FEND v1.0 canonical
release_date: 2026-Q3 (planned)
repository: https://github.com/daemon-blockint-tech/project-raven-d3fend
```

This entry will be submitted as a pull request to [anomalyco/models.dev](https://github.com/anomalyco/models.dev) once the model weights are released.

## Comparator models in models.dev (May 2026 snapshot)

The following entries from models.dev are the relevant comparators for the grant narrative. Pricing and limits are as published on models.dev at the time of inspection; verify before citing in the paper.

| Provider | Model | Weights | Context | Pricing $/1M (in/out) | Notes |
|---|---|---|---|---|---|
| Anthropic | Claude Sonnet 3.7 | Closed | 200k | 3.00 / 15.00 | Tool call + reasoning |
| Anthropic | Claude Opus 4.x (Mythos-class) | Closed | 200k | varies | Frontier; offensive demonstrations (see Xint whitepaper) |
| OpenAI | GPT-5 | Closed | 400k | 5.00 / 20.00 | Tool call + reasoning |
| OpenAI | o1-pro | Closed | 200k | 150.00 / 600.00 | Highest reasoning cost in registry |
| DeepSeek | DeepSeek Reasoner | Closed | 128k | 0.57 / 1.68 | Tool call + reasoning |
| Google | Gemini 2.5 Flash | Closed | 1.05M | 0.30 / 2.50 | Largest context Gemini |
| Alibaba | Qwen Long | Closed | 10M | 0.07 / 0.29 | Largest context in registry |
| xAI | Grok 4 Fast | Closed | 2M | 0.20 / 0.50 | Tool call + reasoning |
| Zhipu AI | GLM-4.6 | Open | 204k | 0.60 / 2.20 | Open weights comparator |
| Meta/Bedrock | Llama 3.3 70B Instruct | Open | 128k | 0.72 / 0.72 | Closest open comparator at 70B scale |
| Alibaba (Hugging Face) | Qwen2.5-7B-Instruct | Open | 32k-128k | local | Raven base model |

The pricing column is for closed-weights API access. Raven is locally deployable, so the marginal inference cost is effectively zero after one-time training; we exclude electricity. This is the structural difference Raven exploits: defender SOC workloads run continuously, and per-token API costs accumulate; an Apple Silicon Mac running an 8-bit LoRA is a different cost curve.

## License posture

- models.dev: MIT license. We can read, fork, and cite the registry data freely. We can submit pull requests to add Raven's entry.
- Raven: AGPL-3.0. Any service that embeds Raven and exposes it over a network triggers the AGPL network-use clause, requiring source distribution. This is intentional; the grant goal is to ensure defender-side AI remains open.

## Operational guidance for the training notebook

`notebooks/train_raven_defender.ipynb` Stage 2 (base model download) uses the Hugging Face model ID directly (`Qwen/Qwen2.5-7B-Instruct`). The Hugging Face repo is the canonical source of weights; models.dev is the secondary catalog/registry for cross-provider comparison. Do not introduce a dependency on models.dev at training time; reference it only for documentation and positioning.
