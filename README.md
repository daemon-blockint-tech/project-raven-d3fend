# Project Raven — D3FEND Defender Edition

Defender-only security AI grounded in [MITRE D3FEND v1.0](https://d3fend.mitre.org/) OWL ontology, with a Contract for Defensible Predictions (CDP) that requires every claim to terminate at one of three groundings:

- **𝒯** — a deterministic tool oracle (Semgrep, SHACL, ASan, the D3FEND ontology itself)
- **𝓜** — an ML detector with a calibrated score
- **𝓛** — a scored hypothesis with an attached falsification test

This repository is the engineering package supporting Project Raven's submission to the [OpenAI Cybersecurity Grant Program](https://openai.com/index/openai-cybersecurity-grant-program/).

## Three pillars

1. **CDP grounding** — every emission terminates at 𝒯 / 𝓜 / 𝓛.
2. **D3FEND OWL v1.0** is canonical — Oxigraph SPARQL store, SHA-256 pinned, runtime verifier in `cdp/verifier.py`.
3. **Defender-only** enforcement — offensive modules (`offensive.py`, `metasploit_integration.py`, `empire_client.py`, `exploitdb*.py`) are excluded from this edition; every skill ships with refusal rules.

## Repository contents

### Core D3FEND deliverables

- [`d3fend-coverage.md`](./d3fend-coverage.md) — Coverage matrix mapping Raven defender modules to D3FEND tactics and techniques, with ATT&CK bidirectional mapping.
- [`decoy-subsystem-spec.md`](./decoy-subsystem-spec.md) — D3FEND Deceive subsystem specification (11 D3-D* techniques).
- [`restore-subsystem-spec.md`](./restore-subsystem-spec.md) — D3FEND Restore subsystem specification (D3-RC, RF, RA, RD, RDI, RNA, RO, RS, RUAA, ULA, RIC, CRO, CERO).
- [`owl-integration.md`](./owl-integration.md) — Oxigraph SPARQL integration, six gap-analysis queries, CDP verifier hook.

### Grant submission package

- [`positioning.md`](./positioning.md) — Grant positioning document, three-pillar narrative, reviewer Q&A prep, citation rules.
- [`raven-modules.md`](./raven-modules.md) — Defender-relevant module reference (excludes offensive modules).

### Skills

| Skill | Purpose |
|---|---|
| [`SKILL.md`](./SKILL.md) | Zero-Day Threat Hunter (top-level) |
| [`skills/zero-day-threat-patterns/`](./skills/zero-day-threat-patterns/SKILL.md) | Pattern catalog curator |
| [`skills/zero-day-defend/`](./skills/zero-day-defend/SKILL.md) | Defensive composer per CVE/campaign |
| [`skills/zero-day-detection/`](./skills/zero-day-detection/SKILL.md) | Online detection (𝓜 + 𝒯) |
| [`skills/zero-day-investigator/`](./skills/zero-day-investigator/SKILL.md) | Single-alert deep dive |
| [`skills/zero-day-auto-prevent/`](./skills/zero-day-auto-prevent/SKILL.md) | Policy enforcer with YAML schema and hash-chained audit |
| [`skills/zero-day-fixing/`](./skills/zero-day-fixing/SKILL.md) | Patch, verify, rollback |
| [`skills/devsec-mythos-class/`](./skills/devsec-mythos-class/SKILL.md) | DevSec gate (Mythos-class source reasoning) |
| [`skills/research-looped-reasoning-eval/`](./skills/research-looped-reasoning-eval/SKILL.md) | Looped-transformer research scaffold |
| [`skills/defender-lora-mlx/`](./skills/defender-lora-mlx/SKILL.md) | Local fine-tuning on Apple Silicon (mlx-lm LoRA) |

### Personas

- [`hermes-mythos-persona.md`](./hermes-mythos-persona.md) — Persona overlay for Hermes (behavioral, not identity); built from public sources.

## Key references

- [MITRE D3FEND v1.0](https://www.mitre.org/news-insights/news-release/mitre-launches-d3fend-10-milestone-cybersecurity-ontology)
- [CISA Secure-by-Design](https://www.cisa.gov/sites/default/files/2023-10/SecureByDesign_1025_508c.pdf)
- [Anthropic — AI for Cyber Defenders](https://red.anthropic.com/2025/ai-for-cyber-defenders/)
- [CyberGym dataset](https://huggingface.co/datasets/sunblaze-ucb/cybergym), [paper arXiv:2506.02548](https://arxiv.org/abs/2506.02548)
- [OSSF CVE Benchmark](https://github.com/wunderalbert/ossf-cve-benchmark)
- [Wake Arena Benchmarks](https://github.com/Ackee-Blockchain/wake-arena-benchmarks)
- [Trident Arena Benchmarks](https://github.com/Ackee-Blockchain/trident-arena-benchmarks)
- [Awesome AI Security Benchmarks](https://github.com/EvanThomasLuke/Awesome-AI-Security-Benchmarks)

## License

[AGPL-3.0](./LICENSE) — strong copyleft. Network use is distribution. Forks and derived services must publish source under AGPL-3.0.

## Status

Work in progress. Pre-grant-submission engineering package. Numbers, evaluations, and benchmark scores in this repository are scaffolding for the experiment design — actual results will be added when training runs complete.

## Contact

Daemon Blockint Technologies — Jakarta, Indonesia.
