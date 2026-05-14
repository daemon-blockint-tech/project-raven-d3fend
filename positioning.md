# Raven — Grant-Submission Positioning Document

This document fixes the positioning for Project Raven's submission to the [OpenAI Cybersecurity Grant Program](https://openai.com/index/openai-cybersecurity-grant-program/). It is the single source of truth for what Raven IS, what it is NOT, what we cite, and what we deliberately do NOT cite. All grant deliverables — pitch deck, proposal text, README, demo script, reviewer Q&A prep — must align with this document.

The positioning was chosen on May 14, 2026 after evaluating three options. Section 8 records the decision and rationale.

## 1. One-line positioning

Raven is a defender-first, CDP-grounded, D3FEND-bound platform that turns LLM reasoning into auditable defensive operations across the software lifecycle — pre-merge, pre-deploy, runtime, and post-incident.

## 2. Three pillars (the entire pitch hangs off these)

### Pillar 1 — CDP grounding (Compositional Defense Pipelines)

Every LLM emission in Raven terminates at exactly one of three terminators:

- 𝒯 — a tool oracle invocation (ARES, Ghidra, radare2, code_flow_scanner, memory_analyzer, volatility, sandbox-verified ASan)
- 𝓜 — a classical-ML detector hit (IsolationForest + RandomForest ensemble, variant_analyzer, sequence_analyzer)
- 𝓛 — a scored hypothesis bound to a concrete falsification test

Anything that does not terminate at one of those three is named, bucketed, and surfaced as speculation — never as a finding. This is the property that makes Raven outputs grant-evaluator-credible: "no hallucinated mitigations" is enforceable, not aspirational.

### Pillar 2 — MITRE D3FEND OWL grounding

Every defensive action Raven emits is bound to a real D3FEND v1.0 technique id, resolved at runtime through the OWL ontology (Oxigraph SPARQL store, see `owl-integration.md`). Coverage is generated from code, not from a hand-curated table — CI gates fail if the coverage matrix drifts from what the source claims.

Raven implements meaningful coverage across all seven D3FEND tactics: Model, Harden, Detect, Isolate, Deceive, Evict, Restore (see `d3fend-coverage.md`, `decoy-subsystem-spec.md`, `restore-subsystem-spec.md`).

### Pillar 3 — Defender-only, by construction

Raven Defender Edition strips every offensive module from the upstream codebase:

- `raven/redteam/offensive.py` — removed
- `raven/tools/metasploit_integration.py` — removed
- `raven/tools/empire_client.py` — removed
- `raven/tools/exploitdb*.py` — removed

The approval gate (`raven/approval/gate.py`) is the single enforcement point — every action that could touch production passes through it. No flag bypasses it.

## 3. What Raven is NOT

This list exists because reviewers will probe for overclaiming. We get ahead of it.

- **Raven is NOT a frontier model.** Raven is a harness. It runs on whichever model the user configures (Sonnet, Opus, GPT, Gemini, or local Ollama). The model is one component, not the value proposition.
- **Raven is NOT Mythos-class.** Claude Mythos Preview is Anthropic's proprietary research preview. Raven does not run Mythos, does not claim Mythos's benchmark numbers, and does not depend on Mythos for any feature. Where Raven adopts a *behavioral* property documented in the public Mythos record (the file-ranking method, the ASan-as-oracle discipline, the severity rigor), it does so as a *prompt-level persona overlay* (`hermes-mythos-persona.md`), explicitly labeled as a persona and not as identity.
- **Raven is NOT a Mythos reconstruction.** The community project [kyegomez/OpenMythos](https://github.com/kyegomez/OpenMythos) is an unaffiliated speculative architecture; Raven does not ship it, does not depend on it, and does not validate any claim about how Mythos was built.
- **Raven is NOT an offensive tool.** Even in research-mode skills, exploit-payload generation is hard-rejected at the approval gate.
- **Raven is NOT a complete kill-chain replacer.** It is one defender's harness. The reviewer should not be told it replaces a SOC, a SAST suite, a SIEM, or a managed-detection vendor — only that it composes their outputs into a CDP-grounded, D3FEND-bound, auditable layer.

## 4. Sources Raven cites — and how

All grant submission materials cite from this list. Citations use markdown links; the anchor text describes the source naturally and never uses "source" or "link".

### Primary sources (always cite)

- [MITRE D3FEND home](https://d3fend.mitre.org/) — defensive ontology home and version reference
- [MITRE D3FEND 1.0 release announcement](https://www.mitre.org/news-insights/news-release/mitre-launches-d3fend-10-milestone-cybersecurity-ontology) — provenance of the v1.0 ontology Raven binds to
- [CISA / NSA Principles and Approaches for Secure by Design](https://www.cisa.gov/sites/default/files/2023-10/SecureByDesign_1025_508c.pdf) — the secure-by-design framing Raven's DevSec gate implements
- [Anthropic AI for Cyber Defenders / Cybergym](https://red.anthropic.com/2025/ai-for-cyber-defenders/) — trial-budget evaluation methodology Raven re-uses
- [OpenAI Cybersecurity Grant Program](https://openai.com/index/openai-cybersecurity-grant-program/) — the program Raven is applying to; cited only in the cover letter

### Secondary sources (cite when relevant)

- [Anthropic Frontier Red Team — zero-days post](https://red.anthropic.com/2026/zero-days/) — what AI-assisted defenders can find now
- [XBOW Mythos evaluation](https://xbow.com/blog/mythos-offensive-security-xbow-evaluation) — cite only to contrast Raven's defender-only positioning against XBOW's offensive validation; never to claim affiliation

### Sources Raven does NOT cite in the grant submission (Opsi C decision)

These are absent from the grant package by design:

- The Xint whitepaper "You Don't Need Mythos" — the specific numerical claims in it (Mythos 89% triager agreement, 20-gadget ROP, CVE-2026-4747 details) are not corroborated by Anthropic's own public posts; including them would weaken submission credibility.
- The Anthropic Glasswing announcement and the 244-page system card — citing these invites the reviewer to compare Raven against Mythos as a model, when Raven is a harness.
- The OpenMythos GitHub repo — it is a community speculative reconstruction. Citing it suggests Raven runs on a Mythos-class architecture, which it does not.
- Project Glasswing partner statements — none of those companies endorsed Raven, and listing them is implicit overclaiming.

When a reviewer asks "what about Mythos / Glasswing / OpenMythos", the prepared answer is in Section 9.

## 5. Match to OpenAI grant program criteria

The grant program ([OpenAI Cybersecurity Grant Program](https://openai.com/index/openai-cybersecurity-grant-program/)) calls out specific focus areas. Raven maps to each as follows:

| Grant focus | Raven delivers | Where in code/docs |
|-------------|----------------|--------------------|
| Defender-first AI for security | All seven 0-day skills + DevSec gate + restore + decoy are defender-only | `skills/`, `restore-subsystem-spec.md`, `decoy-subsystem-spec.md` |
| Automated patching | `raven-zero-day-fixing` with mandatory verifier oracles | `skills/zero-day-fixing/SKILL.md` |
| Deception / honeypots | `decoy/` subsystem implements all 11 D3-D* techniques | `decoy-subsystem-spec.md` |
| Incident triage | `raven-zero-day-investigator` with reproducibility + spirit-vs-letter | `skills/zero-day-investigator/SKILL.md` |
| Reproducibility | Per-run kit with seeds, commits, tool versions, traces | every skill's "Reproducibility kit" section |
| Public benefit + MIT license | Entire Raven Defender Edition is MIT-licensed | `LICENSE` |
| Trial-budget cost discipline | Cybergym-aligned trial counts (1/10/30) and cost caps in every skill | `skills/zero-day-hunter/SKILL.md`, Phase 3.4 of research eval |

## 6. Reproducibility kit (per grant submission requirement)

Submitted alongside the proposal:

- Pinned commit of the Raven Defender Edition fork
- SHA-256 of all dataset manifests
- Dockerfile + requirements pin
- `make demo` reproduces three end-to-end demos in under 10 minutes:
  1. DevSec gate on a vulnerable PR — finding → spirit-recovery → D3FEND Harden binding → patch candidate
  2. 0-day hunter on a Solana program — surface → hypothesis → ARES validation → D3FEND binding → reproducibility kit emission
  3. Auto-prevent policy enforcement against a simulated alert stream — policy validation → trigger → gate approval → audit-chain entry

A reviewer running `make demo` on a clean Ubuntu 22.04 box with Docker should see all three demos pass in one command.

## 7. Evaluation methodology Raven commits to

Following the [Anthropic Cybergym pattern](https://red.anthropic.com/2025/ai-for-cyber-defenders/):

- Public benchmark suite covering: DevSec PR review, 0-day variant analysis, decoy realism A/B (LLM-generated vs hand-crafted), restore RTO/RPO measurement
- Trial counts: 1, 10, 30
- Cost caps: $2 / $5 / $20 per trial
- All findings tagged with both ATT&CK technique id AND D3FEND technique id (bidirectional ontology lookup)
- Severity-agreement against human experts on a held-out set — matching the [imiel.dev system-card-breakdown](https://imiel.dev/blog/claude-mythos-preview-system-card)'s reported 89%/98% format for comparability against published Mythos numbers, while never claiming our numbers ARE Mythos numbers

Negative results are publishable. The `raven-research-looped-reasoning-eval` skill commits to publishing negative architecture-bet results in addition to positive ones.

## 8. Decision record — why Opsi C

Three options were considered for how to position the OpenMythos / Mythos record in the grant submission:

### Opsi A — Run the looped-reasoning experiment and cite results in the grant

Use the `raven-research-looped-reasoning-eval` skill to run the 3B × 30B-token experiment, then cite results in the grant.

Pros: real architectural bet, novel research contribution.
Cons: experiment will not finish on grant-submission timeline; results may be inconclusive; reviewer scrutiny on speculative architecture; ~$3K compute spend before submission with no guarantee of usable results.

### Opsi B — Cite OpenMythos as an inspiration without running the experiment

Pros: cheap, fast.
Cons: invites the reviewer to ask "do you actually use it?" with the answer being "no, just inspired." This is the worst of both worlds — weakens credibility without delivering a real artifact.

### Opsi C — Skip OpenMythos and the Mythos record from the grant entirely

Position Raven on the three pillars: CDP grounding, D3FEND OWL, defender-first. Cite MITRE, CISA, and Anthropic's defender post. Treat Mythos / Glasswing / OpenMythos as parallel-track research that does not need to appear in the submission.

Pros: cleanest pitch; reviewer cannot find an angle to discredit; the three pillars stand on their own merits; the architecture-bet experiment continues independently and gets published on its own terms if results support.
Cons: misses a chance to ride the Mythos news cycle.

**Decision: Opsi C.**

Rationale: Raven's value is the harness, not the model. The three pillars (CDP + D3FEND OWL + defender-first) are already differentiated and defensible. Bringing Mythos into the submission ties Raven's credibility to a model we do not run, on benchmarks we did not produce, in a research preview we have no access to. The architecture-bet experiment is research-track; the grant submission is product-track. These are different audiences.

The `hermes-mythos-persona.md` persona overlay continues to exist as an internal capability — it improves Hermes's voice and discipline at the prompt level — but it is not surfaced in the grant submission.

## 9. Reviewer Q&A — prepared answers

**Q: How does Raven compare to Claude Mythos Preview / Project Glasswing?**

> Mythos Preview is a research-preview frontier model focused on autonomous vulnerability discovery, primarily for the participating Glasswing partners. Raven is a defender-side harness — model-agnostic by design — that turns whatever model is configured into auditable, D3FEND-grounded defensive operations. The two are orthogonal: Mythos demonstrates what a frontier model can find; Raven defines how a defender turns model output into approved, verified action. We do not run Mythos, and we do not claim Mythos's benchmark numbers.

**Q: Why not use the OpenMythos architecture?**

> OpenMythos is a community speculative reconstruction of what Mythos might be, not what Mythos is. Raven is model-agnostic; the model is one swappable component of the harness. We have a separate research-track experiment that tests the underlying looped-transformer hypothesis at 3B scale, independent of the grant submission. Whether or not that experiment produces positive results, it does not change Raven's defender value proposition.

**Q: What does Raven add that existing SAST / SIEM / EDR vendors don't?**

> Three things: CDP grounding (every LLM emission terminates at an oracle, never speculation), MITRE D3FEND OWL binding (every defensive action is a real technique id resolved from the ontology, not a free-text mitigation), and a defender-only enforcement boundary (the approval gate is the single point where any production-touching action passes through). None of the existing vendors compose all three. Raven also publishes a reproducibility kit per run — `manifest.json` with seeds, commits, tool versions, and oracle traces — which makes results auditable to the level a grant evaluator can re-run independently.

**Q: How do you avoid the Mythos "letter-over-spirit" failure mode XBOW documented?**

> Every Raven review pass runs a mandatory spirit-pass after the literal pass — taking the user's threat-model invariants as explicit hypotheses and re-asking the model whether the diff violates them, even when the literal rule was technically satisfied. Recoveries from the spirit pass are surfaced as first-class findings labeled `letter_to_spirit_recovery`. See `skills/devsec-mythos-class/SKILL.md` Stage 5.

**Q: Why MIT and not a more permissive / restrictive license?**

> MIT matches the OpenAI grant program's public-benefit criterion. Restrictive licenses would close out enterprise adopters who need to deploy Raven inside proprietary environments; more permissive (e.g., 0BSD / public domain) would not add value over MIT for the defender-tooling audience.

## 10. Cross-references

- `d3fend-coverage.md` — coverage matrix for the D3FEND OWL pillar
- `decoy-subsystem-spec.md` — Deceive tactic implementation
- `restore-subsystem-spec.md` — Restore tactic implementation
- `owl-integration.md` — OWL runtime + SPARQL queries
- `SKILL.md` (root) — zero-day hunter
- `skills/` — six 0-day operator skills + DevSec gate
- `hermes-mythos-persona.md` — internal persona overlay; NOT part of grant submission
- `skills/research-looped-reasoning-eval/SKILL.md` — architecture-bet research experiment; NOT part of grant submission

## 11. Open positioning questions (track for next revision)

1. Should Raven include a managed-cloud-service offering in the proposal, or keep the submission strictly self-hosted? Current default: self-hosted only.
2. Should the partner-statements section list any existing Raven users, or stay model-only? Current default: none until at least three production deployments outside Daemon Blockint.
3. What's the right framing for the cost-cap criterion if a reviewer pushes back on the $2/$5/$20 Cybergym budget being too low? Current default: cite Cybergym as the public benchmark; offer to raise caps on request.
