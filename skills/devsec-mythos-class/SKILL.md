---
name: raven-devsec-mythos-class
description: Mythos-class source-code reasoning for DevSec — pre-merge, pre-deploy, pre-release. Use when the user says "review this PR for security", "audit this diff", "block bad merges", "secure code review", "DevSec gate", "shift-left security", "pre-deploy security scan", "release security gate", or asks Raven to act as a Mythos-grade auditor inside the CI/CD pipeline. Every finding terminates at a tool oracle (𝒯), classical-ML detector (𝓜), or scored hypothesis (𝓛) with a falsification test — never raw LLM speculation — and ships with the D3FEND Harden technique id it implements. Defender-only: emits findings + remediation candidates, never exploit payloads.
---

# Raven — DevSec (Mythos-class)

This skill is Raven's DevSec gate. It takes the design property that makes Mythos useful — strong source-code reasoning paired with an explicit threat model and a validation harness — and ports it into a defender-only, CI/CD-integrated, D3FEND-grounded workflow.

The skill explicitly answers the criticism XBOW made of Mythos used alone: "needs precise prompts, explicit threat models, and validation infrastructure to turn strong reasoning into reliable security outcomes" ([XBOW Mythos evaluation, May 2026](https://xbow.com/blog/mythos-offensive-security-xbow-evaluation)). Raven supplies the harness; the LLM supplies the reasoning; the tool oracles supply the grounding.

## When to use

Trigger when the user asks any of:

- "Review this PR / diff / commit / branch for security"
- "Audit this codebase before release"
- "DevSec gate before merge / before deploy / before release"
- "Shift-left security review"
- "Block insecure merges automatically"
- "Mythos-class source audit on this repo"
- "Security review with threat model `<file>`"

Do not trigger for: post-deploy 0-day hunting (use `raven-zero-day-hunter`), live-system detection (use `raven-zero-day-detection`), or pattern library curation (use `raven-zero-day-threat-patterns`).

## What makes this "Mythos-class"

The XBOW evaluation identified four properties of Mythos that matter for source-code audit:

1. Source-code reading > source-code writing (strong reasoning over existing code).
2. Honest about ceiling — flags issues that need runtime/configuration validation.
3. Literal-rule discipline — rejects false positives well, but can lose true positives when evidence does not formally satisfy criteria.
4. Strong in native code and reverse engineering, not just web app code.

This skill operationalizes all four — and binds (3) (the false-negative risk) to mandatory `raven-zero-day-hunter` escalation, so issues that fail the literal-rule test do not silently vanish.

## Inputs

Required:

1. Scope — one of:
   - `pr` — pull request (repo + base ref + head ref)
   - `diff` — explicit unified diff
   - `commit-range` — repo + commit range
   - `branch` — repo + branch
   - `release-candidate` — repo + tag
2. Threat model — path to a `THREAT_MODEL.md` file OR an inline threat model block. The skill REFUSES to run without one. This is the property the XBOW post identified as essential for Mythos-class accuracy.
3. Verification depth — `pre-merge` (≤ 5 min, blocking), `pre-deploy` (≤ 30 min), `pre-release` (≤ 2 hours, includes fuzz + formal where applicable)

Optional:

- Approval mode — `smart` for advisory comments, `manual` for merge-blocking
- Cost cap — default scales with depth: $1 / $5 / $20
- Pattern pack version — pinned SHA from `raven-zero-day-threat-patterns` export

## Threat model schema (mandatory)

```yaml
threat_model_id: TM-2026-01
asset_class: <web-app|api|smart-contract|kernel-module|binary-service|library>
trust_boundaries:
  - name: client_to_server
    untrusted_inputs: [http_body, http_query, http_headers, websocket_frames]
  - name: server_to_db
    untrusted_outputs: [sql_query, redis_key, mongodb_filter]
critical_invariants:
  - name: no_user_can_access_other_users_resources
    enforced_by: [middleware.authz, repository.scoped_query]
  - name: all_external_io_is_logged
    enforced_by: [interceptor.audit]
adversary_capabilities:
  - submit_arbitrary_http_input: true
  - control_dns_response: false
  - read_filesystem_directly: false
in_scope_cwes:
  - CWE-89   # SQL Injection
  - CWE-862  # Missing Authorization
  - CWE-79   # XSS
  - CWE-918  # SSRF
out_of_scope_cwes:
  - CWE-209  # Information Exposure Through an Error Message — accepted risk
explicit_invariants_examples:
  - "Every controller that accepts a user_id parameter MUST call authz.assert_self_or_admin(user_id)"
  - "No raw string interpolation into SQL — only parameterized queries via repo.query(...)"
```

The threat model is the "precise prompt" XBOW called out. Without it the skill cannot distinguish "literal rule met" from "spirit of rule met" — Mythos's documented weakness.

## Pipeline — seven mandatory stages

### Stage 1 — Scope resolution (𝒯-grounded)

1. Materialize the diff:
   - `pr` → `gh pr diff` via the GitHub connector (read-only)
   - `commit-range` → `git diff <base>..<head>`
   - `branch` → `git diff origin/main..<branch>`
   - `release-candidate` → `git diff <previous-tag>..<tag>`
2. Bucket changed files by language and target type. Reject if any file is in a denylist (`vendored/`, `*.lock`, generated code) — these go through a separate stricter path.
3. Compute change blast radius:
   - Lines added / removed
   - Public-API surface changed (export list diff)
   - Dependencies changed (`Cargo.toml`, `package.json`, `requirements.txt` diff)
   - IaC / config changed (`*.tf`, `*.yaml`, `Dockerfile`)

Output: `ScopeManifest`. The skill rejects scopes exceeding `pre-merge` depth's line cap (default 2,000 changed lines) — over-large changes are routed to `pre-deploy` or `pre-release` depth.

### Stage 2 — Threat-model alignment (𝒯-grounded)

1. Parse the threat model with schema validation.
2. For each changed file, identify which `trust_boundaries` and `critical_invariants` it touches via AST analysis in `raven/ml/code_flow_scanner.py`.
3. Build a `ThreatProjection`: for every changed function, list which invariants apply and which adversary capabilities are relevant.

A change that does not project onto any invariant is not free-pass — it is flagged for "no-invariant coverage" and surfaced separately. This catches the Mythos failure mode where evidence does not formally satisfy criteria because the criteria were never written down.

### Stage 3 — Source-code reasoning pass (𝓛-scored)

This is the Mythos-class core. The skill invokes `raven/hunters/hypothesis_generator.py` with three precise inputs:

- The unified diff
- The `ThreatProjection` from Stage 2
- The relevant pattern subset from `raven-zero-day-threat-patterns` (filtered by `in_scope_cwes`)

The LLM produces a ranked list of `SecurityHypothesis` records. Each MUST include:

- `cwe` (must be in threat model's `in_scope_cwes`, OR explicitly flagged as out-of-scope-but-noticed)
- `location` — file + line range or symbol
- `precondition` — what attacker input or state is required
- `invariant_broken` — which `critical_invariant` from the threat model this would violate
- `prior` ∈ [0, 1]
- `falsification_test` — concrete tool-oracle invocation that would refute the hypothesis
- `evidence_quote` — the exact diff lines that prompted the hypothesis (verbatim, no paraphrase)

The LLM MUST NOT propose hypotheses without an `evidence_quote`. This enforces XBOW's "literal evidence" discipline.

### Stage 4 — Falsification pass (𝒯-grounded, mandatory)

For every hypothesis from Stage 3, run its `falsification_test` against a sandbox build:

| Target | Validator |
|--------|-----------|
| `solana-program` | `raven/tools/ares.py` (Solana ruleset) |
| `evm-contract` | `raven/tools/ares.py` (EVM ruleset) |
| `c-cpp-source` / `rust-source` | `raven/ml/code_flow_scanner.py` (taint) + `raven/ml/memory_analyzer.py` |
| `python-source` / `js-ts-source` | Semgrep via `code_flow_scanner.py` + `raven/ml/variant_analyzer.py` |
| `kernel-module` | `raven/tools/ghidra_analyzer.py` (post-build) + memory analyzer |
| `binary-service` | `raven/tools/ghidra_analyzer.py` + `raven/tools/radare2.py` |

Outcomes per hypothesis:

- `confirmed` — oracle reproduces the violation against the staged build
- `refuted` — oracle returns evidence inconsistent with the hypothesis
- `inconclusive` — oracle could not run or returned mixed signal
- `runtime_required` — oracle cannot statically resolve; needs runtime validation (this is the honest-ceiling output Mythos is known for)

A `runtime_required` outcome at `pre-merge` depth is NOT a free pass — the hypothesis is recorded as a `deferred_finding` and the gate emits a comment requesting `pre-deploy` re-run with live-site access.

### Stage 5 — Spirit-vs-letter cross-check

XBOW found Mythos prioritizes letter over spirit (77.8% vs Opus 4.6's 81.2% on command-safety benchmark). The skill explicitly counters this:

1. For every hypothesis the LLM marked `refuted`, take the related `critical_invariant` from the threat model and run a second pass with the invariant as the explicit hypothesis ("does this diff violate `<invariant>`?").
2. If the second pass produces a new `confirmed` hypothesis, emit a `letter_to_spirit_recovery` finding — these are flagged as high-value because they would have been false negatives under literal-only reasoning.

This is the harness that turns Mythos's discipline into a strength instead of a blind spot.

### Stage 6 — D3FEND Harden binding (𝒯-grounded)

For each `confirmed` and `letter_to_spirit_recovery` finding:

1. Call `raven.d3fend.api.cwe_to_d3fend(finding.cwe)` and filter to tactic `Harden`.
2. Rank by overlap count: techniques returned by both `cwe_to_d3fend` AND `attack_to_d3fend(known_attack_for_cwe)` rank higher.
3. Attach the top 1–3 D3FEND ids to the finding.

Common bindings:

| CWE | Likely D3FEND Harden |
|-----|----------------------|
| CWE-89 (SQLi) | D3-IVV (Input Value Validation), D3-SCH (Source Code Hardening) |
| CWE-862 (Missing Authz) | D3-AH (Application Hardening), D3-SCH |
| CWE-79 (XSS) | D3-IVV, D3-MOA (Message-Oriented Authentication) |
| CWE-918 (SSRF) | D3-NTPM (Network Traffic Policy Mapping), D3-AH |
| CWE-787 (OOB Write) | D3-SCH, D3-PSEP (Process Segment Execution Prevention) |
| CWE-119 (Memory Bounds) | D3-SCH, D3-MBT (Memory Boundary Tracking) |

Bindings are derived from the ontology, never hardcoded in the skill — the table above is illustrative.

### Stage 7 — Remediation candidate generation (𝓛-scored, 𝒯-bound)

For each `confirmed` finding, generate up to 3 patch candidates via `raven/mitigation/remediation_engine.py`:

- Each candidate MUST pass regex / shlex safety checks the engine already enforces
- Each candidate MUST pass the threat model's invariant assertions on a re-staged build
- The skill DOES NOT apply patches in this skill — application is handed off to `raven-zero-day-fixing`

Output is `RemediationCandidate` records attached to each finding, so the PR comment can include `Apply suggestion` links.

## CDP contract — quick check before returning

```
assert every finding.evidence_quote is verbatim from the diff
assert every confirmed finding has at least one tool-oracle hit (𝒯)
assert every finding.d3fend_techniques resolves through raven.d3fend.api
assert findings without runtime validation are marked deferred, not confirmed
assert no out_of_scope_cwes findings are gating (advisory only)
```

## Gate decision matrix

| Verification depth | Confirmed in-scope findings | Letter-to-spirit findings | Deferred runtime-required | Decision |
|--------------------|----------------------------|---------------------------|---------------------------|----------|
| pre-merge | ≥ 1 critical | any | any | BLOCK |
| pre-merge | ≥ 1 high | any | any | REQUEST_CHANGES |
| pre-merge | medium / low only | none | any | COMMENT |
| pre-merge | none | none | none | APPROVE |
| pre-merge | none | none | ≥ 1 | APPROVE_WITH_DEFERRED_NOTE |
| pre-deploy | ≥ 1 critical / high | any | any | BLOCK |
| pre-deploy | medium only | any | ≥ 1 still deferred | REQUEST_CHANGES |
| pre-release | any unresolved confirmed | any | any | BLOCK |

Critical / high / medium / low severities are computed from `(prior × oracle_confidence × invariant_criticality)` per the threat model — not from CVSS lookups.

## Output contract — PR comment / report

```markdown
# Raven DevSec Review — <pr/diff/branch ref>

## Verdict: <APPROVE|APPROVE_WITH_DEFERRED_NOTE|COMMENT|REQUEST_CHANGES|BLOCK>

## Scope
- Files: <n> / Lines: +<a> -<r>
- Public API changed: <yes|no>
- Dependencies changed: <list>
- Threat model: <id> (`<path>`)

## Findings (<count>)

### F-<n> — <one-line summary>
- Severity: <critical|high|medium|low>
- CWE: <id>
- Invariant violated: <name from threat model>
- Location: <file:line-range>
- Evidence quote:
  ```
  <verbatim diff slice>
  ```
- Falsification test: <oracle invocation>
- Oracle outcome: <confirmed|letter_to_spirit_recovery|deferred_runtime_required>
- D3FEND Harden: <id list>
- Remediation candidates:
  - C1: <one-line summary> (`<diff path>`)
  - C2: <one-line summary> (`<diff path>`)
- Suggested apply skill: `raven-zero-day-fixing`

(repeat per finding)

## Letter-to-spirit recoveries (<count>)
| Finding | Invariant | Why initial pass missed it |
|---------|-----------|----------------------------|
| ... |

## Deferred runtime-required (<count>)
| Hypothesis | Why deferred | Required next step |
|------------|--------------|--------------------|
| ... | needs live request | re-run at pre-deploy depth |

## Out-of-scope notices (<count>)
| Finding | Why advisory only | Out-of-scope CWE |
|---------|-------------------|------------------|

## No-invariant-coverage warnings (<count>)
| Change | File | Why concerning |
|--------|------|----------------|

## Reproducibility kit
- Threat model SHA: <sha>
- Pattern pack SHA: <sha>
- Tool versions: <list>
- Oracle traces: <path>
- Commit: <pr head sha>
```

## CI / CD integration

The skill is designed to run as a GitHub Action / GitLab CI job. Hooks:

- `pre-merge` — GitHub PR check, blocks merge on `BLOCK` and `REQUEST_CHANGES`
- `pre-deploy` — runs after merge to main, blocks deployment pipeline
- `pre-release` — runs against release-candidate tags before public release

The skill MUST post results back as PR review comments with a stable bot identity, and MUST attach the full report as a workflow artifact for audit.

For GitHub specifically, use the connected `github_mcp_direct` integration:

- Read: `gh pr view`, `gh pr diff`
- Write: PR review with one of `APPROVE`, `REQUEST_CHANGES`, `COMMENT`
- The skill MUST NOT push commits, force-push, or close PRs.

## DevSec workflow recipes

### Recipe A — Block-on-merge for high-severity-only repos

```yaml
on: pull_request
jobs:
  raven_devsec:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - run: raven devsec review
        env:
          RAVEN_DEPTH: pre-merge
          RAVEN_THREAT_MODEL: .raven/THREAT_MODEL.yaml
          RAVEN_APPROVAL: smart
```

### Recipe B — Two-stage gate (advisory at PR, blocking at deploy)

PR job runs `pre-merge` in advisory mode (`smart`). Deploy job runs `pre-deploy` in blocking mode (`manual` for any high+). This matches the Mythos "honest ceiling" philosophy: low-cost reading at PR time, deeper validation when the change is about to face the runtime.

### Recipe C — Release-gate with formal verification (Solana / EVM)

For smart contracts. `pre-release` depth invokes the formal-verification stub in `raven/ml/vulnerability_validator.py`. Findings that cannot be formally discharged block the release-tag pipeline.

## Refusal rules

1. Refuse to run without a threat model. No default threat model exists. The skill suggests `raven devsec init` to bootstrap one.
2. Refuse to gate on findings derived from LLM speculation only — every finding must have `evidence_quote` from the diff AND oracle confirmation (or be marked `deferred_runtime_required`).
3. Refuse to apply patches. Application is `raven-zero-day-fixing`'s job.
4. Refuse to bypass the approval gate when posting `BLOCK` or `REQUEST_CHANGES`.
5. Refuse to mark a hypothesis `refuted` without also running the spirit-pass in Stage 5.
6. Refuse to operate on repos the user has not authorized via the GitHub connector.
7. Refuse to import any defender-edition-excluded module (`offensive.py`, `metasploit_integration.py`, `empire_client.py`, `exploitdb*.py`).

## Mythos parity & honest divergence

| Mythos property (per XBOW) | This skill | Divergence rationale |
|----------------------------|------------|----------------------|
| Strong source-code reading | Yes — Stage 3 LLM reasoning with diff + threat model | None |
| Strong native-code / RE | Yes — Stage 4 routes to Ghidra / radare2 | None |
| Honest about runtime ceiling | Yes — `deferred_runtime_required` is a first-class outcome | None |
| Literal-rule precision | Yes — `evidence_quote` mandatory | None |
| Letter-over-spirit weakness | Mitigated by Stage 5 spirit-pass against invariants | Defender cannot afford silent false negatives |
| 5x cost of Opus | This skill is model-agnostic; default routes to cheaper models with `pre-merge` and only escalates to higher-tier on `pre-release` | DevSec runs at PR cadence — cost must scale with depth |
| Offensive-oriented (XBOW use case) | Defender-only; emits findings + remediation, never exploit payloads | OpenAI Cybersecurity Grant scope |

## Related skills

- `raven-zero-day-threat-patterns` — supplies the pattern subset for Stage 3 prompt context.
- `raven-zero-day-hunter` — invoked when a finding requires deep deferred analysis beyond `pre-release` depth.
- `raven-zero-day-investigator` — invoked when a runtime confirmation arrives post-deploy.
- `raven-zero-day-defend` — invoked when a confirmed finding maps to in-the-wild active campaigns.
- `raven-zero-day-fixing` — sibling skill that applies the remediation candidates this skill generates.
- D3FEND OWL integration (`raven/d3fend/`) — source of every Harden technique id ([D3FEND home](https://d3fend.mitre.org/), [MITRE 1.0 release announcement](https://www.mitre.org/news-insights/news-release/mitre-launches-d3fend-10-milestone-cybersecurity-ontology)).

## Provenance & honest comparison

The design of this skill is informed by three public sources:

- [XBOW Mythos evaluation, May 2026](https://xbow.com/blog/mythos-offensive-security-xbow-evaluation) — for Mythos's documented strengths and the specific failure modes (letter-vs-spirit, runtime ceiling) that this skill mitigates by design.
- [CISA / NSA principles for security-by-design and -by-default](https://www.cisa.gov/sites/default/files/2023-10/SecureByDesign_1025_508c.pdf) — for the shift-left framing and the requirement that security be a pipeline property, not a post-hoc audit.
- [Anthropic AI for Cyber Defenders](https://red.anthropic.com/2025/ai-for-cyber-defenders/) — for the Cybergym-style trial/cost budget pattern reused in the verification-depth ladder.

The skill is positioned as the defender-only, D3FEND-grounded complement to the offensive Mythos+XBOW pairing: same source-code reasoning class, opposite goal.
