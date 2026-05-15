---
name: raven-zero-day-fixing
description: Generate, verify, and apply patches for a confirmed 0-day finding. Use when the user says "fix this 0-day", "patch this CVE", "generate the fix", "virtual-patch this", "rollback unsafe change", "apply remediation", or hands over a confirmed root cause from `raven-zero-day-investigator`. Every patch terminates at a tool oracle (𝒯) — static verifier, test suite, formal check, or restore primitive — never raw LLM speculation, and every fix is tagged with a D3FEND Harden / Restore technique id.
---

# Raven — 0-Day Fixing

This skill is Raven's remediation layer. It turns a confirmed root cause into an applied patch or a verified rollback. It does NOT investigate (use `raven-zero-day-investigator`) and it does NOT decide policy (use `raven-zero-day-auto-prevent`). Every patch passes through the approval gate and at least one verifier oracle before it is applied.

## When to use

Trigger when the user asks any of:

- "Fix / patch CVE-YYYY-NNNNN in `<repo>`"
- "Generate a fix for this confirmed finding"
- "Virtual-patch this at the WAF / sidecar layer"
- "Rollback this unsafe deployment"
- "Apply remediation for `<finding>`"

Do not trigger for: pre-confirmation speculation (use `raven-zero-day-investigator` first), routine dependency bumps (handle outside Raven), or any patch without a confirmed root cause record.

## Inputs

Required:

1. Confirmed finding — root-cause record from `raven-zero-day-investigator` OR a validated finding from `raven-zero-day-hunter`. The record MUST include `cwe`, `location`, `d3fend_techniques`, and validator evidence.
2. Fix mode — one of: `source-patch`, `virtual-patch`, `config-harden`, `rollback`
3. Verification depth — `unit-tests`, `unit-plus-static`, `unit-plus-static-plus-fuzz`, `formal` (last is Solana / EVM only)

Optional:

- Approval mode — `manual` by default for `source-patch` and `rollback`, `smart` allowed for `virtual-patch` and `config-harden`
- Time budget — wall-clock cap

## Pipeline — six mandatory stages

### Stage 1 — Finding intake (𝒯-grounded)

1. Validate the finding record's schema; reject if missing CWE, location, or D3FEND ids.
2. Confirm the validator evidence path still exists and re-run the validator one more time. If the issue no longer reproduces, the skill aborts with `already_fixed_or_drift` — patching a non-issue is forbidden.
3. Resolve every D3FEND technique id in the finding via `raven.d3fend.api.lookup_technique`. Reject unresolved ids.

### Stage 2 — Fix-mode routing

| Fix mode | Primary module | Verifier oracles |
|----------|----------------|------------------|
| `source-patch` | `raven/mitigation/remediation_engine.py` | unit tests + `raven/tools/ares.py` re-run + `raven/ml/code_flow_scanner.py` |
| `virtual-patch` | `raven/tools/nuclei_scanner.py` template + WAF/sidecar config emitter | Nuclei replay against the vulnerable surface |
| `config-harden` | `raven/mitigation/response_orchestrator.py` | configuration verifier (own-asset only) |
| `rollback` | `restore/` subsystem (`restore-subsystem-spec.md`) | restore primitive's own verifier (D3-RS / D3-RC return success) |

The skill MUST pick exactly one mode. Multi-mode fixes are decomposed into separate runs.

### Stage 3 — Patch generation (𝓛-scored, 𝒯-bound)

For `source-patch`:

1. `raven/mitigation/remediation_engine.py` emits one or more candidate patches as unified diffs. The engine consults the finding's CWE, the local code style, and any pinned dependencies.
2. Each candidate MUST be regex-validated and shlex-quoted (the engine's existing safety property) — the skill does not write shell-strings.
3. The LLM may rank candidates but MUST NOT author them outside the engine. If the engine cannot produce a candidate, the skill emits `no_engine_candidate` and falls back to `virtual-patch` if eligible, otherwise stops.

For `virtual-patch`:

1. Generate a Nuclei template / WAF rule from the finding's evidence features.
2. The template MUST be reviewable as plain text and MUST be defensive only (block / log, never exploit).

For `config-harden`:

1. Emit a diff against the affected config file (e.g. AppArmor profile, nginx config, sysctl entry).

For `rollback`:

1. Look up the most recent good checkpoint via the `restore/` subsystem.
2. Confirm the checkpoint's hash matches its recorded value.

### Stage 4 — Pre-application verification (𝒯-grounded, mandatory)

For `source-patch`:

1. Apply the patch to a sandboxed branch / worktree.
2. Run the project's test suite. Fail if any test regresses.
3. Re-run `ares.py` or `code_flow_scanner.py` and confirm the finding no longer reproduces.
4. If verification depth includes `fuzz`, run a short fuzz session and require no new crashes.
5. If verification depth is `formal` and the target is Solana / EVM, run the formal-verification stub in `raven/ml/vulnerability_validator.py` against the patched program.

For `virtual-patch`:

1. Stage the rule in a shadow mode against replayed traffic.
2. Confirm zero false positives on a known-good replay batch and ≥ 1 true positive on the exploit payload.

For `config-harden`:

1. Parse-check the new config (syntax).
2. Apply in a staging environment if available; confirm the affected service still starts and serves health checks.

For `rollback`:

1. Verify the checkpoint integrity hash before any state mutation.
2. Dry-run the rollback against an isolated copy if the `restore/` subsystem supports it.

If any verifier fails, the patch is NOT promoted. The skill emits `verification_failed` and exits.

### Stage 5 — Approval gate

Route the verified candidate through `raven/approval/gate.py`. The skill MUST supply:

- The finding record
- The unified diff (or rule / config / checkpoint reference)
- The verifier results (test counts, oracle outputs, fuzz session summary)
- The D3FEND id this fix claims to implement

`raven/approval/smart.py` may auto-approve `virtual-patch` and `config-harden` actions that pass all verifiers. `source-patch` and `rollback` always require `manual` approval unless the user explicitly configured otherwise in policy via `raven-zero-day-auto-prevent`.

`UNRECOVERABLE_BLOCKLIST` patterns are hard-rejected.

### Stage 6 — Apply and post-verify (𝒯-grounded)

After approval, apply the change through the appropriate module:

- `source-patch` → `remediation_engine.apply(...)` — note this is the same module that owns the existing patch-apply path
- `virtual-patch` → install WAF/sidecar rule via the configured provider's API
- `config-harden` → `response_orchestrator.execute_config_change(...)`
- `rollback` → invoke the `restore/` subsystem's primitive matching the D3FEND id (D3-RS, D3-RC, etc.)

After application, run a final verifier pass on the live target. If post-verify fails:

- For `source-patch` / `config-harden` / `rollback` — initiate the `restore/` subsystem's automatic recovery (return to pre-change state) and escalate.
- For `virtual-patch` — disable the rule and escalate.

## CDP contract — quick check before applying

```
assert finding.confirmed is True
assert finding.cwe is not None
assert all d3fend_id in fix.d3fend_techniques resolve through ontology
assert pre_application_verifier_results.all_passed is True
assert approval_gate_decision == "approve"
assert at least one 𝒯 verifier oracle was invoked
```

Any failed assertion blocks the apply step.

## Output contract

```markdown
# Raven 0-Day Fix — <finding_id>

## Finding reference
- CWE: <id>
- Location: <file:lines or symbol or address>
- Validator evidence: <path>
- D3FEND tags on fix: <id list>

## Fix mode
- Mode: <source-patch|virtual-patch|config-harden|rollback>
- Generator module: <module>
- Candidate count: <n>
- Selected candidate: <id>

## Pre-application verification
| Verifier | Result | Detail |
|----------|--------|--------|
| Unit tests | pass / fail (<n>) | <summary> |
| ares.py re-run | not-reproduced / reproduced | <path> |
| code_flow_scanner | clean / hit | <path> |
| fuzz session | no-crash / crash (<n>) | <wall-clock> |
| formal | proved / counterexample | <path> |

## Approval
- Mode: <smart|manual>
- Decision: <approve|deny|escalate>
- Reason: <reason>

## Apply
- Wall-clock: <s>
- Side-effect handle: <pid / rule_id / commit_sha / checkpoint_id>

## Post-verification
| Check | Result |
|-------|--------|
| Live re-run | not-reproduced |
| Service health | green |

## Reproducibility kit
- Patch diff: <path>
- Verifier traces: <path>
- Commit: <sha>
- Audit record: <id>
```

## Refusal rules

1. Refuse to apply any patch without re-running the validator and confirming the issue still reproduces in Stage 1.
2. Refuse to apply any patch that regresses the test suite.
3. Refuse to apply a `source-patch` or `rollback` in `smart` mode unless an active `raven-zero-day-auto-prevent` policy explicitly allows it.
4. Refuse to bypass the approval gate.
5. Refuse to apply without a D3FEND id tag — every fix MUST cite the Harden or Restore technique it implements.
6. Refuse to ship a virtual patch that has zero true positives in shadow mode.
7. Refuse rollback without checkpoint integrity verification.

## Related skills

- `raven-zero-day-investigator` — upstream producer of confirmed findings.
- `raven-zero-day-defend` — sibling skill that stages the same actions before they execute.
- `raven-zero-day-auto-prevent` — invokes this skill when policy authorizes automatic fixes.
- `restore/` subsystem — owns the `rollback` mode primitives ([restore-subsystem-spec](../../restore-subsystem-spec.md)).
- D3FEND OWL integration (`raven/d3fend/`) — source of every Harden / Restore id on every fix ([D3FEND home](https://d3fend.mitre.org/)).
