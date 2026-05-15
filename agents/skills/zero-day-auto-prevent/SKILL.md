---
name: raven-zero-day-auto-prevent
description: Automatically enforce defensive policy against an in-progress 0-day signal, end-to-end, with strict approval gating. Use when the user says "auto-prevent", "auto-block", "auto-quarantine", "policy-driven response", "stop this 0-day now without me clicking through", or asks Raven to execute the Defend plan automatically when criteria are met. Every automatic action terminates at a tool oracle (𝒯) with mandatory approval-gate verification, references a real D3FEND Isolate / Evict / Harden technique id, and emits a tamper-evident audit trail.
---

# Raven — 0-Day Auto-Prevent

This skill is Raven's policy enforcer. It runs the same defensive plan as `raven-zero-day-defend` but with the human pre-authorizing classes of action by policy rather than each individual action. It is the highest-blast-radius skill in the 0-day suite, and the rules below are non-negotiable.

The skill MUST NOT bypass `raven/approval/gate.py`. "Auto" means the gate's `smart` mode is configured with policy-derived rules — it does NOT mean the gate is off.

## When to use

Trigger when the user asks any of:

- "Auto-prevent this 0-day"
- "Auto-block / auto-quarantine on detection of `<pattern>`"
- "Run my response policy automatically"
- "Standing policy: isolate any host that matches `<criteria>`"
- "Apply the playbook without my approval for low-risk actions"

Do not trigger for: a single one-off incident (use `raven-zero-day-defend`), or for any user who has not explicitly written a policy. This skill refuses to fabricate a policy on the user's behalf.

## Inputs

Required:

1. Policy reference — path to a Raven policy file OR an inline policy YAML block. Policies must be validated against the policy schema before execution.
2. Trigger source — one of: `alert-stream` (live from `raven-zero-day-detection`), `single-alert` (one alert id), `signal` (analyst-supplied indicator block)

Optional:

- Dry run — `true` to evaluate the policy and emit the plan without executing; default `false`
- Audit sink — `file` (default), `kafka`, `siem-webhook`

## Policy schema (mandatory)

A policy is a YAML document with these top-level keys. The skill MUST reject any policy that fails schema validation.

```yaml
policy_id: P-PROD-WEB-2026-01
owner: <email or team>
authorized_assets:
  - <fqdn or cidr or asset tag>     # at least one; "*" is rejected
trigger_predicate:
  any_of:
    - alert.severity: critical
    - alert.detector_hits[*].rule_id: raven.binary.suspicious_packer_v3
    - alert.d3fend_techniques: [D3-FA]
actions:
  - name: isolate_host
    d3fend_id: D3-NI
    module: raven.mitigation.containment_actions
    auto_approve_if:
      - asset_tag in [non-production, canary]
      - blast_radius_score < 0.3
    else: manual
  - name: rotate_credentials
    d3fend_id: D3-CH
    module: raven.mitigation.response_orchestrator
    auto_approve_if:
      - principal.type == service-account
    else: manual
  - name: deploy_decoy
    d3fend_id: D3-DF
    module: decoy.file
    auto_approve_if:
      - always
required_negative_constraints:
  - never_touch_assets: [<asset list>]
  - never_apply_to_principals: [<principal list>]
  - max_actions_per_minute: 10
  - max_actions_per_hour: 100
```

Schema notes:

- `authorized_assets` MUST list specific assets — wildcard `*` is rejected.
- Every action MUST have a `d3fend_id` and a `module` from Raven's defender-edition module list. Excluded modules (`offensive.py`, `metasploit_integration.py`, `empire_client.py`, `exploitdb*.py`) fail validation.
- `auto_approve_if` predicates are evaluated against the trigger context; if any predicate is unresolvable, the action falls to `else: manual` automatically.
- `required_negative_constraints` are hard caps; the skill MUST honor them even if `auto_approve_if` would otherwise authorize.

## Pipeline — six mandatory stages

### Stage 1 — Policy load and validate (𝒯-grounded)

1. Parse the policy with a JSON-schema validator. Reject on any schema failure.
2. Resolve every `d3fend_id` via `raven.d3fend.api.lookup_technique` — non-existent ids fail validation.
3. Confirm every `module` reference is in the defender-edition allowlist via `raven.d3fend.coverage.allowed_modules`.
4. Persist the policy hash to the audit log; future runs MUST log the same hash or fail-closed.

### Stage 2 — Trigger evaluation (𝒯-grounded)

For each incoming signal (alert from `raven-zero-day-detection`, finding from `raven-zero-day-investigator`, or analyst-supplied indicator):

1. Evaluate `trigger_predicate` strictly — boolean evaluation only, no LLM interpretation.
2. If the predicate matches, emit a `MatchedTrigger` event with the signal hash and policy id.
3. If multiple actions match, retain order from the policy file — execution is deterministic.

### Stage 3 — Action authorization (G4 + approval-gate)

For each candidate action:

1. Check `required_negative_constraints` first. If any constraint is violated, the action is rejected with `reason=constraint_violation` and dispatched to manual review.
2. Evaluate `auto_approve_if` predicates. If all resolve true, the action is marked `smart_eligible`.
3. The action ALWAYS routes through `raven.mitigation.response_orchestrator.execute(...)`, which calls `raven/approval/gate.py`. Even `smart_eligible` actions go through the gate — the gate is the single enforcement point.
4. The gate's `smart.py` LLM is given the action context, policy snippet, and trigger evidence. It returns approve / deny / escalate.
5. `UNRECOVERABLE_BLOCKLIST` patterns in `raven/approval/patterns.py` are hard-rejected even when policy says auto-approve.

The skill MUST NOT call mitigation modules directly to bypass the gate. This is the most-tested invariant.

### Stage 4 — Rate limiting

Enforce `max_actions_per_minute` and `max_actions_per_hour` using a Redis-backed sliding window. On rate-limit breach:

- Subsequent actions are dispatched to `manual` regardless of policy.
- Emit a `raven_auto_prevent_rate_limit_breach_total` Prometheus counter.
- Notify the policy owner via the configured channel.

### Stage 5 — Execution & verification (𝒯-grounded)

After the gate approves, execute the action through the named module. After execution:

1. Capture the module's return value and any side-effect handle (process id, firewall rule id, decoy deployment id).
2. Verify the side effect with an independent tool-oracle call — e.g. if the action was `isolate_host`, query the firewall to confirm the rule is present.
3. If verification fails, immediately attempt a rollback via the `restore/` subsystem and escalate to manual.

### Stage 6 — Audit log emission

Every action — approved, denied, rate-limited, or rolled-back — appends one record to the audit log:

```json
{
  "ts": "...",
  "policy_id": "...",
  "policy_sha": "...",
  "trigger_signal_hash": "...",
  "action_name": "...",
  "d3fend_id": "...",
  "module": "...",
  "approval_decision": "approve|deny|escalate",
  "approval_reason": "...",
  "executed": true|false,
  "verified": true|false,
  "rolled_back": true|false,
  "blast_radius_score": <float>,
  "operator_override": null,
  "cdp_grounding": {"T": true, "M": true|false, "L": false}
}
```

Audit log is append-only, hash-chained (each record contains `prev_record_sha256`). The skill MUST refuse to start if the chain on disk is broken.

## CDP contract — quick check before each action

```
assert action.d3fend_id resolves through raven.d3fend.api.lookup_technique
assert action.module in defender-edition allowlist
assert approval gate returned a decision (not None)
assert at least one 𝒯 tool oracle invocation was made (this stage or upstream)
assert action satisfies required_negative_constraints
```

Any failed assertion aborts the action and emits an audit record with `approval_decision="abort_cdp_violation"`.

## Output contract

```markdown
# Raven 0-Day Auto-Prevent — policy <policy_id>

## Run metadata
- Policy SHA: <sha>
- Trigger source: <alert-stream|single-alert|signal>
- Window: <start> → <end>
- Dry run: <true|false>

## Triggered actions (<count>)

### Action <action_name> on <target>
- D3FEND: <id>
- Module: <module>
- Approval: <approve|deny|escalate>
- Auto-approve predicates: <list>
- Executed: <yes|no>
- Verified: <yes|no>
- Rolled back: <yes|no>
- Blast radius: <score>
- Audit record: <id>

(repeat)

## Rate-limit events (<count>)
| ts | counter | breach |
|----|---------|--------|

## Constraint violations rejected (<count>)
| action | violation | dispatched_to_manual |
|--------|-----------|-----------------------|

## Audit chain integrity
- Records appended: <n>
- Chain valid: <yes|no>
- Last record SHA: <sha>
```

## Refusal rules

1. Refuse to run without a validated policy. No default policy exists.
2. Refuse any policy with `authorized_assets: ["*"]`.
3. Refuse any policy referencing excluded modules.
4. Refuse to start if the audit log chain on disk is broken.
5. Refuse to bypass `raven/approval/gate.py` under any flag, including `--force`.
6. Refuse to auto-execute any action without a verification step.
7. Refuse to silently downgrade `manual` decisions to `smart` — the gate's decision is final per-action.

## Related skills

- `raven-zero-day-detection` — primary upstream producer of triggers.
- `raven-zero-day-investigator` — alternative upstream producer (investigation outcomes).
- `raven-zero-day-defend` — same action library, but always operator-in-the-loop.
- `raven-zero-day-fixing` — invoked when an action is `apply_patch` or `rollback`.
- `restore/` subsystem — invoked for verified rollback on execution failure.
- D3FEND OWL integration (`raven/d3fend/`) — id resolution for every action ([D3FEND home](https://d3fend.mitre.org/)).
