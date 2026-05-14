---
name: raven-zero-day-defend
description: Stand up Raven's defensive posture against an in-the-wild 0-day campaign. Use when the user says "defend against `<CVE>` / `<campaign>`", "harden us against this 0-day", "deploy mitigations for the new exploit", "isolate exposure", or asks to compose D3FEND Harden + Isolate + Deceive techniques into an active defensive plan. Every action terminates at a tool oracle (𝒯) or approval-gated mitigation module, never raw LLM speculation, and every recommendation is bound to a real D3FEND technique id resolved from the OWL ontology.
---

# Raven — 0-Day Defend

This skill is Raven's defensive composer. Given a 0-day threat description (CVE, campaign report, vendor advisory, exploit-in-the-wild signal), it builds and executes a multi-stage D3FEND defense plan across the Harden, Isolate, Deceive, and Detect tactics. It does NOT hunt for new 0-days (use `raven-zero-day-hunter`), and it does NOT remediate already-confirmed compromises (use `raven-zero-day-fixing` for patch, `restore/` subsystem for rollback).

## When to use

Trigger when the user asks any of:

- "Defend us against CVE-YYYY-NNNNN"
- "There's an active 0-day campaign in `<vendor>` — harden us"
- "Deploy D3FEND Harden + Isolate for this advisory"
- "Build a virtual-patch / WAF rule for this 0-day"
- "Stand up deception around the vulnerable surface"
- "What's our blast-radius reduction plan for this 0-day?"

Do not trigger for: post-compromise response (use `raven-zero-day-investigator` first), pattern catalog curation (use `raven-zero-day-threat-patterns`), or routine hardening unrelated to a specific threat.

## Inputs

Required:

1. Threat reference — at least one of: `cve_id`, `campaign_name`, `advisory_url`, `exploit_artifact_hash`
2. Affected surface — `target_type` plus locator (the user's own assets or named subnet only)
3. Defense posture — `harden_only` (no isolation, no decoys), `harden_isolate` (default), `harden_isolate_deceive` (full posture)

Optional:

- Approval mode — `smart` default, `manual` for high-blast-radius actions
- Time budget — wall-clock cap, default 30 minutes per stage

## Pipeline — six mandatory stages

### Stage 1 — Threat intake (𝒯-grounded)

1. Resolve the threat reference to a structured record:
   - `cve_id` → `raven/ml/cve_matcher.py` against NVD/OSV
   - `advisory_url` → fetch and extract CWE, affected products, exploitation status
   - `campaign_name` → cross-reference Raven's pattern library via `raven-zero-day-threat-patterns` in `match` mode
2. Emit a `ThreatRecord` with: `cwe`, `affected_products`, `attack_vector` (network / local / physical), `exploitation_status` (POC / in-the-wild / theoretical), `attack_chain_attack_ids`
3. Refuse to continue if `exploitation_status` is unknown AND no advisory is provided — defending against a phantom is not a defender action.

### Stage 2 — D3FEND countermeasure resolution (𝒯-grounded)

For each `attack_chain_attack_ids` entry and the `cwe`:

1. Call `raven.d3fend.api.attack_to_d3fend(attack_id)` for ATT&CK-linked countermeasures
2. Call `raven.d3fend.api.cwe_to_d3fend(cwe)` for CWE-linked Harden / Detect techniques
3. Merge results, dedupe, and bucket by tactic

The output is a `CountermeasurePlan`:

```python
plan = {
  "Harden":   [TechniqueRef(...), ...],
  "Isolate":  [TechniqueRef(...), ...],
  "Deceive":  [TechniqueRef(...), ...],
  "Detect":   [TechniqueRef(...), ...],
}
```

If a bucket is empty for a posture that requested it (e.g. user asked for `harden_isolate_deceive` but `Deceive` is empty), the skill MUST emit a `gap_warning` and continue rather than silently skip the tactic.

### Stage 3 — Harden actions (𝒯-grounded, approval-gated)

Map each `Harden` D3FEND id to a concrete Raven action:

| D3FEND id | Raven module | Action |
|-----------|--------------|--------|
| D3-SCH (Source Code Hardening) | `raven/mitigation/remediation_engine.py` | Stage a patch / virtual patch |
| D3-AH (Application Hardening) | `raven/tools/nuclei_scanner.py` (own-asset) | Verify hardening config in place |
| D3-NTPM (Network Traffic Policy Mapping) | `raven/tools/projectdiscovery.py` | Identify exposed services for policy update |
| D3-CH (Credential Hardening) | `raven/mitigation/response_orchestrator.py` | Rotate / disable affected creds |

Every action enters the approval gate via `raven.mitigation.response_orchestrator.execute(...)`. The skill MUST NOT call mitigation modules directly.

### Stage 4 — Isolate actions (𝒯-grounded, approval-gated)

Map each `Isolate` D3FEND id similarly:

| D3FEND id | Raven module | Action |
|-----------|--------------|--------|
| D3-NI (Network Isolation) | `raven/mitigation/containment_actions.py` | Add network egress / ingress block |
| D3-EI (Execution Isolation) | `raven/mitigation/containment_actions.py` | Sandbox the vulnerable process / container |
| D3-MA (Mandatory Access Control) | `raven/mitigation/response_orchestrator.py` | Tighten AppArmor / SELinux profile |

Network isolation actions involving CIDR blocks > /24 require `manual` approval regardless of mode — blast radius is large enough that smart-approval is unsafe.

### Stage 5 — Deceive actions (optional, 𝒯-grounded)

Only if posture is `harden_isolate_deceive`. Delegate to the `decoy/` subsystem (see `decoy-subsystem-spec.md`):

| D3FEND id | Decoy module | Action |
|-----------|--------------|--------|
| D3-DF (Decoy File) | `decoy/file.py` | Drop honeyfile near the vulnerable surface |
| D3-DO (Decoy Object) | `decoy/object.py` | Stand up honeytoken (API key, cred) |
| D3-DNR (Decoy Network Resource) | `decoy/network.py` | Stand up honey-port mimicking vulnerable service |
| D3-DUC (Decoy User Credential) | `decoy/credential.py` | Plant honey-creds in vulnerable surface |

All decoy deployments pass through the decoy spec's four-gate CDP pipeline (𝓜 realism, 𝒯 content-safety, G4 approval, OWL ID validator).

### Stage 6 — Detect actions (𝒯-grounded)

For every `Detect` D3FEND id, install or tune a detector:

| D3FEND id | Raven module | Action |
|-----------|--------------|--------|
| D3-NTA (Network Traffic Analysis) | `raven/core/anomaly_detector.py` | Add feature for vulnerable service traffic |
| D3-FA (File Analysis) | `raven/tools/yara_scanner.py` | Install pattern from `raven-zero-day-threat-patterns` export |
| D3-PA (Process Analysis) | `raven/core/behavioral_profiler.py` | Add behavioral baseline rule |
| D3-IPCTA (IPC Traffic Analysis) | `raven/ml/sequence_analyzer.py` | Add sequence rule for vulnerable syscall pattern |

Detector tuning is not an action with destructive blast radius — `smart` approval is sufficient.

## Approval gate (Hermes-style, mandatory)

All Stage 3, 4, and 5 actions route through `raven/approval/gate.py`. The skill MUST set the gate's `context` field to include the threat reference and the D3FEND id, so the auxiliary LLM in `raven/approval/smart.py` has the rationale needed to auto-approve benign actions and escalate the rest.

`UNRECOVERABLE_BLOCKLIST` in `raven/approval/patterns.py` is hard-rejected even in `smart` mode. Defend MUST NOT bypass.

## Output contract

```markdown
# Raven 0-Day Defend — <threat reference>

## Threat record
- CVE / advisory: <id / url>
- CWE: <id>
- Attack vector: <network|local|physical>
- Exploitation status: <POC|in-the-wild|theoretical>
- ATT&CK chain: <T-id list>

## Defense plan
| Tactic | D3FEND id | Action | Module | Approval | Status |
|--------|-----------|--------|--------|----------|--------|
| Harden | D3-SCH | Apply patch <ref> | remediation_engine | approved | applied |
| Isolate | D3-NI | Block egress to <CIDR> | containment_actions | pending | awaiting manual |
| Deceive | D3-DF | Deploy honeyfile <path> | decoy/file | approved | deployed |
| Detect | D3-FA | YARA rule <id> | yara_scanner | approved | installed |
| ... |

## Gap warnings
- <if any tactic was requested but had no D3FEND coverage>

## Reproducibility kit
- Plan id: <id>
- Commit: <sha>
- Approval ledger: <path>
```

## Refusal rules

1. Refuse to defend against a phantom (no CVE, no advisory, no campaign reference).
2. Refuse to act on assets the user does not own or has not authorized.
3. Refuse to bypass the approval gate.
4. Refuse to silently skip a tactic the user requested — emit `gap_warning` instead.
5. Refuse to take any Stage 4 action with CIDR > /24 in `smart` mode.

## Related skills

- `raven-zero-day-detection` — installs the detectors emitted by Stage 6.
- `raven-zero-day-investigator` — runs first if the user suspects existing compromise; defend runs after.
- `raven-zero-day-fixing` — owns the patch-apply layer that Stage 3 stages.
- `raven-zero-day-auto-prevent` — superset that adds policy enforcement after this skill stands up the plan.
- D3FEND OWL integration (`raven/d3fend/`) — source of every technique id in the plan ([D3FEND home](https://d3fend.mitre.org/), [MITRE 1.0 release](https://www.mitre.org/news-insights/news-release/mitre-launches-d3fend-10-milestone-cybersecurity-ontology)).
