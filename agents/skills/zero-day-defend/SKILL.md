---
name: raven-zero-day-defend
description: Stand up Raven's defensive posture against an in-the-wild 0-day campaign. Use when the user says "defend against `<CVE>` / `<campaign>`", "harden us against this 0-day", "deploy mitigations for the new exploit", "isolate exposure", or asks to compose D3FEND Harden + Isolate + Deceive techniques into an active defensive plan. Every action terminates at a tool oracle (𝒯) or approval-gated mitigation module, never raw LLM speculation, and every recommendation is bound to a real D3FEND technique id from the 271-entry MITRE catalog plus ATT&CK offensive context and exposure scoring. Built for production DevSecOps at enterprise scale.
---

# Raven — 0-Day Defend

This skill is Raven's defensive composer in the MDASH (Multi-Model Agentic Security Harness) pipeline. Given a 0-day threat description (CVE, campaign report, vendor advisory, exploit-in-the-wild signal), it builds and executes a multi-stage D3FEND defense plan across the Harden, Isolate, Deceive, and Detect tactics with ATT&CK threat context and exposure scoring.

This skill is built for production DevSecOps at enterprise scale:
- Every finding has an owner, a triage process, and a Patch Tuesday deadline
- Defensive actions are approval-gated and routed through the proper DevSecOps channels
- The pipeline serves billions of users (Windows, Hyper-V, Xbox, Azure) — there is no quiet drawer for speculative findings
- Collaboration between ACS (Autonomous Code Security), MORSE (Offensive Research & Security Engineering), and WARP (Windows Attack Research and Protection)

It does NOT hunt for new 0-days (use `raven-zero-day-hunter`), and it does NOT remediate already-confirmed compromises (use `raven-zero-day-fixing` for patch, `restore/` subsystem for rollback).

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
4. Finding owner — assigned DevSecOps owner for triage and Patch Tuesday tracking

Optional:

- Approval mode — `smart` default, `manual` for high-blast-radius actions
- Time budget — wall-clock cap, default 30 minutes per stage

## Pipeline — six mandatory stages

### Stage 1 — Threat intake (𝒯-grounded)

1. Resolve the threat reference to a structured record:
   - `cve_id` → `pipeline/scan/finding_collector.py` against NVD/OSV
   - `advisory_url` → fetch and extract CWE, affected products, exploitation status
   - `campaign_name` → cross-reference Raven's pattern library via `pipeline/feedback/cve_parser.py`
2. Emit a `ThreatRecord` with: `cwe`, `affected_products`, `attack_vector` (network / local / physical), `exploitation_status` (POC / in-the-wild / theoretical), `attack_chain_attack_ids`, `finding_owner`
3. Calculate exposure score via `pipeline/threat_intel/onchain_threat_intel.py` for real-world impact prioritization
4. Refuse to continue if `exploitation_status` is unknown AND no advisory is provided — defending against a phantom is not a defender action. At Microsoft scale, noise is everyone's problem.

### Stage 2 — D3FEND + ATT&CK countermeasure resolution (𝒯-grounded)

For each `attack_chain_attack_ids` entry and the `cwe`, invoke `pipeline/d3fend/enrichment_engine.py` to bind:

1. **D3FEND defensive techniques** — from `pipeline/d3fend/d3fend_catalog_loader.py` (real 271-entry MITRE catalog) + `pipeline/d3fend/ontology_client.py`
2. **ATT&CK offensive techniques** — from `pipeline/d3fend/attack_mapper.py` for threat actor context
3. **Exposure scoring** — from `pipeline/threat_intel/onchain_threat_intel.py` for real-world impact
4. **Compliance mapping** — from `pipeline/d3fend/cci_loader.py` (CCI-to-D3FEND NIST SP 800-53 mappings)
5. Merge results, dedupe, and bucket by tactic

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

| D3FEND id | Pipeline module | Action |
|-----------|-----------------|--------|
| D3-SCH (Source Code Hardening) | `pipeline/d3fend/remediation.py` | Stage a patch / virtual patch |
| D3-AH (Application Hardening) | `pipeline/prepare/threat_modeler.py` (own-asset) | Verify hardening config in place |
| D3-NTPM (Network Traffic Policy Mapping) | `pipeline/prepare/threat_modeler.py` | Identify exposed services for policy update |
| D3-CH (Credential Hardening) | `pipeline/d3fend/enrichment_engine.py` | Rotate / disable affected creds |

Every action enters the approval gate via `raven.mitigation.response_orchestrator.execute(...)`. The skill MUST NOT call mitigation modules directly.

### Stage 4 — Isolate actions (𝒯-grounded, approval-gated)

Map each `Isolate` D3FEND id similarly:

| D3FEND id | Pipeline module | Action |
|-----------|-----------------|--------|
| D3-NI (Network Isolation) | `pipeline/prove/sandbox.py` | Add network egress / ingress block |
| D3-EI (Execution Isolation) | `pipeline/prove/sandbox.py` | Sandbox the vulnerable process / container |
| D3-MA (Mandatory Access Control) | `pipeline/d3fend/enrichment_engine.py` | Tighten AppArmor / SELinux profile |

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

| D3FEND id | Pipeline module | Action |
|-----------|-----------------|--------|
| D3-NTA (Network Traffic Analysis) | `pipeline/scan/agent_router.py` | Add feature for vulnerable service traffic |
| D3-FA (File Analysis) | `pipeline/scan/finding_collector.py` | Install pattern from `pipeline/feedback/cve_parser.py` export |
| D3-PA (Process Analysis) | `pipeline/cross_language/taint_tracker.py` | Add behavioral baseline rule |
| D3-IPCTA (IPC Traffic Analysis) | `pipeline/cross_language/ffi_analyzer.py` | Add sequence rule for vulnerable syscall pattern |

Detector tuning is not an action with destructive blast radius — `smart` approval is sufficient.

## Approval gate (Hermes-style, mandatory)

All Stage 3, 4, and 5 actions route through `pipeline/feedback/feedback_agent.py` with approval gates. The skill MUST set the gate's `context` field to include the threat reference, D3FEND id, exposure score, and finding owner, so the auxiliary LLM has the rationale needed to auto-approve benign actions and escalate the rest.

At Microsoft scale, every action has a real owner and a triage process. Defend MUST NOT bypass approval gates.

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

## Related skills and modules

- `raven-zero-day-detection` — installs the detectors emitted by Stage 6.
- `raven-zero-day-investigator` — runs first if the user suspects existing compromise; defend runs after.
- `raven-zero-day-fixing` — owns the patch-apply layer that Stage 3 stages.
- `pipeline/` — source-of-truth implementation of all MDASH stages
- `pipeline/d3fend/` — D3FEND + ATT&CK enrichment with real MITRE catalog data
- `pipeline/threat_intel/` — on-chain exposure scoring for prioritization
- `pipeline/feedback/` — retrospective feedback loop and approval gates
- `pipeline/eval/` — benchmark evaluation framework for measuring defense effectiveness
