# `raven/restore/` — D3FEND Restore Subsystem Specification

**Version:** 0.1 (draft for OpenAI Cybersecurity Grant proposal)
**Owner:** Daemon Blockint Technologies
**Status:** Proposed — closes the last open D3FEND tactic in Project Raven Defender Edition

---

## 1. Purpose and scope

Project Raven currently implements six of MITRE D3FEND v1.0's seven defensive tactics: Model, Harden, Detect, Isolate, Evict, and (in proposal) Deceive. The seventh — **Restore** — is the gap that prevents Raven from claiming complete defensive kill-chain coverage. This document specifies `raven/restore/`, a new subsystem that returns systems to a known-good state after a Detect → Isolate → Evict cycle. Restore is what turns Raven from a *containment* platform into a *recovery* platform, and it is the difference between "we stopped the attack" and "we are back online with verified integrity." The subsystem is grounded in the same Compositional Defense Pipeline (CDP) discipline as the rest of Raven: every LLM-proposed restore action must terminate at a deterministic tool oracle, a classical-ML verifier, or a scored hypothesis with explicit operator approval.

D3FEND tactic reference: [https://d3fend.mitre.org/tactic/d3f:Restore](https://d3fend.mitre.org/tactic/d3f:Restore/)

---

## 2. D3FEND technique coverage

| D3FEND ID | Technique Name | Raven Module | Status (v1) |
|---|---|---|---|
| D3-RC | Restore Configuration | `raven/restore/restore_configuration.py` | v1 |
| D3-RF | Restore File | `raven/restore/restore_file.py` | v1 |
| D3-RA | Restore Access | `raven/restore/restore_access.py` | v1 |
| D3-RD | Restore Database | `raven/restore/restore_database.py` | v1 |
| D3-RDI | Restore Disk Image | `raven/restore/restore_disk_image.py` | v1 |
| D3-RE | Restore Email | `raven/restore/restore_email.py` | v2 (deferred) |
| D3-RNA | Restore Network Access | `raven/restore/restore_network_access.py` | v1 |
| D3-RO | Restore Object | `raven/restore/restore_object.py` | v1 |
| D3-RS | Restore Software | `raven/restore/restore_software.py` | v1 |
| D3-RUAA | Restore User Account Access | `raven/restore/restore_user_account.py` | v1 |
| D3-ULA | Unlock Account | `raven/restore/unlock_account.py` | v1 |
| D3-RIC | Reissue Credential | `raven/restore/reissue_credential.py` | v1 |
| D3-CRO | Credential Rotation | `raven/restore/credential_rotation.py` | v1 |
| D3-CERO | Certificate Rotation | `raven/restore/certificate_rotation.py` | v1 |

The v2-deferred technique (D3-RE) is mailbox-specific and depends on connector availability — pushed to a later milestone to keep v1 scope tight.

---

## 3. Architecture

```
              ┌──────────────────────────────────────────────────────────┐
              │  raven/mitigation/response_orchestrator.py               │
              │  (Detect → Isolate → Evict → RESTORE)                    │
              └──────────────────────────────────────────────────────────┘
                                       │
                                       ▼
              ┌──────────────────────────────────────────────────────────┐
              │  raven/restore/orchestrator.py                           │
              │  selects RestoreAdapter(s) by D3FEND ID + artifact type  │
              └──────────────────────────────────────────────────────────┘
                                       │
        ┌──────────────────────────────┼──────────────────────────────┐
        ▼                              ▼                              ▼
 ┌──────────────────┐         ┌──────────────────┐           ┌──────────────────┐
 │ RestoreAdapter   │         │ RestoreAdapter   │           │ RestoreAdapter   │
 │ (D3-RC)          │   ...   │ (D3-RF)          │     ...   │ (D3-CRO)         │
 │ restore_config   │         │ restore_file     │           │ credential_rot   │
 └──────────────────┘         └──────────────────┘           └──────────────────┘
        │                              │                              │
        ▼                              ▼                              ▼
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │  PRE-CONDITIONS (must all pass before any write):                           │
 │  G1. Eviction confirmed by raven/mitigation/containment_actions.py          │
 │  G2. Snapshot/backup integrity verified by tool oracle (hash + signature)   │
 │  G3. CDP grounding: LLM plan references valid D3-R* ID + evidence trace     │
 │  G4. Approval gate (always manual mode for restore — no smart auto-approve) │
 │  G5. UNRECOVERABLE_BLOCKLIST check (no restore over a worse state)          │
 └─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │  POST-CONDITIONS (must all pass before marking complete):                    │
 │  P1. Integrity verifier (FIM / hash comparison) confirms restored state      │
 │  P2. Functional smoke test passes                                            │
 │  P3. Audit log entry written with actor, request ID, before/after hashes     │
 │  P4. Prometheus metrics updated (raven_restore_*)                            │
 │  P5. New baseline captured for raven/core/behavioral_profiler.py             │
 └─────────────────────────────────────────────────────────────────────────────┘
```

Every restore action is **two-phase**: dry-run plan → operator approval → execute. The dry-run plan emits a structured `RestorePlan` object that includes every file/object that will change, the source-of-truth snapshot reference, the integrity check method, and the rollback path *for the restore itself*. The plan is human-reviewable and is what the approval gate displays.

All restore adapters inherit from a single `RestoreAdapter` ABC parallel to `ToolAdapter`:

```python
class RestoreAdapter(ABC):
    d3fend_id: str            # e.g. "D3-RF"
    attack_techniques_remediated: list[str]  # e.g. ["T1486", "T1490"]
    requires_backup: bool
    requires_offline: bool

    @abstractmethod
    def dry_run(self, target, snapshot_ref) -> RestorePlan: ...

    @abstractmethod
    def verify_snapshot(self, snapshot_ref) -> SnapshotVerification: ...

    @abstractmethod
    def execute(self, plan: RestorePlan, approval_token: str) -> RestoreResult: ...

    @abstractmethod
    def post_verify(self, result: RestoreResult) -> IntegrityReport: ...

    @abstractmethod
    def rollback_restore(self, result: RestoreResult) -> RollbackResult: ...
```

---

## 4. Module-by-module specification

### 4.1 `raven/restore/restore_configuration.py` (D3-RC)

**Purpose.** Restore system, application, or service configuration from a verified known-good snapshot. Covers `/etc`, registry hives, Kubernetes ConfigMaps, Helm values, and application config databases.

**Inputs.** Target identifier (host + path or k8s resource), snapshot reference (git ref, etcd backup ID, S3 versioned object), scope filter (whole tree vs. specific keys).

**Outputs.** `RestorePlan` with diff between current and desired state; per-key change list with cryptographic hashes.

**Tool oracles.** `git`, `etcdctl`, `velero`, `helm rollback`, native config-management adapters. All snapshots are verified via SHA-256 + GPG/Sigstore signature before any read into Raven.

**CDP grounding.** LLM proposes which snapshot to restore from and which keys to restore; the proposal must reference a valid snapshot ID returned by `verify_snapshot()`. The grounding verifier rejects any plan that proposes restoring keys not present in the verified snapshot or that overlap with the active `UNRECOVERABLE_BLOCKLIST`.

**Counters ATT&CK.** T1562 (Impair Defenses), T1078 (Valid Accounts — config-based), T1547 (Boot or Logon Autostart), T1098 (Account Manipulation), T1556 (Modify Authentication Process).

**API.** `POST /restore/configuration` — operator role, requires approval-token header.

### 4.2 `raven/restore/restore_file.py` (D3-RF)

**Purpose.** Restore individual files or directory trees from FIM-monitored baselines or snapshot storage. The primary recovery path for ransomware (T1486), wipers (T1485), and modify-on-disk persistence.

**Inputs.** File path(s), snapshot reference, expected hash (from FIM), behavior selector (`replace` / `merge-preserving-newer` / `restore-permissions-only`).

**Outputs.** Per-file diff with before/after hashes, byte counts, ACL changes; warning when restore would clobber newer legitimate writes.

**Tool oracles.** ZFS snapshots, Btrfs snapshots, NTFS shadow copies, AWS S3 versioning, restic/Borg backups. Integrity verified via stored hash + tool-native checksum.

**CDP grounding.** LLM cannot propose a file restoration without a `FileIntegrityRecord` from `raven/core/threat_detector.py` confirming the file was modified by the incident under remediation. This binds restore actions to detected events — no speculative restores.

**Counters ATT&CK.** T1486 (Data Encrypted for Impact), T1485 (Data Destruction), T1490 (Inhibit System Recovery), T1565 (Data Manipulation), T1070 (Indicator Removal — file deletion).

### 4.3 `raven/restore/restore_access.py` (D3-RA)

**Purpose.** Re-grant legitimate access that was revoked during isolation/eviction once the incident is contained. Reverses temporary network/account/service-account suspensions written by `raven/mitigation/containment_actions.py`.

**Inputs.** ContainmentAction ID(s) to reverse, scope (per-user, per-service-account, per-CIDR).

**Outputs.** `RestoreAccessPlan` showing which IAM/firewall/DNS changes will be reverted, with explicit ordering.

**CDP grounding.** Every reversal must reference the original `ContainmentAction` audit-log entry. The verifier confirms the linked incident is in `status=contained` before allowing restore. Re-enabling access to an account that fired a credential-eviction event requires a separate fresh approval, not just inheritance.

**Counters ATT&CK.** Restoration after T1531 (Account Access Removal) caused by either attacker or by Raven's own containment.

### 4.4 `raven/restore/restore_database.py` (D3-RD)

**Purpose.** Point-in-time restore for relational and key-value databases.

**Inputs.** Database connection, target PITR timestamp (must be *before* the earliest indicator-of-compromise timestamp by ≥ N minutes), table scope (full vs. selective).

**Outputs.** Restore plan with estimated downtime, replication impact, schema-drift warnings.

**Tool oracles.** PostgreSQL WAL replay, MySQL binlog point-in-time, MongoDB oplog replay, S3 versioned object replay for object stores, native cloud-provider PITR APIs (RDS, Cloud SQL, Aurora).

**CDP grounding.** The proposed PITR timestamp must be validated against `raven/audit/store.py` IOC timeline — restore target must precede earliest IOC. LLM cannot select an arbitrary timestamp.

**Counters ATT&CK.** T1486 (Data Encrypted), T1565 (Data Manipulation), T1490 (Inhibit System Recovery), T1565.001 (Stored Data Manipulation).

### 4.5 `raven/restore/restore_disk_image.py` (D3-RDI)

**Purpose.** Whole-disk or whole-volume image restore. Last-resort recovery for compromised hosts where partial restore is insufficient (bootkits, firmware persistence, rootkits).

**Inputs.** Host identifier, image reference (versioned S3 / iSCSI snapshot / cloud disk snapshot), boot order policy, network re-attachment policy.

**Outputs.** Plan that includes detach-network → image-write → integrity-verify → re-attach-isolated → smoke-test → re-attach-prod sequence.

**Tool oracles.** Cloud-provider disk snapshot APIs (EBS, GCP PD, Azure Managed Disks), `dd` over verified iSCSI for on-prem, TPM-attested boot integrity verification.

**CDP grounding.** Must reference forensic acquisition record from `raven/tools/volatility_analyzer.py` or equivalent. Plan cannot propose imaging a host whose forensic capture is incomplete — host stays isolated until forensics finishes.

**Counters ATT&CK.** T1542 (Pre-OS Boot — bootkit), T1014 (Rootkit), T1495 (Firmware Corruption), T1601 (Modify System Image).

### 4.6 `raven/restore/restore_network_access.py` (D3-RNA)

**Purpose.** Restore network connectivity for hosts or subnets after isolation. Reverses `raven/mitigation/containment_actions.py` network actions.

**Inputs.** ContainmentAction ID(s), staged restore policy (DMZ first, then internal), required health checks before each stage.

**Outputs.** Staged plan with per-stage health-gate conditions.

**CDP grounding.** Each stage's health-gate is a tool-oracle assertion (Nmap clean, no IOC traffic from `raven/tools/projectdiscovery.py` interactsh callbacks, no anomaly from `raven/core/anomaly_detector.py` in last N minutes). Stage advance is gated on oracle output, not LLM judgment.

**Counters ATT&CK.** Restoration after T1531 / T1485 / containment actions.

### 4.7 `raven/restore/restore_object.py` (D3-RO)

**Purpose.** Generic object restore for things that don't fit other adapters — registry keys, scheduled tasks, systemd units, cron entries, browser extensions, kernel modules, Windows services.

**Inputs.** Object type, object identifier, snapshot reference.

**Outputs.** Type-specific restore plan with platform-appropriate verification (e.g., registry export hash for Windows).

**CDP grounding.** LLM must select the correct adapter sub-handler; the verifier validates that the object-type handler exists and that the platform supports the requested object operation.

**Counters ATT&CK.** T1547 (Boot/Logon Autostart), T1053 (Scheduled Task/Job), T1543 (Create or Modify System Process), T1112 (Modify Registry), T1176 (Browser Extensions), T1547.006 (Kernel Modules and Extensions).

### 4.8 `raven/restore/restore_software.py` (D3-RS)

**Purpose.** Restore a known-good version of a software package, container image, or binary. The reverse of "attacker dropped a backdoored update."

**Inputs.** Package identifier, target version, supply-chain attestation requirements (SLSA level, Sigstore signature, SBOM availability).

**Outputs.** Plan with package source verification, signature-check evidence, and post-install behavioral baseline reset.

**Tool oracles.** OS package managers (`apt`, `dnf`, `apk`), container registries with signed manifests, language package managers with lockfiles, Sigstore `cosign verify`, in-toto attestation verification.

**CDP grounding.** Restore target version must have a verified attestation chain. LLM cannot propose installing an unsigned or unverified version even if it is "the previous version" — silent supply-chain compromises must not be repeated by the restore step.

**Counters ATT&CK.** T1195 (Supply Chain Compromise), T1574 (Hijack Execution Flow), T1554 (Compromise Host Software Binary), T1495 (Firmware Corruption).

### 4.9 `raven/restore/restore_user_account.py` (D3-RUAA)

**Purpose.** Restore user-account state — group memberships, permissions, MFA enrollment, recovery factors — to a known-good profile after compromise.

**Inputs.** Account identifier, profile snapshot reference (HRIS-sourced ground truth preferred), reset scope.

**Outputs.** Plan showing role/group/permission/MFA diffs.

**Tool oracles.** Cloud IAM APIs (AWS IAM, Entra ID, Okta, Google Workspace), LDAP/Active Directory, HRIS connector for ground-truth role assignment.

**CDP grounding.** Profile snapshot must originate from a *separate trust domain* than the compromised account's home directory (e.g., HRIS, not local AD). LLM cannot propose restoring from a snapshot that exists only inside the breach blast radius.

**Counters ATT&CK.** T1098 (Account Manipulation), T1136 (Create Account), T1078 (Valid Accounts).

### 4.10 `raven/restore/unlock_account.py` (D3-ULA)

**Purpose.** Targeted lift of account locks set by `raven/mitigation/containment_actions.py` after attacker eviction is confirmed.

**CDP grounding.** Requires linked eviction confirmation and step-up authentication of the operator approving.

**Counters ATT&CK.** Restoration after T1531.

### 4.11 `raven/restore/reissue_credential.py` (D3-RIC)

**Purpose.** Issue fresh credentials for accounts whose credentials were compromised. Distinct from rotation in that the previous credential is *immediately* revoked, not gracefully retired.

**Tool oracles.** AWS STS, GCP service-account keys, GitHub PAT API, Hashicorp Vault, Azure Key Vault.

**CDP grounding.** Must reference a credential-eviction event from `raven/mitigation/`. Cannot reissue without a documented compromise — prevents over-rotation churn.

**Counters ATT&CK.** T1552 (Unsecured Credentials), T1555 (Credentials from Password Stores), T1003 (OS Credential Dumping), T1558 (Steal or Forge Kerberos Tickets).

### 4.12 `raven/restore/credential_rotation.py` (D3-CRO)

**Purpose.** Scheduled or event-triggered credential rotation. Less urgent than reissue; covers routine hygiene.

**Schedules.** Configurable per credential type (e.g., service-account 30d, machine identity 7d, break-glass 24h after use).

**CDP grounding.** Schedules are policy-bound; LLM can propose accelerated rotation in response to risk signal but cannot defer rotation beyond policy.

**Counters ATT&CK.** Preemptive against T1078 (Valid Accounts).

### 4.13 `raven/restore/certificate_rotation.py` (D3-CERO)

**Purpose.** Certificate lifecycle management — issue, rotate, revoke. Wraps ACME (Let's Encrypt, internal ACME), private CA APIs, mTLS cert distribution.

**CDP grounding.** Rotations during incident must invalidate cached certs in `raven/tools/ssh_manager.py` known_hosts and trigger fresh TOFU validation. LLM cannot propose certificate operations without verified CA reachability.

**Counters ATT&CK.** T1553 (Subvert Trust Controls), T1587.003 (Develop Capabilities: Digital Certificates), T1588.004 (Obtain Capabilities: Digital Certificates).

---

## 5. CDP grounding for restore actions

Restore is the most dangerous tactic in D3FEND — done wrong, it overwrites legitimate state, undoes forensic evidence, or reintroduces the very vulnerability the attacker exploited. CDP grounding is therefore *stricter* here than for Detect or Isolate. Three rules are non-negotiable:

1. **No restore without confirmed eviction.** Every `RestoreAdapter.execute()` call requires an `eviction_confirmation_token` issued by `raven/mitigation/response_orchestrator.py` after the relevant `D3-PT` / `D3-FEV` / `D3-CE` / `D3-OE` action returned success and a new baseline-clean detection sweep passed. The grounding verifier inspects the token's signature and the linked audit-log chain.

2. **No restore from in-blast-radius snapshots.** Every snapshot reference must pass `verify_snapshot()`, which checks (a) cryptographic signature, (b) provenance metadata showing the snapshot pre-dates the earliest IOC, and (c) storage location outside the compromised blast radius. The verifier rejects any plan whose snapshot was written from a host or account that appears in the incident timeline.

3. **Approval gate locked to `manual` mode.** Smart auto-approval is disabled for the entire `/restore/*` route namespace. Operators must explicitly approve each restore plan after reviewing the dry-run diff. This is enforced at `raven/approval/gate.py` via a route-level policy override.

In addition, every emitted plan carries a structured `evidence_trace`:

```json
{
  "d3fend_id": "D3-RF",
  "attack_techniques_remediated": ["T1486"],
  "supporting_evidence": [
    {"source": "tool", "name": "yara_scan", "finding_id": "f-9a3c2"},
    {"source": "ml",   "name": "zero_day_detector", "verdict_id": "v-7b21d"},
    {"source": "audit", "ref": "incident-2026-05-14-007"}
  ],
  "snapshot_ref": "s3://raven-backups/host-42/2026-05-14T03:00:00Z",
  "snapshot_signature": "sigstore:...",
  "eviction_confirmation_token": "evct-..."
}
```

The grounding verifier (`raven/cdp/verifier.py`) rejects any plan missing any of these fields.

---

## 6. Telemetry and alerting

New Prometheus metrics, namespaced under `raven_restore_`:

| Metric | Type | Labels | Purpose |
|---|---|---|---|
| `raven_restore_plans_total` | Counter | `d3fend_id`, `status{generated,approved,rejected}` | Plan throughput |
| `raven_restore_executed_total` | Counter | `d3fend_id`, `outcome{success,failure,rolled_back}` | Execution success rate |
| `raven_restore_duration_seconds` | Histogram | `d3fend_id` | Wall-clock recovery time |
| `raven_restore_snapshot_age_seconds` | Histogram | `d3fend_id` | Freshness of restore source |
| `raven_restore_blast_radius_violations_total` | Counter | `d3fend_id`, `reason` | CRITICAL — incidents where verifier rejected an in-blast-radius snapshot |
| `raven_restore_rollback_total` | Counter | `d3fend_id`, `trigger` | How often we had to undo a restore |
| `raven_restore_post_verify_failures_total` | Counter | `d3fend_id` | Integrity-check failures after restore |

The `blast_radius_violations_total` metric is alert-worthy on first occurrence — it indicates either a bad LLM plan (training data signal) or a compromised snapshot store (incident).

The orchestrator emits structured events (`event=restore.plan.generated`, `event=restore.executed`, `event=restore.post_verify.failed`) to `raven/audit/store.py` so the full lifecycle is queryable through `/audit/log`.

---

## 7. Threat model

**Adversary capabilities considered.**

| # | Threat | Mitigation |
|---|---|---|
| T1 | Attacker poisons the snapshot store before initial compromise so that "clean" backups are already backdoored | `verify_snapshot()` requires signature chain rooted in offline-CA; snapshot store is in separate trust domain; provenance metadata checked against IOC timeline |
| T2 | Attacker compromises the Raven admin and triggers a restore that overwrites forensic evidence | Approval gate locked to manual; UNRECOVERABLE_BLOCKLIST includes "restore over un-acquired forensic image"; forensics-first lock-step with `raven/tools/volatility_analyzer.py` |
| T3 | LLM hallucinates a restore plan that targets the wrong host or wrong file scope | Dry-run plan diff is mandatory; CDP verifier checks every target appears in the linked incident's artifact set |
| T4 | Race condition: restore runs while attacker still present | `eviction_confirmation_token` lifetime ≤ 5 min; fresh detection sweep required before token issued; post-restore re-detection sweep mandatory |
| T5 | Restore re-introduces the vulnerability that was exploited | Coupled with `raven/mitigation/remediation_engine.py` — patch must apply before restore for the relevant CVE, enforced by orchestrator policy |
| T6 | Credential reissue creates a privilege creep (new credential has more rights than old) | Profile snapshot ground-truth from HRIS, not local AD; diff displayed in approval gate |
| T7 | Snapshot decryption key compromised | Snapshot encryption keys held in HSM separate from Raven; rotation cadence ≤ 90d; `verify_snapshot()` records key-version used |
| T8 | Restore action audit log itself is tampered | Audit log entries Merkle-chained and periodically anchored to external transparency log (Sigstore Rekor or equivalent) |

---

## 8. Evaluation plan

To match the empirical standard set by Anthropic's Cybergym ([red.anthropic.com](https://red.anthropic.com/2025/ai-for-cyber-defenders/)) and Xint Code's "no human guided the scan" methodology, restore performance is measured against four explicit scenarios:

1. **Ransomware recovery scenario.** Detonate a benchmark ransomware sample (e.g., from MITRE Caldera or a synthetic encryptor) in an isolated VM with FIM and snapshot enabled. Measure: time-to-restore, files correctly restored, files missed, post-restore integrity check pass rate. Compare against manual restore by an SRE.
2. **Supply-chain rollback scenario.** Plant a backdoored container image, detect via behavioral anomaly, evict, restore from prior signed version. Measure: detection-to-restore wall-clock, attestation chain completeness, false-positive blast-radius rejections.
3. **Account compromise scenario.** Simulated credential theft → containment → restore. Measure: time-to-reissue, privilege correctness post-restore (diff against HRIS ground truth), follow-on access attempts blocked.
4. **Destructive wiper scenario.** Wiper detonates against a database; PITR restore + post-verify. Measure: data loss in seconds, integrity check, downstream replica reseed correctness.

For each scenario, publish:
- Trial count (1, 10, 30) following Anthropic's Cybergym methodology.
- Per-trial wall-clock, cost (LLM tokens consumed), and human-intervention count.
- D3FEND coverage delta: which D3-R* techniques exercised per trial.

Target initial numbers (to be confirmed):
- Ransomware recovery: median wall-clock under 8 minutes (vs ~45 min manual baseline).
- Blast-radius rejection rate: 0 false rejects on a curated 100-snapshot test set.
- Post-restore integrity check: ≥ 99.5% on benchmark.

Datasets and scripts published in `bench/restore/` alongside the existing CDP benchmarks. CI gate: a regression test that runs scenario 1 on every PR touching `raven/restore/`.

---

## 9. Integration with OpenAI Cybersecurity Grant focus areas

The OpenAI Cybersecurity Grant Program ([openai.com](https://openai.com/index/openai-cybersecurity-grant-program/)) lists multiple focus areas that the Restore subsystem directly satisfies:

- **"Automatically patch vulnerabilities"** — Restore is the inverse: revert to a state where the vulnerability has been patched. Coupled with `remediation_engine.py`, this is patch-and-recover as one workflow.
- **"Optimize patch management processes to improve prioritization, scheduling, and deployment of security updates"** — `D3-CRO` and `D3-CERO` schedulers are exactly this.
- **"Automate incident triage"** — Restore is the final triage step that closes incidents; without it, Raven is open-ended.
- **"Aid security engineers and developers to create robust threat models"** — Section 7 above is a publishable threat-model artifact.

The subsystem is MIT-licensed in line with the rest of Raven Defender Edition and is intended to be the *first* open-source autonomous restore system grounded in D3FEND's formal ontology.

---

## 10. Roadmap

| Quarter | Milestone |
|---|---|
| **Q1** | `RestoreAdapter` ABC + `restore_file.py` (D3-RF) + `restore_configuration.py` (D3-RC) + Prometheus metrics + dry-run/approval flow. Bench scenario 1 (ransomware) shipped. |
| **Q2** | `restore_access.py` (D3-RA) + `restore_network_access.py` (D3-RNA) + `unlock_account.py` (D3-ULA) + `restore_user_account.py` (D3-RUAA). Integration with `mitigation/response_orchestrator.py`. |
| **Q3** | `restore_database.py` (D3-RD) + `restore_disk_image.py` (D3-RDI) + `restore_software.py` (D3-RS) with SLSA attestation. Bench scenarios 2 and 4. |
| **Q4** | `reissue_credential.py` (D3-RIC) + `credential_rotation.py` (D3-CRO) + `certificate_rotation.py` (D3-CERO) + `restore_object.py` (D3-RO). Bench scenario 3. Publication of evaluation paper. D3-RE deferred to v2. |

Each quarter milestone is gated on (a) D3FEND coverage matrix updated, (b) bench scenario added, (c) CI regression test added.

---

## 11. Open questions for reviewers

1. **Forensic-first vs recovery-first.** Should `restore_disk_image.py` block on forensic acquisition even when business pressure demands immediate recovery? Current spec says yes; some SOCs may disagree. Proposed: configurable per-environment with `manual` approval override but never `smart` auto-approve.
2. **Cross-cloud snapshot trust.** When the Raven control plane runs in cloud A and snapshots are in cloud B, how is the trust root established for `verify_snapshot()`? Possible answer: customer-managed Sigstore key + external transparency log anchor. Needs design.
3. **Restore vs rebuild.** For some attack classes (firmware compromise, deep persistence), restore from snapshot is insufficient — only a clean rebuild from upstream image is safe. Should `restore_disk_image.py` detect this case and refuse, or delegate to a future `raven/rebuild/` subsystem? Current spec defers to operator judgment via dry-run plan annotation.
4. **Approval-gate fatigue.** Manual approval on every restore is correct for high-stakes; routine credential rotation is not high-stakes. Proposal: D3-CRO and D3-CERO routine rotations are `smart`-approvable when within policy schedule; everything else `manual`-only.
5. **Tinker training signal.** Should successful restore plans become SFT training data for the next LoRA cycle? Concern: amplifies any one organization's restore patterns into the model. Proposed: opt-in per-tenant; defaults to off.

---

## See also

- D3FEND Restore tactic — [https://d3fend.mitre.org/tactic/d3f:Restore](https://d3fend.mitre.org/tactic/d3f:Restore/)
- CISA Secure-by-Design — [Shifting the Balance of Cybersecurity Risk](https://www.cisa.gov/resources-tools/resources/secure-by-design)
- CDP methodology — `docs/methodology.md`
- Decoy subsystem spec — `docs/decoy-subsystem-spec.md`
- D3FEND coverage matrix — `docs/d3fend-coverage.md`
