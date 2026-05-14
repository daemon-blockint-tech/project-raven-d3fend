# raven/decoy/ — D3FEND Deceive Subsystem Specification

**Version:** 0.1 (draft for OpenAI Cybersecurity Grant proposal)  
**Status:** Draft  
**Authors:** Raven Defender Edition Engineering  
**Date:** 2025-07

---

## 1. Purpose & Scope

The `raven/decoy/` subsystem implements the **Deceive** tactic from the MITRE D3FEND™ v1.0 knowledge graph ([D3FEND Deceive tactic](https://d3fend.mitre.org/tactic/d3f:Deceive)), extending Raven Defender Edition from a purely reactive detection posture into an active deception layer that degrades attacker confidence, increases attacker dwell cost, and produces high-fidelity compromise signals. Where Raven's existing `raven/core/threat_detector.py` fanout and `raven/hunters/` modules identify and investigate attacker activity after it begins, deception operates earlier and continuously: synthetic artifacts are seeded throughout the defended environment so that any attacker who reaches them — file access, credential use, network probe, or persona contact — generates an alert with a near-zero false-positive rate by construction. The subsystem generates decoy content via the project's multi-provider LLM backend, grounds every LLM emission through the Compositional Defense Pipeline (CDP), enforces operator approval via `raven/approval/gate.py`, and writes a complete lifecycle record to the audit store at `raven/audit/store.py`. All decoy classes inherit from a single `DecoyAdapter` abstract base class, parallel in design to `raven/tools/adapter_base.py` (`ToolAdapter`), so that existing Prometheus instrumentation, approval gate wiring, and audit log conventions extend naturally to the new subsystem.

---

## 2. D3FEND Technique Coverage

| D3FEND ID | Technique | Raven Module | Status (v1) |
|-----------|-----------|--------------|-------------|
| D3-DF | Decoy File | `raven/decoy/decoy_file.py` | v1 |
| D3-DO | Decoy Object | `raven/decoy/decoy_object.py` | v1 |
| D3-DP | Decoy Persona | `raven/decoy/decoy_persona.py` | v1 |
| D3-DNR | Decoy Network Resource | `raven/decoy/decoy_network_resource.py` | v1 |
| D3-DUC | Decoy User Credential | `raven/decoy/decoy_credential.py` | v1 |
| D3-DST | Decoy Session Token | `raven/decoy/decoy_session_token.py` | v1 |
| D3-DPR | Decoy Public Release | `raven/decoy/decoy_public_release.py` | v1 |
| D3-DE | Decoy Environment | `raven/decoy/decoy_environment.py` | v1 |
| D3-CHN | Connected Honeynet | `raven/decoy/honeynet.py` (mode=connected) | v1 |
| D3-SHN | Standalone Honeynet | `raven/decoy/honeynet.py` (mode=standalone) | v1 |
| D3-IHN | Integrated Honeynet | `raven/decoy/honeynet.py` (mode=integrated) | v1 |

---

## 3. Architecture

### 3.1 Component Diagram (ASCII)

```
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                         raven/decoy/ subsystem                              │
 │                                                                             │
 │  Operator Request                                                           │
 │      │                                                                      │
 │      ▼                                                                      │
 │  ┌──────────────────┐     ┌────────────────────────────────────────────┐   │
 │  │  DecoyAdapter    │────▶│  CDP Grounding Verifier                    │   │
 │  │  .generate()     │     │  ① Realism classifier 𝓜 ≥ threshold       │   │
 │  │  (LLM emission)  │     │  ② Content-safety oracle 𝒯 (no real PII)  │   │
 │  └──────────────────┘     │  ③ D3FEND OWL ontology ID validation       │   │
 │                           │  ④ approval/gate.py  (G4, operator role)   │   │
 │                           └───────────────────────┬────────────────────┘   │
 │                                                   │ approved                │
 │                                                   ▼                        │
 │  ┌──────────────────┐     ┌────────────────────────────────────────────┐   │
 │  │  DecoyAdapter    │◀────│  Decoy Deployer                            │   │
 │  │  .deploy()       │     │  Places artifact in target system/net/env  │   │
 │  └──────┬───────────┘     └────────────────────────────────────────────┘   │
 │         │                                                                   │
 │         ▼                                                                   │
 │  ┌──────────────────┐     ┌────────────────────────────────────────────┐   │
 │  │  DecoyAdapter    │────▶│  core/threat_detector.py                   │   │
 │  │  .monitor()      │     │  (fanout to anomaly + behavioral + ML)     │   │
 │  └──────┬───────────┘     └───────────────────────┬────────────────────┘   │
 │         │ trigger event                            │ correlated signal      │
 │         ▼                                         ▼                        │
 │  ┌──────────────────┐     ┌────────────────────────────────────────────┐   │
 │  │  DecoyAdapter    │────▶│  audit/store.py   (lifecycle record)       │   │
 │  │  .trigger_handler│     │  generated → deployed → triggered →        │   │
 │  └──────────────────┘     │  retired                                   │   │
 │                           └───────────────────────┬────────────────────┘   │
 │                                                   │                        │
 │                                                   ▼                        │
 │                           ┌────────────────────────────────────────────┐   │
 │                           │  SOC Alert  →  POST /alerts                │   │
 │                           │  Prometheus metrics update                 │   │
 │                           └────────────────────────────────────────────┘   │
 └─────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 `DecoyAdapter` Abstract Base Class

All decoy modules subclass `DecoyAdapter`, defined in `raven/decoy/adapter.py`, mirroring the interface contract of `raven/tools/adapter_base.py`:

```python
# raven/decoy/adapter.py
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional
from datetime import datetime

@dataclass
class DecoyMetadata:
    d3fend_id: str          # e.g. "D3-DF"
    decoy_id: str           # UUID
    created_at: datetime
    deployed_at: Optional[datetime] = None
    triggered_at: Optional[datetime] = None
    retired_at: Optional[datetime] = None
    realism_score: float = 0.0
    operator_approved_by: Optional[str] = None

class DecoyAdapter(ABC):
    """Base class for all D3FEND Deceive technique implementations."""

    @abstractmethod
    async def generate(self, **kwargs) -> Any:
        """LLM-generated decoy content; must pass CDP grounding before deploy()."""

    @abstractmethod
    async def deploy(self, artifact: Any) -> DecoyMetadata:
        """Place the decoy in the target environment. Requires gate approval."""

    @abstractmethod
    async def monitor(self) -> None:
        """Start watch loop; emits events to threat_detector.py on interaction."""

    @abstractmethod
    async def trigger_handler(self, event: dict) -> None:
        """Called when decoy interaction is detected; fires SOC alert + audit entry."""

    @abstractmethod
    def is_active(self) -> bool:
        """Return True if the decoy is currently deployed and monitored."""

    @property
    @abstractmethod
    def decoy_metadata(self) -> DecoyMetadata:
        """Return current DecoyMetadata snapshot."""
```

### 3.3 CDP Grounding Constraints

The Compositional Defense Pipeline rule — *every LLM emission must terminate at a tool oracle, classical-ML detector, or scored hypothesis* — applies to decoy generation as a four-gate pipeline:

1. **𝓜 (Realism classifier):** A fine-tuned binary classifier (see §5) scores generated content for how convincingly it mimics the target artifact type. Deployment is blocked if score < configurable threshold (default: 0.80).
2. **𝒯 (Content-safety oracle):** A deterministic scanner (`raven/ml/vulnerability_validator.py`-style) confirms the generated artifact contains no real credentials, PII, or leaked training data.
3. **G4 (Approval gate):** `raven/approval/gate.py` in `manual` mode (operator role required) before any `deploy()` call is executed. The `UNRECOVERABLE_BLOCKLIST` in `raven/approval/patterns.py` is extended with decoy-specific patterns: no destructive payloads, no impersonation of real users without written consent, no live credentials.
4. **D3FEND OWL validator:** The `d3fend_id` field is validated against a locally cached import of the D3FEND OWL ontology; unknown or deprecated IDs are rejected.

---

## 4. Module-by-Module Specification

### 4.1 `raven/decoy/decoy_file.py` — D3-DF: Decoy File

**Purpose.** Generate and deploy synthetic files that mimic high-value documents (SSH private keys, `.env` secrets, database dumps, source code with hardcoded tokens) in directories that legitimate processes have no reason to access. Any filesystem interaction with these files is a high-confidence attacker signal with near-zero false-positive rate.

**Inputs.**
- `sensitive_type`: enum — `ssh_key | env_file | db_dump | source_code | certificate | password_file`
- `target_directory`: absolute path (operator-supplied; validated against allowed-directory allowlist)
- `attractiveness_profile`: dict specifying filename conventions, modification timestamps, apparent file owner, and size envelope to maximize decoy credibility
- `tripwire_backend`: enum — `ebpf | inotify` (default: `ebpf` on Linux kernels ≥ 5.8)

**Outputs.** A `DecoyFile` dataclass containing:
- `content: bytes` — LLM-generated plausible file content
- `sha256_hash: str` — integrity anchor stored in audit log
- `tripwire_path: str` — filesystem path being watched
- `decoy_metadata: DecoyMetadata` — lifecycle record

**Tripwire mechanism.** On `deploy()`, the module registers a watch with `raven/core/threat_detector.py` via an internal event bus. In eBPF mode, a BPF program attached to `open(2)` / `openat(2)` syscalls watches the inode; access events are passed to the threat detector's fanout pipeline. In inotify fallback mode, a `inotify_add_watch(IN_ACCESS | IN_OPEN | IN_READ)` watch is established. Any access not attributable to the deploying operator's UID fires `trigger_handler()`.

**CDP grounding.** The LLM generates file content conditioned on `sensitive_type` and `attractiveness_profile`. Before deployment: (a) realism classifier 𝓜 checks that generated SSH key PEM headers, ENV variable names, or DB dump schema follow authentic format distributions; (b) content-safety oracle 𝒯 runs `vulnerability_validator.py`-style static analysis to confirm the generated content contains no real private keys, real credentials, or recognizable PII from training data; (c) gate approval is obtained.

**API endpoint.**
```
POST /decoy/file
Authorization: Bearer <operator-token>   (role: operator)
{
  "sensitive_type": "env_file",
  "target_directory": "/srv/app",
  "attractiveness_profile": { "filename": ".env.prod", "owner": "deploy", "mtime_days_ago": 14 },
  "tripwire_backend": "ebpf"
}
→ 202 Accepted  { "decoy_id": "<uuid>", "status": "pending_approval" }
```

---

### 4.2 `raven/decoy/decoy_object.py` — D3-DO: Decoy Object

**Purpose.** Deploy synthetic high-value objects in non-filesystem stores: Windows registry keys that mimic credential caches or LSA secrets, cloud resource ARNs (S3 bucket names, RDS endpoint strings, KMS key IDs), and database rows shaped like privileged account records or payment data. Attacker reconnaissance or access to any decoy object fires an alert.

**Inputs.**
- `object_type`: enum — `registry_key | cloud_resource | db_row | cloud_storage_path | secrets_manager_entry`
- `backend_config`: connection parameters for the target store (registry path, AWS account/region, DB DSN)
- `attractiveness_profile`: naming convention, apparent sensitivity level, access pattern hints

**Outputs.** A `DecoyObject` dataclass with `object_ref` (URI or registry path), `object_type`, `content_fingerprint`, `watch_handle`, and `decoy_metadata`.

**Implementation notes.** For cloud objects, the module wraps `raven/tools/adapter_base.py`-style tool calls to AWS SDK / GCP SDK via the existing `mcp_registry.py` MCP integration. Registry keys are managed via `raven/tools/bash_executor.py` with `shell=False`. Database rows are inserted via parameterized queries only. Watch mechanisms are backend-specific: CloudTrail data events for S3, AWS Config rules for IAM/KMS, SQL triggers for DB rows. All backend credentials must be operator-approved secrets; the UNRECOVERABLE_BLOCKLIST blocks deployment to production namespaces without explicit override.

**CDP grounding.** LLM generates object names and content shaped to match the naming conventions of real objects in the target environment (e.g., `arn:aws:s3:::company-backup-2024-prod-archive`). Realism classifier 𝓜 is trained on a corpus of real resource naming patterns per cloud provider. Content-safety oracle 𝒯 validates that no real ARNs, real account IDs, or real resource names are embedded.

**API endpoint.** `POST /decoy/object` (operator role).

---

### 4.3 `raven/decoy/decoy_persona.py` — D3-DP: Decoy Persona

**Purpose.** Construct and operate synthetic digital identities — LinkedIn-style professional profiles, GitHub accounts with commit history, email addresses — deployed in adversary-facing channels to detect social-engineering reconnaissance, spear-phishing targeting, or insider-threat behavioral patterns.

**Inputs.**
- `persona_template`: dict specifying industry, seniority level, apparent technical role, geographic region, and social graph density
- `platform_targets`: list — `github | linkedin_style | email | slack_workspace`
- `legend_depth`: enum — `shallow (profile only) | medium (+ activity history) | deep (+ cross-platform consistency)`

**Outputs.** A `DecoyPersona` dataclass with generated biography, avatar seed, synthetic work history, platform handles, and contact endpoints wired to `trigger_handler()`.

**Ethical guardrails — critical.** This module enforces the strictest UNRECOVERABLE_BLOCKLIST checks in the subsystem:
1. **Real-name collision check:** Before finalizing any persona, the generated name is queried against an internal registry of real employees, contractors, and public figures. Any collision is a hard block — not a soft warning.
2. **No real-person impersonation:** The CDP content-safety oracle 𝒯 runs identity-uniqueness validation; the persona biography must not describe a real person's actual employment history, education, or publications.
3. **Consent record:** Deployment requires a written consent artifact stored in `audit/store.py` attesting that no real identities are being impersonated and that the deploying organization has legal authority to operate synthetic accounts on each target platform.
4. **Platform ToS compliance flag:** Operator must explicitly acknowledge platform terms-of-service implications per platform before deployment proceeds.

**Trigger mechanism.** Any inbound contact to persona endpoints (email opens tracked via pixel, GitHub profile visits via server-side analytics, credential use) fires `trigger_handler()` with the originating IP, timestamp, and interaction type.

**CDP grounding.** LLM generates biography and commit messages. Realism classifier 𝓜 is a fine-tuned model on authentic professional profile corpora. Gate approval is mandatory (no smart-approve path for personas).

**API endpoint.** `POST /decoy/persona` (operator role; additional `legal_acknowledgment` field required).

---

### 4.4 `raven/decoy/decoy_network_resource.py` — D3-DNR: Decoy Network Resource

**Purpose.** Expose synthetic network services — SMB/NFS shares, FTP servers, Telnet listeners, fake database endpoints (MySQL wire protocol), fake LDAP servers — on the internal network or DMZ. Any connection attempt to these services is an attacker signal; they serve no legitimate business function.

**Inputs.**
- `service_type`: enum — `smb_share | nfs_share | ftp | telnet | mysql_listener | ldap | http_admin_panel`
- `bind_address`: IP/interface on which to listen (must be on decoy VLAN or explicitly approved network segment)
- `banner_profile`: dict for service banner generation (OS version, software version, share name list)
- `interaction_depth`: enum — `banner_only | auth_capture | partial_session` (deep interaction logs credentials attempted)

**Outputs.** A `DecoyNetworkResource` dataclass with `service_endpoint`, `interaction_log_path`, `decoy_metadata`.

**Implementation notes.** Services are launched as isolated containers (Docker via subprocess through `bash_executor.py`) or via `python3 -m` protocol emulators. The SMB decoy uses Impacket's `smbserver.py` in read-only, no-auth-success mode. MySQL uses a custom wire-protocol listener that captures the client handshake and immediately resets the connection. All captured authentication attempts (usernames, password hashes) are passed to `threat_detector.py` as attacker IOCs. The `nmap_scanner.py` module is used post-deployment for operator-visible verification that the service appears authentic from external vantage.

**CDP grounding.** Banners are LLM-generated to match the target environment's technology stack. Realism classifier 𝓜 validates banner text against known-good Shodan-sourced banner corpora. No real service credentials are used in banner generation.

**API endpoint.** `POST /decoy/network-resource` (operator role).

---

### 4.5 `raven/decoy/decoy_credential.py` — D3-DUC: Decoy User Credential

**Purpose.** Generate and deploy canary credentials — AWS access key pairs, GitHub Personal Access Tokens, Azure SAS tokens, SSH keypairs, database password strings — that are syntactically valid and format-correct but are either pre-revoked or connected to a monitoring-only IAM role with zero permissions and full CloudTrail/audit logging. Any use of a canary credential is an unambiguous attacker signal.

**Inputs.**
- `credential_type`: enum — `aws_access_key | github_pat | azure_sas | ssh_keypair | db_password | k8s_service_account_token`
- `placement_targets`: list of locations where the credential is seeded (config files, environment variable blocks, credential managers, code comments)
- `backend_config`: cloud account / git org config for actual key registration (where applicable)
- `canarytoken_integration`: bool — if True, also registers with Thinkst Canary / canarytokens.org webhook for out-of-band alerting

**Outputs.** A `DecoyCredential` dataclass with `credential_string`, `placement_map`, `revocation_handle`, `webhook_url` (if Thinkst), `decoy_metadata`.

**Implementation notes.** For AWS: real IAM users are created with a deny-all policy and `cloudtrail:LookupEvents` enabled on the decoy account; any `AssumeRole`, `GetCallerIdentity`, or API call fires an EventBridge rule that calls `trigger_handler()`. For GitHub PATs: tokens are generated with `public_repo:read` scope only, pointing to a canary monitoring repo; any API call using the token is captured. For SSH keypairs: the public key is deployed; `sshd` is configured with `ForceCommand` for that key to log and immediately disconnect. The Thinkst Canary integration uses their REST API via `bash_executor.py` to register tokens and receive HTTP callbacks.

**CDP grounding.** Credential strings are generated to match authentic format patterns (AWS AKIA prefix, 40-character alphanumeric; GitHub ghp_ prefix). The content-safety oracle 𝒯 performs a format-equivalence check — the string must match the provider's regex exactly. No real account credentials are used as generation seeds.

**API endpoint.** `POST /decoy/credential` (operator role).

---

### 4.6 `raven/decoy/decoy_session_token.py` — D3-DST: Decoy Session Token

**Purpose.** Generate and plant synthetic browser session cookies, OAuth 2.0 access tokens, JWT tokens, and SAML assertions in locations an attacker conducting lateral movement or session hijacking is likely to harvest: browser profile directories, memory dumps, intercepted HTTP traffic captures, and credential-store exports. Any backend validation attempt against a planted token fires an alert.

**Inputs.**
- `token_type`: enum — `session_cookie | oauth_access_token | jwt | saml_assertion | api_key_header`
- `placement_context`: enum — `browser_profile | memory_region | config_file | http_capture | credential_store`
- `issuer_profile`: dict — mimicked domain, apparent token issuer, expiry window, scopes/claims
- `backend_validator_url`: internal endpoint that receives any use attempt and fires `trigger_handler()`

**Outputs.** A `DecoySessionToken` dataclass with `token_string`, `token_type`, `placement_context`, `validator_endpoint`, `decoy_metadata`.

**Implementation notes.** JWTs are signed with a dedicated decoy RSA key whose JWKS endpoint is live at a monitored URL; any JWKS fetch or token validation call to that endpoint is logged. OAuth tokens are registered with a mock authorization server (a minimal FastAPI route under `/decoy/oauth/`) that accepts any client and logs the request. Session cookies use `HttpOnly; SameSite=Strict` in their placement metadata but are deployed in offline artifacts (browser profile directories, stored cookie exports) where they appear harvestable. The SAML assertion variant mimics a common IdP XML structure.

**CDP grounding.** Token content (JWT claims, cookie values) is LLM-generated to mimic authentic token distributions for the specified issuer profile. Realism classifier 𝓜 checks structural validity. Content-safety oracle 𝒯 validates that no real user sub/email claims appear in generated tokens.

**API endpoint.** `POST /decoy/session-token` (operator role).

---

### 4.7 `raven/decoy/decoy_public_release.py` — D3-DPR: Decoy Public Release

**Purpose.** Seed synthetic high-value artifacts into public-facing repositories and storage: GitHub repositories containing plausible-looking internal tooling with embedded canary credentials, fake API documentation with honey-tokens, fake database exports, and fabricated internal wikis. Attackers harvesting public exposure are detected when they attempt to use any seeded token.

**Inputs.**
- `artifact_type`: enum — `github_repo | gist | pastebin_style | npm_package_readme | docker_image_env | s3_public_bucket_listing`
- `repo_template`: dict — language, apparent purpose, commit history depth, README style
- `embedded_canaries`: list of `DecoyCredential` references to embed in the artifact
- `tracking_pixels`: bool — embed URL-based tracking tokens in README/HTML artifacts

**Outputs.** A `DecoyPublicRelease` dataclass with `artifact_url`, `embedded_canary_ids`, `canary_trigger_urls`, `decoy_metadata`.

**Implementation notes.** GitHub repo creation and population use the GitHub API via the `github_mcp_direct` connector already configured in the project. Repositories are created under a dedicated decoy GitHub organization. Commit history is generated by the LLM to simulate realistic development activity over a plausible time horizon. Embedded credentials are always pre-revoked canary tokens from `decoy_credential.py`; the UNRECOVERABLE_BLOCKLIST blocks embedding of any string matching a live credential regex. Tracking pixels are 1×1 transparent GIF URLs served by a Raven-controlled endpoint that calls `trigger_handler()` on any GET request.

**CDP grounding.** LLM generates README content, source code comments, and commit messages. Realism classifier 𝓜 evaluates the generated repository against a corpus of authentic public repositories for the specified language and apparent purpose. Content-safety oracle 𝒯 performs a final sweep for any inadvertently generated real API keys or PII before public push.

**API endpoint.** `POST /decoy/public-release` (operator role; requires additional `public_exposure_acknowledged: true` field).

---

### 4.8 `raven/decoy/decoy_environment.py` — D3-DE: Decoy Environment

**Purpose.** Provision and operate a complete synthetic environment — a virtual machine, container cluster, or cloud account — pre-populated with a coordinated set of decoys from multiple modules (files, credentials, network services, objects). The environment is designed to absorb and study attacker activity after initial compromise, functioning as a high-interaction honeypot with full behavioral telemetry.

**Inputs.**
- `environment_type`: enum — `vm | container | cloud_account | kubernetes_namespace`
- `environment_profile`: dict — OS/distro, apparent organization, installed software stack, user accounts, network topology
- `decoy_manifest`: list of `DecoyAdapter` subclass configurations to pre-populate
- `observation_config`: dict — pcap interface, syscall trace backend (`ebpf | ptrace`), log collection endpoint

**Outputs.** A `DecoyEnvironment` dataclass with `environment_id`, `access_endpoint`, `deployed_decoy_ids`, `telemetry_stream_url`, `decoy_metadata`.

**Implementation notes.** VM provisioning uses cloud provider APIs via MCP registry. Container environments are managed via Docker SDK through `bash_executor.py`. The environment runs a `raven/core/threat_detector.py` agent in monitor-only mode that streams all detections to the parent Raven instance via a dedicated gRPC channel. eBPF probes from `raven/tools/ebpf_ghidra.py` monitor syscall sequences; process behavior is analyzed by `raven/ml/sequence_analyzer.py`. The environment is network-isolated by default (standalone mode); promotion to connected mode requires explicit operator approval and is managed by `honeynet.py`. Raven's `kill_chain_planner.py` can be invoked to anticipate likely attacker progression within the environment and pre-position additional decoys.

**CDP grounding.** The LLM generates the apparent "legend" of the environment: hostname conventions, user home directory contents, shell history, cron jobs, and installed package lists. Realism classifier 𝓜 evaluates environment legend coherence. Content-safety oracle 𝒯 validates that no real hostnames, real internal IP ranges, or real employee names are embedded.

**API endpoint.** `POST /decoy/environment` (operator role; `environment_type: cloud_account` requires additional approval tier).

---

### 4.9 `raven/decoy/honeynet.py` — D3-CHN, D3-SHN, D3-IHN: Honeynet Modes

**Purpose.** Orchestrate networks of coordinated decoy environments operating in one of three D3FEND-defined modes: Standalone (fully isolated, no path to production), Connected (routed to real network but instrumented at every hop), and Integrated (mixed with production assets, highest realism, highest operational risk).

**Mode: Standalone Honeynet (D3-SHN).** The default and safest mode. One or more `DecoyEnvironment` instances are deployed on an isolated VLAN with no routing path to production systems. Attacker entry is only possible via deliberate advertisement (e.g., canary credential that includes the honeynet IP in a comment, or a decoy network resource that redirects deep connections). All traffic is captured via span port or eBPF. This mode is appropriate for all organizations and is the default deployment target for M3.

**Mode: Connected Honeynet (D3-CHN).** The honeynet is routed to the real network but every ingress and egress packet passes through an inline inspection tap managed by Raven's `nmap_scanner.py` (for topology mapping) and a dedicated `threat_detector.py` instance. Any lateral movement from the honeynet toward production is blocked by a Raven-managed firewall rule and fires a CRITICAL alert. Requires operator approval at the `cloud_account` tier. Appropriate for organizations with mature SOC capabilities.

**Mode: Integrated Honeynet (D3-IHN).** Decoy assets are co-mingled with real production infrastructure — decoy files on production file servers, canary credentials in real credential stores, decoy network resources on real VLANs. This mode provides maximum realism and maximum attacker engagement but requires the highest operational discipline to avoid false positives from legitimate processes. A `legitimate_access_allowlist` of process names, user accounts, and scheduled job signatures is maintained; any access not on the allowlist fires the trigger pipeline. The allowlist is managed via `raven/approval/store.py` and requires approval-gate sign-off for every modification. Integrated mode is the target of M4.

**Telemetry.** All three modes emit structured events to `threat_detector.py` via the internal event bus. Events include: connection attempt (src IP, dst IP, dst port, protocol), authentication attempt (credential type, value hash, outcome), file access (path, inode, UID, PID), and lateral movement attempt (source env ID, target host, technique). `raven/ml/behavioral_analyzer.py` correlates honeynet events against known attacker TTP patterns. `kill_chain_planner.py` receives real-time honeynet telemetry to update kill-chain position estimates for active threat actors.

**API endpoints.** `POST /decoy/honeynet` (create), `PATCH /decoy/honeynet/{id}/mode` (mode transition, operator role, requires gate approval for transitions to connected/integrated), `GET /decoy/honeynet/{id}/telemetry`.

---

## 5. CDP Grounding for Decoys

The Compositional Defense Pipeline rule — *every LLM emission must terminate at a tool oracle, classical-ML detector, or scored hypothesis* — is particularly critical for decoy generation because a poorly grounded decoy can leak real secrets, generate false positives, or be trivially identified by an adversary. The grounding pipeline for all `DecoyAdapter.generate()` calls is as follows.

**Stage 1 — Realism classifier 𝓜.** A fine-tuned binary classifier, trained on a labeled corpus of authentic artifacts (real `.env` files with secrets redacted, real GitHub PAT format samples, real professional profile text, real service banners) versus LLM-generated counterparts, scores each generated artifact on the interval \([0, 1]\). A score ≥ 0.80 is required for deployment. The classifier is versioned and stored in `raven/ml/`; its predictions are logged to `audit/store.py` alongside the decoy ID and generation timestamp. For `decoy_persona.py` and `decoy_environment.py`, a separate coherence classifier validates internal consistency across multi-artifact sets (e.g., commit messages match the stated programming language; persona biography dates are consistent across platforms).

**Stage 2 — Content-safety oracle 𝒯.** A deterministic, non-LLM pipeline adapted from `raven/ml/vulnerability_validator.py` runs static analysis on generated content. It applies: (a) a regex battery matching known real credential formats (AWS AKIA patterns, GitHub ghp_ tokens, PEM private key headers, high-entropy string detection) to block any inadvertent real-credential leakage; (b) a PII scanner (email address patterns, phone numbers, national ID formats, IP addresses in RFC-1918 ranges that match the operator's real network) to block real PII in public-facing artifacts; (c) a training-data memorization probe that queries a small reference model for verbatim reproduction likelihood. Any 𝒯 failure is a hard block with a structured error written to the audit log.

**Stage 3 — Operator approval gate G4.** `raven/approval/gate.py` is invoked with `mode=manual` for all decoy deployment requests. The approval UI presents: decoy type, target location, realism score, 𝒯 scan summary, D3FEND technique ID, and the full generated content. The operator approves or rejects with a typed justification. `raven/approval/patterns.py`'s `UNRECOVERABLE_BLOCKLIST` is extended for decoys to include: destructive payload patterns, real-name strings matching the internal employee registry, and production system hostnames/IPs in decoy network resource configurations. Approval decisions are stored in `raven/approval/store.py` and linked to the decoy lifecycle record.

---

## 6. Telemetry & Alerting

### 6.1 Prometheus Metrics

New metrics registered in the Raven metrics registry:

| Metric Name | Type | Labels | Description |
|---|---|---|---|
| `raven_decoy_deployed_total` | Counter | `d3fend_id`, `decoy_type` | Total decoy deployments, by technique |
| `raven_decoy_triggered_total` | Counter | `d3fend_id`, `decoy_type`, `trigger_type` | Total trigger events |
| `raven_decoy_active` | Gauge | `d3fend_id`, `decoy_type` | Currently active (deployed + monitored) decoys |
| `raven_decoy_realism_score` | Histogram | `d3fend_id`, `decoy_type` | Distribution of realism classifier 𝓜 scores at generation time |
| `raven_decoy_false_trigger_total` | Counter | `d3fend_id`, `decoy_type` | Triggers attributable to allowlisted legitimate processes (false positives) |

### 6.2 Alert Pipeline

When `trigger_handler()` fires: (1) a synchronous `POST /alerts` is issued with a structured alert body including `decoy_id`, `trigger_type`, `attacker_observable` (IP, credential hash, user agent), `d3fend_id`, and `confidence: HIGH`; (2) `threat_detector.py`'s fanout pipeline is invoked to correlate the trigger with concurrent anomaly detections, behavioral deviations, and kill-chain position; (3) the trigger event is appended to the decoy's lifecycle record in `audit/store.py` with status transition `deployed → triggered`.

### 6.3 Signal Quality

Decoy interactions are structurally different from detection signals generated by anomaly or behavioral classifiers: a legitimate process accessing a properly deployed canary credential or decoy file is a near-impossibility by design (the artifact serves no legitimate function and is placed in a location no scheduled job or business process touches). The theoretical true-positive rate approaches 100% for well-placed decoys; empirical false-positive rate is driven almost entirely by misconfigured allowlists in integrated honeynet mode. This is the core value proposition of the deception layer relative to statistical ML detectors: it converts low-confidence anomaly signals into high-confidence attacker attributions.

---

## 7. Threat Model

**Decoy poisoning by attackers.** An attacker with write access to the Raven configuration API could attempt to register allowlist entries that suppress decoy triggers or modify placement targets to reduce coverage. Mitigated by: (a) all allowlist modifications require approval-gate sign-off; (b) allowlist changes are append-only with a mandatory retention window (no deletions within 30 days); (c) modifications to `raven/approval/patterns.py` require a code-review commit to the main branch.

**Decoy detection by sophisticated adversaries.** Advanced threat actors employ anti-honeypot reconnaissance: checking for sparse file metadata, detecting VM hypervisor artifacts, probing for unrealistically uniform file modification times, or using timing analysis to distinguish decoy services from real ones. Mitigated by: (a) the realism classifier 𝓜 is specifically trained on adversarial anti-decoy probes in addition to authentic artifact distributions; (b) `decoy_environment.py` injects realistic entropy into file modification times, shell history, and process tables using LLM-generated but 𝒯-validated histories; (c) decoy realism metrics are continuously evaluated via the A/B engagement study in the evaluation plan (§8).

**LLM-generated decoys leaking training data.** Generative models can reproduce memorized training data verbatim, potentially causing a decoy file to contain a real leaked credential or a decoy persona to describe a real person's biography. Fully mitigated by the mandatory 𝒯 content-safety oracle stage, which runs before any operator approval request is generated; no generated content reaches the approval UI until 𝒯 passes.

**Mis-targeted decoys causing false positives in legitimate workflows.** A decoy deployed at a path that overlaps with a legitimate scheduled job will generate a flood of false trigger alerts that erode operator trust. Mitigated by: (a) the `target_directory` and `placement_targets` fields are validated against an operator-maintained `legitimate_access_registry`; (b) `raven_decoy_false_trigger_total` is monitored with an alert threshold; (c) integrated honeynet mode requires an explicit allowlist review before activation.

**Approval gate bypass attempts.** An attacker with operator credentials (or a compromised operator account) could attempt to deploy a decoy with a destructive payload or a real credential embedded as a "decoy." The `UNRECOVERABLE_BLOCKLIST` in `raven/approval/patterns.py` catches destructive patterns at the pattern-match level, before human review; the content-safety oracle 𝒯 catches real credentials. Additionally, the `gate.py` audit trail means any approval decision is attributable to a specific operator identity and reviewable post-incident.

---

## 8. Evaluation Plan

**Study 1 — Synthetic adversary campaign on standalone honeynet.** A simulated adversary (automated using Raven's own `kill_chain_planner.py` in a sandboxed evaluation environment) executes a multi-stage attack sequence (initial access → discovery → credential access → lateral movement) against a honeynet pre-populated with the full decoy manifest. Primary metrics: dwell time before first decoy trigger, technique coverage (fraction of D3-D* techniques that fire at least one trigger per campaign), and false positive rate. Baseline comparison: T-Pot (dockerized multi-honeypot) and Thinkst CanaryTokens under the same adversary scenario.

**Study 2 — Decoy realism A/B test.** A blind evaluation panel of 10+ security practitioners is shown pairs of artifacts: one LLM-generated (post-CDP-grounding) and one hand-crafted by the evaluation team. Practitioners rate each artifact's realism on a 1–5 scale and attempt to identify which is the decoy. Acceptance criterion: LLM-generated artifacts achieve mean realism score ≥ hand-crafted artifacts and are correctly identified as decoys at a rate no better than chance. This study is a primary deliverable of the OpenAI grant and will be submitted as a peer-reviewed conference paper.

**Study 3 — D3FEND technique coverage metric in CI.** A pytest suite under `tests/decoy/` validates that each D3-D* technique ID listed in §2 has at least one deployed-and-triggered test case in a mocked environment. The CI metric `d3fend_coverage_pct` = (passing technique tests / total technique tests) is tracked per commit. Target: 100% at M4.

---

## 9. Integration with OpenAI Grant Focus Areas

OpenAI's Cybersecurity Grant program explicitly lists the focus area: **"Create honeypots and deception technology to misdirect or trap attackers."** The `raven/decoy/` subsystem is a direct, technically specified implementation of this focus area across eleven D3FEND Deceive techniques ([D3FEND Deceive tactic](https://d3fend.mitre.org/tactic/d3f:Deceive)).

The specific ways the subsystem addresses the grant focus area:

1. **Honeypots at scale, LLM-generated:** The combination of `decoy_file.py`, `decoy_credential.py`, `decoy_network_resource.py`, and `decoy_environment.py` constitutes a full-stack honeypot deployment pipeline. Unlike static honeypot tools (T-Pot, Cowrie), Raven uses LLM generation to produce contextually appropriate decoys tailored to the specific organization's technology stack — a key differentiator that increases attacker engagement rates and is a testable hypothesis in Study 2 above.

2. **Deception technology grounded by CDP:** The CDP grounding pipeline (realism classifier 𝓜 + content-safety oracle 𝒯 + approval gate G4) ensures that LLM-generated deception content meets a rigorous quality and safety bar before deployment — a novel contribution not present in existing deception tools. This is directly relevant to OpenAI's interest in demonstrating that LLMs can be applied safely and effectively to defensive cybersecurity tasks.

3. **Misdirection and trapping:** `decoy_persona.py` (D3-DP) and `decoy_public_release.py` (D3-DPR) implement outward-facing deception that misdirects adversaries conducting reconnaissance or harvesting public repositories. `honeynet.py` in Connected and Integrated modes traps attackers who have already breached the perimeter, extending dwell time in a monitored environment and enabling detailed TTP collection.

4. **Published evaluation:** The A/B realism study (§8, Study 2) directly answers a research question of interest to OpenAI and the broader security community: can LLM-generated deception artifacts match or exceed hand-crafted artifacts in attacker engagement? The paper will be submitted to an academic security venue (target: USENIX Security or IEEE S&P workshop track).

---

## 10. Roadmap

### M1 — Q1 (Months 1–3): Foundation
- `raven/decoy/adapter.py` — `DecoyAdapter` ABC, `DecoyMetadata` dataclass
- `raven/decoy/decoy_file.py` (D3-DF) — full implementation including eBPF/inotify tripwire
- `raven/decoy/decoy_credential.py` (D3-DUC) — AWS, GitHub PAT, SSH keypair variants; Thinkst Canary webhook integration
- CDP grounding pipeline wired to `vulnerability_validator.py` (content-safety oracle 𝒯) and approval gate
- Prometheus metrics (`raven_decoy_deployed_total`, `raven_decoy_triggered_total`, `raven_decoy_active`)
- Basic `POST /decoy/file` and `POST /decoy/credential` API endpoints under `raven/api/`
- Milestone exit criterion: both modules pass full pytest suite including trigger simulation; CI `d3fend_coverage_pct` ≥ 18% (2 of 11 techniques)

### M2 — Q2 (Months 4–6): Core Decoy Library
- `raven/decoy/decoy_persona.py` (D3-DP) — synthetic identity generation with ethical guardrails and real-name collision check
- `raven/decoy/decoy_object.py` (D3-DO) — registry key, cloud resource, DB row variants
- `raven/decoy/decoy_session_token.py` (D3-DST) — JWT, OAuth, cookie variants
- `raven/decoy/decoy_network_resource.py` (D3-DNR) — SMB, FTP, MySQL listener variants
- `raven/decoy/decoy_public_release.py` (D3-DPR) — GitHub repo generation via `github_mcp_direct` integration
- Realism classifier 𝓜 — initial training run on artifact corpora; deployed in `raven/ml/`
- `raven_decoy_realism_score` histogram metric added
- Milestone exit criterion: 7 of 11 D3-D* techniques with passing CI test; realism classifier achieves ≥ 0.80 AUC on held-out evaluation set

### M3 — Q3 (Months 7–9): Environments & Honeynet MVP
- `raven/decoy/decoy_environment.py` (D3-DE) — VM and container provisioning; legend generation; eBPF telemetry pipeline
- `raven/decoy/honeynet.py` — Standalone mode (D3-SHN) fully operational; Connected mode (D3-CHN) in beta
- `kill_chain_planner.py` integration — honeynet telemetry feeds kill-chain position estimates; anticipatory decoy placement
- Prometheus `raven_decoy_false_trigger_total` metric; allowlist management UI
- Study 1 (synthetic adversary campaign) initiated on standalone honeynet
- Milestone exit criterion: 9 of 11 D3-D* techniques with passing CI test; standalone honeynet passes adversary campaign with false-positive rate < 2%

### M4 — Q4 (Months 10–12): Production Hardening & Publication
- `honeynet.py` — Connected (D3-CHN) and Integrated (D3-IHN) modes production-ready
- D3FEND OWL ontology import and ID validation integrated into CDP grounding pipeline
- D3FEND gap-analysis dashboard in Raven UI — visualizes technique coverage, trigger rates, realism score trends
- Study 2 (realism A/B test) completed; paper drafted and submitted
- Study 3 CI metric at 100% (all 11 D3-D* techniques with passing tests)
- Full evaluation comparison vs T-Pot and CanaryTokens published in paper
- Milestone exit criterion: all 11 D3-D* techniques in CI; paper submitted; `d3fend_coverage_pct` = 100%

---

## 11. Open Questions

1. **Realism classifier training data sourcing.** The realism classifier 𝓜 requires a labeled corpus of authentic artifacts (real `.env` files, real service banners, real professional profiles) with secrets and PII redacted. What is the acceptable sourcing methodology — public datasets only, operator-contributed samples under NDA, or synthetic bootstrapping from a stronger reference model? Each choice has different coverage and bias implications for the classifier's effectiveness against targeted attacks.

2. **Integrated honeynet allowlist scalability.** In large enterprises, the `legitimate_access_registry` for integrated honeynet mode may contain thousands of process signatures and scheduled job fingerprints. At what point does allowlist maintenance overhead exceed the operational value of integrated mode over connected mode? Should Raven provide an automated allowlist discovery mode (observe-for-30-days before switching to enforcement) as a default onboarding path?

3. **Legal jurisdiction for decoy persona platforms.** Operating synthetic social media accounts and GitHub accounts may violate the terms of service of those platforms in ways that carry legal risk for the deploying organization, particularly in the EU (GDPR, potential identity fraud implications) and California (CCPA). What is the minimum viable legal review checklist that Raven should enforce via the approval gate before any `decoy_persona.py` deployment, and should Raven ship a default `legal_acknowledgment` template drafted by counsel?

4. **LLM provider selection for decoy generation.** Different LLM providers have different tendencies toward training-data memorization. Should `decoy_credential.py` and `decoy_file.py` use a different provider than the rest of Raven's pipeline — specifically, one with stronger documented memorization mitigation — even at the cost of prompt compatibility? What provider-agnostic abstraction in `raven/api/` would make this switchable per decoy type?

5. **Trigger handler latency vs. alert fidelity tradeoff.** `trigger_handler()` must decide between (a) firing an immediate alert with minimal context (low latency, high operator responsiveness) and (b) waiting for `threat_detector.py`'s correlated analysis before alerting (richer context, higher latency, risk that the attacker detects the monitoring delay and aborts). What is the appropriate default latency budget for trigger handling, and should it be configurable per decoy type (e.g., canary credentials warrant immediate alerting; honeynet interactions can tolerate a 30-second correlation window)?
