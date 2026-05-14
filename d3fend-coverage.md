# D3FEND v1.0 Coverage Matrix — Project Raven Defender Edition

This matrix maps Project Raven Defender Edition's implemented and planned capabilities against the [MITRE D3FEND v1.0 ontology](https://d3fend.mitre.org) — the defensive counterpart to ATT&CK, [released January 2025](https://www.mitre.org/news-insights/news-release/mitre-launches-d3fend-10-milestone-cybersecurity-ontology). Coverage is assessed across all seven D3FEND tactics (Model, Harden, Detect, Isolate, Deceive, Evict, Restore), using only the defender-relevant modules retained in the Raven Defender Edition; all offensive tooling (`raven/redteam/offensive.py`, Metasploit, Empire, ExploitDB) is explicitly excluded.

---

## 1. Model

Raven's Model tactic coverage is anchored in its asset-discovery and vulnerability-enumeration toolchain. `raven/tools/nmap_scanner.py` drives network mapping and host enumeration, while `raven/tools/nuclei_scanner.py` and `raven/ml/cve_matcher.py` together enumerate and correlate known software vulnerabilities against NVD/OSV feeds. `raven/integrations/shodan_client.py` supplements external attack-surface visibility. Operational dependency mapping and data-exchange mapping are gaps today — Raven has no dedicated topology or data-flow ingestion pipeline — but the `raven/ml/behavioral_analyzer.py` baseline partially proxies operational activity modeling.

| D3FEND ID | Technique Name | Status | Raven Module / Evidence | ATT&CK Countered | Notes |
|-----------|---------------|--------|------------------------|-----------------|-------|
| D3-AI | Asset Inventory | **Partial** | `raven/tools/nmap_scanner.py`, `raven/tools/projectdiscovery.py` — no CMDB persistence layer | T1018, T1046, T1592 | Discovers live hosts and services; no persistent inventory store yet |
| D3-NM | Network Mapping | **Implemented** | `raven/tools/nmap_scanner.py` | T1018, T1046, T1590 | Nmap port/version scan covers topology discovery |
| D3-AVE | Asset Vulnerability Enumeration | **Implemented** | `raven/ml/cve_matcher.py`, `raven/tools/nuclei_scanner.py` | T1190, T1210, T1068 | CVE/NVD/OSV lookup with nuclei template correlation |
| D3-NVA | Network Vulnerability Assessment | **Implemented** | `raven/tools/nuclei_scanner.py`, `raven/tools/nmap_scanner.py` | T1190, T1046 | Nuclei runs own-asset template-based assessment |
| D3-SYSVA | System Vulnerability Assessment | **Partial** | `raven/ml/cve_matcher.py`, `raven/ml/vulnerability_validator.py` — host-level OS scanning not integrated | T1068, T1203, T1210 | CVE scoring present; OS-level patch-state enumeration missing |
| D3-CI | Configuration Inventory | **Partial** | `raven/monitoring/metrics_collector.py`, `raven/observability/logging.py` — no dedicated config-state collector | T1562, T1601 | Metrics and logs give partial config visibility; no structured CIS-benchmark inventory |
| D3-SWI | Software Inventory | **Partial** | `raven/ml/cve_matcher.py` — correlates against known packages, no active SBOM generation | T1195, T1525, T1574 | CVE matcher implies software list; explicit SBOM pipeline is a gap |
| D3-OAM | Operational Activity Mapping | **Gap** | — Proposed: ingest Raven audit log (`raven/audit/store.py`) into graph for activity mapping | T1059, T1078, T1098 | Audit store exists but no graph-based activity map built from it |

---

## 2. Harden

Raven's Harden posture is its second-strongest area after detection. The `raven/auth/` subsystem provides JWT-based credential hardening with strong password policy enforcement (`raven/auth/password.py`). The `raven/approval/` gate enforces an allowlist of safe actions and a denylisting blocklist (`raven/approval/patterns.py`) for catastrophic operations. The `raven/redteam/` middleware hardens the AI API surface against jailbreak and prompt-injection attacks. Gaps exist in executable allowlisting (no kernel-level enforcement), pointer authentication, and stack canary validation — these are OS/platform controls that Raven delegates to the host OS and container runtime.

| D3FEND ID | Technique Name | Status | Raven Module / Evidence | ATT&CK Countered | Notes |
|-----------|---------------|--------|------------------------|-----------------|-------|
| D3-CH | Credential Hardening | **Implemented** | `raven/auth/password.py`, `raven/auth/jwt_manager.py` | T1078, T1110, T1552, T1555 | Bcrypt hashing, JWT signing; strong password policy enforced |
| D3-MFA | Multi-factor Authentication | **Gap** | — Proposed: extend `raven/auth/routes.py` with TOTP/WebAuthn second factor | T1078, T1110, T1550 | Current auth is single-factor JWT only |
| D3-SPP | Strong Password Policy | **Implemented** | `raven/auth/password.py` | T1110, T1078 | Password complexity and length rules enforced at registration |
| D3-AH | Application Hardening | **Implemented** | `raven/redteam/middleware.py`, `raven/redteam/normalizer.py`, `raven/redteam/detector.py` | T1059, T1203, T1566 | L1B3RT4S jailbreak fingerprinting + Parseltongue normalization harden /ai/* API |
| D3-PH | Platform Hardening | **Partial** | `deployment/helm/raven/templates/networkpolicy.yaml`, `deployment/helm/raven/templates/deployment.yaml` — no seccomp/AppArmor profile attached | T1068, T1611 | K8s NetworkPolicy deployed; seccomp profile and read-only root FS not yet mandated |
| D3-EAL | Executable Allowlisting | **Partial** | `raven/approval/patterns.py` (UNRECOVERABLE_BLOCKLIST), `raven/approval/gate.py` — application-layer only; no kernel allowlist | T1059, T1027, T1218 | Approval gate blocks dangerous shell commands; no eBPF/fanotify allowlist |
| D3-EDL | Executable Denylisting | **Implemented** | `raven/approval/patterns.py` | T1059, T1027, T1570 | Blocklist patterns (rm -rf /, fork bombs, mkfs) enforced before execution |
| D3-SCH | Source Code Hardening | **Partial** | `raven/ml/code_flow_scanner.py`, `raven/ml/vulnerability_validator.py` — static analysis at scan time, not CI-gate | T1195, T1505, T1027 | Code flow + vuln validation runs; no blocking CI-pipeline integration yet |
| D3-CFI | Control Flow Integrity | **Partial** | `raven/ml/code_flow_scanner.py` — behavioral CFI analysis, not compile-time CFI | T1055, T1574, T1203 | Code-flow scanner detects CFI violations in analyzed binaries; no compiler instrumentation |
| D3-CDP | Change Default Password | **Implemented** | `raven/auth/password.py`, `raven/auth/user_store.py` | T1078, T1552 | New user provisioning enforces password change; no default credential paths |

---

## 3. Detect

Detection is Raven's core strength, spanning ML-based anomaly detection, process and memory forensics, YARA file scanning, network/behavioral analytics, and a dedicated redteam detector for AI-layer threats. The `raven/core/` orchestrator fans out to `raven/ml/` ensemble detectors, while `raven/hunters/` implements hypothesis-driven hunting with LLM-generated hypotheses validated by tool oracles. This covers the broadest range of D3FEND detection techniques of any tactic.

| D3FEND ID | Technique Name | Status | Raven Module / Evidence | ATT&CK Countered | Notes |
|-----------|---------------|--------|------------------------|-----------------|-------|
| D3-PA | Process Analysis | **Implemented** | `raven/ml/sequence_analyzer.py`, `raven/core/threat_detector.py` | T1055, T1059, T1543, T1574 | Syscall/process sequence anomaly detection |
| D3-PSA | Process Spawn Analysis | **Implemented** | `raven/ml/sequence_analyzer.py`, `raven/core/anomaly_detector.py` | T1059, T1053, T1547 | IsolationForest on spawn sequences detects unusual child-process chains |
| D3-PLA | Process Lineage Analysis | **Partial** | `raven/ml/sequence_analyzer.py` — sequence captured but no graph-based lineage tree built | T1059, T1055, T1574 | Sequence anomalies inferred; full parent-child lineage graph not yet constructed |
| D3-SCA | System Call Analysis | **Implemented** | `raven/ml/sequence_analyzer.py` | T1055, T1059, T1574, T1068 | Sequence analyzer models syscall patterns for anomaly scoring |
| D3-FA | File Analysis | **Implemented** | `raven/tools/yara_scan.py`, `raven/tools/yara_scanner.py` | T1027, T1036, T1105, T1570 | YARA rule-based file analysis covers malware signatures |
| D3-FCR | File Content Rules | **Implemented** | `raven/tools/yara_scan.py`, `raven/tools/yara_scanner.py` | T1027, T1036, T1564 | YARA is the standard for file content rule matching |
| D3-FH | File Hashing | **Partial** | `raven/tools/yara_scanner.py` — hashes computed during YARA scan; no standalone hash-store for integrity baseline | T1027, T1036, T1070 | Hash computation present; no persistent integrity baseline to diff against |
| D3-FIM | File Integrity Monitoring | **Gap** | — Proposed: extend `raven/tools/yara_scanner.py` with inotify/fanotify baseline + delta alerts | T1027, T1036, T1070, T1565 | No continuous watch on critical file paths today |
| D3-FHRA | File Hash Reputation Analysis | **Gap** | — Proposed: integrate VirusTotal/CIRCL HASHLOOKUP API into `raven/tools/yara_scanner.py` pipeline | T1027, T1105, T1036 | Hash reputation lookup not implemented; CVE matcher covers package hashes only |
| D3-EFA | Emulated File Analysis | **Partial** | `raven/tools/frida.py`, `raven/tools/frida_hook.py` — dynamic instrumentation for malware analysis | T1027, T1203, T1055 | Frida hooks enable behavioral emulation; no dedicated sandbox detonation pipeline |
| D3-DA | Dynamic Analysis | **Implemented** | `raven/tools/frida.py`, `raven/tools/frida_hook.py`, `raven/ml/memory_analyzer.py` | T1027, T1055, T1059, T1203 | Frida dynamic instrumentation + memory analysis for runtime behavior |
| D3-NTA | Network Traffic Analysis | **Partial** | `raven/core/anomaly_detector.py`, `raven/core/behavioral_profiler.py` — behavioral telemetry includes network features; no dedicated pcap/flow ingestion | T1071, T1041, T1095, T1571 | Anomaly detection operates on behavioral features including network; raw traffic parsing not integrated |
| D3-NTSA | Network Traffic Signature Analysis | **Gap** | — Proposed: integrate Suricata/Zeek output as a tool oracle feeding `raven/hunters/automated_investigator.py` | T1071, T1041, T1572, T1573 | No network signature engine in current codebase |
| D3-DNSTA | DNS Traffic Analysis | **Gap** | — Proposed: DNS query log ingestion into `raven/core/anomaly_detector.py` | T1071, T1568, T1048 | DNS telemetry not yet ingested |
| D3-PMAD | Protocol Metadata Anomaly Detection | **Gap** | — Proposed: parse HTTP/TLS/DNS metadata fields in `raven/core/anomaly_detector.py` | T1571, T1572, T1573 | Protocol-level metadata features not modeled today |
| D3-UBA | User Behavior Analysis | **Implemented** | `raven/ml/behavioral_analyzer.py`, `raven/core/behavioral_profiler.py` | T1078, T1134, T1098, T1530 | Per-entity behavioral baselines + UEBA classification |
| D3-UDTA | User Data Transfer Analysis | **Partial** | `raven/ml/behavioral_analyzer.py` — transfer volume is a feature; no DLP pipeline | T1048, T1041, T1567 | Behavioral features include data volume; no content-aware DLP |
| D3-JFAPA | Job Function Access Pattern Analysis | **Partial** | `raven/ml/behavioral_analyzer.py`, `raven/core/behavioral_profiler.py` — role-based baseline; no IAM feed integration | T1078, T1098, T1213 | Behavioral profiler models per-entity access; no direct IAM/RBAC integration |
| D3-SEA | Script Execution Analysis | **Implemented** | `raven/redteam/detector.py`, `raven/redteam/normalizer.py`, `raven/core/threat_detector.py` | T1059, T1027, T1140, T1564 | Redteam detector catches obfuscated/encoded script payloads in AI-layer traffic |
| D3-SJA | Scheduled Job Analysis | **Gap** | — Proposed: enumerate cron/systemd jobs and feed into `raven/core/anomaly_detector.py` | T1053, T1543 | No scheduled task monitoring today |
| D3-CIA | Container Image Analysis | **Partial** | `raven/tools/nuclei_scanner.py` — template-based; no native OCI layer scan | T1525, T1610 | Nuclei covers some container vulns; no dedicated Trivy/Grype integration |
| D3-CAA | Connection Attempt Analysis | **Partial** | `raven/core/anomaly_detector.py` — connection count is a behavioral feature; no dedicated auth-log parser | T1110, T1021, T1046 | Anomaly scoring includes connection rates; raw auth log not parsed |
| D3-OSM | Operating System Monitoring | **Partial** | `raven/tools/volatility.py`, `raven/tools/volatility_analyzer.py` — memory-forensics-based OS monitoring | T1055, T1068, T1543, T1547 | Volatility provides OS-state visibility; no continuous agent-based OS telemetry |
| D3-FBA | Firmware Behavior Analysis | **Gap** | — Proposed: integrate binwalk + Ghidra for firmware images via `raven/tools/ghidra_analyzer.py` | T1542, T1601 | No firmware analysis pipeline; Ghidra present but not firmware-targeted |
| D3-IPCTA | IPC Traffic Analysis | **Partial** | `raven/ml/sequence_analyzer.py` — IPC syscalls (pipe, socket, shmget) modeled in syscall sequences | T1559, T1055 | Syscall sequences capture IPC patterns; no dedicated IPC tracing |
| D3-MA | Message Analysis | **Implemented** | `raven/redteam/detector.py`, `raven/redteam/middleware.py`, `raven/redteam/jailbreak_patterns.py` | T1566, T1598, T1059 | 8-family jailbreak fingerprinting inspects every AI message payload |
| D3-WSAA | Web Session Activity Analysis | **Partial** | `raven/audit/middleware.py`, `raven/audit/store.py` — audit log captures session actions; no ML session-profiling yet | T1185, T1539, T1550 | Audit trail present; no behavioral session anomaly scoring |
| D3-HD | Homoglyph Detection | **Implemented** | `raven/redteam/normalizer.py` — Parseltongue 33-decoder handles Unicode normalization and homoglyph attacks | T1036, T1566, T1027 | Normalizer specifically targets homoglyph/lookalike payloads in AI prompt injection |

---

## 4. Isolate

Raven's Isolate coverage centers on its approval gate and response containment actions. `raven/mitigation/containment_actions.py` provides process kill and network isolation primitives. The Kubernetes deployment manifests include NetworkPolicy objects for broadcast domain isolation. Gaps exist in full execution isolation (no eBPF sandbox), content filtering, and DNS-layer filtering — areas where Raven delegates to infrastructure controls rather than application code.

| D3FEND ID | Technique Name | Status | Raven Module / Evidence | ATT&CK Countered | Notes |
|-----------|---------------|--------|------------------------|-----------------|-------|
| D3-EI | Execution Isolation | **Partial** | `raven/approval/gate.py`, `raven/approval/patterns.py` — application-layer isolation; no eBPF/seccomp sandbox | T1059, T1068, T1203, T1610 | Approval gate blocks dangerous executions; OS-level sandbox not enforced by Raven |
| D3-ABPI | Application-based Process Isolation | **Implemented** | `raven/approval/gate.py`, `raven/mitigation/containment_actions.py` | T1055, T1059, T1574 | Containment actions isolate misbehaving processes at application layer |
| D3-NI | Network Isolation | **Implemented** | `raven/mitigation/containment_actions.py`, `deployment/helm/raven/templates/networkpolicy.yaml` | T1021, T1041, T1071, T1095 | Containment actions perform host-level network isolation; K8s NetworkPolicy enforced |
| D3-NTF | Network Traffic Filtering | **Partial** | `deployment/helm/raven/templates/networkpolicy.yaml` — K8s-layer only; no application-layer filtering rules | T1071, T1095, T1041 | NetworkPolicy restricts pod-to-pod traffic; no dynamic rule injection from Raven |
| D3-ITF | Inbound Traffic Filtering | **Partial** | `raven/redteam/middleware.py` — filters inbound /ai/* traffic; no L3/L4 inbound filter | T1190, T1566, T1598 | Middleware blocks malicious AI-layer payloads; network-layer inbound filter is infra concern |
| D3-OTF | Outbound Traffic Filtering | **Gap** | — Proposed: add egress NetworkPolicy rules + application-layer egress checks in `raven/mitigation/containment_actions.py` | T1041, T1048, T1567 | No programmatic outbound filter in Raven today |
| D3-CF | Content Filtering | **Partial** | `raven/redteam/detector.py`, `raven/redteam/normalizer.py` — filters AI-layer content only | T1566, T1059, T1027 | Content filtering scoped to prompt injection; no general data content filter |
| D3-LFP | Local File Permissions | **Gap** | — Proposed: add permission auditing to `raven/tools/bash_executor.py` and container securityContext | T1083, T1070, T1564 | No active file permission enforcement or auditing in Raven code today |
| D3-DNSAL | DNS Allowlisting | **Gap** | — Proposed: integrate CoreDNS policy plugin with allowlist managed by `raven/mitigation/containment_actions.py` | T1568, T1071, T1048 | No DNS-layer allowlisting today |
| D3-AMED | Access Mediation | **Implemented** | `raven/auth/dependencies.py`, `raven/approval/gate.py` | T1078, T1098, T1134, T1548 | JWT auth + approval gate mediate every action requiring elevated access |

---

## 5. Deceive

Raven currently has **no decoy subsystem**. All Deceive techniques are marked Gap. A dedicated `raven/decoy/` subsystem is planned — see `docs/decoy-subsystem.md` for the proposed architecture, which will include decoy files, credentials, network services, and honeynet integration to provide early-warning tripwires and adversary misdirection.

| D3FEND ID | Technique Name | Status | Raven Module / Evidence | ATT&CK Countered | Notes |
|-----------|---------------|--------|------------------------|-----------------|-------|
| D3-DF | Decoy File | **Gap** | — Planned in `docs/decoy-subsystem.md` under `raven/decoy/files.py` | T1083, T1005, T1213 | No decoy file placement capability today |
| D3-DO | Decoy Object | **Gap** | — Planned in `docs/decoy-subsystem.md` under `raven/decoy/objects.py` | T1083, T1530, T1213 | No generic decoy object subsystem yet |
| D3-DP | Decoy Persona | **Gap** | — Planned in `docs/decoy-subsystem.md` under `raven/decoy/persona.py` | T1589, T1598, T1585 | No synthetic user/persona capability |
| D3-DNR | Decoy Network Resource | **Gap** | — Planned in `docs/decoy-subsystem.md` under `raven/decoy/network.py` | T1046, T1590, T1018 | No decoy host/service deployed by Raven |
| D3-DUC | Decoy User Credential | **Gap** | — Planned in `docs/decoy-subsystem.md` under `raven/decoy/credentials.py` | T1552, T1078, T1555 | No honey credential seeding in Raven today |
| D3-DST | Decoy Session Token | **Gap** | — Planned in `docs/decoy-subsystem.md` under `raven/decoy/tokens.py` | T1539, T1550, T1528 | No canary token generation |
| D3-DE | Decoy Environment | **Gap** | — Planned in `docs/decoy-subsystem.md` under `raven/decoy/environment.py` | T1082, T1592, T1590 | Full honeynet/sandbox environment not yet implemented |
| D3-SHN | Standalone Honeynet | **Gap** | — Planned in `docs/decoy-subsystem.md` under `raven/decoy/honeynet.py` | T1046, T1590, T1595 | No standalone honeynet deployment capability |

---

## 6. Evict

Raven's Evict coverage is anchored in `raven/mitigation/containment_actions.py`, which provides process termination, network isolation, and account disabling. The `raven/approval/gate.py` ensures all eviction actions pass human or smart-LLM review before execution, preventing erroneous evictions. `raven/mitigation/remediation_engine.py` handles patch application (a form of software restoration/eviction of vulnerable components). Credential eviction and registry cleanup are gaps for environments outside Linux.

| D3FEND ID | Technique Name | Status | Raven Module / Evidence | ATT&CK Countered | Notes |
|-----------|---------------|--------|------------------------|-----------------|-------|
| D3-PT | Process Termination | **Implemented** | `raven/mitigation/containment_actions.py` | T1055, T1059, T1543, T1574 | Process kill is a primary containment action |
| D3-PS | Process Suspension | **Partial** | `raven/mitigation/containment_actions.py` — kill implemented; SIGSTOP/suspend not explicitly surfaced | T1055, T1059 | Kill present; non-destructive suspension action could be added |
| D3-PE | Process Eviction | **Implemented** | `raven/mitigation/containment_actions.py`, `raven/mitigation/response_orchestrator.py` | T1055, T1059, T1574, T1543 | Orchestrated process eviction with approval gate |
| D3-FEV | File Eviction | **Partial** | `raven/mitigation/containment_actions.py` — file removal possible via `bash_executor.py`; no dedicated file-eviction action | T1027, T1105, T1036, T1570 | File deletion possible; not a named, structured eviction primitive |
| D3-CE | Credential Eviction | **Partial** | `raven/mitigation/containment_actions.py` (account disable), `raven/auth/user_store.py` — local accounts only | T1078, T1552, T1098 | Account disabling implemented; token/certificate revocation not yet structured |
| D3-AL | Account Locking | **Implemented** | `raven/mitigation/containment_actions.py`, `raven/auth/user_store.py` | T1078, T1110, T1098 | Account disable is an explicit containment action |
| D3-ANCI | Authentication Cache Invalidation | **Gap** | — Proposed: extend `raven/auth/jwt_manager.py` with token blocklist/revocation cache | T1550, T1539, T1528 | JWT is stateless; no revocation store today |
| D3-CR | Credential Revocation | **Gap** | — Proposed: add revocation endpoint in `raven/auth/routes.py` + blocklist in `raven/auth/jwt_manager.py` | T1552, T1078, T1098 | No credential revocation mechanism beyond account disable |
| D3-ST | Session Termination | **Partial** | `raven/auth/jwt_manager.py` — token expiry terminates sessions; no active force-terminate | T1185, T1539, T1550 | JWT expiry is passive; no server-side forced session kill |
| D3-DRA | Disable Remote Access | **Implemented** | `raven/mitigation/containment_actions.py` — network isolation action disables external reach | T1021, T1219, T1133 | Network isolation action covers remote access termination |

---

## 7. Restore

Raven currently has **no restore subsystem**. All Restore techniques are marked Gap. A dedicated `raven/restore/` subsystem is planned — see `docs/restore-subsystem.md` for the proposed architecture, covering configuration restoration, file recovery, credential rotation, and account re-enablement, integrated with `raven/mitigation/response_orchestrator.py` as the post-containment recovery phase.

| D3FEND ID | Technique Name | Status | Raven Module / Evidence | ATT&CK Countered | Notes |
|-----------|---------------|--------|------------------------|-----------------|-------|
| D3-RC | Restore Configuration | **Gap** | — Planned in `docs/restore-subsystem.md` under `raven/restore/configuration.py` | T1562, T1601, T1112 | No configuration snapshot/restore capability today |
| D3-RF | Restore File | **Gap** | — Planned in `docs/restore-subsystem.md` under `raven/restore/files.py` | T1486, T1490, T1070, T1565 | No file backup/restore capability in Raven |
| D3-RA | Restore Access | **Gap** | — Planned in `docs/restore-subsystem.md` under `raven/restore/access.py` | T1531, T1098, T1078 | No structured access restoration workflow |
| D3-RS | Restore Software | **Partial** | `raven/mitigation/remediation_engine.py` — patch apply is a form of software restoration; no rollback | T1195, T1525, T1574 | Patch application implemented; clean-snapshot rollback is a gap |
| D3-RIC | Reissue Credential | **Gap** | — Planned in `docs/restore-subsystem.md` under `raven/restore/credentials.py` | T1552, T1078, T1098 | No credential reissuance workflow |
| D3-CRO | Credential Rotation | **Gap** | — Planned in `docs/restore-subsystem.md` under `raven/restore/credentials.py`; see `docs/runbooks/api-key-rotation.md` for manual process | T1552, T1078, T1528 | Manual key rotation documented; automated rotation not implemented |
| D3-RUAA | Restore User Account Access | **Gap** | — Planned in `docs/restore-subsystem.md` under `raven/restore/accounts.py` | T1531, T1098 | No structured account restoration after containment eviction |
| D3-ULA | Unlock Account | **Gap** | — Planned in `docs/restore-subsystem.md` under `raven/restore/accounts.py`; `raven/auth/user_store.py` has the data model | T1110, T1078 | Account unlock is manual today; automation needed |

---

## Coverage Summary Table

| Tactic | Implemented | Partial | Gap | Out of Scope | Total |
|--------|------------|---------|-----|--------------|-------|
| Model | 2 | 5 | 1 | 0 | 8 |
| Harden | 5 | 4 | 1 | 0 | 10 |
| Detect | 12 | 10 | 3 | 0 | 25 |
| Isolate | 3 | 4 | 3 | 0 | 10 |
| Deceive | 0 | 0 | 8 | 0 | 8 |
| Evict | 4 | 3 | 3 | 0 | 10 |
| Restore | 0 | 1 | 7 | 0 | 8 |
| **Total** | **26** | **27** | **26** | **0** | **79** |

---

## Top 10 Priority Gaps to Close

1. **D3-DF / D3-DUC / D3-DST (Decoy subsystem)** — Decoy files, honey credentials, and canary tokens provide high-fidelity early warning for lateral movement (T1552, T1083) at minimal implementation cost; implement `raven/decoy/` as first Deceive milestone.

2. **D3-MFA (Multi-factor Authentication)** — Single-factor JWT auth is the single highest-risk authentication gap; adding TOTP/WebAuthn to `raven/auth/routes.py` closes T1078 and T1110 exposure with established library support.

3. **D3-ANCI / D3-CR (Credential Revocation + Cache Invalidation)** — Without a JWT blocklist, account disable does not immediately terminate active sessions; adding a Redis-backed revocation store to `raven/auth/jwt_manager.py` closes T1550 and T1539.

4. **D3-RC / D3-RF (Restore Configuration + File)** — Post-incident recovery today requires manual intervention; `raven/restore/` implementation completes the respond-recover loop and is prerequisite for autonomous full-cycle defense.

5. **D3-FIM (File Integrity Monitoring)** — Inotify/fanotify-based continuous watch of critical paths (e.g., `/etc`, systemd units, Raven binaries) detects T1070 and T1565 log/file tampering that YARA scanning misses between scheduled runs.

6. **D3-NTSA (Network Traffic Signature Analysis)** — Integrating Suricata or Zeek output as a tool oracle into `raven/hunters/automated_investigator.py` fills the largest single gap in the Detect tactic and counters T1071, T1572, T1573 C2 channels.

7. **D3-KBPI / D3-EI (Kernel-based Process Isolation)** — Attaching a seccomp profile and AppArmor/SELinux policy to the Raven container closes T1068 and T1610 container-escape vectors; achievable entirely via Helm `securityContext` changes.

8. **D3-LFP (Local File Permissions)** — Adding a permission-audit step to `raven/tools/bash_executor.py` and enforcing read-only root filesystem in `deployment/helm/raven/templates/deployment.yaml` closes T1083 and T1070 without new code.

9. **D3-SJA (Scheduled Job Analysis)** — Enumerating cron/systemd timers and feeding them into `raven/core/anomaly_detector.py` closes T1053 persistence detection with low implementation effort.

10. **D3-FHRA (File Hash Reputation Analysis)** — Plugging a VirusTotal or CIRCL HASHLOOKUP API call into the `raven/tools/yara_scanner.py` pipeline adds a high-confidence malware identification signal (T1027, T1105) at the cost of a single API integration.

---

## How CDP Grounding Integrates with D3FEND

Every LLM-emitted defensive action in Raven must reference a valid D3-XXX identifier drawn from the imported D3FEND v1.0 OWL ontology before it can be submitted to the approval gate. The **Calibrated Defense Posture (CDP) grounding verifier** — implemented as a pre-execution hook in `raven/mitigation/response_orchestrator.py` — validates two properties: (1) the cited D3-XXX ID exists as a named individual in the D3FEND ontology (structural validity), and (2) the action is backed by a concrete evidence artifact — either a tool oracle result (𝒯, e.g., a Nuclei finding from `raven/tools/nuclei_scanner.py`), a classical-ML detector score (𝓜, e.g., an IsolationForest anomaly score from `raven/core/anomaly_detector.py`), or a scored hypothesis (𝓛, e.g., a confidence-weighted hypothesis from `raven/hunters/hypothesis_generator.py`). An action that passes structural validation but lacks an evidence anchor is blocked and routed to the human approval queue with a `GROUNDING_FAILURE` label, preventing LLM hallucination from manifesting as unchecked system changes.

This two-layer grounding design — ontological reference + empirical evidence — produces what the Raven whitepaper terms *ontologically-grounded autonomous defense*. A response chain such as "IsolationForest scores PID 4821 at anomaly score 0.94 (𝓜) → hypothesis generator produces `T1055.001 (Process Injection via reflective DLL)` at 𝓛=0.87 → response orchestrator emits `D3-PT (Process Termination)` against PID 4821" is verifiably grounded: the D3-PT ID is present in the D3FEND OWL graph, and the evidence chain is fully traceable from ML detector through hypothesis to action. This makes the defense auditable, replayable from the `raven/audit/store.py` log, and compliant with emerging AI-system accountability requirements.

The D3FEND ontology import also enables cross-tactic consistency checking: if the orchestrator emits both a `D3-NI (Network Isolation)` action and a `D3-RNA (Restore Network Access)` action for the same host within the same incident window, the grounding verifier can detect the semantic contradiction and escalate rather than executing conflicting actions. As the Restore and Deceive subsystems are built out, every new action type must be registered against a D3-XXX ID before it can be invoked autonomously, ensuring the matrix above remains the living authoritative contract between Raven's capability set and the [D3FEND ontology at d3fend.mitre.org](https://d3fend.mitre.org).
