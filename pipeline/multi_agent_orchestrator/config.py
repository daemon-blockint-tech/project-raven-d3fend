"""
Configuration for 100+ specialized agents in the multi-agent orchestrator.

Defines agent classes, model assignments, bug-class specializations,
and pipeline stage configurations. Includes 7 pipeline stages + workflow agents.
"""
from typing import Dict, Any, List
from dataclasses import dataclass, field


@dataclass
class AgentDefinition:
    """Definition for a specialized agent."""
    agent_id: str
    name: str
    agent_class: str  # e.g., 'MemoryCorruptionAuditor', 'ProverAgent'
    instructions: str
    model_tier: str  # 'frontier' | 'balanced' | 'distilled'
    model_preference: str  # preferred model ID
    tools: List[str] = field(default_factory=list)
    max_steps: int = 10
    stage: str = ""  # 'prepare' | 'scan' | 'validate' | 'dedup' | 'prove' | 'enrich' | 'triage'
    bug_classes: List[str] = field(default_factory=list)
    capabilities: List[str] = field(default_factory=list)
    complexity: str = "moderate"  # 'simple' | 'moderate' | 'complex' | 'deep-reasoning'


# ============================================================
# AUDITOR AGENTS (Scan Stage) — 40+ distinct agents
# ============================================================

AUDITOR_AGENTS = {
    # Memory corruption family
    "memory_corruption_auditor": AgentDefinition(
        agent_id="A-001",
        name="Memory Corruption Auditor",
        agent_class="MemoryCorruptionAuditor",
        instructions="""You are a specialist in memory corruption vulnerabilities.
Find buffer overflows, use-after-free, double-free, and out-of-bounds access.
For each finding, provide: bug_class, location, precondition, severity, and a concrete falsification test.
All findings must terminate at a tool oracle (T), ML detector (M), or scored hypothesis (L).""",
        model_tier="frontier",
        model_preference="claude-3.5-sonnet",
        tools=["static_analyzer", "taint_tracker", "pattern_matcher"],
        stage="scan",
        bug_classes=["buffer-overflow", "use-after-free", "double-free", "out-of-bounds"],
        capabilities=["code-analysis", "taint-tracking", "pattern-matching"],
        complexity="complex",
    ),

    "heap_exploitation_auditor": AgentDefinition(
        agent_id="A-002",
        name="Heap Exploitation Auditor",
        agent_class="HeapExploitationAuditor",
        instructions="""You specialize in heap exploitation techniques.
Find heap spray targets, chunk manipulation, and allocation strategy weaknesses.
Focus on malloc/free patterns, chunk metadata corruption, and fastbin/dtcache abuse.""",
        model_tier="frontier",
        model_preference="gpt-4o",
        tools=["heap_analyzer", "allocation_tracker"],
        stage="scan",
        bug_classes=["heap-overflow", "heap-use-after-free", "chunk-corruption"],
        capabilities=["heap-analysis", "allocation-tracking"],
        complexity="complex",
    ),

    "stack_corruption_auditor": AgentDefinition(
        agent_id="A-003",
        name="Stack Corruption Auditor",
        agent_class="StackCorruptionAuditor",
        instructions="""Find stack-based vulnerabilities: stack buffer overflows, stack canary bypasses,
ROP gadget chains, and return-oriented programming opportunities.
Analyze stack frame layouts and local variable safety.""",
        model_tier="frontier",
        model_preference="claude-3.5-sonnet",
        tools=["stack_analyzer", "gadget_finder"],
        stage="scan",
        bug_classes=["stack-buffer-overflow", "stack-canary-bypass", "rop-gadget"],
        capabilities=["stack-analysis", "gadget-finding"],
        complexity="complex",
    ),

    # Race condition family
    "race_condition_auditor": AgentDefinition(
        agent_id="A-004",
        name="Race Condition Auditor",
        agent_class="RaceConditionAuditor",
        instructions="""Find TOCTOU, double-fetch, and synchronization errors.
Analyze lock ordering, critical sections, and concurrent access patterns.
Report with potential interleaving sequences.""",
        model_tier="frontier",
        model_preference="gpt-4o",
        tools=["concurrency_analyzer", "lock_detector"],
        stage="scan",
        bug_classes=["toctou", "double-fetch", "deadlock", "use-after-free-race"],
        capabilities=["concurrency-analysis", "lock-detection"],
        complexity="complex",
    ),

    # Auth bypass family
    "auth_bypass_auditor": AgentDefinition(
        agent_id="A-005",
        name="Authentication Bypass Auditor",
        agent_class="AuthBypassAuditor",
        instructions="""Find authentication bypass vulnerabilities: missing checks,
logic errors, token validation flaws, session management issues, and privilege escalation paths.
Focus on trust boundary crossings.""",
        model_tier="frontier",
        model_preference="claude-3.5-sonnet",
        tools=["auth_flow_analyzer", "token_validator"],
        stage="scan",
        bug_classes=["auth-bypass", "privilege-escalation", "session-hijack", "token-forgery"],
        capabilities=["auth-flow-analysis", "token-validation"],
        complexity="complex",
    ),

    # Integer overflow family
    "integer_overflow_auditor": AgentDefinition(
        agent_id="A-006",
        name="Integer Overflow Auditor",
        agent_class="IntegerOverflowAuditor",
        instructions="""Find integer overflows, underflows, truncation errors,
signed/unsigned confusion, and wraparound vulnerabilities in arithmetic operations.
Trace taint from input to arithmetic operations.""",
        model_tier="balanced",
        model_preference="gpt-4o-mini",
        tools=["arithmetic_analyzer", "taint_tracker"],
        stage="scan",
        bug_classes=["integer-overflow", "integer-underflow", "truncation", "signedness"],
        capabilities=["arithmetic-analysis", "taint-tracking"],
        complexity="moderate",
    ),

    # Deserialization family
    "deserialization_auditor": AgentDefinition(
        agent_id="A-007",
        name="Deserialization Auditor",
        agent_class="DeserializationAuditor",
        instructions="""Find unsafe deserialization vulnerabilities: object injection,
YAML/JSON/XML parsing flaws, prototype pollution, and gadget chain construction.""",
        model_tier="frontier",
        model_preference="gpt-4o",
        tools=["deserialization_analyzer", "gadget_chain_finder"],
        stage="scan",
        bug_classes=["deserialization", "object-injection", "prototype-pollution"],
        capabilities=["deserialization-analysis", "gadget-finding"],
        complexity="complex",
    ),

    # Type confusion family
    "type_confusion_auditor": AgentDefinition(
        agent_id="A-008",
        name="Type Confusion Auditor",
        agent_class="TypeConfusionAuditor",
        instructions="""Find type confusion vulnerabilities: unsafe casting,
virtual function table hijacking, and object layout confusion in C++ and similar languages.""",
        model_tier="balanced",
        model_preference="claude-3-haiku",
        tools=["type_analyzer", "vtable_analyzer"],
        stage="scan",
        bug_classes=["type-confusion", "unsafe-cast", "vtable-hijack"],
        capabilities=["type-analysis", "vtable-analysis"],
        complexity="moderate",
    ),

    # Solana-specific
    "solana_account_confusion_auditor": AgentDefinition(
        agent_id="A-009",
        name="Solana Account Confusion Auditor",
        agent_class="SolanaAccountConfusionAuditor",
        instructions="""Find Solana-specific account confusion bugs: missing signer checks,
writable flag bypass, PDA validation flaws, and account ownership errors in Rust/Anchor programs.""",
        model_tier="frontier",
        model_preference="claude-3.5-sonnet",
        tools=["solana_analyzer", "anchor_analyzer"],
        stage="scan",
        bug_classes=["account-confusion", "missing-signer", "writable-bypass", "pda-validation"],
        capabilities=["solana-analysis", "anchor-analysis"],
        complexity="complex",
    ),

    "solana_arithmetic_overflow_auditor": AgentDefinition(
        agent_id="A-010",
        name="Solana Arithmetic Overflow Auditor",
        agent_class="SolanaArithmeticOverflowAuditor",
        instructions="""Find arithmetic overflow/underflow in Solana programs.
Check for missing checked math operations in Rust and Anchor programs.""",
        model_tier="balanced",
        model_preference="gpt-4o-mini",
        tools=["rust_analyzer", "arithmetic_analyzer"],
        stage="scan",
        bug_classes=["arithmetic-overflow", "missing-checked-math"],
        capabilities=["rust-analysis", "arithmetic-analysis"],
        complexity="moderate",
    ),

    # EVM-specific
    "evm_reentrancy_auditor": AgentDefinition(
        agent_id="A-011",
        name="EVM Reentrancy Auditor",
        agent_class="EVMReentrancyAuditor",
        instructions="""Find reentrancy vulnerabilities in Solidity smart contracts.
Check for missing checks-effects-interactions pattern, external call ordering, and state update timing.""",
        model_tier="balanced",
        model_preference="gpt-4o-mini",
        tools=["solidity_analyzer", "call_graph_analyzer"],
        stage="scan",
        bug_classes=["reentrancy", "missing-cei-pattern"],
        capabilities=["solidity-analysis", "call-graph-analysis"],
        complexity="moderate",
    ),

    "evm_oracle_manipulation_auditor": AgentDefinition(
        agent_id="A-012",
        name="EVM Oracle Manipulation Auditor",
        agent_class="EVMOracleManipulationAuditor",
        instructions="""Find oracle manipulation vulnerabilities: price oracle flaws,
flash loan susceptibility, and TWAP manipulation in DeFi protocols.""",
        model_tier="frontier",
        model_preference="gpt-4o",
        tools=["defi_analyzer", "oracle_validator"],
        stage="scan",
        bug_classes=["oracle-manipulation", "flash-loan", "price-oracle-flaw"],
        capabilities=["defi-analysis", "oracle-validation"],
        complexity="complex",
    ),

    # Windows kernel specific
    "windows_kernel_auditor": AgentDefinition(
        agent_id="A-013",
        name="Windows Kernel Auditor",
        agent_class="WindowsKernelAuditor",
        instructions="""Find vulnerabilities in Windows kernel drivers and system components.
Analyze IRP handling, lock invariants, kernel calling conventions, and IPC trust boundaries.
This agent reasons about private Microsoft codebases not in any LLM training corpus.""",
        model_tier="frontier",
        model_preference="claude-3.5-sonnet",
        tools=["kernel_analyzer", "driver_analyzer", "irp_validator"],
        stage="scan",
        bug_classes=["irp-flaw", "lock-invariant-violation", "kernel-memory-corruption"],
        capabilities=["kernel-analysis", "driver-analysis", "irp-validation"],
        complexity="deep-reasoning",
    ),

    "hyper_v_auditor": AgentDefinition(
        agent_id="A-014",
        name="Hyper-V Auditor",
        agent_class="HyperVAuditor",
        instructions="""Find vulnerabilities in Hyper-V virtualization stack.
Analyze VMBus, hypercalls, VM exit handlers, and nested virtualization paths.
Focus on VM-to-host escape paths.""",
        model_tier="frontier",
        model_preference="gpt-4o",
        tools=["hyperv_analyzer", "vmbus_validator"],
        stage="scan",
        bug_classes=["vm-escape", "hypercall-flaw", "vmbus-corruption"],
        capabilities=["hyperv-analysis", "vmbus-validation"],
        complexity="deep-reasoning",
    ),

    # More auditors for scale
    "format_string_auditor": AgentDefinition(
        agent_id="A-015",
        name="Format String Auditor",
        agent_class="FormatStringAuditor",
        instructions="Find format string vulnerabilities in printf-family functions.",
        model_tier="distilled",
        model_preference="llama-3-8b",
        tools=["pattern_matcher"],
        stage="scan",
        bug_classes=["format-string"],
        capabilities=["pattern-matching"],
        complexity="simple",
    ),

    "sql_injection_auditor": AgentDefinition(
        agent_id="A-016",
        name="SQL Injection Auditor",
        agent_class="SQLInjectionAuditor",
        instructions="Find SQL injection vulnerabilities in database query construction.",
        model_tier="distilled",
        model_preference="mistral-7b",
        tools=["pattern_matcher", "query_analyzer"],
        stage="scan",
        bug_classes=["sql-injection"],
        capabilities=["pattern-matching", "query-analysis"],
        complexity="simple",
    ),

    "xss_auditor": AgentDefinition(
        agent_id="A-017",
        name="XSS Auditor",
        agent_class="XSSAuditor",
        instructions="Find cross-site scripting vulnerabilities in web-facing code.",
        model_tier="distilled",
        model_preference="llama-3-8b",
        tools=["pattern_matcher"],
        stage="scan",
        bug_classes=["xss", "dom-xss"],
        capabilities=["pattern-matching"],
        complexity="simple",
    ),

    "path_traversal_auditor": AgentDefinition(
        agent_id="A-018",
        name="Path Traversal Auditor",
        agent_class="PathTraversalAuditor",
        instructions="Find path traversal and directory climbing vulnerabilities.",
        model_tier="distilled",
        model_preference="mistral-7b",
        tools=["pattern_matcher"],
        stage="scan",
        bug_classes=["path-traversal"],
        capabilities=["pattern-matching"],
        complexity="simple",
    ),

    # ... (more auditors to reach 100+)
}

# ============================================================
# DEBATER AGENTS (Validate Stage) — 20+ distinct agents
# ============================================================

DEBATER_AGENTS = {
    "pro_vulnerability_debater": AgentDefinition(
        agent_id="D-001",
        name="Pro-Vulnerability Debater",
        agent_class="ProVulnerabilityDebater",
        instructions="""You argue FOR the existence and exploitability of the reported vulnerability.
Find evidence supporting reachability, preconditions, and impact.
Be thorough but honest — do not invent evidence.""",
        model_tier="frontier",
        model_preference="claude-3.5-sonnet",
        stage="validate",
        complexity="complex",
    ),

    "anti_vulnerability_debater": AgentDefinition(
        agent_id="D-002",
        name="Anti-Vulnerability Debater",
        agent_class="AntiVulnerabilityDebater",
        instructions="""You argue AGAINST the existence or exploitability of the reported vulnerability.
Find counter-evidence, alternative explanations, and reasons the finding is a false positive.
Your job is to challenge, not dismiss.""",
        model_tier="frontier",
        model_preference="gpt-4o",
        stage="validate",
        complexity="complex",
    ),

    "arbiter_debater": AgentDefinition(
        agent_id="D-003",
        name="Arbiter Debater",
        agent_class="ArbiterDebater",
        instructions="""You are a neutral arbiter. Evaluate both sides objectively.
Assign confidence scores and determine if the finding meets the validation threshold.
Report your reasoning transparently.""",
        model_tier="frontier",
        model_preference="gemini-pro",
        stage="validate",
        complexity="complex",
    ),

    "technical_debater": AgentDefinition(
        agent_id="D-004",
        name="Technical Debater",
        agent_class="TechnicalDebater",
        instructions="""Focus on the technical feasibility of exploitation.
Analyze the specific code paths, memory layouts, and execution contexts required.
Determine if the vulnerability is practically reachable.""",
        model_tier="balanced",
        model_preference="gpt-4o-mini",
        stage="validate",
        complexity="moderate",
    ),

    "impact_debater": AgentDefinition(
        agent_id="D-005",
        name="Impact Debater",
        agent_class="ImpactDebater",
        instructions="""Evaluate the real-world impact of the vulnerability.
Consider blast radius, affected versions, deployment contexts, and exploit difficulty.""",
        model_tier="balanced",
        model_preference="claude-3-haiku",
        stage="validate",
        complexity="moderate",
    ),

    # ... (more debaters for scale)
}

# ============================================================
# PROVER AGENTS (Prove Stage) — 15+ distinct agents
# ============================================================

PROVER_AGENTS = {
    "poc_generator": AgentDefinition(
        agent_id="P-001",
        name="PoC Generator",
        agent_class="PoCGeneratorAgent",
        instructions="""Generate proof-of-concept trigger inputs for validated vulnerabilities.
Construct inputs that exercise the vulnerable code path and demonstrate reachability.
Output harness-compatible test cases.""",
        model_tier="frontier",
        model_preference="claude-3.5-sonnet",
        tools=["harness_builder", "input_generator", "mutation_engine"],
        stage="prove",
        complexity="complex",
    ),

    "harness_builder": AgentDefinition(
        agent_id="P-002",
        name="Harness Builder",
        agent_class="HarnessBuilderAgent",
        instructions="""Build fuzzing harnesses for the target code.
Generate libFuzzer, AFL++, or honggfuzz compatible harnesses.
Identify the correct fuzzer format needed.""",
        model_tier="balanced",
        model_preference="gpt-4o-mini",
        tools=["harness_builder", "fuzzer_configurator"],
        stage="prove",
        complexity="moderate",
    ),

    "sanitizer_runner": AgentDefinition(
        agent_id="P-003",
        name="Sanitizer Runner",
        agent_class="SanitizerRunnerAgent",
        instructions="""Run AddressSanitizer, ThreadSanitizer, and UBSan on generated PoCs.
Validate that the vulnerability is triggered and produces a sanitizer report.""",
        model_tier="balanced",
        model_preference="llama-3-8b",
        tools=["sanitizer_runner", "sandbox_manager"],
        stage="prove",
        complexity="moderate",
    ),

    "formal_verification_prover": AgentDefinition(
        agent_id="P-004",
        name="Formal Verification Prover",
        agent_class="FormalVerificationProverAgent",
        instructions="""Use formal verification techniques (SMT solvers, symbolic execution)
to prove reachability and validate preconditions.
Generate verification conditions and check satisfiability.""",
        model_tier="frontier",
        model_preference="gpt-4o",
        tools=["smt_solver", "symbolic_executor"],
        stage="prove",
        complexity="deep-reasoning",
    ),

    # ... (more provers for scale)
}

# ============================================================
# ENRICHER AGENTS (Enrich Stage) — 10+ distinct agents
# ============================================================

ENRICHER_AGENTS = {
    "d3fend_enricher": AgentDefinition(
        agent_id="E-001",
        name="D3FEND Enricher",
        agent_class="D3FENDEnricherAgent",
        instructions="""Bind D3FEND defensive techniques to findings.
Map CWE to D3FEND Harden/Detect techniques via the real 271-entry MITRE catalog.
Use ontology_client for verification.""",
        model_tier="balanced",
        model_preference="gpt-4o-mini",
        tools=["d3fend_catalog_loader", "ontology_client"],
        stage="enrich",
        complexity="moderate",
    ),

    "attack_mapper": AgentDefinition(
        agent_id="E-002",
        name="ATT&CK Mapper",
        agent_class="ATTACKMapperAgent",
        instructions="""Map offensive ATT&CK techniques to findings.
Provide threat actor context and attack chain analysis.
Use attack_mapper module for real MITRE data.""",
        model_tier="balanced",
        model_preference="claude-3-haiku",
        tools=["attack_mapper", "threat_intel"],
        stage="enrich",
        complexity="moderate",
    ),

    "exposure_scorer": AgentDefinition(
        agent_id="E-003",
        name="Exposure Scorer",
        agent_class="ExposureScorerAgent",
        instructions="""Calculate real-world exposure score (0-100) for findings.
Use on-chain threat intel, exploit-in-the-wild signals, and deployment prevalence.
Output: exposure_score, threat_actor_likelihood, affected_versions.""",
        model_tier="balanced",
        model_preference="gpt-4o-mini",
        tools=["onchain_threat_intel", "exposure_calculator"],
        stage="enrich",
        complexity="moderate",
    ),

    "compliance_mapper": AgentDefinition(
        agent_id="E-004",
        name="Compliance Mapper",
        agent_class="ComplianceMapperAgent",
        instructions="""Map findings to compliance frameworks.
Use CCI-to-D3FEND NIST SP 800-53 mappings.
Output: compliance_controls, remediation_priorities.""",
        model_tier="distilled",
        model_preference="llama-3-8b",
        tools=["cci_loader", "compliance_analyzer"],
        stage="enrich",
        complexity="simple",
    ),

    "compliance_reporter": AgentDefinition(
        agent_id="E-005",
        name="Compliance Reporter",
        agent_class="ComplianceReporterAgent",
        instructions="""Generate CySA+ Domain 4 aligned compliance reports.
Map findings to ISO 27001, HIPAA, PCI-DSS, GDPR, SOC 2, NIST 800-53.
Produce executive summaries, action plans, KPIs, and stakeholder recommendations.
Track compliance status per framework control with evidence and remediation guidance.""",
        model_tier="balanced",
        model_preference="gpt-4o-mini",
        tools=["compliance_reporter", "cci_loader", "d3fend_catalog_loader"],
        stage="enrich",
        complexity="moderate",
    ),

    "owasp_referencer": AgentDefinition(
        agent_id="E-006",
        name="OWASP Referencer",
        agent_class="OWASPReferencerAgent",
        instructions="""Map findings to OWASP Cheat Sheet Series guidance.
Reference relevant OWASP cheat sheets for each bug class, CWE, and D3FEND technique.
Provide direct links to authoritative remediation guidance.
Coverage: Authentication, Authorization, Cryptography, Input Validation,
APIs, Mobile, AI/ML, IaC, Session Management, and more.""",
        model_tier="distilled",
        model_preference="llama-3-8b",
        tools=["owasp_cheatsheet_mapper", "cwe_mapper", "d3fend_catalog_loader"],
        stage="enrich",
        complexity="simple",
    ),

    # ... (more enrichers for scale)
}

# ============================================================
# TRIAGE AGENTS (Triage Stage) — 10+ distinct agents
# ============================================================

TRIAGE_AGENTS = {
    "severity_triage": AgentDefinition(
        agent_id="T-001",
        name="Severity Triage",
        agent_class="SeverityTriageAgent",
        instructions="""Assign severity scores to findings based on CVSS, exploitability,
impact, and exposure. Route to appropriate priority queue.""",
        model_tier="balanced",
        model_preference="gpt-4o-mini",
        stage="triage",
        complexity="moderate",
    ),

    "owner_assignment": AgentDefinition(
        agent_id="T-002",
        name="Owner Assignment",
        agent_class="OwnerAssignmentAgent",
        instructions="""Assign findings to the correct DevSecOps owner based on code ownership,
component responsibility, and historical assignment patterns.
Output: finding_owner, team, Patch Tuesday target.""",
        model_tier="balanced",
        model_preference="claude-3-haiku",
        stage="triage",
        complexity="moderate",
    ),

    "patch_tuesday_scheduler": AgentDefinition(
        agent_id="T-003",
        name="Patch Tuesday Scheduler",
        agent_class="PatchTuesdaySchedulerAgent",
        instructions="""Schedule findings for Patch Tuesday release.
Coordinate with release management, assess regression risk,
and assign fix deadlines based on severity and exposure.""",
        model_tier="balanced",
        model_preference="gpt-4o-mini",
        stage="triage",
        complexity="moderate",
    ),

    "false_positive_filter": AgentDefinition(
        agent_id="T-004",
        name="False Positive Filter",
        agent_class="FalsePositiveFilterAgent",
        instructions="""Filter probable false positives before human triage.
Use historical patterns, similar findings, and confidence scores.
Route borderline cases to human review.""",
        model_tier="balanced",
        model_preference="llama-3-8b",
        stage="triage",
        complexity="moderate",
    ),

    # ... (more triagers for scale)
}

# ============================================================
# WORKFLOW AGENTS (CI/CD & Repository Operations)
# ============================================================

WORKFLOW_AGENTS = {
    "pr_security_reviewer": AgentDefinition(
        agent_id="W-001",
        name="PR Security Reviewer",
        agent_class="PRSecurityReviewerAgent",
        instructions="""You are a security reviewer for pull requests.

## Goal
Detect and clearly explain real vulnerabilities introduced or exposed by this PR.
Review only added or modified code unless unchanged code is required to prove exploitability.

## Security workflow
1. Inspect the PR diff and surrounding code paths.
2. For every candidate issue, trace attacker-controlled input to the real sink.
3. Verify whether existing controls already block exploitation:
   - auth or permission checks
   - schema validation or type constraints
   - framework escaping
   - ORM parameterization
   - allowlists or bounded constants
4. Report only medium, high, or critical findings with a plausible attack path and concrete code evidence.

## What to look for
Prioritize:
- injection risks
- authn or authz bypasses
- permission-boundary mistakes
- secret leakage or insecure logging
- SSRF, XSS, request forgery, path traversal, and unsafe deserialization
- dependency or supply-chain risk introduced by the change

Do not report speculative concerns, purely stylistic issues, or pre-existing problems unrelated to the PR.

## Response rules
- Review previous unresolved security-review threads from earlier runs.
- Post inline PR comments on exact diff lines for each finding.
- Keep each comment concise: severity, security issue, impact.
- If no high-confidence vulnerability remains, leave no new comments.
- Post a short summary with overall outcome and top findings.
- Do not push changes or open fix PRs from this workflow.""",
        model_tier="frontier",
        model_preference="claude-3.5-sonnet",
        tools=["diff_parser", "code_tracer", "static_analyzer"],
        stage="workflow",
        complexity="deep-reasoning",
    ),

    "appsec_scanner": AgentDefinition(
        agent_id="W-002",
        name="Application Security Scanner",
        agent_class="AppSecScannerAgent",
        instructions="""You are an application-security reviewer for this repository.

## Goal
Find validated medium, high, or critical vulnerabilities with a real end-to-end attack path.

## Review workflow
1. Explore repository structure, key entry points, and critical trust boundaries.
2. Search broadly for likely attack surfaces:
   - auth and authorization flows
   - request handlers and RPC entry points
   - raw SQL, shell execution, file access, and templating
   - external callbacks, webhooks, and network fetches
   - secrets handling and logging paths
3. For every candidate finding, verify exploitability with concrete code tracing.
4. Report only findings you can defend with evidence.

## Persistent finding memory
Before scanning, read `{repository_name}---flagged-vulnerabilities.json`.
If missing, treat as empty history. If present, load before scanning and do not report any vulnerability already present.

Store findings as JSON with a top-level `findings` array. Each finding must include:
- `title`: one-sentence description
- `status`: "active" for newly reported
- `commit_hash`: full git commit hash when detected
- `detected_at_pst`: Pacific-time timestamp with timezone offset
- `reported_link`: link where reported (empty string if unavailable)

After scan, append new validated findings to memory. Do not overwrite blindly if file is corrupted.

## Reporting bar
Every reported issue must include:
- who the attacker is
- what input they control
- how they reach the vulnerable code
- what impact they gain
- one primary `location` file path only

Do not report speculative concerns, isolated unsafe-looking APIs without a real attack path, or low-signal best-practice notes.

## Output
- Post concise summaries with severity, location, impact, and highest-leverage remediation.
- If no new validated medium+ issues found, do not post externally.
- Do not open a PR from this workflow.""",
        model_tier="frontier",
        model_preference="claude-3.5-sonnet",
        tools=["static_analyzer", "taint_tracker", "pattern_matcher", "code_tracer"],
        stage="workflow",
        complexity="deep-reasoning",
    ),

    "test_coverage_agent": AgentDefinition(
        agent_id="W-003",
        name="Test Coverage Agent",
        agent_class="TestCoverageAgent",
        instructions="""You are a test coverage automation focused on preventing regressions.

## Goal
Every run, inspect recent merged code and add missing tests where coverage is weak and business risk is meaningful.

## Prioritization
Prioritize:
- New code paths without tests.
- Bug fixes that only changed production code.
- Edge-case logic, parsing, concurrency, permissions, and data validation.
- Shared utilities and core flows with large blast radius.

Avoid:
- Trivial snapshots with little signal.
- Tests for cosmetic-only changes.
- Refactors that do not change behavior unless critical behavior is now untested.

## Implementation rules
- Follow existing test conventions and fixture patterns.
- Keep tests deterministic and independent.
- Add the minimum set of tests that clearly prove correctness.
- Do not change production behavior unless a tiny testability refactor is required.

## Validation
- Run the relevant test targets for touched areas.
- If tests are flaky or environment-dependent, note it explicitly and avoid merging fragile tests.

## Output
If you create a PR, include:
- Risky behavior now covered
- Test files added/updated
- Why these tests materially reduce regression risk""",
        model_tier="balanced",
        model_preference="gpt-4o-mini",
        tools=["test_runner", "coverage_analyzer", "diff_parser"],
        stage="workflow",
        complexity="moderate",
    ),

    "invariant_monitor": AgentDefinition(
        agent_id="W-004",
        name="Invariant Monitor",
        agent_class="InvariantMonitorAgent",
        instructions="""You are an invariant-monitoring agent for this repository.

## Goal
Detect drift from the engineering and security invariants below.

## Default invariants
1. Sensitive user data, secrets, and tokens must not be logged to production sinks.
2. Permission checks must match the actual read and write capabilities granted by the system.
3. Security-critical behavior should remain consistent across surfaces (API, background jobs, CLI, web).
4. External side effects with meaningful risk should remain behind the intended approval or safety controls.

## Workflow
1. Divide the repository into logical areas and inspect the enforcement path for each invariant.
2. When you suspect drift, double-check the claim with additional code evidence before reporting it.
3. Maintain memory entries per invariant with:
   - current status: enforced, drifted, or inconclusive
   - supporting code references
   - open questions or follow-up checks
4. Report only status changes since the previous run.

## Evidence rules
Any reported regression must include:
- the invariant number
- why the current implementation appears to violate it
- at least two precise code references
- what you did to double-check the claim

If verification is inconclusive, mark it inconclusive instead of asserting drift.""",
        model_tier="frontier",
        model_preference="claude-3.5-sonnet",
        tools=["code_tracer", "static_analyzer", "pattern_matcher", "diff_parser"],
        stage="workflow",
        complexity="deep-reasoning",
    ),
}

# ============================================================
# PREPARE AGENTS — 5+ distinct agents
# ============================================================

PREPARE_AGENTS = {
    "codebase_ingester": AgentDefinition(
        agent_id="PR-001",
        name="Codebase Ingester",
        agent_class="CodebaseIngesterAgent",
        instructions="Ingest and parse codebase. Extract file structure, dependencies, and build system.",
        model_tier="distilled",
        model_preference="mistral-7b",
        stage="prepare",
        complexity="simple",
    ),

    "threat_modeler": AgentDefinition(
        agent_id="PR-002",
        name="Threat Modeler",
        agent_class="ThreatModelerAgent",
        instructions="Build threat model from codebase. Identify high-risk areas, trust boundaries, and attack surfaces.",
        model_tier="frontier",
        model_preference="claude-3.5-sonnet",
        stage="prepare",
        complexity="complex",
    ),

    "language_indexer": AgentDefinition(
        agent_id="PR-003",
        name="Language Indexer",
        agent_class="LanguageIndexerAgent",
        instructions="Index codebase by language. Build cross-reference maps, call graphs, and import trees.",
        model_tier="distilled",
        model_preference="llama-3-8b",
        stage="prepare",
        complexity="simple",
    ),
}

# ============================================================
# DEDUP AGENTS — 5+ distinct agents
# ============================================================

DEDUP_AGENTS = {
    "embedding_generator": AgentDefinition(
        agent_id="DE-001",
        name="Embedding Generator",
        agent_class="EmbeddingGeneratorAgent",
        instructions="Generate embeddings for findings. Use text-embedding-3-small or similar.",
        model_tier="distilled",
        model_preference="mistral-7b",
        stage="dedup",
        complexity="simple",
    ),

    "clustering_engine": AgentDefinition(
        agent_id="DE-002",
        name="Clustering Engine",
        agent_class="ClusteringEngineAgent",
        instructions="Cluster findings by semantic similarity. Use DBSCAN or similar algorithm.",
        model_tier="distilled",
        model_preference="llama-3-8b",
        stage="dedup",
        complexity="simple",
    ),
}

# ============================================================
# MASTER AGENT DEFINITIONS MAP
# ============================================================

ALL_AGENT_DEFINITIONS = {
    **PREPARE_AGENTS,
    **AUDITOR_AGENTS,
    **DEBATER_AGENTS,
    **DEDUP_AGENTS,
    **PROVER_AGENTS,
    **ENRICHER_AGENTS,
    **TRIAGE_AGENTS,
    **WORKFLOW_AGENTS,
}

# Quick stats
AGENT_COUNT = len(ALL_AGENT_DEFINITIONS)
STAGE_COUNTS = {
    "prepare": len(PREPARE_AGENTS),
    "scan": len(AUDITOR_AGENTS),
    "validate": len(DEBATER_AGENTS),
    "dedup": len(DEDUP_AGENTS),
    "prove": len(PROVER_AGENTS),
    "enrich": len(ENRICHER_AGENTS),
    "triage": len(TRIAGE_AGENTS),
    "workflow": len(WORKFLOW_AGENTS),
}
