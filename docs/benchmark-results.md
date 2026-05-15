# MDASH Benchmark Results

## Summary

| Benchmark | Metric | Result |
|-----------|--------|--------|
| **StorageDrive** (private driver, 21 injected bugs) | Recall | **100%** (21/21) |
| | False Positives | **0** |
| **MSRC-CLFS** (28 cases, 5 years) | Retrospective Recall | **96%** |
| **MSRC-tcpip.sys** (7 cases, 5 years) | Retrospective Recall | **100%** |
| **CyberGym** (1,507 tasks, 188 OSS-Fuzz projects) | Success Rate | **88.45%** (leaderboard #1) |
| **Patch Tuesday April 2026** (16 CVEs) | Found by MDASH | **16/16** |

---

## StorageDrive: Private Device Driver

**Dataset**: Microsoft interview device driver with 21 deliberately injected vulnerabilities. Never published, not in any LLM training corpus.

**Vulnerability Mix**:
- 3× Use-After-Free (`CWE-416`)
- 3× Missing Lock / Race Condition (`CWE-362`)
- 3× IOCTL Validation Gap (`CWE-20`)
- 2× Integer Overflow (`CWE-190`)
- 2× Double-Fetch TOCTOU (`CWE-367`)
- 2× Null Pointer Dereference (`CWE-476`)
- 2× Buffer Overflow (`CWE-121`, `CWE-122`)
- 2× Information Disclosure (`CWE-200`)
- 1× Integer Underflow (`CWE-191`)
- 1× Logic Error / Infinite Loop (`CWE-834`)

**Result**: 21/21 found, 0 false positives. Because the codebase is private, all correct findings are evidence of genuine vulnerability discovery reasoning rather than pattern matching from memorized training examples.

---

## MSRC Retrospective Recall

These benchmarks measure whether MDASH would have rediscovered historical MSRC-confirmed bugs had it been running against pre-patch snapshots.

### clfs.sys — 96% Recall (28 cases, 5 years)

Common Log File System (CLFS) is a heavily reviewed Windows kernel component. The 96% recall number is in part a story about the **prove stage**: many CLFS findings look interesting until you try to construct a triggering log file. The CLFS-specific proving plugin knows how to build triggering logs given a candidate finding — it understands the on-disk container layout, block-validation sequence, and in-memory state machine. This is what plugin extensibility is for: the foundation models do not internalize Microsoft-specific filesystem invariants. The plugin embeds them, the model uses them, and the outcome is bugs that survive being proven, not bugs that get filed and forgotten.

### tcpip.sys — 100% Recall (7 cases, 5 years)

The Windows TCP/IP network stack. All 7 MSRC-confirmed cases across 5 years were recovered.

**Why these numbers matter**: MSRC cases represent the ground truth for what real attackers exploited, what required a Patch Tuesday fix, and what defenders had to react to. A system that recovers 96% of a five-year MSRC backlog in a heavily reviewed kernel component is finding the bugs that mattered, not theoretical weaknesses.

**Limitation**: These are retrospective recall benchmarks on internal code with a finite case count. They tell us the system would have been useful had it existed at the time. They do not, by themselves, predict that the next 38 bugs in CLFS will be found at the same rate. The forward-looking signal is the Patch Tuesday cohort itself.

---

## Patch Tuesday Cohort (April 2026)

16 CVEs found by MDASH across the Windows network stack and adjacent services, all patched in April 2026 Patch Tuesday.

**Breakdown**:
- 10 kernel-mode, 6 usermode
- Majority reachable from network position with no credentials
- 2 Critical, 14 Important

### Deep Dive: CVE-2026-33827 — SSRR IPv4 UAF in tcpip.sys

**Type**: Remote unauthenticated use-after-free → potential RCE

**Root cause**: In `Ipv4pReceiveRoutingHeader`, after a routing lookup drops its owned reference to a `Path` object, the same pointer is later reused during Strict Source and Record Route (SSRR) processing. Because the reference count can reach zero at the earlier release, the memory can be reclaimed by the per-processor lookaside allocator and reused, turning the later access into a UAF in kernel context.

**Concurrency model**: Multiple subsystems (path-cache scavenger, explicit flush routines, interface state-driven GC) can concurrently remove the object and drop the final reference. These are not synchronized with the receive-side execution window, and no lock is held.

**Why single-model systems missed this**:
1. The lifetime violation is not locally visible — release and reuse are separated by non-trivial control flow (alternate branches, validation checks, early-drop conditions)
2. The decisive signal lives elsewhere in the codebase: the same logical operation appears with the correct order at another call-site
3. Reachability requires composing multiple conditions (SSRR flag, default config, concurrent subsystems reclaiming during the exposed window)

A staged pipeline with cross-file pattern comparison and multi-model debate surfaces these inconsistencies.

### Deep Dive: CVE-2026-33824 — IKEv2 Double-Free in ikeext.dll

**Type**: Unauthenticated double-free → LocalSystem RCE

**Root cause**: When IKEEXT reinjects a reassembled fragment back through its receive pipeline, it duplicates the packet's receive context with a flat `memcpy`. This is a shallow copy — it clones struct bytes but not heap allocations pointed to. Both the queued context and the live Main Mode SA hold the same pointer to the attacker-supplied security-realm identifier, and both believe they own it. On teardown, each frees it.

**Trigger**: Two UDP packets, no race, no special timing. IKEEXT runs as LocalSystem in `svchost.exe`.

**Why single-model systems missed this**:
1. The aliasing lifecycle bug spans **6 source files** (ike_A.c through ike_F.c)
2. The strongest evidence is the **correct version of the same pattern** in `ike_D.c` — immediately after the memcpy of the selector, the code does the right thing
3. Catching this requires recognizing the missing step at one site by reference to the present step at another

Our specialized auditor agents surface exactly these cross-file comparisons; the debate stage forces them to stand up under cross-examination.

---

## CyberGym Public Benchmark

**Dataset**: 1,507 real-world vulnerability reproduction tasks from 188 OSS-Fuzz projects.

**Result**: **88.45%** success rate — highest on CyberGym's published leaderboard at time of writing, roughly 5 points above the next entry (83.1%).

**Models used**: Generally available models (no special access).

**Key insight**: The strong results suggest the surrounding **agentic system contributes substantially beyond raw model capability**.

### Failure Analysis (~12%)

Two structural patterns dominate failures:

1. **Wrong code area** (82% of these): Tasks with vague descriptions lacking function or file identifiers. The scan agent targets the wrong location.
   - *Implication*: Description quality is a major factor in scan accuracy.
   - *Pending feature*: Pre-processing agent for task descriptions — parse vague tasks, query code index for candidate files/functions, inject identifiers before scan stage.

2. **Harness format mismatch**: Agent constructs libFuzzer-style inputs, but the benchmark task requires honggfuzz-format inputs. Otherwise sound reproductions fail on format mismatch.
   - *Implication*: Fuzzer format awareness is needed before prove stage.
   - *Pending feature*: Harness format detector — fingerprint benchmark task to determine required fuzzer format (libFuzzer, honggfuzz, AFL++, etc.) before prove stage.

---

## What These Numbers Mean

### What they claim
- The MDASH pipeline, with its multi-model ensemble, specialized agents, and extensible plugins, can approximate professional offensive security researcher capabilities on unseen code
- The agentic architecture (not just raw model capability) contributes substantially to end-to-end performance
- Plugin extensibility is essential for domain-specific invariants (CLFS on-disk layout, kernel calling conventions, etc.)

### What they do NOT claim
- Retrospective recall does not predict forward-looking performance on the next N bugs
- 88.45% on CyberGym does not mean 88.45% on arbitrary real-world code
- Results on Windows kernel components do not generalize to all codebases equally

### The forward-looking signal
The Patch Tuesday cohort itself is the strongest forward-looking evidence: these are bugs found in actively maintained, heavily reviewed production code and confirmed by MSRC before patch release.

---

## Reproducibility

Every benchmark run produces:
- `manifest.json` — target hash, model IDs, temperatures, random seeds, cost ledger
- `hypotheses.jsonl` — all Stage 2 emissions
- `validation_traces/` — raw tool-oracle outputs, debate transcripts
- `findings.json` — final validated set with D3FEND + ATT&CK bindings
- `d3fend-coverage-delta.md` — techniques exercised in the run

This kit makes the "no human guided the scan" claim verifiable for grant applications and publications.
