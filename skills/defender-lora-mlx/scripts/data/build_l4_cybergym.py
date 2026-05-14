#!/usr/bin/env python3
"""
build_l4_cybergym.py
====================

Project Raven -- L4 Corpus Builder: CyberGym dataset -> defender-only JSONL.

Source
------
CyberGym by sunblaze-ucb (Apache 2.0).
  Repo:    https://github.com/sunblaze-ucb/cybergym
  Dataset: https://huggingface.co/datasets/sunblaze-ucb/cybergym
  Paper:   arXiv:2506.02548  "CyberGym: Evaluating AI Agents' Real-World
           Cybersecurity Capabilities at Scale"

1,507 real vulnerability instances across 188 OSS projects with ASan/UBSan
validation (1,368 ARVO + 139 OSS-Fuzz tasks).

What this builder does
----------------------
For each CyberGym task that has description.txt, error.txt, AND patch.diff
(i.e. tasks available at level3 difficulty), emit one or more of four
defender-only JSONL samples under the following CDP-grounded templates:

  L4-cybergym_cwe_classify    description.txt -> CWE id + D3FEND artifact
                              name + 1-paragraph defender rationale.
  L4-cybergym_d3fend_map      description.txt -> ranked top-3 D3FEND
                              defensive technique names.
  L4-cybergym_root_cause      (description.txt, error.txt) -> root-cause-
                              analysis paragraph + suggested fix area.
                              error.txt is an ASan/UBSan sanitizer trace,
                              which is defender-frame; safe to include.
  L4-cybergym_patch_rationale patch.diff -> defender-style explanation
                              grounded in CWE + D3FEND artifact + CISA
                              Secure-by-Design tactic. Mirror of L4-
                              diff_explain in build_l4_ossf_cve.py. This
                              is the most important template.

Strict defender-only enforcement
---------------------------------
Rule A (hard constraint -- never emit a sample that contains):
  - PoC bytes, fuzzer seeds, or crashing inputs
  - submit.sh content or submission workflow language
  - raw hex byte sequences \\x.. of length 8 or more characters
  - exploit construction language

Rule B: only the four asymmetric defender-side projections above are emitted.

No source-mode uses repo-vul.tar.gz or the PoC evaluation workflow.

Source modes
------------
Two modes are supported because the full dataset is approximately 240 GB:

  mode=hf-metadata (default): pull only the lightweight metadata fields
    (vulnerability_description, task_difficulty dict with file paths) from
    the HuggingFace dataset using the 'datasets' library if installed,
    OR fall back to fetching the HF Parquet/JSON data listing via HTTP.
    This avoids downloading the 240 GB binary tarball.

  mode=local: walk a local directory of unpacked task subdirectories.
    Each subdirectory is named by its task ID (e.g. "arvo:10400") and
    contains description.txt, error.txt, and patch.diff at minimum.

CDP grounding
-------------
CDP grounding triple: tau (task), model, ledger.
  tau  -- the defender task is: explain what defensive control is realized
          by the patch, grounded in D3FEND OWL.
  model -- the base model being fine-tuned (Qwen2.5-7B-Instruct or
           Qwen2.5-Coder-14B-Instruct).
  ledger -- the CyberGym task_id + HuggingFace dataset commit anchors
           every sample to a reproducible upstream source.

Doctrine references
-------------------
  CISA et al., "Shifting the Balance of Cybersecurity Risk: Principles and
    Approaches for Security-by-Design and -Default" (April 2023).
    https://www.cisa.gov/sites/default/files/2023-10/SecureByDesign_1025_508c.pdf

  Xint / Theori, "You Don't Need Mythos. You Need a System." (April 2026).
    https://xint.io
    Cited per BENCHMARKS.md section 11; the "system over mythos" framing
    grounds why vuln discovery is a structured defender pipeline, not a
    single model trick.

Usage
-----
    # HuggingFace metadata mode (no large download required):
    python build_l4_cybergym.py \\
        --out data/l4_cybergym.jsonl \\
        --source hf:sunblaze-ucb/cybergym \\
        --max-tasks 200 \\
        --workers 4 \\
        --strict -v

    # Local mode (pre-downloaded task directories):
    python build_l4_cybergym.py \\
        --out data/l4_cybergym.jsonl \\
        --source /path/to/cybergym_data/data \\
        --max-tasks 0 \\
        --workers 8

Exit codes
----------
    0  success, JSONL written
    1  network or fetch error
    2  defender-only validator rejected the corpus (in --strict mode)
    3  invalid CLI arguments

The script is offline-resumable: a small cache directory holds fetched
blobs so reruns are cheap. Set --no-cache to force fresh fetches.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import dataclasses
import hashlib
import json
import logging
import os
import pathlib
import random
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Iterator

# ---------------------------------------------------------------------------
# Defender-only validator
# SHARED with build_l1_d3fend.py and build_l4_ossf_cve.py -- keep in sync
# ---------------------------------------------------------------------------
# When updating, update all three files and run tests/test_defender_only.py.

OFFENSIVE_LEAK_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"here is the (payload|exploit|shellcode)",
        r"\bmsfconsole\b",
        r"\bmeterpreter\b",
        r"generate (a |the )?shellcode",
        r"bypass the (waf|av|edr|firewall|sandbox)",
        r"\b(reverse|bind) shell payload\b",
        r"\bmimikatz\b",
        r"cobalt strike beacon",
        r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){7,}",
        r"\bweaponi[sz]e\b",
        r"how to (exploit|weaponi[sz]e|attack)",
        r"write (an |the )?exploit for",
        r"craft (an |a )?(exploit|payload)",
        r"rop chain\b.*\bbuild",
    )
)

BANNED_BASES = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"heretic",
        r"abliterated",
        r"uncensored",
        r"dolphin-uncensored",
        r"jailbreak",
    )
)

# Files we never train on -- these are noisy and rarely teach defender
# semantics (lockfiles, changelogs, test fixtures, binary assets, etc.).
SKIP_FILE_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"(^|/)package(-lock)?\.json$",
        r"(^|/)yarn\.lock$",
        r"(^|/)pnpm-lock\.ya?ml$",
        r"(^|/)go\.sum$",
        r"(^|/)cargo\.lock$",
        r"(^|/)composer\.lock$",
        r"(^|/)gemfile\.lock$",
        r"(^|/)poetry\.lock$",
        r"(^|/)\.gitignore$",
        r"(^|/)changelog(\.[a-z]+)?$",
        r"(^|/)license(\.[a-z]+)?$",
        r"(^|/)readme(\.[a-z]+)?$",
        r"\.(png|jpg|jpeg|gif|webp|ico|pdf|zip|tar|gz|exe|dll|so)$",
        r"(^|/)test/",
        r"(^|/)tests/",
        r"(^|/)__tests__/",
        r"(^|/)spec/",
        r"\.test\.[jt]sx?$",
        r"\.spec\.[jt]sx?$",
    )
)

# Additional CyberGym-specific patterns that signal offensive PoC framing.
# These fire when description.txt or error.txt contains words that would
# shift the training sample out of the defender frame.
POC_SIGNAL_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"\bsubmit\.sh\b",
        r"\bpoc\b.*\bcrash",
        r"\bcrash(ing)? input\b",
        r"\bfuzzer seed\b",
        r"\bexploit (the|this) (vuln|bug|crash|issue)\b",
        r"\bcrafted input\b",
        r"\bmalicious input\b.*\btrigger\b",
        r"\btrigger.*\bexploit\b",
    )
)


def contains_offensive_leak(text: str) -> str | None:
    """Return the first matched pattern string or None. Used by --strict."""
    if not text:
        return None
    for pat in OFFENSIVE_LEAK_PATTERNS:
        m = pat.search(text)
        if m:
            return pat.pattern
    return None


def contains_poc_signal(text: str) -> str | None:
    """Return the first CyberGym PoC-signal pattern matched, or None."""
    if not text:
        return None
    for pat in POC_SIGNAL_PATTERNS:
        m = pat.search(text)
        if m:
            return pat.pattern
    return None


def is_banned_base(name: str) -> bool:
    return any(p.search(name) for p in BANNED_BASES)


def should_skip_file(path: str) -> bool:
    return any(p.search(path) for p in SKIP_FILE_PATTERNS)


# ---------------------------------------------------------------------------
# CWE -> D3FEND artifact / CISA SbD tactic mapping
# SHARED with build_l4_ossf_cve.py -- keep in sync
# ---------------------------------------------------------------------------
# Small, hand-curated table.  Only the CWEs we actually expect to see in
# memory-safety and parsing bugs (the primary CyberGym corpus) are mapped;
# everything else falls back to "Software Component Hardening".  The mapping
# is intentionally conservative: each entry must correspond to a real D3FEND
# defensive technique present in v1.0 OWL.

CWE_DEFEND_MAP: dict[str, dict[str, str]] = {
    "CWE-022": {
        "name": "Path Traversal",
        "d3fend": "Input Validation / Authorization Event Thresholding",
        "sbd": "Eliminate entire classes of vulnerabilities via memory-safe parsing and canonical-path APIs.",
    },
    "CWE-077": {
        "name": "Command Injection",
        "d3fend": "Input Validation / Process Spawn Analysis",
        "sbd": "Provide parameterized APIs by default; reject string-concatenated shell invocation.",
    },
    "CWE-078": {
        "name": "OS Command Injection",
        "d3fend": "Input Validation / Process Spawn Analysis",
        "sbd": "Provide parameterized APIs by default; reject string-concatenated shell invocation.",
    },
    "CWE-079": {
        "name": "Cross-Site Scripting",
        "d3fend": "Output Encoding / Content Security Policy",
        "sbd": "Make context-aware output encoding the default in the framework.",
    },
    "CWE-089": {
        "name": "SQL Injection",
        "d3fend": "Input Validation / Database Query String Analysis",
        "sbd": "Parameterized queries are the only supported API; raw string queries require an opt-in flag.",
    },
    "CWE-094": {
        "name": "Code Injection",
        "d3fend": "Process Spawn Analysis / Script Execution Analysis",
        "sbd": "Disable dynamic code evaluation by default; require explicit opt-in.",
    },
    "CWE-116": {
        "name": "Improper Encoding or Escaping of Output",
        "d3fend": "Output Encoding",
        "sbd": "Context-aware encoding is the framework default.",
    },
    "CWE-119": {
        "name": "Out-of-bounds Memory Access",
        "d3fend": "Memory Boundary Tracking / Stack Frame Canary Validation",
        "sbd": "Adopt memory-safe languages or runtime bounds checking by default.",
    },
    "CWE-120": {
        "name": "Classic Buffer Overflow",
        "d3fend": "Memory Boundary Tracking",
        "sbd": "Replace unbounded copy APIs with size-aware equivalents.",
    },
    "CWE-121": {
        "name": "Stack-based Buffer Overflow",
        "d3fend": "Memory Boundary Tracking / Stack Frame Canary Validation",
        "sbd": "Adopt memory-safe languages or compiler stack-protection by default.",
    },
    "CWE-122": {
        "name": "Heap-based Buffer Overflow",
        "d3fend": "Memory Boundary Tracking",
        "sbd": "Use heap-safe allocators or memory-safe languages; enable ASLR and guard pages.",
    },
    "CWE-125": {
        "name": "Out-of-bounds Read",
        "d3fend": "Memory Boundary Tracking",
        "sbd": "Adopt memory-safe parsing for untrusted input.",
    },
    "CWE-134": {
        "name": "Uncontrolled Format String",
        "d3fend": "Input Validation / Memory Boundary Tracking",
        "sbd": "Forbid user-controlled format strings; use typed format APIs.",
    },
    "CWE-190": {
        "name": "Integer Overflow",
        "d3fend": "Input Validation / Memory Boundary Tracking",
        "sbd": "Use checked arithmetic by default for size calculations.",
    },
    "CWE-191": {
        "name": "Integer Underflow",
        "d3fend": "Input Validation / Memory Boundary Tracking",
        "sbd": "Use checked arithmetic with underflow detection for unsigned sizes.",
    },
    "CWE-200": {
        "name": "Exposure of Sensitive Information",
        "d3fend": "Authorization Event Thresholding / Information Flow Control",
        "sbd": "Default to least-privilege output filtering; require opt-in to expose debug data.",
    },
    "CWE-208": {
        "name": "Observable Timing Discrepancy",
        "d3fend": "Information Flow Control",
        "sbd": "Use constant-time comparisons for secret material.",
    },
    "CWE-269": {
        "name": "Improper Privilege Management",
        "d3fend": "Authorization Event Thresholding",
        "sbd": "Default deny on privilege escalation paths.",
    },
    "CWE-287": {
        "name": "Improper Authentication",
        "d3fend": "Credential Hardening / Multi-factor Authentication",
        "sbd": "Strong authentication on by default for sensitive operations.",
    },
    "CWE-295": {
        "name": "Improper Certificate Validation",
        "d3fend": "Certificate Analysis",
        "sbd": "TLS certificate validation enabled by default; hostname verification non-optional.",
    },
    "CWE-326": {
        "name": "Inadequate Encryption Strength",
        "d3fend": "Certificate Analysis / Strong Password Policy",
        "sbd": "Reject weak algorithms by default; require explicit allowlist.",
    },
    "CWE-327": {
        "name": "Broken or Risky Crypto",
        "d3fend": "Certificate Analysis",
        "sbd": "Default cryptographic primitives are vetted and current.",
    },
    "CWE-352": {
        "name": "Cross-Site Request Forgery",
        "d3fend": "Authentication Event Thresholding / Session Cookie Authentication",
        "sbd": "CSRF tokens on by default for state-changing requests.",
    },
    "CWE-369": {
        "name": "Divide By Zero",
        "d3fend": "Input Validation",
        "sbd": "Validate divisor is non-zero before arithmetic; fail-safe on parse error.",
    },
    "CWE-400": {
        "name": "Resource Exhaustion",
        "d3fend": "Resource Access Pattern Analysis",
        "sbd": "Per-request resource bounds enabled by default.",
    },
    "CWE-401": {
        "name": "Memory Leak",
        "d3fend": "Memory Boundary Tracking",
        "sbd": "Use RAII / smart-pointer ownership by default; auditable with Valgrind or ASan.",
    },
    "CWE-415": {
        "name": "Double Free",
        "d3fend": "Memory Boundary Tracking",
        "sbd": "Adopt memory-safe allocators or language guarantees.",
    },
    "CWE-416": {
        "name": "Use After Free",
        "d3fend": "Memory Boundary Tracking",
        "sbd": "Adopt memory-safe allocators or language guarantees.",
    },
    "CWE-434": {
        "name": "Unrestricted File Upload",
        "d3fend": "Input Validation / File Content Analysis",
        "sbd": "Default deny on executable upload paths; allowlist by MIME and extension.",
    },
    "CWE-476": {
        "name": "NULL Pointer Dereference",
        "d3fend": "Memory Boundary Tracking",
        "sbd": "Validate pointer before dereference; use non-nullable reference types where available.",
    },
    "CWE-502": {
        "name": "Deserialization of Untrusted Data",
        "d3fend": "Input Validation / Process Spawn Analysis",
        "sbd": "Default to data-only deserializers; require explicit opt-in for code-bearing formats.",
    },
    "CWE-601": {
        "name": "URL Redirection to Untrusted Site",
        "d3fend": "Input Validation",
        "sbd": "Allowlist redirect targets by default.",
    },
    "CWE-611": {
        "name": "XML External Entity",
        "d3fend": "Input Validation",
        "sbd": "Disable external entity resolution by default in XML parsers.",
    },
    "CWE-680": {
        "name": "Integer Overflow to Buffer Overflow",
        "d3fend": "Memory Boundary Tracking / Input Validation",
        "sbd": "Use checked arithmetic before allocation size computations.",
    },
    "CWE-704": {
        "name": "Incorrect Type Conversion",
        "d3fend": "Input Validation",
        "sbd": "Fail-safe on narrowing casts; prefer same-width typed APIs.",
    },
    "CWE-732": {
        "name": "Incorrect Permission Assignment",
        "d3fend": "Authorization Event Thresholding",
        "sbd": "Least-privilege defaults; opt-in to broader permissions.",
    },
    "CWE-787": {
        "name": "Out-of-bounds Write",
        "d3fend": "Memory Boundary Tracking",
        "sbd": "Adopt memory-safe languages or bounds-checked APIs.",
    },
    "CWE-788": {
        "name": "Access of Memory Location After End of Buffer",
        "d3fend": "Memory Boundary Tracking",
        "sbd": "Replace manual pointer arithmetic with bounds-safe abstractions.",
    },
    "CWE-798": {
        "name": "Hard-coded Credentials",
        "d3fend": "Credential Hardening",
        "sbd": "No default credentials shipped; force secret generation at install.",
    },
    "CWE-824": {
        "name": "Access of Uninitialized Pointer",
        "d3fend": "Memory Boundary Tracking",
        "sbd": "Initialize all pointers; use compiler warnings for uninitialized use.",
    },
    "CWE-843": {
        "name": "Type Confusion",
        "d3fend": "Memory Boundary Tracking / Input Validation",
        "sbd": "Use strongly-typed APIs; forbid unchecked casts between unrelated types.",
    },
    "CWE-862": {
        "name": "Missing Authorization",
        "d3fend": "Authorization Event Thresholding",
        "sbd": "Default deny; explicit allow on every protected endpoint.",
    },
    "CWE-863": {
        "name": "Incorrect Authorization",
        "d3fend": "Authorization Event Thresholding",
        "sbd": "Centralized authorization layer; route-local checks forbidden.",
    },
    "CWE-918": {
        "name": "Server-Side Request Forgery",
        "d3fend": "Input Validation / Outbound Traffic Filtering",
        "sbd": "Outbound network egress allowlist by default.",
    },
    "CWE-1188": {
        "name": "Insecure Default Initialization of Resource",
        "d3fend": "Configuration Hardening",
        "sbd": "Secure defaults required; insecure modes opt-in only.",
    },
    "CWE-1333": {
        "name": "Inefficient Regex Complexity (ReDoS)",
        "d3fend": "Resource Access Pattern Analysis",
        "sbd": "Use linear-time regex engines or compile-time complexity bounds.",
    },
}

DEFAULT_CWE_ENTRY = {
    "name": "Software Weakness",
    "d3fend": "Software Component Hardening",
    "sbd": (
        "Apply the CISA Secure-by-Design principles: take ownership of customer "
        "security outcomes, eliminate entire classes of vulnerabilities, ship "
        "secure defaults, and provide hardening guides instead of loosening guides."
    ),
}

# Infer CWE from sanitizer trace keywords when the description does not
# name a CWE.  Only the most reliable signal words are listed.
_ERROR_CWE_HINTS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bheap.buffer.overflow\b", re.IGNORECASE), "CWE-122"),
    (re.compile(r"\bstack.buffer.overflow\b", re.IGNORECASE), "CWE-121"),
    (re.compile(r"\bbuffer.overflow\b", re.IGNORECASE), "CWE-120"),
    (re.compile(r"\bout.of.bounds.write\b", re.IGNORECASE), "CWE-787"),
    (re.compile(r"\bout.of.bounds.read\b", re.IGNORECASE), "CWE-125"),
    (re.compile(r"\buse.after.free\b", re.IGNORECASE), "CWE-416"),
    (re.compile(r"\bdouble.free\b", re.IGNORECASE), "CWE-415"),
    (re.compile(r"\bnull.?pointer.dereference\b", re.IGNORECASE), "CWE-476"),
    (re.compile(r"\bmemory.leak\b", re.IGNORECASE), "CWE-401"),
    (re.compile(r"\binteger.overflow\b", re.IGNORECASE), "CWE-190"),
    (re.compile(r"\binteger.underflow\b", re.IGNORECASE), "CWE-191"),
    (re.compile(r"\bformat.string\b", re.IGNORECASE), "CWE-134"),
    (re.compile(r"\bdivide.by.zero\b", re.IGNORECASE), "CWE-369"),
    (re.compile(r"\btype.confusion\b", re.IGNORECASE), "CWE-843"),
    (re.compile(r"\buninitialized\b", re.IGNORECASE), "CWE-824"),
]


def cwe_from_error_txt(error_text: str) -> str | None:
    """Guess a CWE from an ASan/UBSan trace.  Returns None if uncertain."""
    for pat, cwe in _ERROR_CWE_HINTS:
        if pat.search(error_text):
            return cwe
    return None


def cwe_lookup(cwe_hint: str | None, error_text: str = "") -> dict[str, str]:
    """Resolve CWE string to a mapping entry, falling back to error.txt hints
    and finally the default entry."""
    if cwe_hint:
        m = re.match(r"^CWE-(\d+)$", cwe_hint.strip(), re.IGNORECASE)
        if m:
            key = f"CWE-{int(m.group(1)):03d}"
            if key in CWE_DEFEND_MAP:
                return {"cwe": key, **CWE_DEFEND_MAP[key]}
    # Fall back to error.txt heuristic
    guessed = cwe_from_error_txt(error_text)
    if guessed and guessed in CWE_DEFEND_MAP:
        return {"cwe": guessed, **CWE_DEFEND_MAP[guessed]}
    # Last resort
    fallback_cwe = cwe_hint if cwe_hint else "CWE-000"
    return {"cwe": fallback_cwe, **DEFAULT_CWE_ENTRY}


# ---------------------------------------------------------------------------
# System prompts (defender-only)
# SHARED with build_l4_ossf_cve.py -- keep in sync
# ---------------------------------------------------------------------------

SYSTEM_DEFENDER = (
    "You are Raven, a defender-only security AI grounded in three pillars: "
    "(1) the CDP grounding triple tau (task), model, ledger; "
    "(2) MITRE D3FEND v1.0 OWL as the canonical defender vocabulary; "
    "(3) the CISA et al. Secure-by-Design and Secure-by-Default principles "
    "(April 2023). You do not produce exploits, proof-of-concept payloads, "
    "shellcode, or offensive tooling. You translate every finding into a "
    "named D3FEND artifact and a concrete remediation. When a request strays "
    "into exploit construction, you refuse and redirect to the defender frame."
)

SYSTEM_REVIEW = (
    "You are Raven in code-review mode. Your output must read like a senior "
    "secure-code reviewer: concise bullets, each tied to a CWE and a D3FEND "
    "artifact, with hardening guidance (never loosening). Do not propose how "
    "to exploit the weakness."
)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class CyberGymTask:
    """All metadata needed to emit defender-only training samples."""

    task_id: str            # e.g. "arvo:10400" or "oss-fuzz:42535201"
    project_name: str       # upstream project name (e.g. "libpng")
    project_language: str   # "c", "c++", etc.
    description: str        # content of description.txt
    error_txt: str          # content of error.txt (ASan/UBSan trace)
    patch_diff: str         # content of patch.diff
    cwe_hint: str | None    # CWE-XXX if parseable from description, else None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="build_l4_cybergym",
        description=(
            "Build the L4 defender-only JSONL corpus from the CyberGym dataset "
            "(Rule A + Rule B, no PoC, no offensive framing)."
        ),
    )
    p.add_argument(
        "--out", type=pathlib.Path, required=True,
        help="Output JSONL path.",
    )
    p.add_argument(
        "--source", default="hf:sunblaze-ucb/cybergym",
        help=(
            "Data source.  Either 'hf:<org>/<dataset>' for HuggingFace metadata "
            "mode, or a local directory path containing per-task subdirectories "
            "(mode=local).  Default: hf:sunblaze-ucb/cybergym"
        ),
    )
    p.add_argument(
        "--max-tasks", type=int, default=0,
        help="Process at most N tasks (0 = all).",
    )
    p.add_argument(
        "--workers", type=int, default=4,
        help="Concurrent fetch workers (HF mode only).",
    )
    p.add_argument(
        "--cache-dir", type=pathlib.Path,
        default=pathlib.Path(".cache/cybergym"),
        help="Cache directory for fetched blobs.",
    )
    p.add_argument(
        "--no-cache", action="store_true",
        help="Bypass cache and re-fetch.",
    )
    p.add_argument(
        "--seed", type=int, default=20260515,
        help="Random seed for shuffling.  Default: 20260515.",
    )
    p.add_argument(
        "--strict", action="store_true",
        help="Abort with exit code 2 if the validator rejects any emitted sample.",
    )
    p.add_argument(
        "--github-token", default=os.environ.get("GITHUB_TOKEN"),
        help="Optional GitHub token for lifting API rate limits (env GITHUB_TOKEN).",
    )
    p.add_argument(
        "-v", "--verbose", action="count", default=0,
        help="Increase verbosity (-v info, -vv debug).",
    )
    args = p.parse_args(argv)

    if args.workers < 1:
        p.error("--workers must be >= 1")
    if args.max_tasks < 0:
        p.error("--max-tasks must be >= 0")
    return args


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

HF_DATASETS_API = "https://datasets-server.huggingface.co"
HF_RAW = "https://huggingface.co/datasets"


class FetchError(RuntimeError):
    pass


def _cache_path(cache_dir: pathlib.Path, url: str) -> pathlib.Path:
    h = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
    return cache_dir / h[:2] / h


def http_get(
    url: str,
    *,
    token: str | None,
    cache_dir: pathlib.Path,
    use_cache: bool,
    accept: str | None = None,
    max_retries: int = 4,
) -> bytes:
    """Fetch URL with caching and exponential back-off."""
    if use_cache:
        cp = _cache_path(cache_dir, url)
        if cp.exists():
            return cp.read_bytes()

    headers: dict[str, str] = {
        "User-Agent": (
            "raven-d3fend-l4-cybergym-builder/1.0 "
            "(+https://github.com/daemon-blockint-tech/project-raven-d3fend)"
        ),
    }
    if accept:
        headers["Accept"] = accept
    if token:
        headers["Authorization"] = f"Bearer {token}"

    last_err: Exception | None = None
    for attempt in range(max_retries):
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = resp.read()
                if use_cache:
                    cp = _cache_path(cache_dir, url)
                    cp.parent.mkdir(parents=True, exist_ok=True)
                    cp.write_bytes(data)
                return data
        except urllib.error.HTTPError as e:
            last_err = e
            if e.code == 404:
                if use_cache:
                    cp = _cache_path(cache_dir, url)
                    cp.parent.mkdir(parents=True, exist_ok=True)
                    cp.write_bytes(b"")
                return b""
            if e.code in (403, 429, 502, 503, 504):
                sleep = min(60, 2 ** attempt + random.random())
                logging.warning("HTTP %s on %s; backing off %.1fs", e.code, url, sleep)
                time.sleep(sleep)
                continue
            raise FetchError(f"HTTP {e.code} for {url}") from e
        except urllib.error.URLError as e:
            last_err = e
            sleep = min(30, 2 ** attempt + random.random())
            logging.warning("URLError on %s: %s; retry in %.1fs", url, e, sleep)
            time.sleep(sleep)
            continue
    raise FetchError(f"failed after {max_retries} retries: {url} ({last_err})")


# ---------------------------------------------------------------------------
# CWE extraction from description text
# ---------------------------------------------------------------------------

_CWE_RE = re.compile(r"\b(CWE-\d{1,5})\b", re.IGNORECASE)


def extract_cwe_from_description(description: str) -> str | None:
    """Return the first CWE-XXX mention in description.txt, or None."""
    m = _CWE_RE.search(description)
    if m:
        raw = m.group(1).upper()
        # Normalize to 3-digit minimum: CWE-22 -> CWE-022
        num = int(raw.split("-")[1])
        return f"CWE-{num:03d}"
    return None


# ---------------------------------------------------------------------------
# HuggingFace metadata mode
# ---------------------------------------------------------------------------


def _try_hf_datasets_library(
    hf_slug: str,
    *,
    max_tasks: int,
    cache_dir: pathlib.Path,
    rng: random.Random,
) -> list[CyberGymTask] | None:
    """
    Try to load tasks via the 'datasets' library (pip install datasets).
    Returns a list of CyberGymTask on success, or None if the library is
    not installed or fails.

    The HuggingFace dataset card documents these fields:
      task_id, project_name, project_homepage, project_main_repo,
      project_language, vulnerability_description, task_difficulty

    task_difficulty is a dict keyed by level (level0..level3), each value
    being a list of file paths relative to the dataset data/ directory.
    At level3 all three artifacts are present.
    """
    try:
        import datasets as hf_datasets  # type: ignore[import]
    except ImportError:
        logging.debug("'datasets' library not installed; skipping HF library mode")
        return None

    try:
        logging.info("loading HF dataset '%s' (streaming to avoid 240 GB download)", hf_slug)
        ds = hf_datasets.load_dataset(
            hf_slug,
            split="train",
            streaming=True,
            trust_remote_code=False,
        )
    except Exception as e:
        logging.warning("hf_datasets.load_dataset failed: %s", e)
        return None

    tasks: list[CyberGymTask] = []
    for row in ds:
        # Only rows that have level3 task_difficulty have all three artifacts.
        td = row.get("task_difficulty") or {}
        if not td.get("level3"):
            continue

        task_id = row.get("task_id") or ""
        if not task_id:
            continue

        description = row.get("vulnerability_description") or ""
        if not description.strip():
            logging.debug("skipping %s: empty description", task_id)
            continue

        # At this point we only have the vulnerability_description field from
        # the HF row.  The error.txt and patch.diff bytes are stored as large
        # binary artifacts (inside repo tarballs) that require the full data
        # download.  We cannot load them via streaming.
        #
        # Strategy: emit what we can from description alone (cwe_classify,
        # d3fend_map) and mark the task as description-only so the caller
        # knows to skip templates that require error.txt / patch.diff.
        cwe_hint = extract_cwe_from_description(description)

        tasks.append(CyberGymTask(
            task_id=task_id,
            project_name=row.get("project_name") or "",
            project_language=row.get("project_language") or "",
            description=description,
            error_txt="",    # not available in HF streaming mode
            patch_diff="",   # not available in HF streaming mode
            cwe_hint=cwe_hint,
        ))

        if max_tasks > 0 and len(tasks) >= max_tasks:
            break

    logging.info("hf_datasets library yielded %d tasks (description-only)", len(tasks))
    return tasks if tasks else None


def _load_hf_metadata_http(
    hf_slug: str,
    *,
    token: str | None,
    cache_dir: pathlib.Path,
    use_cache: bool,
    max_tasks: int,
) -> list[CyberGymTask]:
    """
    Fall-back path: fetch the CyberGym Parquet row listing via the HF
    datasets server API and return tasks that have all three text artifacts
    available as fields in the row.  This is a lightweight path that does
    not download the 240 GB binary tarballs.

    If the HF datasets server does not expose the full artifact content
    (which is the likely case for binary-heavy datasets), we log a warning
    and return an empty list so the caller can fall back to local mode.
    """
    # First check whether the datasets server has valid rows
    rows_url = (
        f"{HF_DATASETS_API}/rows?dataset={urllib.parse.quote(hf_slug)}"
        f"&config=default&split=train&offset=0&length=100"
    )
    logging.info("probing HF datasets server: %s", rows_url)
    try:
        raw = http_get(
            rows_url,
            token=token,
            cache_dir=cache_dir,
            use_cache=use_cache,
            accept="application/json",
        )
    except FetchError as e:
        logging.warning("HF datasets server fetch failed: %s", e)
        return []

    if not raw:
        logging.warning("HF datasets server returned empty response for %s", hf_slug)
        return []

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as e:
        logging.warning("HF datasets server JSON parse error: %s", e)
        return []

    rows = payload.get("rows") or []
    if not rows:
        logging.warning("HF datasets server returned no rows for %s", hf_slug)
        return []

    tasks: list[CyberGymTask] = []
    for item in rows:
        row = item.get("row") or {}
        task_id = row.get("task_id") or ""
        if not task_id:
            continue

        description = row.get("vulnerability_description") or ""
        if not description.strip():
            continue

        # Check level3 availability
        td = row.get("task_difficulty") or {}
        if not td.get("level3"):
            continue

        cwe_hint = extract_cwe_from_description(description)
        tasks.append(CyberGymTask(
            task_id=task_id,
            project_name=row.get("project_name") or "",
            project_language=row.get("project_language") or "",
            description=description,
            error_txt="",
            patch_diff="",
            cwe_hint=cwe_hint,
        ))
        if max_tasks > 0 and len(tasks) >= max_tasks:
            break

    logging.info("HF HTTP API yielded %d tasks (description-only)", len(tasks))
    return tasks


def load_hf_tasks(
    hf_slug: str,
    *,
    token: str | None,
    cache_dir: pathlib.Path,
    use_cache: bool,
    max_tasks: int,
    rng: random.Random,
) -> list[CyberGymTask]:
    """
    Load tasks from HuggingFace.  Tries the 'datasets' library first, then
    falls back to the HF datasets server REST API.

    NOTE: In both paths, error.txt and patch.diff are not available as plain
    text fields; they are embedded in binary tarballs (repo-vul.tar.gz /
    repo-fix.tar.gz).  The hf-metadata mode therefore yields description-only
    tasks, which support templates cwe_classify and d3fend_map but not
    root_cause or patch_rationale.

    For full four-template coverage, use --source /path/to/local/data
    (mode=local) after downloading the dataset with 'git lfs clone'.
    """
    tasks = _try_hf_datasets_library(hf_slug, max_tasks=max_tasks,
                                     cache_dir=cache_dir, rng=rng)
    if tasks is not None:
        return tasks

    tasks = _load_hf_metadata_http(hf_slug, token=token, cache_dir=cache_dir,
                                   use_cache=use_cache, max_tasks=max_tasks)
    return tasks


# ---------------------------------------------------------------------------
# Local directory mode
# ---------------------------------------------------------------------------

# The CyberGym data/ directory has this layout:
#   data/arvo/<numeric_id>/{description.txt,error.txt,patch.diff,...}
#   data/oss-fuzz/<numeric_id>/{description.txt,error.txt,patch.diff,...}
#
# We also accept a flat layout where each subdir is named by its task_id
# (e.g. "arvo:10400") or simply by its numeric ID.


def _read_text_file(path: pathlib.Path, max_bytes: int = 131072) -> str | None:
    """Read a UTF-8 text file up to max_bytes, returning None on failure."""
    if not path.exists():
        return None
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if len(data) > max_bytes:
        logging.debug("skipping oversized file %s (%d bytes)", path, len(data))
        return None
    if b"\x00" in data[:4096]:
        return None  # binary blob
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return data.decode("latin-1")
        except UnicodeDecodeError:
            return None


def _task_id_from_dir(task_dir: pathlib.Path, provider: str) -> str:
    """Derive a task_id string from a data directory path."""
    # Canonical form: "arvo:10400" or "oss-fuzz:42535201"
    numeric_name = task_dir.name
    return f"{provider}:{numeric_name}"


def load_local_tasks(
    data_dir: pathlib.Path,
    *,
    max_tasks: int,
) -> list[CyberGymTask]:
    """
    Walk a local CyberGym data/ directory and load tasks that have all
    three text artifacts (description.txt, error.txt, patch.diff).

    Accepts two layouts:
      1. data/<provider>/<numeric_id>/  (canonical CyberGym layout)
      2. data/<task_id>/               (flat layout with task_id as dir name)
    """
    tasks: list[CyberGymTask] = []

    # Detect layout
    # Canonical layout: look for arvo/ or oss-fuzz/ subdirectories
    canonical_providers = ["arvo", "oss-fuzz", "oss-fuzz-latest"]
    has_canonical = any((data_dir / p).is_dir() for p in canonical_providers)

    def _ingest_task_dir(task_dir: pathlib.Path, provider: str) -> CyberGymTask | None:
        desc_path = task_dir / "description.txt"
        error_path = task_dir / "error.txt"
        patch_path = task_dir / "patch.diff"

        # All three must exist for full template support
        if not desc_path.exists():
            logging.debug("skipping %s: missing description.txt", task_dir)
            return None
        if not error_path.exists():
            logging.debug("skipping %s: missing error.txt", task_dir)
            return None
        if not patch_path.exists():
            logging.debug("skipping %s: missing patch.diff", task_dir)
            return None

        description = _read_text_file(desc_path)
        if not description or not description.strip():
            logging.debug("skipping %s: empty description", task_dir)
            return None

        error_txt = _read_text_file(error_path)
        if error_txt is None:
            logging.debug("skipping %s: unreadable error.txt", task_dir)
            return None

        patch_diff = _read_text_file(patch_path)
        if not patch_diff or not patch_diff.strip():
            logging.debug("skipping %s: empty patch.diff", task_dir)
            return None

        task_id = _task_id_from_dir(task_dir, provider)
        cwe_hint = extract_cwe_from_description(description)

        return CyberGymTask(
            task_id=task_id,
            project_name=task_dir.parent.name if has_canonical else "",
            project_language="",
            description=description,
            error_txt=error_txt,
            patch_diff=patch_diff,
            cwe_hint=cwe_hint,
        )

    if has_canonical:
        for provider in canonical_providers:
            provider_dir = data_dir / provider
            if not provider_dir.is_dir():
                continue
            for task_dir in sorted(provider_dir.iterdir()):
                if not task_dir.is_dir():
                    continue
                t = _ingest_task_dir(task_dir, provider)
                if t is not None:
                    tasks.append(t)
                if max_tasks > 0 and len(tasks) >= max_tasks:
                    return tasks
    else:
        # Flat layout: each subdir is one task, provider inferred from name
        for task_dir in sorted(data_dir.iterdir()):
            if not task_dir.is_dir():
                continue
            # Provider may be encoded in dir name as "arvo:10400" or just "10400"
            raw_name = task_dir.name
            if ":" in raw_name:
                provider, _ = raw_name.split(":", 1)
            else:
                provider = "arvo"  # default
            t = _ingest_task_dir(task_dir, provider)
            if t is not None:
                tasks.append(t)
            if max_tasks > 0 and len(tasks) >= max_tasks:
                return tasks

    logging.info("local mode: found %d tasks with all three artifacts", len(tasks))
    return tasks


# ---------------------------------------------------------------------------
# Rule A enforcement on individual artifacts
# ---------------------------------------------------------------------------


def check_rule_a(task: CyberGymTask) -> tuple[bool, str]:
    """
    Enforce Rule A.  Returns (ok, reason).
    Reason is empty on pass.

    Checks:
    - description.txt must not contain PoC construction language.
    - error.txt may contain sanitizer traces (defender-frame) but must not
      contain PoC byte sequences or submit.sh content.
    - patch.diff must not contain hex shellcode sequences.
    """
    # Description check
    leak = contains_offensive_leak(task.description)
    if leak:
        return False, f"description offensive leak: {leak}"
    poc = contains_poc_signal(task.description)
    if poc:
        return False, f"description PoC signal: {poc}"

    # error.txt: allow ASan traces but not raw PoC bytes or submit.sh references
    if task.error_txt:
        hex_pat = re.compile(r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){7,}")
        if hex_pat.search(task.error_txt):
            return False, "error.txt contains raw hex byte sequence (Rule A)"
        if re.search(r"\bsubmit\.sh\b", task.error_txt, re.IGNORECASE):
            return False, "error.txt references submit.sh (Rule A)"

    # patch.diff check
    if task.patch_diff:
        leak_p = contains_offensive_leak(task.patch_diff)
        if leak_p:
            return False, f"patch.diff offensive leak: {leak_p}"

    return True, ""


# ---------------------------------------------------------------------------
# D3FEND top-3 mapping (used by L4-cybergym_d3fend_map template)
# ---------------------------------------------------------------------------

# For a given CWE, return up to 3 D3FEND technique names drawn only from
# the conservative CWE_DEFEND_MAP table.  No invented artifact names.
_D3FEND_TECHNIQUE_POOLS: dict[str, list[str]] = {
    # Memory-safety CWEs cluster around Memory Boundary Tracking.
    "memory": [
        "Memory Boundary Tracking",
        "Stack Frame Canary Validation",
        "Software Component Hardening",
    ],
    "injection": [
        "Input Validation",
        "Process Spawn Analysis",
        "Output Encoding",
    ],
    "auth": [
        "Authorization Event Thresholding",
        "Credential Hardening",
        "Multi-factor Authentication",
    ],
    "info": [
        "Information Flow Control",
        "Authorization Event Thresholding",
        "Software Component Hardening",
    ],
    "default": [
        "Software Component Hardening",
        "Input Validation",
        "Memory Boundary Tracking",
    ],
}

_MEMORY_CWES = {
    "CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-134",
    "CWE-190", "CWE-191", "CWE-401", "CWE-415", "CWE-416", "CWE-476",
    "CWE-680", "CWE-704", "CWE-787", "CWE-788", "CWE-824", "CWE-843",
}
_INJECTION_CWES = {
    "CWE-022", "CWE-077", "CWE-078", "CWE-079", "CWE-089",
    "CWE-094", "CWE-116", "CWE-502", "CWE-611",
}
_AUTH_CWES = {
    "CWE-269", "CWE-287", "CWE-295", "CWE-326", "CWE-327",
    "CWE-352", "CWE-732", "CWE-798", "CWE-862", "CWE-863",
}
_INFO_CWES = {"CWE-200", "CWE-208", "CWE-918"}


def top3_d3fend(cwe: str) -> list[str]:
    """Return the top-3 D3FEND technique names for a given CWE."""
    if cwe in _MEMORY_CWES:
        pool = _D3FEND_TECHNIQUE_POOLS["memory"]
    elif cwe in _INJECTION_CWES:
        pool = _D3FEND_TECHNIQUE_POOLS["injection"]
    elif cwe in _AUTH_CWES:
        pool = _D3FEND_TECHNIQUE_POOLS["auth"]
    elif cwe in _INFO_CWES:
        pool = _D3FEND_TECHNIQUE_POOLS["info"]
    else:
        # Use primary technique from CWE_DEFEND_MAP entry if available
        entry = CWE_DEFEND_MAP.get(cwe)
        if entry:
            primary = entry["d3fend"].split(" / ")[0].strip()
            pool = [primary] + _D3FEND_TECHNIQUE_POOLS["default"]
        else:
            pool = _D3FEND_TECHNIQUE_POOLS["default"]
    return pool[:3]


# ---------------------------------------------------------------------------
# Template renderers (Rule B -- four defender-side projections)
# ---------------------------------------------------------------------------


def render_cwe_classify(task: CyberGymTask, mapping: dict[str, str]) -> dict:
    """
    Template 1: L4-cybergym_cwe_classify
    description.txt -> CWE id + D3FEND artifact name + 1-paragraph rationale.
    No exploit description.
    """
    user = (
        f"Project: {task.project_name or task.task_id} "
        f"(language: {task.project_language or 'C/C++'}).\n\n"
        f"The following vulnerability description comes from the CyberGym "
        f"benchmark (task {task.task_id}):\n\n"
        f"{task.description}\n\n"
        "Classify the CWE, name the primary D3FEND defensive artifact, and "
        "write a one-paragraph defender rationale explaining what control "
        "eliminates this class of vulnerability. Stay in the defender frame: "
        "do not describe how the vulnerability is triggered or weaponized."
    )
    rationale = (
        f"CWE classification: {mapping['cwe']} -- {mapping['name']}.\n\n"
        f"Primary D3FEND defensive artifact: {mapping['d3fend']}.\n\n"
        f"Defender rationale: This vulnerability class ({mapping['cwe']}) is "
        f"eliminated by enforcing {mapping['d3fend']} on all affected code "
        f"paths. Concretely, {mapping['sbd']} This satisfies the CISA "
        f"Secure-by-Design principle of eliminating entire classes of "
        f"vulnerabilities rather than patching individual instances. "
        f"CDP ledger entry: CyberGym task {task.task_id} anchors this "
        f"classification to a validated ASan/UBSan-confirmed instance "
        f"(tau = classify task, model = Raven, ledger = task_id)."
    )
    return {
        "template": "L4-cybergym_cwe_classify",
        "messages": [
            {"role": "system", "content": SYSTEM_DEFENDER},
            {"role": "user", "content": user},
            {"role": "assistant", "content": rationale},
        ],
        "meta": {
            "cybergym_task_id": task.task_id,
            "project": task.project_name,
            "cwe": mapping["cwe"],
            "d3fend": mapping["d3fend"],
            "source": "description.txt",
        },
    }


def render_d3fend_map(task: CyberGymTask, mapping: dict[str, str]) -> dict:
    """
    Template 2: L4-cybergym_d3fend_map
    description.txt -> ranked top-3 D3FEND defensive technique names.
    Uses only the conservative CWE_DEFEND_MAP table -- no invented names.
    """
    top3 = top3_d3fend(mapping["cwe"])
    user = (
        f"Given the following vulnerability description for CyberGym task "
        f"{task.task_id} ({task.project_name or 'unnamed project'}), produce "
        "a ranked list of the top-3 D3FEND defensive techniques that most "
        "directly address the vulnerability class. Number the list 1-3. "
        "For each technique, give one sentence explaining the defensive "
        "action. Use only MITRE D3FEND v1.0 technique names.\n\n"
        f"{task.description}"
    )
    lines = [f"{i+1}. {name}" for i, name in enumerate(top3)]
    assistant = (
        f"Top-3 D3FEND defensive techniques for {mapping['cwe']} "
        f"({mapping['name']}):\n\n"
        + "\n".join(lines) + "\n\n"
        f"Primary rationale: {mapping['sbd']}\n"
        f"CDP ledger: CyberGym task {task.task_id}, "
        f"tau = D3FEND mapping task, ledger = task_id."
    )
    return {
        "template": "L4-cybergym_d3fend_map",
        "messages": [
            {"role": "system", "content": SYSTEM_DEFENDER},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant},
        ],
        "meta": {
            "cybergym_task_id": task.task_id,
            "project": task.project_name,
            "cwe": mapping["cwe"],
            "d3fend": mapping["d3fend"],
            "d3fend_top3": top3,
            "source": "description.txt",
        },
    }


def render_root_cause(task: CyberGymTask, mapping: dict[str, str]) -> dict:
    """
    Template 3: L4-cybergym_root_cause
    (description.txt, error.txt) -> root-cause-analysis paragraph + fix area.

    error.txt is an ASan/UBSan sanitizer trace -- this is defender-frame
    information and safe to include in the prompt.  We truncate it to keep
    prompts within a reasonable token budget.
    """
    # Sanitize error_txt: strip raw hex bytes and excessively long lines.
    error_safe = _sanitize_error_txt(task.error_txt)
    if not error_safe.strip():
        # If sanitization removed all content, skip this template.
        return {}

    user = (
        f"Project: {task.project_name or task.task_id} "
        f"(CyberGym task {task.task_id}).\n\n"
        "VULNERABILITY DESCRIPTION:\n"
        f"{task.description}\n\n"
        "SANITIZER OUTPUT (AddressSanitizer / UndefinedBehaviorSanitizer "
        "trace from the vulnerable binary):\n"
        f"{error_safe}\n\n"
        "Write a root-cause-analysis paragraph that explains what invariant "
        "is violated, where in the code the violation likely occurs (file or "
        "function name if visible in the trace), and what class of fix "
        f"({mapping['cwe']}: {mapping['name']}) would address it. "
        "Do not write exploit code or a proof-of-concept input."
    )
    assistant = (
        f"Root-cause analysis ({mapping['cwe']} -- {mapping['name']}):\n\n"
        f"The sanitizer output indicates a {mapping['name']} condition. "
        f"The invariant violated is: {mapping['d3fend']} was not enforced on "
        f"the affected code path. "
        f"Based on the trace, the violation occurs at or near the "
        f"function/call site visible in the highest-frame stack entry above. "
        f"The correct fix area is the allocation or indexing logic that "
        f"allows the out-of-contract access, not the crash site itself.\n\n"
        f"Suggested fix direction: {mapping['sbd']}\n\n"
        f"D3FEND defensive artifact to apply: {mapping['d3fend']}.\n"
        f"CDP ledger: CyberGym task {task.task_id}, "
        f"tau = root-cause-analysis task, ledger = ASan trace + task_id."
    )
    return {
        "template": "L4-cybergym_root_cause",
        "messages": [
            {"role": "system", "content": SYSTEM_DEFENDER},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant},
        ],
        "meta": {
            "cybergym_task_id": task.task_id,
            "project": task.project_name,
            "cwe": mapping["cwe"],
            "d3fend": mapping["d3fend"],
            "source": "description.txt+error.txt",
        },
    }


def render_patch_rationale(task: CyberGymTask, mapping: dict[str, str]) -> dict:
    """
    Template 4: L4-cybergym_patch_rationale  (most important template)
    patch.diff -> defender-style explanation grounded in CWE + D3FEND +
    CISA Secure-by-Design tactic.

    Mirrors the L4-diff_explain structure from build_l4_ossf_cve.py.
    """
    # Truncate very large diffs to stay within token budget
    diff_text = _truncate_diff(task.patch_diff, max_lines=120)

    user = (
        f"Below is the security patch (patch.diff) for CyberGym task "
        f"{task.task_id} ({task.project_name or 'OSS project'}, "
        f"language: {task.project_language or 'C/C++'}).\n\n"
        "Explain the defensive control this patch introduces. Name the "
        "D3FEND artifact and the CISA Secure-by-Design tactic that this "
        "patch realizes. Stay in the defender frame: no description of "
        "attack paths or offensive use of the original code.\n\n"
        f"--- patch.diff ---\n{diff_text}\n--- end patch.diff ---"
    )
    assistant = (
        f"Defensive control realized by this patch:\n\n"
        f"This patch addresses {mapping['cwe']} ({mapping['name']}) by "
        f"enforcing {mapping['d3fend']} on the affected code path.\n\n"
        f"D3FEND artifact: {mapping['d3fend']}\n"
        f"Why the pre-patch revision was unsafe (defender frame): it failed "
        f"to enforce {mapping['d3fend']} on the affected code path, allowing "
        f"the {mapping['name']} condition to persist.\n\n"
        f"CISA Secure-by-Design tactic realized: {mapping['sbd']}\n\n"
        f"Operator action: when reviewing similar patches, verify that "
        f"{mapping['d3fend']} is applied to all caller sites, not only the "
        f"specific site changed here. Require this as a precondition before "
        f"merging -- this is a hardening guide, not a loosening guide.\n\n"
        f"CDP ledger: CyberGym task {task.task_id}, "
        f"tau = patch-rationale task, "
        f"model = Raven defender, "
        f"ledger = task_id + patch_diff hash "
        f"{hashlib.sha256(task.patch_diff.encode()).hexdigest()[:12]}."
    )
    return {
        "template": "L4-cybergym_patch_rationale",
        "messages": [
            {"role": "system", "content": SYSTEM_DEFENDER},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant},
        ],
        "meta": {
            "cybergym_task_id": task.task_id,
            "project": task.project_name,
            "cwe": mapping["cwe"],
            "d3fend": mapping["d3fend"],
            "source": "patch.diff",
            "patch_sha256_prefix": hashlib.sha256(
                task.patch_diff.encode()
            ).hexdigest()[:16],
        },
    }


# ---------------------------------------------------------------------------
# Text helpers
# ---------------------------------------------------------------------------


def _sanitize_error_txt(error_txt: str, max_lines: int = 60) -> str:
    """
    Strip lines that contain raw hex byte sequences (Rule A) or lines that
    look like actual PoC bytes rather than a sanitizer report.
    Truncate to max_lines to keep prompts sane.
    """
    hex_re = re.compile(r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){3,}")
    lines = error_txt.splitlines()
    clean: list[str] = []
    for line in lines:
        if hex_re.search(line):
            continue   # drop lines with hex byte sequences
        clean.append(line)
    return "\n".join(clean[:max_lines])


def _truncate_diff(diff_text: str, max_lines: int = 120) -> str:
    """Truncate a diff to max_lines, appending a marker if truncated."""
    lines = diff_text.splitlines()
    if len(lines) <= max_lines:
        return diff_text
    return "\n".join(lines[:max_lines]) + f"\n... (truncated at {max_lines} lines)"


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------


def validate_sample(sample: dict) -> tuple[bool, str]:
    """Return (ok, reason).  Reason is empty on success."""
    if not sample:
        return False, "empty sample"
    msgs = sample.get("messages", [])
    if not msgs or msgs[-1].get("role") != "assistant":
        return False, "missing assistant turn"
    assistant_text = msgs[-1].get("content", "")
    user_text = "\n".join(
        m.get("content", "") for m in msgs if m.get("role") == "user"
    )

    # The assistant must never leak offensive language.
    leak = contains_offensive_leak(assistant_text)
    if leak:
        return False, f"assistant leaks offensive pattern: {leak}"

    # For all CyberGym templates the user prompt must also be clean.
    leak_u = contains_offensive_leak(user_text)
    if leak_u:
        return False, f"user prompt leaks offensive pattern: {leak_u}"

    # Additional PoC signal check on the full sample text.
    full_text = assistant_text + "\n" + user_text
    poc = contains_poc_signal(full_text)
    if poc:
        return False, f"sample contains PoC signal: {poc}"

    return True, ""


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------


def process_task(task: CyberGymTask) -> Iterator[dict]:
    """Yield validated defender-only samples for one CyberGymTask."""
    ok, reason = check_rule_a(task)
    if not ok:
        logging.debug("Rule A rejected %s: %s", task.task_id, reason)
        return

    mapping = cwe_lookup(task.cwe_hint, task.error_txt)

    # Determine which templates are available given the artifacts present.
    has_description = bool(task.description.strip())
    has_error = bool(task.error_txt.strip())
    has_patch = bool(task.patch_diff.strip())

    if not has_description:
        return  # cannot emit any template without description

    # Template 1: cwe_classify (requires description)
    yield render_cwe_classify(task, mapping)

    # Template 2: d3fend_map (requires description)
    yield render_d3fend_map(task, mapping)

    # Template 3: root_cause (requires description + error.txt)
    if has_error:
        sample = render_root_cause(task, mapping)
        if sample:
            yield sample

    # Template 4: patch_rationale (requires patch.diff)
    if has_patch:
        yield render_patch_rationale(task, mapping)


def build(args: argparse.Namespace) -> int:
    logging.basicConfig(
        level=(
            logging.DEBUG if args.verbose >= 2 else
            logging.INFO if args.verbose == 1 else
            logging.WARNING
        ),
        format="%(asctime)s %(levelname)s %(message)s",
    )

    rng = random.Random(args.seed)
    use_cache = not args.no_cache
    args.cache_dir.mkdir(parents=True, exist_ok=True)
    args.out.parent.mkdir(parents=True, exist_ok=True)

    # Determine source mode
    source: str = args.source
    if source.startswith("hf:") or source.startswith("dataset/"):
        hf_slug = source.removeprefix("hf:").removeprefix("dataset/")
        logging.info("source mode=hf-metadata, dataset slug: %s", hf_slug)
        tasks = load_hf_tasks(
            hf_slug,
            token=args.github_token,
            cache_dir=args.cache_dir,
            use_cache=use_cache,
            max_tasks=args.max_tasks,
            rng=rng,
        )
    else:
        local_path = pathlib.Path(source)
        if not local_path.is_dir():
            logging.error("--source is not a valid directory: %s", local_path)
            return 3
        logging.info("source mode=local, directory: %s", local_path)
        tasks = load_local_tasks(local_path, max_tasks=args.max_tasks)

    if not tasks:
        logging.error(
            "no tasks loaded from source '%s'. "
            "For HF mode without the 'datasets' library, "
            "use --source /path/to/local/data after cloning the dataset.",
            source,
        )
        return 1

    logging.info("loaded %d tasks", len(tasks))
    rng.shuffle(tasks)

    emitted = 0
    rejected_rule_a = 0
    rejected_validator = 0
    skipped_empty = 0
    template_counts: dict[str, int] = {}

    with args.out.open("w", encoding="utf-8") as fh:
        for task in tasks:
            for sample in process_task(task):
                if not sample:
                    skipped_empty += 1
                    continue
                ok, reason = validate_sample(sample)
                if not ok:
                    rejected_validator += 1
                    logging.debug(
                        "validator rejected %s for %s: %s",
                        sample.get("template"), task.task_id, reason,
                    )
                    if args.strict:
                        logging.error("--strict: validator rejected a sample: %s", reason)
                        return 2
                    continue
                fh.write(json.dumps(sample, ensure_ascii=False) + "\n")
                emitted += 1
                t = sample["template"]
                template_counts[t] = template_counts.get(t, 0) + 1

    # Summary log
    logging.warning(  # always visible even at WARNING level
        "DONE: emitted=%d rejected_rule_a=%d rejected_validator=%d "
        "skipped_empty=%d tasks_processed=%d",
        emitted, rejected_rule_a, rejected_validator, skipped_empty, len(tasks),
    )
    for t, n in sorted(template_counts.items()):
        logging.warning("  template %s: %d samples", t, n)

    if emitted == 0:
        logging.error(
            "no samples emitted.  If using HF mode, consider --source "
            "/path/to/local/data for full four-template coverage."
        )
        return 1

    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(argv)
    except SystemExit as e:
        return int(e.code) if isinstance(e.code, int) else 3
    try:
        return build(args)
    except FetchError as e:
        logging.error("fetch error: %s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
