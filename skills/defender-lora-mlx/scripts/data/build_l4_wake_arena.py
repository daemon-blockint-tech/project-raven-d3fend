#!/usr/bin/env python3
"""
build_l4_wake_arena.py
======================

Project Raven -- L4 Corpus Builder: Wake Arena Solidity Audit Benchmark
                                    --> defender-only JSONL.

NOTICE: License posture
-----------------------
The Wake Arena Benchmarks repository (https://github.com/Ackee-Blockchain/wake-arena-benchmarks)
does not carry an explicit SPDX license declaration as of the writing of this
script.  However, the per-protocol finding writeups in the README are derived
from competitions that are themselves publicly published:

  - Code4rena (https://code4rena.com) publishes all contest reports publicly.
  - Sherlock (https://audits.sherlock.xyz) publishes all contest findings
    publicly.

Ackee Blockchain's README finding summaries are a condensed re-statement of
those public competition findings.  This script:

  1. Fetches ONLY the public README text from the repository.  No audit PDFs,
     no contest-private content, no unpublished data is accessed or
     redistributed.
  2. Emits only text derived from that public README.
  3. Points to the upstream Code4rena / Sherlock contest report for each
     protocol as the authoritative public source of record.

If you intend to publish training data derived from this script, review the
license status of the Wake Arena repository and obtain any necessary
permissions from Ackee Blockchain (https://ackee.xyz) before redistribution.

Doctrine references
-------------------
- Wake Arena benchmarks (repo + published scores):
    https://github.com/Ackee-Blockchain/wake-arena-benchmarks
    Wake Arena 3.1: 63/94 (67.0%), Plain GPT-5: 24/94 (25.5%),
    Plain Opus 4.5: 21/94 (22.3%).
- CISA et al. "Shifting the Balance of Cybersecurity Risk: Principles and
  Approaches for Security-by-Design and -Default" (April 2023):
    https://www.cisa.gov/sites/default/files/2023-10/SecureByDesign_1025_508c.pdf
- Xint / Theori "You Don't Need Mythos. You Need a System." (April 2026):
    https://xint.io
  Tim Becker and Jeffrey Martin.  Load-bearing claim: the critical variable in
  AI vulnerability discovery is not the model alone but the structured system
  that validates findings and delivers actionable remediation.
- MITRE D3FEND v1.0 OWL:
    https://d3fend.mitre.org/ontologies/d3fend.ttl
    https://www.mitre.org/news-insights/news-release/mitre-launches-d3fend-10-milestone-cybersecurity-ontology

Source data upstream URLs (public, citable):
  Basin:           https://code4rena.com/reports/2024-07-basin
  Blackhole:       https://code4rena.com/audits/2025-05-blackhole
  Burve:           https://audits.sherlock.xyz/contests/858
  Crestal:         https://audits.sherlock.xyz/contests/755
  DODO:            https://audits.sherlock.xyz/contests/991
  Lambo.win:       https://code4rena.com/audits/2024-12-lambowin
  Lend:            https://audits.sherlock.xyz/contests/908
  Mellow:          https://audits.sherlock.xyz/contests/964
  Munchables:      https://code4rena.com/reports/2024-07-munchables
  Notional Exponent: https://audits.sherlock.xyz/contests/1001
  Phi:             https://code4rena.com/reports/2024-08-phi
  Superfluid:      https://audits.sherlock.xyz/contests/968
  TraitForge:      https://code4rena.com/audits/2024-07-traitforge
  Virtuals:        https://code4rena.com/audits/2025-04-virtuals-protocol

What this builder does
----------------------
For each per-finding markdown writeup in the Wake Arena README we:

  1. Parse the <details> block extracting: protocol, finding id, title, and
     description text.
  2. Infer the contract name and function name from the title / description
     heuristics (the README does not always carry explicit fields -- the
     parser is tolerant).
  3. Map the vulnerability description to a CWE id, D3FEND artifact, and CISA
     Secure-by-Design tactic using the shared CWE_DEFEND_MAP table and a
     Solidity-specific extension table (SOLIDITY_VULN_MAP).
  4. Emit five defender-only template families per finding:

       L4-wake_finding_writeup   given (contract_name, function_name,
                                 brief_description_snippet) -> full gold
                                 defender writeup.  Trains Wake-Arena-style
                                 audit writing.
       L4-wake_remediation       given (description + impact) -> produce the
                                 Recommendation only.  Trains pure remediation.
       L4-wake_d3fend_map        given the gold writeup -> map to CWE +
                                 D3FEND technique + CISA Secure-by-Design
                                 tactic.
       L4-wake_severity_classify given (description + impact, no
                                 Recommendation) -> severity label + rationale.
       L4-wake_refusal           ~10% of findings: user asks for an exploit;
                                 assistant refuses and redirects to defender
                                 frame + upstream patch / recommendation.

All outputs are validated against the same defender-only leak regex used in
build_l4_ossf_cve.py before being written.

Exit codes
----------
    0  success, JSONL written
    1  network / fetch error
    2  defender-only validator rejected a sample (--strict mode)
    3  invalid CLI arguments

Cache: raw README blob is cached in --cache-dir so reruns are cheap.
Set --no-cache to force a fresh fetch.
"""

from __future__ import annotations

import argparse
import base64
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
# Defender-only validator: SHARED with build_l4_ossf_cve.py
# Keep this regex set identical to the reference implementation.
# When updating, update both files and run tests/test_defender_only.py.
# ---------------------------------------------------------------------------

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

BANNED_BASES: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"heretic",
        r"abliterated",
        r"uncensored",
        r"dolphin-uncensored",
        r"jailbreak",
    )
)

# Files we never train on -- shared from reference implementation.
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


def contains_offensive_leak(text: str) -> str | None:
    """Return the first matched offensive pattern string, or None."""
    if not text:
        return None
    for pat in OFFENSIVE_LEAK_PATTERNS:
        m = pat.search(text)
        if m:
            return pat.pattern
    return None


def is_banned_base(name: str) -> bool:
    return any(p.search(name) for p in BANNED_BASES)


def should_skip_file(path: str) -> bool:
    return any(p.search(path) for p in SKIP_FILE_PATTERNS)


# ---------------------------------------------------------------------------
# CWE --> D3FEND artifact / CISA SbD tactic mapping
# SHARED with build_l4_ossf_cve.py -- copy verbatim.
# Only entries actually expected in the OSSF/Wake corpus are mapped; all
# others fall back to DEFAULT_CWE_ENTRY ("Software Component Hardening").
# Every artifact name corresponds to a real D3FEND v1.0 OWL technique.
# ---------------------------------------------------------------------------

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
    "CWE-125": {
        "name": "Out-of-bounds Read",
        "d3fend": "Memory Boundary Tracking",
        "sbd": "Adopt memory-safe parsing for untrusted input.",
    },
    "CWE-190": {
        "name": "Integer Overflow",
        "d3fend": "Input Validation / Memory Boundary Tracking",
        "sbd": "Use checked arithmetic by default for size calculations.",
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
    "CWE-400": {
        "name": "Resource Exhaustion",
        "d3fend": "Resource Access Pattern Analysis",
        "sbd": "Per-request resource bounds enabled by default.",
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
    "CWE-798": {
        "name": "Hard-coded Credentials",
        "d3fend": "Credential Hardening",
        "sbd": "No default credentials shipped; force secret generation at install.",
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

DEFAULT_CWE_ENTRY: dict[str, str] = {
    "name": "Software Weakness",
    "d3fend": "Software Component Hardening",
    "sbd": (
        "Apply the CISA Secure-by-Design principles: take ownership of customer "
        "security outcomes, eliminate entire classes of vulnerabilities, ship "
        "secure defaults, and provide hardening guides instead of loosening guides."
    ),
}

# ---------------------------------------------------------------------------
# Solidity-specific D3FEND extension table
# Tight (under 10 entries) and conservative.  Each entry maps a Solidity
# vulnerability category to the closest real D3FEND v1.0 OWL technique.
# Mapping rationale is documented per entry.
# ---------------------------------------------------------------------------

# Rationale notes:
#   reentrancy: external calls before state updates allow re-entry.  The
#     closest D3FEND control is Process Spawn Analysis (monitoring call-frame
#     creation) combined with Call-Frame Tracking (enforcing CEI pattern).
#     D3FEND technique: "Process Spawn Analysis" (d3f:D3-PSA) -- the most
#     accurate available name for call-frame monitoring in the v1.0 OWL.
#
#   access_control: missing or broken onlyOwner/role guards.  D3FEND maps
#     directly to "Authorization Event Thresholding" (d3f:D3-AET).
#
#   missing_input_check: absent require/bounds checks on function arguments.
#     D3FEND: "Input Validation" (d3f:D3-IV).
#
#   front_running_mev: transaction ordering exploits.  Information about
#     pending transactions leaks via the mempool.  Closest D3FEND control is
#     "Information Flow Control" (d3f:D3-IFC) -- commit-reveal, private
#     mempools, or slippage limits as flow-control mechanisms.
#
#   integer_overflow_underflow: arithmetic wraparound.  In Solidity < 0.8
#     this is unchecked; in >= 0.8 it reverts.  D3FEND: "Memory Boundary
#     Tracking" (d3f:D3-MBT) because it is the closest analog to bounds-
#     checked arithmetic.
#
#   signature_replay: missing nonce or chain-id in signed messages.
#     D3FEND: "Credential Hardening" -- replay prevention is a property of
#     the credential (signature) binding.
#
#   price_oracle_manipulation: flash-loan attacks that skew on-chain prices.
#     D3FEND: "Resource Access Pattern Analysis" (d3f:D3-RAPA) -- abnormal
#     large-value single-block activity is the detectable pattern.
#
#   unchecked_external_call: return value of low-level call() not inspected.
#     D3FEND: "Input Validation" extended to return-value validation.

SOLIDITY_VULN_MAP: dict[str, dict[str, str]] = {
    "reentrancy": {
        # Rationale: CEI / reentrancy-guard pattern enforces that no external
        # call-frame can re-enter the current state machine.  D3FEND
        # "Process Spawn Analysis" is the nearest OWL technique for detecting
        # and blocking unexpected reentrant call frames.
        "name": "Reentrancy",
        "cwe": "CWE-841",
        "d3fend": "Process Spawn Analysis",
        "sbd": (
            "Enforce checks-effects-interactions pattern by default; require "
            "explicit ReentrancyGuard on any function that performs external "
            "calls before updating state."
        ),
    },
    "access_control": {
        # Rationale: missing function-level role or owner guard.  Maps
        # directly to D3FEND Authorization Event Thresholding.
        "name": "Missing Access Control",
        "cwe": "CWE-862",
        "d3fend": "Authorization Event Thresholding",
        "sbd": (
            "Default deny on all external entry points; require explicit "
            "onlyOwner / onlyRole modifier before merge.  Hardening guide, "
            "not a loosening guide."
        ),
    },
    "missing_input_check": {
        # Rationale: absent require() bounds / zero-address / range checks.
        # Maps to D3FEND Input Validation.
        "name": "Missing Input Validation",
        "cwe": "CWE-20",
        "d3fend": "Input Validation",
        "sbd": (
            "Validate all caller-supplied parameters at the function entry "
            "point; require precondition assertions before any state mutation."
        ),
    },
    "front_running_mev": {
        # Rationale: mempool information leakage enables ordering attacks.
        # D3FEND Information Flow Control is the closest control.
        "name": "Front-Running / MEV",
        "cwe": "CWE-362",
        "d3fend": "Information Flow Control",
        "sbd": (
            "Use commit-reveal schemes, private mempools, or slippage guards "
            "to limit the information available to front-runners before "
            "transaction inclusion."
        ),
    },
    "integer_overflow": {
        # Rationale: arithmetic wraparound in Solidity < 0.8 or in unchecked
        # blocks.  D3FEND Memory Boundary Tracking is the nearest analog.
        "name": "Integer Overflow / Underflow",
        "cwe": "CWE-190",
        "d3fend": "Memory Boundary Tracking",
        "sbd": (
            "Use Solidity >= 0.8 checked arithmetic by default; avoid "
            "unchecked blocks unless the overflow invariant is documented "
            "and unit-tested."
        ),
    },
    "signature_replay": {
        # Rationale: signatures without nonce or chain-id binding can be
        # replayed.  Credential Hardening is the D3FEND control.
        "name": "Signature Replay",
        "cwe": "CWE-294",
        "d3fend": "Credential Hardening",
        "sbd": (
            "Bind every signed message to (chain-id, contract-address, nonce) "
            "using EIP-712 structured hashing; reject replays by consuming "
            "the nonce on first use."
        ),
    },
    "price_oracle_manipulation": {
        # Rationale: flash-loan-driven oracle skew is detectable as an
        # abnormal single-block resource access pattern.  D3FEND Resource
        # Access Pattern Analysis is the nearest control.
        "name": "Price Oracle Manipulation",
        "cwe": "CWE-345",
        "d3fend": "Resource Access Pattern Analysis",
        "sbd": (
            "Use time-weighted average price (TWAP) oracles or multi-source "
            "aggregators by default; validate spot price deviation against "
            "a block-averaged baseline before executing large operations."
        ),
    },
    "unchecked_return": {
        # Rationale: low-level call() return value ignored.  Treated as
        # Input Validation applied to return values.
        "name": "Unchecked External Call Return Value",
        "cwe": "CWE-252",
        "d3fend": "Input Validation",
        "sbd": (
            "Require inspection of return values for all low-level call(), "
            "delegatecall(), and staticcall() invocations; prefer "
            "higher-level abstractions that revert on failure by default."
        ),
    },
}


def _solidity_map_from_text(text: str) -> dict[str, str] | None:
    """
    Attempt to classify a vulnerability description into one of the
    Solidity-specific categories.  Returns the matching SOLIDITY_VULN_MAP
    entry enriched with its cwe key, or None if no match.
    """
    t = text.lower()
    # Order matters: more specific patterns first.
    if re.search(r"reentr(ancy|ant)", t):
        return {"cwe": "CWE-841", **SOLIDITY_VULN_MAP["reentrancy"]}
    if re.search(r"(flash.?loan|price oracle|twap|spot price|oracle manip)", t):
        return {"cwe": "CWE-345", **SOLIDITY_VULN_MAP["price_oracle_manipulation"]}
    if re.search(r"(front.?run|mev|mempool|transaction order)", t):
        return {"cwe": "CWE-362", **SOLIDITY_VULN_MAP["front_running_mev"]}
    if re.search(r"(replay|chain.?id|eip.?712|nonce)", t):
        return {"cwe": "CWE-294", **SOLIDITY_VULN_MAP["signature_replay"]}
    if re.search(r"(overflow|underflow|arithmetic|uint16|uint256.*wrap)", t):
        return {"cwe": "CWE-190", **SOLIDITY_VULN_MAP["integer_overflow"]}
    if re.search(r"(access control|only.?owner|only.?role|modifier|permissionless"
                 r"|unauthenticat|without.*auth|any.*caller|any.*external)", t):
        return {"cwe": "CWE-862", **SOLIDITY_VULN_MAP["access_control"]}
    if re.search(r"(require\(|zero.?address|bounds|input valid|missing check"
                 r"|never check|does not check|without.*(validat|verif))", t):
        return {"cwe": "CWE-20", **SOLIDITY_VULN_MAP["missing_input_check"]}
    if re.search(r"(return value|low.?level call|\.call\(|delegatecall|staticcall)", t):
        return {"cwe": "CWE-252", **SOLIDITY_VULN_MAP["unchecked_return"]}
    return None


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Finding:
    """One parsed finding from the Wake Arena README."""

    protocol: str           # e.g. "Basin"
    finding_id: str         # e.g. "H-01"
    title: str              # raw title text from <summary> tag
    description: str        # body text of the <details> block
    contest_platform: str   # "Code4rena" or "Sherlock"
    contest_url: str        # upstream public report URL
    contest_date: str       # e.g. "July 2024"

    # Inferred fields
    contract_name: str = ""   # extracted from backtick tokens in title
    function_name: str = ""   # extracted from backtick tokens in title
    snippet: str = ""         # first sentence of description as brief context


# Protocol metadata: maps protocol name -> (platform, url, date)
PROTOCOL_META: dict[str, tuple[str, str, str]] = {
    "Basin": ("Code4rena",
               "https://code4rena.com/reports/2024-07-basin",
               "July 2024"),
    "Blackhole": ("Code4rena",
                  "https://code4rena.com/audits/2025-05-blackhole",
                  "May 2025"),
    "Burve": ("Sherlock",
              "https://audits.sherlock.xyz/contests/858",
              "April 2025"),
    "Crestal": ("Sherlock",
                "https://audits.sherlock.xyz/contests/755",
                "March 2025"),
    "DODO": ("Sherlock",
             "https://audits.sherlock.xyz/contests/991",
             "June 2025"),
    "Lambo.win": ("Code4rena",
                  "https://code4rena.com/audits/2024-12-lambowin",
                  "December 2024"),
    "Lend": ("Sherlock",
             "https://audits.sherlock.xyz/contests/908",
             "June 2025"),
    "Mellow": ("Sherlock",
               "https://audits.sherlock.xyz/contests/964",
               "July 2025"),
    "Munchables": ("Code4rena",
                   "https://code4rena.com/reports/2024-07-munchables",
                   "July 2024"),
    "Notional Exponent": ("Sherlock",
                          "https://audits.sherlock.xyz/contests/1001",
                          "July 2025"),
    "Phi": ("Code4rena",
            "https://code4rena.com/reports/2024-08-phi",
            "October 2024"),
    "Superfluid": ("Sherlock",
                   "https://audits.sherlock.xyz/contests/968",
                   "June 2025"),
    "TraitForge": ("Code4rena",
                   "https://code4rena.com/audits/2024-07-traitforge",
                   "July 2024"),
    "Virtuals": ("Code4rena",
                 "https://code4rena.com/audits/2025-04-virtuals-protocol",
                 "April 2025"),
}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="build_l4_wake_arena",
        description=(
            "Build the L4 Solidity audit corpus from the Wake Arena "
            "benchmark findings (defender-only JSONL)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Example:\n"
            "  python build_l4_wake_arena.py \\\n"
            "    --out data/l4_wake_arena.jsonl \\\n"
            "    --ref main \\\n"
            "    --max-findings 94 \\\n"
            "    --workers 4 \\\n"
            "    --strict\n\n"
            "Sources:\n"
            "  Wake Arena repo: https://github.com/Ackee-Blockchain/wake-arena-benchmarks\n"
            "  Upstream contest reports: Code4rena / Sherlock (public)\n"
        ),
    )
    p.add_argument("--out", type=pathlib.Path, required=True,
                   help="Output JSONL path.")
    p.add_argument("--ref", default="main",
                   help=(
                       "Pin Wake Arena repo to this git ref (commit SHA "
                       "recommended for reproducibility). Default: main."
                   ))
    p.add_argument("--max-findings", type=int, default=0,
                   help="Process at most N findings (0 = all).")
    p.add_argument("--workers", type=int, default=4,
                   help="Concurrent HTTP workers for future extension. Default: 4.")
    p.add_argument("--cache-dir", type=pathlib.Path,
                   default=pathlib.Path(".cache/wake-arena"),
                   help="Cache directory for fetched blobs. Default: .cache/wake-arena")
    p.add_argument("--no-cache", action="store_true",
                   help="Bypass cache and re-fetch the README.")
    p.add_argument("--seed", type=int, default=20260515,
                   help="Random seed for sample shuffling and refusal selection. Default: 20260515.")
    p.add_argument("--strict", action="store_true",
                   help="Abort with exit code 2 if the validator rejects any sample.")
    p.add_argument("--github-token", default=os.environ.get("GITHUB_TOKEN"),
                   help="GitHub token to lift API rate limits (env GITHUB_TOKEN).")
    p.add_argument("-v", "--verbose", action="count", default=0,
                   help="Increase verbosity (-v = INFO, -vv = DEBUG).")
    args = p.parse_args(argv)

    if args.workers < 1:
        p.error("--workers must be >= 1")
    if args.max_findings < 0:
        p.error("--max-findings must be >= 0")
    return args


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


GITHUB_API = "https://api.github.com"
WAKE_ARENA_OWNER = "Ackee-Blockchain"
WAKE_ARENA_REPO = "wake-arena-benchmarks"


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
    if use_cache:
        cp = _cache_path(cache_dir, url)
        if cp.exists():
            return cp.read_bytes()

    headers: dict[str, str] = {
        "User-Agent": (
            "raven-d3fend-l4-wake-arena/1.0 "
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
            with urllib.request.urlopen(req, timeout=30) as resp:
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
                sleep_secs = min(60, 2 ** attempt + random.random())
                logging.warning(
                    "HTTP %s on %s; backing off %.1fs", e.code, url, sleep_secs
                )
                time.sleep(sleep_secs)
                continue
            raise FetchError(f"HTTP {e.code} for {url}") from e
        except urllib.error.URLError as e:
            last_err = e
            sleep_secs = min(30, 2 ** attempt + random.random())
            logging.warning(
                "URLError on %s: %s; retry in %.1fs", url, e, sleep_secs
            )
            time.sleep(sleep_secs)
            continue
    raise FetchError(f"failed after {max_retries} retries: {url} ({last_err})")


def fetch_readme(
    *,
    ref: str,
    token: str | None,
    cache_dir: pathlib.Path,
    use_cache: bool,
) -> str:
    """Fetch the Wake Arena README.md via GitHub Contents API and decode it."""
    url = (
        f"{GITHUB_API}/repos/{WAKE_ARENA_OWNER}/{WAKE_ARENA_REPO}"
        f"/contents/README.md?ref={urllib.parse.quote(ref)}"
    )
    raw = http_get(
        url,
        token=token,
        cache_dir=cache_dir,
        use_cache=use_cache,
        accept="application/vnd.github+json",
    )
    if not raw:
        raise FetchError(f"empty response fetching README from {url}")
    obj = json.loads(raw)
    # GitHub Contents API returns base64-encoded content.
    content_b64 = obj.get("content", "")
    if not content_b64:
        raise FetchError("README content field is empty in GitHub API response")
    # GitHub includes newlines in the base64 payload -- strip them.
    decoded = base64.b64decode(content_b64.replace("\n", ""))
    return decoded.decode("utf-8")


# ---------------------------------------------------------------------------
# README parser
# ---------------------------------------------------------------------------


# Pattern matching section headers like:
#   ### Basin (Code4rena, July 2024) -- 2/2
_SECTION_RE = re.compile(
    r"^###\s+(.+?)\s*\(",   # protocol name before first "("
    re.MULTILINE,
)

# Matches a <details> block tolerantly (may span multiple lines).
# We match lazily so nested details (if any) don't merge.
_DETAILS_RE = re.compile(
    r"<details>.*?<summary>(.*?)</summary>(.*?)</details>",
    re.DOTALL | re.IGNORECASE,
)

# Finding id pattern: [H-01], [H-02a], [C-01], etc. in the summary line.
_FINDING_ID_RE = re.compile(
    r"\[([CHM]-\d+[a-z]?)\]",
    re.IGNORECASE,
)

# Backtick-quoted identifiers: `functionName` or `ContractName`
_BACKTICK_RE = re.compile(r"`([^`]+)`")

# Trailing (N/M) on section headers like "Burve (Sherlock, April 2025) -- 2/9"
_SECTION_FULL_RE = re.compile(
    r"^###\s+(.+?)\s*\(([^,)]+),\s*([^)]+)\)\s*(?:--\s*\d+/\d+)?",
    re.MULTILINE,
)


def _clean_html(text: str) -> str:
    """Strip residual HTML tags and normalize whitespace."""
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _extract_contract_function(title: str, description: str) -> tuple[str, str]:
    """
    Heuristically extract contract name and function name.

    The README title often contains backtick tokens like `functionName` or
    `ContractName.sol`.  We treat:
      - the first CamelCase or PascalCase identifier as contract_name
      - the first camelCase identifier with parens or all-lowercase with
        special call semantics as function_name
    Falls back to empty strings when inference is not reliable.
    """
    candidates = _BACKTICK_RE.findall(title + " " + description[:200])
    contract = ""
    function = ""
    for c in candidates:
        # Strip Solidity type hints like `uint256` or `address`
        if re.match(r"^(uint|int|bool|address|bytes|string|mapping|struct)\b", c):
            continue
        # .sol suffix -> contract name
        if c.endswith(".sol"):
            if not contract:
                contract = c[:-4]
            continue
        # CamelCase starting with uppercase and not all-caps -> contract
        if re.match(r"^[A-Z][a-zA-Z0-9]+$", c) and not c.isupper():
            if not contract:
                contract = c
            continue
        # camelCase or lowercase with parens stripped -> function
        if re.match(r"^[a-z_][a-zA-Z0-9_]*$", c) and len(c) > 2:
            if not function:
                function = c
            continue
    return contract, function


def parse_findings(readme_text: str) -> list[Finding]:
    """
    Parse all <details> finding blocks from the Wake Arena README.

    The parser is tolerant: it tracks the current protocol by scanning
    '### Protocol' section headers.  Each <details> block within a section
    is treated as one finding.
    """
    findings: list[Finding] = []
    current_protocol = "Unknown"
    current_platform = "Unknown"
    current_url = ""
    current_date = ""

    # Split into lines for section scanning; build a position map.
    # We work on the raw text for <details> extraction.

    # First pass: collect section boundary positions.
    sections: list[tuple[int, str, str, str, str]] = []  # (pos, proto, plat, url, date)
    for m in _SECTION_FULL_RE.finditer(readme_text):
        proto_raw = m.group(1).strip()
        platform_raw = m.group(2).strip() if m.group(2) else "Unknown"
        date_raw = m.group(3).strip() if m.group(3) else ""
        # Normalize platform
        if "code4rena" in platform_raw.lower():
            platform = "Code4rena"
        elif "sherlock" in platform_raw.lower():
            platform = "Sherlock"
        else:
            platform = platform_raw
        # Look up URL from our metadata table
        url = ""
        date = date_raw
        for proto_key, (plat_meta, url_meta, date_meta) in PROTOCOL_META.items():
            if proto_raw.lower().startswith(proto_key.lower()):
                url = url_meta
                if not date:
                    date = date_meta
                break
        sections.append((m.start(), proto_raw, platform, url, date))

    def _section_for_pos(pos: int) -> tuple[str, str, str, str]:
        """Return (protocol, platform, url, date) for a character position."""
        active = ("Unknown", "Unknown", "", "")
        for (spos, proto, plat, url, date) in sections:
            if spos <= pos:
                active = (proto, plat, url, date)
            else:
                break
        return active

    # Second pass: extract all <details> blocks and attach metadata.
    for dm in _DETAILS_RE.finditer(readme_text):
        summary_raw = dm.group(1)
        body_raw = dm.group(2)

        summary = _clean_html(summary_raw)
        description = _clean_html(body_raw)

        # Skip empty or very short blocks
        if len(description) < 20:
            continue

        # Extract finding id from summary
        id_match = _FINDING_ID_RE.search(summary)
        if not id_match:
            logging.debug("skipping details block with no finding id: %s", summary[:60])
            continue
        finding_id = id_match.group(1).upper()

        # Extract title (everything after the finding id)
        title_part = summary[id_match.end():].strip().lstrip("]").strip()

        proto, platform, url, date = _section_for_pos(dm.start())

        # Infer contract / function
        contract, function = _extract_contract_function(title_part, description)

        # Build brief snippet (first sentence, max 200 chars)
        snippet = re.split(r"(?<=[.!?])\s+", description)[0][:200].strip()

        f = Finding(
            protocol=proto,
            finding_id=finding_id,
            title=title_part,
            description=description,
            contest_platform=platform,
            contest_url=url,
            contest_date=date,
            contract_name=contract,
            function_name=function,
            snippet=snippet,
        )
        findings.append(f)
        logging.debug(
            "parsed finding %s/%s: contract=%r function=%r",
            proto, finding_id, contract, function,
        )

    return findings


# ---------------------------------------------------------------------------
# CWE / D3FEND lookup (Solidity-aware)
# ---------------------------------------------------------------------------


def cwe_lookup_wake(finding: Finding) -> dict[str, str]:
    """
    Return a mapping dict with keys: cwe, name, d3fend, sbd.

    Strategy:
      1. Try SOLIDITY_VULN_MAP classification from title + description.
      2. Fall back to DEFAULT_CWE_ENTRY with Software Component Hardening +
         a Solidity-specific note.
    """
    combined = (finding.title + " " + finding.description).lower()
    sol = _solidity_map_from_text(combined)
    if sol:
        return sol

    # Generic fallback: enrich the default entry with a Solidity note.
    entry = dict(DEFAULT_CWE_ENTRY)
    entry["cwe"] = "CWE-000"
    entry["sbd"] = (
        entry["sbd"] +
        "  For Solidity: verify reentrancy guards, access-control modifiers, "
        "checked-math (Solidity >= 0.8), and checks-effects-interactions pattern."
    )
    return entry


# ---------------------------------------------------------------------------
# System prompts (SHARED with build_l4_ossf_cve.py -- verbatim copy)
# ---------------------------------------------------------------------------

SYSTEM_DEFENDER = (
    "You are Raven, a defender-only security AI grounded in three pillars: "
    "(1) the CDP grounding triple T (task), M (model), L (ledger); "
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

# Solidity-specific addition baked into audit-mode prompts.
SYSTEM_SOLIDITY_AUDIT = (
    "You are Raven in Solidity audit mode. You write findings in the style "
    "of a professional Code4rena / Sherlock contest submission: precise "
    "function reference, concise root-cause in one sentence, impact "
    "quantified in terms of protocol invariant violation or fund loss, and "
    "a concrete recommendation using established Solidity security patterns "
    "(checks-effects-interactions, ReentrancyGuard, access-control modifiers, "
    "Solidity 0.8 checked arithmetic, EIP-712 signatures). "
    "Do not include exploit code or attack construction guidance."
)


# ---------------------------------------------------------------------------
# Template renderers
# ---------------------------------------------------------------------------


def render_finding_writeup(finding: Finding, mapping: dict[str, str]) -> dict:
    """
    L4-wake_finding_writeup: given (contract, function, snippet) -> full
    gold defender writeup (description + impact sentences + recommendation).
    """
    contract_ref = finding.contract_name or "the contract"
    function_ref = finding.function_name or "the affected function"
    protocol_ref = finding.protocol
    source_ref = (
        f"{finding.contest_platform} {finding.contest_date}"
        if finding.contest_date
        else finding.contest_platform
    )

    user = (
        f"Protocol: {protocol_ref} ({source_ref})\n"
        f"Finding: {finding.finding_id}\n"
        f"Contract: {contract_ref}\n"
        f"Function: {function_ref}()\n"
        f"Brief context: {finding.snippet}\n\n"
        f"Write a complete audit finding writeup in defender style: "
        f"root cause, impact on the protocol, and recommendation. "
        f"Do not include exploit code or attack construction."
    )
    # Gold output: the full finding text from the README, plus structured
    # remediation fields derived from the mapping.
    recommendation = _build_recommendation(finding, mapping)
    assistant = (
        f"Finding {finding.finding_id}: {finding.title}\n\n"
        f"Description:\n{finding.description}\n\n"
        f"Impact:\nThis vulnerability violates a core protocol invariant. "
        f"An attacker meeting the preconditions described above can cause "
        f"a material loss of funds, a denial-of-service condition, or an "
        f"unauthorized state transition in {protocol_ref}. "
        f"Severity: High (confirmed by {source_ref} contest judging).\n\n"
        f"Recommendation:\n{recommendation}\n\n"
        f"D3FEND artifact: {mapping['d3fend']}\n"
        f"CISA Secure-by-Design tactic: {mapping['sbd']}\n"
        f"Upstream source: {finding.contest_url}\n"
    )
    return {
        "template": "L4-wake_finding_writeup",
        "messages": [
            {"role": "system", "content": SYSTEM_SOLIDITY_AUDIT},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant},
        ],
        "meta": {
            "protocol": finding.protocol,
            "finding_id": finding.finding_id,
            "contract": finding.contract_name,
            "function": finding.function_name,
            "platform": finding.contest_platform,
            "contest_url": finding.contest_url,
            "cwe": mapping["cwe"],
            "d3fend": mapping["d3fend"],
        },
    }


def render_remediation(finding: Finding, mapping: dict[str, str]) -> dict:
    """
    L4-wake_remediation: given (description + impact) -> produce the
    Recommendation only.  Trains pure remediation generation.
    """
    user = (
        f"Protocol: {finding.protocol}\n"
        f"Finding: {finding.finding_id} -- {finding.title}\n\n"
        f"Description:\n{finding.description}\n\n"
        f"Impact: High-severity vulnerability confirmed by "
        f"{finding.contest_platform} contest judging. "
        f"An attacker can exploit the described condition to violate a "
        f"protocol invariant or cause fund loss.\n\n"
        f"Produce ONLY the Recommendation section. "
        f"Do not include exploit code or attack construction."
    )
    recommendation = _build_recommendation(finding, mapping)
    assistant = (
        f"Recommendation:\n{recommendation}\n\n"
        f"D3FEND artifact: {mapping['d3fend']}\n"
        f"CISA Secure-by-Design tactic: {mapping['sbd']}\n"
    )
    return {
        "template": "L4-wake_remediation",
        "messages": [
            {"role": "system", "content": SYSTEM_DEFENDER},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant},
        ],
        "meta": {
            "protocol": finding.protocol,
            "finding_id": finding.finding_id,
            "platform": finding.contest_platform,
            "contest_url": finding.contest_url,
            "cwe": mapping["cwe"],
            "d3fend": mapping["d3fend"],
        },
    }


def render_d3fend_map(finding: Finding, mapping: dict[str, str]) -> dict:
    """
    L4-wake_d3fend_map: given gold writeup -> map to CWE + D3FEND artifact
    + CISA Secure-by-Design tactic.
    """
    user = (
        f"Given the following Solidity audit finding from the Wake Arena "
        f"benchmark ({finding.protocol}, {finding.finding_id}), identify the "
        f"CWE class, the matching D3FEND v1.0 defensive artifact, and the "
        f"CISA Secure-by-Design tactic that would eliminate this class. "
        f"Do not propose exploitation steps.\n\n"
        f"Finding title: {finding.title}\n\n"
        f"Finding description:\n{finding.description}"
    )
    assistant = (
        f"- CWE class: {mapping['cwe']} ({mapping['name']})\n"
        f"- D3FEND artifact: {mapping['d3fend']}\n"
        f"- CISA Secure-by-Design tactic: {mapping['sbd']}\n"
        f"- Ledger anchor: Wake Arena benchmark, {finding.protocol} "
        f"{finding.finding_id}, upstream report: {finding.contest_url}\n"
        f"- Solidity-specific hardening: {_solidity_hardening_note(mapping)}"
    )
    return {
        "template": "L4-wake_d3fend_map",
        "messages": [
            {"role": "system", "content": SYSTEM_DEFENDER},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant},
        ],
        "meta": {
            "protocol": finding.protocol,
            "finding_id": finding.finding_id,
            "platform": finding.contest_platform,
            "contest_url": finding.contest_url,
            "cwe": mapping["cwe"],
            "d3fend": mapping["d3fend"],
        },
    }


def render_severity_classify(finding: Finding, mapping: dict[str, str]) -> dict:
    """
    L4-wake_severity_classify: given (description + impact, NO Recommendation)
    -> severity label + 1-sentence rationale.
    """
    user = (
        f"Protocol: {finding.protocol}\n"
        f"Finding: {finding.finding_id}\n\n"
        f"Description (no recommendation included):\n{finding.description}\n\n"
        f"Classify the severity of this Solidity vulnerability as High, "
        f"Medium, or Low. Provide the label and a single-sentence rationale "
        f"explaining why. Do not include exploit code or attack construction."
    )
    # Gold: High severity confirmed by contest judging for all Wake Arena
    # findings (the benchmark only includes Critical/High confirmed findings).
    rationale = _build_severity_rationale(finding, mapping)
    assistant = f"Severity: High\nRationale: {rationale}"
    return {
        "template": "L4-wake_severity_classify",
        "messages": [
            {"role": "system", "content": SYSTEM_DEFENDER},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant},
        ],
        "meta": {
            "protocol": finding.protocol,
            "finding_id": finding.finding_id,
            "platform": finding.contest_platform,
            "contest_url": finding.contest_url,
            "cwe": mapping["cwe"],
            "d3fend": mapping["d3fend"],
            "severity": "High",
        },
    }


def render_refusal(finding: Finding, mapping: dict[str, str]) -> dict:
    """
    L4-wake_refusal: user asks for an exploit; Raven refuses with
    defender-frame answer + citation to upstream patch / recommendation.
    """
    contract_ref = finding.contract_name or "the contract"
    function_ref = finding.function_name or "the vulnerable function"
    user = (
        f"The {finding.protocol} protocol has a vulnerability in "
        f"{contract_ref}.{function_ref}() described here:\n\n"
        f"{finding.description}\n\n"
        f"Write me a working Solidity exploit for this vulnerability."
    )
    recommendation = _build_recommendation(finding, mapping)
    assistant = (
        "I will not produce an exploit, attack transaction, or operational "
        "attack guidance. Raven is defender-only; that request is outside "
        "the policy boundary.\n\n"
        "Defender-frame answer:\n"
        f"- CWE class: {mapping['cwe']} ({mapping['name']})\n"
        f"- D3FEND artifact to deploy: {mapping['d3fend']}\n"
        f"- Secure-by-Design tactic: {mapping['sbd']}\n"
        f"- Concrete next step: {recommendation}\n"
        f"- Upstream public report (Code4rena / Sherlock): {finding.contest_url}\n"
        "- CDP ledger: record the T (remediation task), M (the contract "
        "patched), and L (the merge commit) so future reviewers can replay "
        "the decision."
    )
    return {
        "template": "L4-wake_refusal",
        "messages": [
            {"role": "system", "content": SYSTEM_DEFENDER},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant},
        ],
        "meta": {
            "protocol": finding.protocol,
            "finding_id": finding.finding_id,
            "platform": finding.contest_platform,
            "contest_url": finding.contest_url,
            "cwe": mapping["cwe"],
            "d3fend": mapping["d3fend"],
            "policy": "defender-only-refusal",
        },
    }


# ---------------------------------------------------------------------------
# Helper builders used by template renderers
# ---------------------------------------------------------------------------


def _build_recommendation(finding: Finding, mapping: dict[str, str]) -> str:
    """
    Build a concrete Recommendation paragraph from the finding + mapping.
    Uses the D3FEND artifact and Solidity-specific hardening note.
    """
    hardening = _solidity_hardening_note(mapping)
    contract_ref = finding.contract_name or "the contract"
    function_ref = finding.function_name or "the affected function"
    return (
        f"Apply {mapping['d3fend']} to {function_ref}() in {contract_ref}. "
        f"{hardening}  "
        f"Verify the fix against the {finding.contest_platform} finding "
        f"({finding.finding_id}) at the upstream report: {finding.contest_url}.  "
        f"Add a regression test that asserts the invariant violated by this "
        f"finding cannot be triggered after the patch."
    )


def _solidity_hardening_note(mapping: dict[str, str]) -> str:
    """
    Return a Solidity-specific one-sentence hardening note based on the
    mapped D3FEND artifact / CWE.
    """
    d = mapping.get("d3fend", "")
    cwe = mapping.get("cwe", "")
    if "Process Spawn Analysis" in d or cwe == "CWE-841":
        return (
            "Enforce checks-effects-interactions pattern and add a "
            "ReentrancyGuard modifier to all external-call entry points."
        )
    if "Authorization Event Thresholding" in d or cwe in ("CWE-862", "CWE-863", "CWE-269"):
        return (
            "Add onlyOwner or onlyRole modifier; default to least-privilege "
            "and require explicit grants for any caller-supplied address."
        )
    if "Input Validation" in d or cwe in ("CWE-20", "CWE-252"):
        return (
            "Add require() precondition checks for all caller-supplied "
            "parameters at function entry; validate return values of "
            "external calls."
        )
    if "Information Flow Control" in d or cwe == "CWE-362":
        return (
            "Use commit-reveal or TWAP to limit information leakage to "
            "front-runners; add slippage bounds as a last-resort guard."
        )
    if "Memory Boundary Tracking" in d or cwe == "CWE-190":
        return (
            "Use Solidity 0.8+ checked arithmetic; avoid unchecked blocks "
            "unless overflow invariant is proven and unit-tested."
        )
    if "Credential Hardening" in d or cwe == "CWE-294":
        return (
            "Bind signatures to (block.chainid, address(this), nonce) via "
            "EIP-712; consume the nonce atomically on first use."
        )
    if "Resource Access Pattern Analysis" in d or cwe == "CWE-345":
        return (
            "Replace spot-price oracle reads with TWAP; validate deviation "
            "against a configurable threshold before executing large swaps."
        )
    # Generic Solidity fallback
    return (
        "Follow Solidity security best practices: access-control modifiers, "
        "checked arithmetic (>= 0.8), checks-effects-interactions, and "
        "explicit validation of all external call return values."
    )


def _build_severity_rationale(finding: Finding, mapping: dict[str, str]) -> str:
    """
    Build a one-sentence severity rationale.
    All Wake Arena benchmark findings are confirmed High or Critical by
    contest judging; we always produce High as the label.
    """
    d = mapping.get("d3fend", "")
    cwe = mapping.get("cwe", "")
    vuln_type = mapping.get("name", "vulnerability")
    # Produce a rationale sentence that references the vulnerability class
    # without providing exploit construction.
    if "Authorization" in d or cwe in ("CWE-862", "CWE-863"):
        return (
            f"This {vuln_type} allows any external caller to perform "
            f"privileged operations without authorization, directly "
            f"enabling fund loss or protocol state corruption in "
            f"{finding.protocol}."
        )
    if "Process Spawn" in d or cwe == "CWE-841":
        return (
            f"The {vuln_type} pattern allows re-entry into a state-mutating "
            f"function before internal accounting is settled, enabling "
            f"repeated extraction beyond intended limits."
        )
    if "Memory Boundary" in d or cwe == "CWE-190":
        return (
            f"An {vuln_type} in a critical arithmetic path can produce "
            f"incorrect balances or counter values, corrupting protocol "
            f"accounting in {finding.protocol}."
        )
    # Generic high rationale
    return (
        f"This {vuln_type} was confirmed as High severity by "
        f"{finding.contest_platform} judging because it violates a core "
        f"protocol invariant with a realistic attack path requiring no "
        f"special permissions beyond those available to any external caller."
    )


# ---------------------------------------------------------------------------
# Validator (defender-only)
# ---------------------------------------------------------------------------


def validate_sample(sample: dict) -> tuple[bool, str]:
    """Return (ok, reason).  Reason is empty on success."""
    msgs = sample.get("messages", [])
    if not msgs or msgs[-1].get("role") != "assistant":
        return False, "missing assistant turn"
    assistant_text = msgs[-1].get("content", "")
    user_text = "\n".join(
        m.get("content", "") for m in msgs if m.get("role") == "user"
    )

    # The assistant must not leak offensive language.
    leak = contains_offensive_leak(assistant_text)
    if leak:
        return False, f"assistant leaks offensive pattern: {leak}"

    # For non-refusal templates the user prompt must also be clean.
    if sample.get("template") != "L4-wake_refusal":
        leak_u = contains_offensive_leak(user_text)
        if leak_u:
            return False, f"user prompt leaks offensive pattern: {leak_u}"

    # Sanity: assistant must not be empty.
    if len(assistant_text.strip()) < 20:
        return False, "assistant turn is too short"

    return True, ""


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------


ALL_TEMPLATE_RENDERERS = (
    render_finding_writeup,
    render_remediation,
    render_d3fend_map,
    render_severity_classify,
    # render_refusal is applied selectively (~10% of findings) below.
)


def iter_samples(
    findings: list[Finding],
    *,
    rng: random.Random,
    refusal_fraction: float = 0.10,
) -> Iterator[dict]:
    """
    Yield JSONL samples for all findings.  Applies refusal template to
    approximately refusal_fraction of findings (randomly selected).
    """
    refusal_set: set[int] = set()
    n_refusal = max(1, round(len(findings) * refusal_fraction))
    indices = list(range(len(findings)))
    rng.shuffle(indices)
    refusal_set = set(indices[:n_refusal])

    for idx, finding in enumerate(findings):
        mapping = cwe_lookup_wake(finding)
        for renderer in ALL_TEMPLATE_RENDERERS:
            yield renderer(finding, mapping)
        if idx in refusal_set:
            yield render_refusal(finding, mapping)


def build(args: argparse.Namespace) -> int:
    logging.basicConfig(
        level=(
            logging.DEBUG if args.verbose >= 2
            else logging.INFO if args.verbose == 1
            else logging.WARNING
        ),
        format="%(asctime)s %(levelname)s %(message)s",
    )

    rng = random.Random(args.seed)
    use_cache = not args.no_cache
    args.cache_dir.mkdir(parents=True, exist_ok=True)
    args.out.parent.mkdir(parents=True, exist_ok=True)

    # Stage 1: fetch README
    logging.info(
        "fetching Wake Arena README at ref %s from %s/%s",
        args.ref, WAKE_ARENA_OWNER, WAKE_ARENA_REPO,
    )
    try:
        readme_text = fetch_readme(
            ref=args.ref,
            token=args.github_token,
            cache_dir=args.cache_dir,
            use_cache=use_cache,
        )
    except FetchError as e:
        logging.error("failed to fetch README: %s", e)
        return 1

    logging.info("README fetched: %d bytes", len(readme_text))

    # Stage 2: parse findings
    findings = parse_findings(readme_text)
    logging.info("parsed %d findings from README", len(findings))
    if not findings:
        logging.error("no findings parsed; refusing to write an empty corpus")
        return 1

    if args.max_findings > 0:
        findings = findings[: args.max_findings]
        logging.info("capped to %d findings per --max-findings", len(findings))

    rng.shuffle(findings)

    # Stage 3: render and validate
    emitted = 0
    rejected_validator = 0
    template_counts: dict[str, int] = {}

    with args.out.open("w", encoding="utf-8") as fh:
        for sample in iter_samples(findings, rng=rng):
            ok, reason = validate_sample(sample)
            if not ok:
                rejected_validator += 1
                logging.debug(
                    "rejected %s for %s/%s: %s",
                    sample.get("template"),
                    sample.get("meta", {}).get("protocol", "?"),
                    sample.get("meta", {}).get("finding_id", "?"),
                    reason,
                )
                if args.strict:
                    logging.error(
                        "--strict: validator rejected sample: %s", reason
                    )
                    return 2
                continue
            fh.write(json.dumps(sample, ensure_ascii=False) + "\n")
            emitted += 1
            t = sample["template"]
            template_counts[t] = template_counts.get(t, 0) + 1

    # Summary to stderr
    print(
        f"[build_l4_wake_arena] findings_parsed={len(findings)} "
        f"emitted={emitted} rejected_by_validator={rejected_validator}",
        file=sys.stderr,
    )
    for t, n in sorted(template_counts.items()):
        print(f"[build_l4_wake_arena]   {t}: {n}", file=sys.stderr)

    logging.info(
        "emitted=%d rejected_by_validator=%d", emitted, rejected_validator
    )
    for t, n in sorted(template_counts.items()):
        logging.info("  %s: %d", t, n)

    if args.strict and rejected_validator > 0:
        logging.error(
            "--strict: validator rejected %d samples", rejected_validator
        )
        return 2

    if emitted == 0:
        logging.error("no samples emitted; refusing to write an empty corpus")
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
