#!/usr/bin/env python3
"""
build_l4_ossf_cve.py
====================

Project Raven — L4 Corpus Builder: OSSF CVE Benchmark → defender-only secure-rewrite JSONL.

Source
------
Upstream:  https://github.com/wunderalbert/ossf-cve-benchmark  (MIT license)
Records:   220 real-world CVEs, each with vulnerable (prePatch) and fixed (postPatch)
           git commits in a known repository, plus CWE labels and weakness annotations.

What this builder does
----------------------
For each benchmark CVE we:

  1. Pull the CVE JSON record from the OSSF benchmark repository at a pinned commit.
  2. Resolve the affected source file at the prePatch commit (vulnerable version) and at
     the postPatch commit (fixed version) via raw.githubusercontent.com.
  3. Compute a small unified diff between the two file revisions.
  4. Reject any pair that does not fit the defender-only frame:
       - diff too large (likely a feature commit, not a vuln fix)
       - touched file is binary, lockfile, package manifest, or test fixture
       - the diff or weakness text contains offensive-leak patterns
         (PoC strings, exploit construction language, shellcode, etc.)
  5. For pairs that survive, emit one or more JSONL samples in five defender-only
     template families:

       L4-secure_rewrite       given vulnerable file + CWE + weakness explanation,
                               produce the patched file with rationale
       L4-diff_explain         given vuln/patch diff, explain what defensive control
                               the fix introduces (D3FEND artifact + CISA SbD principle)
       L4-cwe_mapping          given vulnerable code, map to CWE + D3FEND artifact +
                               CISA Secure-by-Design tactic, without producing exploit
       L4-review_checklist     given vulnerable code, produce a review checklist a
                               human defender would use to spot this class
       L4-refusal              for prompts that ask for PoC / exploit construction /
                               weaponization, produce a refusal that still cites the
                               CWE and the legitimate defensive remediation

All outputs are validated against the defender-only leak regex from
``build_l1_d3fend.py`` (single source of truth) before being written.

Grounding language baked into the system prompts
------------------------------------------------
- D3FEND v1.0 OWL (canonical defender vocabulary)
- CISA "Shifting the Balance of Cybersecurity Risk: Principles and Approaches for
  Security-by-Design and -Default" (April 2023)
  https://www.cisa.gov/sites/default/files/2023-10/SecureByDesign_1025_508c.pdf
- CDP grounding triple (𝒯 task, 𝓜 model, 𝓛 ledger) — Raven's three-pillar frame
- "System over mythos": vuln discovery is a structured pipeline, not a single model
  trick.  See Xint / Theori, "You Don't Need Mythos. You Need a System." (April 2026)
  https://xint.io

Usage
-----
    python build_l4_ossf_cve.py \
        --out data/l4_ossf_cve.jsonl \
        --benchmark-commit main \
        --max-cves 220 \
        --max-diff-lines 80 \
        --max-file-bytes 65536 \
        --workers 8 \
        --strict

Exit codes
----------
    0  success, JSONL written
    1  network / fetch error
    2  defender-only validator rejected the corpus (in --strict mode)
    3  invalid CLI arguments

The script is offline-resumable: a small cache directory holds raw blobs so reruns are
cheap.  Set ``--no-cache`` to force fresh fetches.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import dataclasses
import difflib
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
from typing import Iterable, Iterator

# ---------------------------------------------------------------------------
# Defender-only validator: SHARED with build_l1_d3fend.py
# ---------------------------------------------------------------------------
# Keep this regex set identical to L1.  When updating, update both files and
# run the unit test in tests/test_defender_only.py.

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

# Files we never train on, even if the patch is small.  These are noisy and
# rarely teach defender semantics.
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
    """Return the first matched pattern or None.  Used by --strict."""
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
# Data structures
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Weakness:
    file: str
    line: int | None
    explanation: str


@dataclasses.dataclass(frozen=True)
class CommitDescription:
    commit: str
    weaknesses: tuple[Weakness, ...] = ()


@dataclasses.dataclass(frozen=True)
class CveRecord:
    cve_id: str
    state: str
    repository: str            # e.g. https://github.com/owner/repo.git
    pre: CommitDescription     # vulnerable
    post: CommitDescription    # fixed
    cwes: tuple[str, ...]

    @property
    def owner_repo(self) -> tuple[str, str]:
        # strip trailing .git and any trailing /
        url = self.repository.rstrip("/")
        if url.endswith(".git"):
            url = url[:-4]
        parts = urllib.parse.urlparse(url)
        # path is /owner/repo
        owner, _, repo = parts.path.lstrip("/").partition("/")
        return owner, repo


@dataclasses.dataclass(frozen=True)
class FilePair:
    """One (vulnerable file, patched file) pair from a CVE."""

    cve_id: str
    path: str
    cwes: tuple[str, ...]
    weakness_explanation: str
    pre_commit: str
    post_commit: str
    pre_text: str
    post_text: str
    unified_diff: str


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="build_l4_ossf_cve",
        description="Build the L4 secure-rewrite corpus from the OSSF CVE benchmark.",
    )
    p.add_argument("--out", type=pathlib.Path, required=True,
                   help="Output JSONL path.")
    p.add_argument("--benchmark-commit", default="main",
                   help="Pin OSSF benchmark to this ref (commit SHA recommended). Default: main.")
    p.add_argument("--max-cves", type=int, default=0,
                   help="Process at most N CVEs (0 = all).")
    p.add_argument("--max-diff-lines", type=int, default=80,
                   help="Skip pairs whose unified diff exceeds this many lines.")
    p.add_argument("--max-file-bytes", type=int, default=65536,
                   help="Skip pairs whose pre- or post-patch file exceeds this many bytes.")
    p.add_argument("--workers", type=int, default=8,
                   help="Concurrent HTTP workers.")
    p.add_argument("--cache-dir", type=pathlib.Path,
                   default=pathlib.Path(".cache/ossf-cve"),
                   help="Cache directory for fetched blobs.")
    p.add_argument("--no-cache", action="store_true",
                   help="Bypass cache and re-fetch.")
    p.add_argument("--seed", type=int, default=20260515,
                   help="Random seed for sample shuffling and template selection.")
    p.add_argument("--strict", action="store_true",
                   help="Abort with exit code 2 if the validator rejects any emitted sample.")
    p.add_argument("--github-token", default=os.environ.get("GITHUB_TOKEN"),
                   help="Optional GitHub token to lift API rate limits (env GITHUB_TOKEN).")
    p.add_argument("-v", "--verbose", action="count", default=0)
    args = p.parse_args(argv)

    if args.workers < 1:
        p.error("--workers must be >= 1")
    if args.max_diff_lines < 4:
        p.error("--max-diff-lines must be >= 4")
    if args.max_file_bytes < 256:
        p.error("--max-file-bytes must be >= 256")
    return args


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


GITHUB_API = "https://api.github.com"
RAW_GITHUB = "https://raw.githubusercontent.com"
BENCHMARK_OWNER = "wunderalbert"
BENCHMARK_REPO = "ossf-cve-benchmark"


class FetchError(RuntimeError):
    pass


def _cache_path(cache_dir: pathlib.Path, url: str) -> pathlib.Path:
    h = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
    return cache_dir / h[:2] / h


def http_get(url: str, *, token: str | None, cache_dir: pathlib.Path,
             use_cache: bool, accept: str | None = None,
             max_retries: int = 4) -> bytes:
    if use_cache:
        cp = _cache_path(cache_dir, url)
        if cp.exists():
            return cp.read_bytes()

    headers = {
        "User-Agent": "raven-d3fend-l4-builder/1.0 (+https://github.com/daemon-blockint-tech/project-raven-d3fend)",
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
                # Cache the 404 too so we don't retry forever
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
# Benchmark loading
# ---------------------------------------------------------------------------


def list_benchmark_cves(*, ref: str, token: str | None,
                        cache_dir: pathlib.Path, use_cache: bool) -> list[str]:
    """List all CVE JSON filenames in the benchmark at a given ref."""
    url = (f"{GITHUB_API}/repos/{BENCHMARK_OWNER}/{BENCHMARK_REPO}"
           f"/contents/CVEs?ref={urllib.parse.quote(ref)}")
    data = http_get(url, token=token, cache_dir=cache_dir, use_cache=use_cache,
                    accept="application/vnd.github+json")
    if not data:
        raise FetchError(f"empty listing for {url}")
    listing = json.loads(data)
    names = sorted(
        item["name"] for item in listing
        if item.get("type") == "file" and item.get("name", "").startswith("CVE-")
        and item.get("name", "").endswith(".json")
    )
    if not names:
        raise FetchError("OSSF benchmark CVEs/ directory returned no .json files")
    return names


def load_cve_record(name: str, *, ref: str, token: str | None,
                    cache_dir: pathlib.Path, use_cache: bool) -> CveRecord | None:
    url = (f"{RAW_GITHUB}/{BENCHMARK_OWNER}/{BENCHMARK_REPO}/{ref}"
           f"/CVEs/{urllib.parse.quote(name)}")
    raw = http_get(url, token=token, cache_dir=cache_dir, use_cache=use_cache)
    if not raw:
        return None
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as e:
        logging.warning("bad JSON in %s: %s", name, e)
        return None

    state = obj.get("state", "")
    if state != "PUBLISHED":
        return None  # ignore DISPUTED / REJECTED / RESERVED

    repository = obj.get("repository") or ""
    pre = obj.get("prePatch") or {}
    post = obj.get("postPatch") or {}
    pre_commit = pre.get("commit") or ""
    post_commit = post.get("commit") or ""
    if not (repository and pre_commit and post_commit):
        return None

    def _weaknesses(d: dict) -> tuple[Weakness, ...]:
        out: list[Weakness] = []
        for w in d.get("weaknesses", []) or []:
            loc = w.get("location") or {}
            f = loc.get("file") or ""
            ln = loc.get("line")
            expl = (w.get("explanation") or "").strip()
            if f:
                out.append(Weakness(file=f, line=ln if isinstance(ln, int) else None,
                                    explanation=expl))
        return tuple(out)

    return CveRecord(
        cve_id=obj.get("CVE") or name.removesuffix(".json"),
        state=state,
        repository=repository,
        pre=CommitDescription(commit=pre_commit, weaknesses=_weaknesses(pre)),
        post=CommitDescription(commit=post_commit, weaknesses=_weaknesses(post)),
        cwes=tuple(obj.get("CWEs", []) or []),
    )


def fetch_file_at_commit(owner: str, repo: str, commit: str, path: str, *,
                         token: str | None, cache_dir: pathlib.Path,
                         use_cache: bool, max_bytes: int) -> str | None:
    """Fetch a single file via raw.githubusercontent.com.  Returns None on miss."""
    url = (f"{RAW_GITHUB}/{owner}/{repo}/{commit}/"
           f"{urllib.parse.quote(path, safe='/_.-')}")
    data = http_get(url, token=token, cache_dir=cache_dir, use_cache=use_cache)
    if not data:
        return None
    if len(data) > max_bytes:
        return None
    # Reject obviously binary blobs
    if b"\x00" in data[:4096]:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return data.decode("latin-1")
        except UnicodeDecodeError:
            return None


# ---------------------------------------------------------------------------
# Pair extraction
# ---------------------------------------------------------------------------


def extract_pairs(rec: CveRecord, *, token: str | None, cache_dir: pathlib.Path,
                  use_cache: bool, max_file_bytes: int,
                  max_diff_lines: int) -> list[FilePair]:
    owner, repo = rec.owner_repo
    pairs: list[FilePair] = []

    # We trust the benchmark's prePatch weakness annotations to identify the
    # affected file.  If multiple weaknesses share a file, we collapse them.
    seen_files: dict[str, str] = {}  # file -> explanation
    for w in rec.pre.weaknesses:
        if should_skip_file(w.file):
            continue
        seen_files.setdefault(w.file, w.explanation)

    if not seen_files:
        return pairs

    for path, explanation in seen_files.items():
        pre_text = fetch_file_at_commit(owner, repo, rec.pre.commit, path,
                                        token=token, cache_dir=cache_dir,
                                        use_cache=use_cache,
                                        max_bytes=max_file_bytes)
        if pre_text is None:
            continue
        post_text = fetch_file_at_commit(owner, repo, rec.post.commit, path,
                                         token=token, cache_dir=cache_dir,
                                         use_cache=use_cache,
                                         max_bytes=max_file_bytes)
        if post_text is None:
            continue
        if pre_text == post_text:
            continue

        diff_lines = list(difflib.unified_diff(
            pre_text.splitlines(keepends=True),
            post_text.splitlines(keepends=True),
            fromfile=f"a/{path}@{rec.pre.commit[:12]}",
            tofile=f"b/{path}@{rec.post.commit[:12]}",
            n=3,
        ))
        if not diff_lines:
            continue
        # Count only +/- lines, not headers
        changed = sum(1 for ln in diff_lines
                      if (ln.startswith("+") or ln.startswith("-"))
                      and not ln.startswith(("+++", "---")))
        if changed > max_diff_lines:
            continue

        pairs.append(FilePair(
            cve_id=rec.cve_id,
            path=path,
            cwes=rec.cwes,
            weakness_explanation=explanation,
            pre_commit=rec.pre.commit,
            post_commit=rec.post.commit,
            pre_text=pre_text,
            post_text=post_text,
            unified_diff="".join(diff_lines),
        ))
    return pairs


# ---------------------------------------------------------------------------
# CWE → D3FEND artifact / CISA SbD tactic mapping
# ---------------------------------------------------------------------------
# Small, hand-curated table.  Only the CWEs we actually expect to see in the
# OSSF benchmark are mapped; everything else falls back to "Software Component
# Hardening".  The mapping is intentionally conservative: each entry must
# correspond to a real D3FEND defensive technique present in v1.0 OWL.

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

DEFAULT_CWE_ENTRY = {
    "name": "Software Weakness",
    "d3fend": "Software Component Hardening",
    "sbd": ("Apply the CISA Secure-by-Design principles: take ownership of customer "
            "security outcomes, eliminate entire classes of vulnerabilities, ship "
            "secure defaults, and provide hardening guides instead of loosening guides."),
}


def cwe_lookup(cwes: tuple[str, ...]) -> dict[str, str]:
    """Pick the first known CWE, fall back to default."""
    for c in cwes:
        # Normalize CWE-XXX form
        m = re.match(r"^CWE-(\d+)$", c.strip(), re.IGNORECASE)
        if not m:
            continue
        key = f"CWE-{int(m.group(1)):03d}"
        if key in CWE_DEFEND_MAP:
            return {"cwe": key, **CWE_DEFEND_MAP[key]}
    # No known CWE: emit the first one verbatim with default mapping
    first = cwes[0] if cwes else "CWE-000"
    return {"cwe": first, **DEFAULT_CWE_ENTRY}


# ---------------------------------------------------------------------------
# Sample templates (defender-only)
# ---------------------------------------------------------------------------


SYSTEM_DEFENDER = (
    "You are Raven, a defender-only security AI grounded in three pillars: "
    "(1) the CDP grounding triple 𝒯 (task), 𝓜 (model), 𝓛 (ledger); "
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


def render_secure_rewrite(pair: FilePair, mapping: dict[str, str]) -> dict:
    user = (
        f"File: {pair.path}\n"
        f"CWE: {mapping['cwe']} ({mapping['name']})\n"
        f"Annotated weakness (from OSSF CVE benchmark, CVE {pair.cve_id}):\n"
        f"  {pair.weakness_explanation or 'No upstream explanation; infer from code.'}\n\n"
        f"--- vulnerable version ---\n{pair.pre_text}\n"
        "--- end vulnerable ---\n\n"
        "Produce the patched file. Then write a 'Defender Rationale' section "
        f"that names the D3FEND artifact ({mapping['d3fend']}) and the CISA "
        "Secure-by-Design tactic this patch realizes. Do not describe how to "
        "exploit the original code."
    )
    rationale = (
        "Defender Rationale\n"
        f"- CWE: {mapping['cwe']} ({mapping['name']})\n"
        f"- D3FEND artifact: {mapping['d3fend']}\n"
        f"- CISA Secure-by-Design tactic: {mapping['sbd']}\n"
        f"- CDP ledger entry: CVE {pair.cve_id} prePatch "
        f"{pair.pre_commit[:12]} -> postPatch {pair.post_commit[:12]}, "
        f"file {pair.path}."
    )
    assistant = f"{pair.post_text}\n\n{rationale}\n"
    return {
        "template": "L4-secure_rewrite",
        "messages": [
            {"role": "system", "content": SYSTEM_DEFENDER},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant},
        ],
        "meta": {
            "cve": pair.cve_id,
            "path": pair.path,
            "cwe": mapping["cwe"],
            "d3fend": mapping["d3fend"],
            "pre_commit": pair.pre_commit,
            "post_commit": pair.post_commit,
        },
    }


def render_diff_explain(pair: FilePair, mapping: dict[str, str]) -> dict:
    user = (
        f"Below is the unified diff between the vulnerable and the patched "
        f"version of {pair.path} (CVE {pair.cve_id}). Explain the defensive "
        "control the fix introduces. Name the D3FEND artifact and the CISA "
        "Secure-by-Design tactic. Do not explain how to exploit the original.\n\n"
        f"{pair.unified_diff}"
    )
    assistant = (
        f"Defensive control: this patch realizes {mapping['d3fend']} for "
        f"{mapping['cwe']} ({mapping['name']}).\n"
        f"Secure-by-Design tactic: {mapping['sbd']}\n"
        f"Why the original was unsafe (defender frame): the prePatch revision "
        f"failed to enforce {mapping['d3fend']} on the affected code path, "
        f"which the OSSF benchmark annotates as: "
        f"{pair.weakness_explanation or 'a violation of the CWE invariant above'}.\n"
        f"Operator action: when reviewing similar code, look for the absence "
        f"of {mapping['d3fend']} and require it as a precondition before "
        f"merging. This is a hardening guide, not a loosening guide.\n"
        f"CDP ledger: CVE {pair.cve_id} prePatch {pair.pre_commit[:12]} -> "
        f"postPatch {pair.post_commit[:12]}, file {pair.path}."
    )
    return {
        "template": "L4-diff_explain",
        "messages": [
            {"role": "system", "content": SYSTEM_DEFENDER},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant},
        ],
        "meta": {
            "cve": pair.cve_id,
            "path": pair.path,
            "cwe": mapping["cwe"],
            "d3fend": mapping["d3fend"],
        },
    }


def render_cwe_mapping(pair: FilePair, mapping: dict[str, str]) -> dict:
    user = (
        f"Given this code from {pair.path}, identify the CWE class, the "
        "matching D3FEND defensive artifact, and the CISA Secure-by-Design "
        "tactic that would eliminate this class entirely. Do not propose "
        "exploitation steps.\n\n"
        f"```\n{pair.pre_text}\n```"
    )
    assistant = (
        f"- CWE class: {mapping['cwe']} ({mapping['name']})\n"
        f"- D3FEND artifact: {mapping['d3fend']}\n"
        f"- CISA Secure-by-Design tactic: {mapping['sbd']}\n"
        f"- Ledger anchor: CVE {pair.cve_id}, prePatch {pair.pre_commit[:12]}."
    )
    return {
        "template": "L4-cwe_mapping",
        "messages": [
            {"role": "system", "content": SYSTEM_DEFENDER},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant},
        ],
        "meta": {
            "cve": pair.cve_id,
            "path": pair.path,
            "cwe": mapping["cwe"],
            "d3fend": mapping["d3fend"],
        },
    }


def render_review_checklist(pair: FilePair, mapping: dict[str, str]) -> dict:
    user = (
        f"Act as a senior secure-code reviewer. Produce a short checklist a "
        f"reviewer should run against code resembling the file below "
        f"({pair.path}, CWE class {mapping['cwe']}). Tie each item to a "
        "D3FEND artifact. Output as a bullet list. Do not describe attacks.\n\n"
        f"```\n{pair.pre_text}\n```"
    )
    bullets = [
        f"- Is {mapping['d3fend']} applied on every untrusted input path in this file? "
        f"(blocks {mapping['cwe']} {mapping['name']})",
        f"- Are the CISA Secure-by-Default tactics in effect for this module: "
        f"{mapping['sbd']}",
        f"- Does the change set introduce a loosening guide? If yes, require a hardening "
        f"guide instead before merge.",
        f"- Is there a CDP ledger entry naming the 𝒯 (task), the 𝓜 (model or component "
        f"under review), and the 𝓛 (commit + reviewer) for this change?",
        f"- Is a regression test asserting the D3FEND artifact's invariant added in the "
        f"same merge request?",
    ]
    assistant = "\n".join(bullets)
    return {
        "template": "L4-review_checklist",
        "messages": [
            {"role": "system", "content": SYSTEM_REVIEW},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant},
        ],
        "meta": {
            "cve": pair.cve_id,
            "path": pair.path,
            "cwe": mapping["cwe"],
            "d3fend": mapping["d3fend"],
        },
    }


def render_refusal(pair: FilePair, mapping: dict[str, str]) -> dict:
    user = (
        f"Here is vulnerable code from {pair.path} (CVE {pair.cve_id}). "
        "Write a working proof-of-concept exploit and explain how to "
        "weaponize it against a production target.\n\n"
        f"```\n{pair.pre_text}\n```"
    )
    assistant = (
        "I will not produce a proof-of-concept exploit, weaponized payload, "
        "or operational exploitation guidance. Raven is defender-only; that "
        "request is outside the policy boundary.\n\n"
        "Defender-frame answer:\n"
        f"- CWE class: {mapping['cwe']} ({mapping['name']})\n"
        f"- D3FEND artifact to deploy: {mapping['d3fend']}\n"
        f"- Secure-by-Design tactic: {mapping['sbd']}\n"
        f"- Concrete next step: apply the upstream patch at postPatch "
        f"{pair.post_commit[:12]} for CVE {pair.cve_id}, then add a regression "
        f"test asserting the {mapping['d3fend']} invariant on the affected path.\n"
        "- CDP ledger: record the 𝒯 (remediation task), 𝓜 (the component patched), "
        "and 𝓛 (the merge commit) so future reviewers can replay the decision."
    )
    return {
        "template": "L4-refusal",
        "messages": [
            {"role": "system", "content": SYSTEM_DEFENDER},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant},
        ],
        "meta": {
            "cve": pair.cve_id,
            "path": pair.path,
            "cwe": mapping["cwe"],
            "d3fend": mapping["d3fend"],
            "policy": "defender-only-refusal",
        },
    }


TEMPLATE_RENDERERS = (
    render_secure_rewrite,
    render_diff_explain,
    render_cwe_mapping,
    render_review_checklist,
    render_refusal,
)


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------


def validate_sample(sample: dict) -> tuple[bool, str]:
    """Return (ok, reason).  Reason is empty on success."""
    msgs = sample.get("messages", [])
    if not msgs or msgs[-1].get("role") != "assistant":
        return False, "missing assistant turn"
    assistant_text = msgs[-1].get("content", "")
    user_text = "\n".join(m.get("content", "") for m in msgs if m.get("role") == "user")

    # The assistant must not leak offensive language.  The user turn may
    # legitimately contain offensive *requests* in refusal samples; we only
    # scan the assistant output for leakage.
    leak = contains_offensive_leak(assistant_text)
    if leak:
        return False, f"assistant leaks offensive pattern: {leak}"

    # For non-refusal templates the user prompt itself must also be clean,
    # otherwise we are training on offensive prompts.
    if sample.get("template") != "L4-refusal":
        leak_u = contains_offensive_leak(user_text)
        if leak_u:
            return False, f"user prompt leaks offensive pattern: {leak_u}"

    return True, ""


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------


def build(args: argparse.Namespace) -> int:
    logging.basicConfig(
        level=logging.DEBUG if args.verbose >= 2 else (
            logging.INFO if args.verbose == 1 else logging.WARNING),
        format="%(asctime)s %(levelname)s %(message)s",
    )

    rng = random.Random(args.seed)
    use_cache = not args.no_cache
    args.cache_dir.mkdir(parents=True, exist_ok=True)
    args.out.parent.mkdir(parents=True, exist_ok=True)

    logging.info("listing benchmark CVEs at ref %s", args.benchmark_commit)
    names = list_benchmark_cves(ref=args.benchmark_commit, token=args.github_token,
                                cache_dir=args.cache_dir, use_cache=use_cache)
    if args.max_cves > 0:
        names = names[:args.max_cves]
    logging.info("loaded %d CVE filenames", len(names))

    # Stage 1: load records
    records: list[CveRecord] = []
    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {
            ex.submit(load_cve_record, n, ref=args.benchmark_commit,
                      token=args.github_token, cache_dir=args.cache_dir,
                      use_cache=use_cache): n for n in names
        }
        for fut in cf.as_completed(futs):
            try:
                rec = fut.result()
            except Exception as e:
                logging.warning("failed to load %s: %s", futs[fut], e)
                continue
            if rec is not None:
                records.append(rec)
    logging.info("loaded %d PUBLISHED records", len(records))

    # Stage 2: extract file pairs
    pairs: list[FilePair] = []
    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {
            ex.submit(extract_pairs, r,
                      token=args.github_token,
                      cache_dir=args.cache_dir,
                      use_cache=use_cache,
                      max_file_bytes=args.max_file_bytes,
                      max_diff_lines=args.max_diff_lines): r for r in records
        }
        for fut in cf.as_completed(futs):
            try:
                pairs.extend(fut.result())
            except Exception as e:
                logging.warning("pair extraction failed for %s: %s",
                                futs[fut].cve_id, e)
                continue
    logging.info("extracted %d usable file pairs", len(pairs))

    # Stage 3: render and validate
    rng.shuffle(pairs)
    emitted = 0
    rejected_validator = 0
    template_counts: dict[str, int] = {}

    with args.out.open("w", encoding="utf-8") as fh:
        for pair in pairs:
            mapping = cwe_lookup(pair.cwes)
            for renderer in TEMPLATE_RENDERERS:
                sample = renderer(pair, mapping)
                ok, reason = validate_sample(sample)
                if not ok:
                    rejected_validator += 1
                    logging.debug("rejected %s for %s: %s",
                                  sample.get("template"), pair.cve_id, reason)
                    continue
                fh.write(json.dumps(sample, ensure_ascii=False) + "\n")
                emitted += 1
                t = sample["template"]
                template_counts[t] = template_counts.get(t, 0) + 1

    logging.info("emitted=%d rejected_by_validator=%d", emitted, rejected_validator)
    for t, n in sorted(template_counts.items()):
        logging.info("  %s: %d", t, n)

    if args.strict and rejected_validator > 0:
        logging.error("--strict: validator rejected %d samples", rejected_validator)
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
