# Raven existing modules (defender-relevant only)

## raven/core/ — runtime detection
- anomaly_detector.py — IsolationForest anomaly detection on behavioral telemetry
- behavioral_profiler.py — per-entity behavioral baselines
- threat_detector.py — orchestrator that fans out to anomaly + behavioral + ML

## raven/hunters/ — hypothesis-driven hunt
- hypothesis_generator.py — LLM-driven hypothesis generation
- automated_investigator.py — runs tool oracles against hypotheses
- threat_hunter.py — proactive scan loop
- kill_chain_planner.py — kill-chain anticipation (Incalmo-style; reframe as anticipation, not execution)

## raven/ml/ — ML detectors and analyzers
- zero_day_detector.py — IsolationForest + RandomForest ensemble for novel pattern detection
- variant_analyzer.py — variant analysis for known CVE patterns (ZeroDayBench style)
- code_flow_scanner.py — control- and data-flow scanner for source code
- memory_analyzer.py — memory-corruption pattern detection
- sequence_analyzer.py — process/syscall sequence anomalies
- behavioral_analyzer.py — user/entity behavioral classification
- cve_matcher.py — CVE/NVD/OSV lookup and correlation
- vulnerability_validator.py — exploitability scoring of LLM-claimed bugs (G-Bind grounding step)

## raven/mitigation/ — response actions
- containment_actions.py — process kill, network isolation, account disable
- remediation_engine.py — patch ID lookup + apply (regex-validated, shlex-quoted)
- response_orchestrator.py — orchestrator over containment + remediation with approval gate

## raven/approval/ — Hermes-style approval gate
- gate.py — manual/smart/off modes
- smart.py — auxiliary LLM that auto-approves benign actions
- patterns.py — UNRECOVERABLE_BLOCKLIST patterns (rm -rf /, fork bombs, mkfs /dev/sd*)
- store.py — pending-decision queue

## raven/redteam/ — defensive scanning of inbound /ai/* traffic
- detector.py — 8-family L1B3RT4S jailbreak fingerprinting
- normalizer.py — Parseltongue 33-decoder obfuscation normalization
- middleware.py — FastAPI middleware that runs detector on every /ai/* request
- hardness_test.py — provider 0-10 hardness scoring
- jailbreak_patterns.py — pattern corpus
- offensive.py — DEFENDER EDITION will EXCLUDE this file (godmode)

## raven/tools/ (defender-only subset to keep)
- adapter_base.py — unified ToolAdapter base class
- ares.py — ARES-v3 Solana smart-contract static auditor
- ebpf_ghidra.py — Solana eBPF for Ghidra decompiler
- ghidra_analyzer.py — Ghidra headless analysis
- radare2.py / radare_client.py — radare2 disassembly
- jadx.py / jadx_analyzer.py — JADX Android decompilation
- frida.py / frida_hook.py — Frida dynamic instrumentation (DEFENSIVE use: malware analysis)
- volatility.py / volatility_analyzer.py — Volatility 3 memory forensics
- yara_scan.py / yara_scanner.py — YARA malware signatures
- nmap_scanner.py — Nmap port scan (DEFENSIVE: asset discovery, vuln assessment)
- nuclei_scanner.py — Nuclei template-based vuln assessment (DEFENSIVE: own-asset scanning)
- projectdiscovery.py — subfinder/naabu/httpx/interactsh (DEFENSIVE: own-asset attack-surface management)
- recon_ng.py / recon_ng_client.py — recon-ng (DEFENSIVE: own-asset reconnaissance)
- whois_client.py — WHOIS lookup
- ssh_manager.py — strict SSH (paramiko RejectPolicy + operator known_hosts)
- bash_executor.py — safe bash (shell=False default)
- cyberchef.py / cyberchef_client.py — CyberChef data ops
- mcp_registry.py — MCP server registry

## raven/tools/ — TOOLS TO REMOVE FROM DEFENDER EDITION
- metasploit_integration.py — exploitation framework
- empire_client.py — post-exploitation C2
- exploitdb.py / exploitdb_client.py — searchsploit (exploit lookup)
- x64dbg_client.py — x64dbg debugger (boundary case — can keep for malware analysis)
