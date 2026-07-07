---
name: garak-llm-scanner
description: >-
  LLM vulnerability scanning with NVIDIA Garak. Probes for prompt
  injection, jailbreak, data leakage, hallucination, encoding
  vulnerabilities, and encoding-based attacks.
domain: ai-security
subdomain: llm-redteam
tags: [garak, llm, vulnerability-scanning, prompt-injection, jailbreak]
mitre_attack: [T1190]
nist_csf: [DE.CM-01, ID.RA-01]
mitre_atlas: [AML.T0051]
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Description
NVIDIA Garak LLM vulnerability scanner. Automated probing for prompt injection, jailbreak, data leakage, hallucination, and encoding attacks.

## Capabilities
- Prompt injection probe testing
- Jailbreak detection (DAN, roleplay, etc.)
- Data leakage testing (PII extraction)
- Hallucination measurement
- Encoding/obfuscation probe bypass
- Support for multiple model types (OpenAI, local)

## Probe Categories
- Prompt injection: direct and indirect
- Jailbreak: roleplay, encoding, multi-turn
- Data leakage: system prompt extraction
- Hallucination: factual consistency
- Encoding: base64, rot13, Unicode

## Workflow
1. Configure target model endpoint
2. Run Garak with probe selection
3. Parse JSON output for hits
4. Classify findings by probe type and severity
5. Generate remediation recommendations
