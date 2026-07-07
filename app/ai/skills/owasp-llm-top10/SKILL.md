---
name: owasp-llm-top10
description: >-
  OWASP Top 10 for Large Language Model Applications v1.1. Prompt Injection,
  Insecure Output Handling, Training Data Poisoning, Model DoS, Supply Chain,
  Sensitive Information Disclosure, Insecure Plugin Design, and more.
domain: ai-security
subdomain: llm-security
tags: [owasp, llm, prompt-injection, security, llm-top10]
mitre_attack: [T1190, T1059.007]
nist_csf: [ID.RA-01, PR.AC-01]
mitre_atlas: [AML.T0051]
version: "1.1"
author: OWASP / Jaizz Noir
license: Apache-2.0
---

## LLM01: Prompt Injection
Manipulating LLMs via crafted inputs can lead to unauthorized access, data breaches.
- Tools: Garak, PyRIT, PromptInjector, LLM Guard, Rebuff, HarmBench

## LLM02: Insecure Output Handling
Neglecting to validate LLM outputs may lead to downstream security exploits.
- Tools: LLM Guard (output scanners)

## LLM03: Training Data Poisoning
Tampered training data can impair LLM models.
- Tools: HarmBench

## LLM04: Model Denial of Service
Overloading LLMs with resource-heavy operations.
- Tools: LLM Guard (TokenLimit scanner)

## LLM05: Supply Chain Vulnerabilities
Depending on compromised components.
- Audit dependencies regularly

## LLM06: Sensitive Information Disclosure
Failure to protect sensitive information in LLM outputs.
- Tools: LLM Guard (Secrets, Anonymize), Garak

## LLM07: Insecure Plugin Design
LLM plugins processing untrusted inputs with insufficient access control.
- Validate all plugin inputs

## LLM08: Excessive Agency
LLM-based systems with excessive functionality.
- Limit plugin capabilities

## LLM09: Overreliance
Users over-relying on LLM outputs without oversight.
- Implement human-in-the-loop

## LLM10: Model Theft
Unauthorized access to proprietary LLM models.
- Implement access controls
