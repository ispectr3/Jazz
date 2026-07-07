---
name: promptinject-test
description: >-
  LLM prompt injection vulnerability testing. Tests models for direct
  injection, jailbreak, and encoding bypass with success/failure
  classification and indicator analysis.
domain: ai-security
subdomain: llm-redteam
tags: [prompt-injection, jailbreak, llm, testing, vulnerability]
mitre_attack: [T1190]
nist_csf: [DE.CM-01]
mitre_atlas: [AML.T0051]
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Description
Automated prompt injection testing for LLM models. Classifies results as vulnerable, resistant, or errored.

## Capabilities
- Prompt injection testing with multiple payloads
- Success/failure classification
- Indicator reporting (what broke guardrails)
- Response preview capture
- Test summary with injection success rates

## Injection Types
- Direct override: "Ignore previous instructions..."
- Roleplay/jailbreak: "You are DAN..."
- Encoding bypass: base64, Unicode, zero-width chars
- Multi-turn progressive extraction
- Indirect injection via RAG context

## Workflow
1. Configure target model endpoint
2. Send injection payloads
3. Classify responses (vulnerable/resistant)
4. Analyze indicators of successful injection
5. Generate vulnerability report
