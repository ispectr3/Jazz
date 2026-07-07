---
name: llmguard-scanner
description: >-
  LLM Guard security scanning by ProtectAI. 15 input scanners and 21
  output scanners for sanitizing LLM inputs and outputs including
  prompt injection, secrets, toxicity, and factual consistency.
domain: ai-security
subdomain: llm-security
tags: [llmguard, protectai, input-scanning, output-scanning, security]
mitre_attack: [T1190]
nist_csf: [PR.AC-01, DE.CM-01]
mitre_atlas: [AML.T0051]
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Description
ProtectAI LLM Guard security gateway. Scans LLM inputs and outputs for injection, secrets, toxicity, bias, and consistency.

## Input Scanners (15)
Anonymize, BanCode, BanTopics, Gibberish, InvisibleText, Language, PromptInjection, Regex, Secrets, Sentiment, TokenLimit, Toxicity

## Output Scanners (21)
Bias, Deanonymize, FactualConsistency, MaliciousURLs, NoRefusal, Relevance, Sensitive, and 14 more

## Workflow
1. Configure LLM Guard endpoint
2. Send input for scanning
3. Check blocking decisions
4. Send output for scanning
5. Analyze risk scores per scanner
6. Generate security report
