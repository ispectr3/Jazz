---
name: reverse-skill-llm-security
description: >-
  Reverse engineering approach to LLM security testing. Extracts system
  prompts, probing hidden capabilities, identifying safety guardrails,
  and testing alignment bypasses.
domain: ai-security
subdomain: llm-redteam
tags: [llm, reverse-engineering, red-team, alignment, system-prompt]
mitre_attack: [T1190]
nist_csf: [DE.CM-01]
mitre_atlas: [AML.T0051]
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Approach
Reverse engineering LLM security by:
1. System prompt extraction through progressive probing
2. Identifying safety guardrails and their boundaries
3. Testing alignment bypass techniques
4. Mapping capability boundaries
5. Discovering hidden/emergent behaviors

## Techniques
- Token-level gradient analysis
- Output distribution probing
- Prompt leakage via verbose responses
- Constraint relaxation through multi-turn dialogue
- Role-playing to bypass alignment

## Detection
Monitor for:
- Repeated refusal patterns with specific topics
- Sudden behavior changes at topic boundaries
- Inconsistent application of safety rules
- Leaked formatting/instructions in error messages
