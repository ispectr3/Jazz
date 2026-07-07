---
name: prompt-injection-detection
description: >-
  Detection patterns and bypass techniques for prompt injection in LLMs.
  Includes system prompt extraction, DAN-style attacks, and RAG poisoning.
domain: ai-security
subdomain: llm-redteam
tags: [llm, prompt-injection, red-team, garak, dan]
mitre_attack: [T1190]
nist_csf: [DE.CM-01]
mitre_atlas: [AML.T0051]
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## When to Use
Ao testar seguranca de LLM applications contra prompt injection.

## Detection Patterns
- "Ignore as instrucoes anteriores"
- "You are now" / "DAN" / "do anything now"
- System prompt extraction attempts
- Token smuggling in RAG context

## Bypass Techniques
1. Role-playing: "Act as a Linux terminal..."
2. Character encoding: Unicode normalization
3. Context switching: Multi-turn injection
4. Token smuggling: Split payload across contexts
5. Base64/encoded injection: Obfuscated instructions

## Tools
- Garak: LLM vulnerability scanner
- PyRIT: Microsoft adversarial framework
- PromptInjector: Automated injection testing
- LLM Guard: Input/output scanning
- Rebuff: Prompt injection detection

## Mitigation
1. Input sanitization with allowlists
2. Output validation before rendering
3. Context isolation per user session
4. Rate limiting on sensitive operations
5. Human-in-the-loop for critical actions
