---
name: hiddenlayer-monitor
description: >-
  ML/DL model security monitoring simulation. Covers prompt injection
  detection, data exfiltration, model extraction, jailbreak attempts,
  adversarial inputs, and drift detection alerts.
domain: ai-security
subdomain: llm-security
tags: [hiddenlayer, monitoring, detection, drift, ml-security]
mitre_attack: [T1190, T1498]
nist_csf: [DE.CM-01, DE.AE-01]
mitre_atlas: [AML.T0051]
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Description
HiddenLayer-style ML/DL model security monitoring. Detects attacks against production AI systems.

## Capabilities
- LLM monitoring alerts (prompt injection, data exfiltration, model extraction, jailbreak)
- ML model monitoring (adversarial input detection, drift detection)
- Confidence scoring per alert type
- Recommended actions (block, flag, rate-limit, retrain)

## Alert Types
- Prompt injection attempts
- Data exfiltration patterns
- Model extraction queries
- Jailbreak attempts
- Adversarial inputs
- Model drift detection

## Workflow
1. Configure monitoring parameters
2. Simulate attack scenarios
3. Classify alerts by type and severity
4. Generate recommended actions
5. Report detection coverage
