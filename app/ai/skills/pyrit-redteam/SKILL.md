---
name: pyrit-redteam
description: >-
  Microsoft PyRIT red teaming for generative AI. Multi-turn orchestrators,
  converters (base64, rot13, Unicode, leetspeak), and automatic scoring
  for vulnerability assessment.
domain: ai-security
subdomain: llm-redteam
tags: [pyrit, microsoft, red-teaming, orchestrator, scoring]
mitre_attack: [T1190]
nist_csf: [DE.CM-01, ID.RA-01]
mitre_atlas: [AML.T0051]
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Description
Microsoft PyRIT (Python Risk Identification Tool) for generative AI red teaming.

## Capabilities
- Multi-turn orchestrator analysis (RedTeamingOrchestrator, XAIOrchestrator, SkeletonKey)
- Converter support (base64, rot13, ascii, unicode, leetspeak)
- Self-Ask scorers (Category, TrueFalse)
- Vulnerability/resistance classification
- Automated red teaming pipelines

## Workflow
1. Configure target and orchestrator
2. Run red teaming with converters
3. Score responses for vulnerability
4. Classify as vulnerable or resistant
5. Report findings with orchestrator breakdown
