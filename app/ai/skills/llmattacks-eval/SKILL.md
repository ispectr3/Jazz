---
name: llmattacks-eval
description: >-
  GCG and transfer attacks on LLMs. Optimizes adversarial suffixes
  to elicit harmful behaviors across open-source and API-based models.
domain: ai-security
subdomain: llm-redteam
tags: [gcg, transfer-attack, adversarial-suffix, llm, red-team]
mitre_attack: [T1190]
nist_csf: [DE.CM-01]
mitre_atlas: [AML.T0051]
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Description
GCG (Greedy Coordinate Gradient) and transfer attacks on LLMs. Optimizes adversarial suffixes to bypass safety alignment.

## Capabilities
- GCG direct attack (adversarial suffix optimization)
- Transfer attack (open-source to API model transfer)
- Harmful behavior testing (bomb-making, hacking, malware, phishing)
- Attack success rate reporting

## Workflow
1. Configure target and source models
2. Run GCG to optimize adversarial suffix
3. Test suffix on target model
4. Attempt transfer from open-source to API model
5. Report attack success rates per behavior category
