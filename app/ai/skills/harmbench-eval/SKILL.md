---
name: harmbench-eval
description: >-
  CAIS HarmBench evaluation. Standardized benchmark for automated
  red teaming across 18 attack methods (GCG, AutoDAN, PAIR, TAP,
  ZeroShot, PEZ, Transfer) and 33 LLMs.
domain: ai-security
subdomain: llm-redteam
tags: [harmbench, benchmark, red-teaming, llm, attack-methods]
mitre_attack: [T1190]
nist_csf: [DE.CM-01, ID.RA-01]
mitre_atlas: [AML.T0051]
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Description
CAIS HarmBench academic benchmark for automated red teaming evaluation.

## Attack Methods (18)
GCG, AutoDAN, PAIR, TAP, ZeroShot, PEZ, Transfer, and 11 more

## Capabilities
- Attack success rate analysis per method
- Robustness scoring across methods
- Refusal rate metrics
- Llama-2-13b classifier for harm detection
- Multi-LLM evaluation (33 models)

## Workflow
1. Configure target LLM
2. Run HarmBench with selected attack methods
3. Parse attack success rates
4. Calculate robustness score
5. Compare across attack methods
