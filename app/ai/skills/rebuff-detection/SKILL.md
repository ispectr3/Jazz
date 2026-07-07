---
name: rebuff-detection
description: >-
  ProtectAI Rebuff prompt injection detection. 4-layer defense:
  heuristics, LLM detection, VectorDB similarity, and canary token
  analysis for self-hardening protection.
domain: ai-security
subdomain: llm-security
tags: [rebuff, prompt-injection, detection, heuristics, vector-db]
mitre_attack: [T1190]
nist_csf: [DE.CM-01, PR.AC-01]
mitre_atlas: [AML.T0051]
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Description
ProtectAI Rebuff prompt injection detection with 4 defense layers.

## Defense Layers
1. Heuristics: pattern-based injection detection
2. LLM-based: model classifies input as injection
3. VectorDB: similarity matching against known attacks
4. Canary tokens: leak detection in LLM outputs

## Capabilities
- 4-layer defense analysis
- Injection detection scoring
- VectorDB similarity matching
- Canary token leak detection

## Workflow
1. Configure Rebuff API endpoint
2. Send input through all 4 layers
3. Compare layer scores
4. Detect canary token leakage
5. Generate defense recommendation
