---
name: osintgpt-analysis
description: >-
  GPT-based OSINT analysis processing. Flexible field mapping for
  results, analysis, findings, and embeddings with confidence scoring
  and source attribution.
domain: ai-security
subdomain: llm-osint
tags: [osint, gpt, analysis, embeddings, confidence-scoring]
mitre_attack: [T1595]
nist_csf: [ID.AM-01]
mitre_atlas: []
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Description
GPT-based OSINT analysis processing that handles flexible JSON input formats.

## Capabilities
- Flexible field mapping (results/analysis/findings/embeddings)
- Confidence/score extraction
- Source attribution
- Severity classification
- Embedding vector processing

## Workflow
1. Receive GPT analysis JSON
2. Map fields to standard format
3. Extract confidence scores
4. Attribute findings to sources
5. Classify severity
6. Store with embeddings for similarity search
