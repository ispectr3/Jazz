---
name: promptbench-eval
description: >-
  Microsoft PromptBench evaluation. Measures LLM accuracy degradation
  under adversarial prompts across multiple datasets (MMLU, GSM8K,
  SST-2, BBH) and attack types.
domain: ai-security
subdomain: llm-redteam
tags: [promptbench, microsoft, benchmark, adversarial, llm]
mitre_attack: [T1190]
nist_csf: [DE.CM-01]
mitre_atlas: [AML.T0051]
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Description
Microsoft PromptBench for measuring LLM accuracy degradation under adversarial attacks.

## Capabilities
- Accuracy baseline vs under-attack comparison
- Degradation measurement
- Dataset support (MMLU, GSM8K, SST-2, BBH)
- Attack type classification (character, word, sentence, semantic)
- Multi-model comparison

## Attack Types
- Character-level: typos, swaps, deletions
- Word-level: synonym substitution, misspelling
- Sentence-level: paraphrasing
- Semantic: meaning-preserving perturbations

## Workflow
1. Configure model and datasets
2. Run baseline accuracy evaluation
3. Run adversarial attack evaluation
4. Calculate accuracy degradation
5. Report vulnerability by attack type
