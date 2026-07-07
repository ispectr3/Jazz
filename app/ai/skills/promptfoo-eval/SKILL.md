---
name: promptfoo-eval
description: >-
  LLM red-teaming evaluation with Promptfoo. Custom YAML configs,
  providers, test cases, and named score analysis for red teaming
  and regression testing.
domain: ai-security
subdomain: llm-redteam
tags: [promptfoo, evaluation, red-teaming, testing, llm]
mitre_attack: [T1190]
nist_csf: [DE.CM-01]
mitre_atlas: [AML.T0051]
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Description
Promptfoo LLM red-teaming evaluation framework with custom test configurations.

## Capabilities
- Custom YAML config generation
- Multiple provider support
- Test failure detection
- Named score analysis
- Regression testing across model versions

## Workflow
1. Create promptfoo YAML config
2. Define providers and test cases
3. Run evaluation: `npx promptfoo eval`
4. Parse results for failures
5. Analyze score distribution
6. Generate comparison reports
