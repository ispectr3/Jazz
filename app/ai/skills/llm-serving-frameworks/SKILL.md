---
name: llm-serving-frameworks
description: >-
  Security analysis of LLM serving frameworks. Covers vLLM, TGI, Triton,
  Ray Serve, BentoML, and Ollama. Includes prompt injection, model theft,
  and DoS vectors specific to each framework.
domain: ai-security
subdomain: llm-infrastructure
tags: [llm, serving, vllm, tgi, triton, bentoml, ollama]
mitre_attack: [T1190, T1498]
nist_csf: [PR.AC-01, PR.DS-01]
mitre_atlas: [AML.T0051]
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Framework Security Comparison

| Framework | Prompt Inject | Model Theft | DoS Vulns |
|-----------|--------------|-------------|-----------|
| vLLM | Medium | High | High |
| TGI | Medium | Medium | Medium |
| Triton | Low | Low | Medium |
| Ray Serve | High | Medium | Medium |
| BentoML | High | High | Low |
| Ollama | High | Low | Low |

## Key Vectors
- vLLM: Unvalidated sampling params, prompt leak via logprobs
- TGI: Token-level side channels
- Triton: Model name enumeration, unauthenticated inference
- Ray Serve: Dashboard exposure (port 8265), RCE via Jobs API
- BentoML: API without auth, model file traversal
- Ollama: No auth by default, model pull from any source
