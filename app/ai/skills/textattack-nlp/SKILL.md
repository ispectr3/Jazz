---
name: textattack-nlp
description: >-
  NLP adversarial attack framework. 8 attack methods including
  TextFooler, DeepWordBug, BAE, PWWS, IGA, CLARE, ALICE, and
  FasterGenetic for evaluating NLP model robustness.
domain: ai-security
subdomain: nlp-security
tags: [textattack, nlp, adversarial, synonym-substitution, ml]
mitre_attack: [T1574.002]
nist_csf: [DE.CM-04]
mitre_atlas: [AML.T0012]
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Description
TextAttack NLP adversarial attack framework for evaluating text model robustness.

## Attack Methods (8)
TextFooler, DeepWordBug, BAE, PWWS, IGA, CLARE, ALICE, FasterGenetic

## Capabilities
- Synonym substitution attacks
- Character perturbation (typos, swaps)
- Insertion-based attacks
- Genetic algorithm optimization
- Masked language model attacks
- Success rate and query count metrics

## Workflow
1. Configure target NLP model
2. Select attack method(s)
3. Run attack on test inputs
4. Measure accuracy degradation
5. Compare attack effectiveness
