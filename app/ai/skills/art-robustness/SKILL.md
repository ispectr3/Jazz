---
name: art-robustness
description: >-
  IBM ART (Adversarial Robustness Toolbox) for ML model security.
  Evasion (FGSM, PGD, C&W, DeepFool, Boundary), poisoning
  (Backdoor, LabelFlipping), extraction, and inference attacks.
domain: ai-security
subdomain: ml-security
tags: [art, ibm, adversarial-robustness, evasion, poisoning, ml]
mitre_attack: [T1574.002]
nist_csf: [DE.CM-04, PR.DS-01]
mitre_atlas: [AML.T0012, AML.T0018]
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Description
IBM ART (Adversarial Robustness Toolbox) for comprehensive ML/DL model security evaluation.

## Attack Categories
- Evasion: FGSM, PGD, C&W L2, DeepFool, ElasticNet, Boundary, HopSkipJump
- Poisoning: Backdoor, LabelFlipping
- Extraction: KnockoffNets, CopycatCNN
- Inference: MembershipInference, ModelInversion

## Capabilities
- Multi-framework support (PyTorch, TensorFlow, scikit-learn)
- Recommended defenses per attack type
- Robustness metrics and reporting
- Certified defenses (randomized smoothing)

## Workflow
1. Load target model and dataset
2. Select attack category and method
3. Execute attack with parameters
4. Measure success rate and confidence
5. Generate defense recommendations
