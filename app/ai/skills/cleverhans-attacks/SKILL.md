---
name: cleverhans-attacks
description: >-
  Adversarial ML attacks via CleverHans library. FGSM, PGD, C&W L2
  attacks with adversarial training and feature squeezing defenses
  for accuracy benchmarking.
domain: ai-security
subdomain: ml-security
tags: [cleverhans, adversarial, fgsm, pgd, ml-security]
mitre_attack: [T1574.002]
nist_csf: [DE.CM-04]
mitre_atlas: [AML.T0012]
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Description
CleverHans adversarial ML benchmark library for evaluating model robustness.

## Capabilities
- FGSM (Fast Gradient Sign Method)
- PGD (Projected Gradient Descent)
- C&W L2 (Carlini & Wagner)
- Adversarial Training defense
- Feature Squeezing defense
- Accuracy degradation benchmarking
- Dataset support (MNIST, CIFAR-10)

## Workflow
1. Load model and dataset
2. Run attack (FGSM, PGD, or C&W)
3. Measure accuracy before/after
4. Apply defense (adversarial training or feature squeezing)
5. Report accuracy improvement
