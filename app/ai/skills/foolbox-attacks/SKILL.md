---
name: foolbox-attacks
description: >-
  Adversarial attacks via Foolbox library. FGSM, PGD, DeepFool,
  Boundary Attack, and C&W for evaluating ML model robustness with
  success rate and confidence metrics.
domain: ai-security
subdomain: ml-security
tags: [foolbox, adversarial, deepfool, boundary-attack, ml]
mitre_attack: [T1574.002]
nist_csf: [DE.CM-04]
mitre_atlas: [AML.T0012]
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Description
Foolbox adversarial attack library for ML/DL model robustness evaluation.

## Attack Methods
- FGSM (Fast Gradient Sign Method)
- PGD (Projected Gradient Descent)
- DeepFool (minimum perturbation)
- Boundary Attack (black-box)
- Carlini & Wagner L2

## Capabilities
- Per-attack success rate
- Confidence degradation metrics
- Minimum perturbation measurement
- PyTorch and TensorFlow support

## Workflow
1. Load model into Foolbox
2. Select attack method
3. Run attack on test samples
4. Measure success rate and confidence
5. Compare attack effectiveness
