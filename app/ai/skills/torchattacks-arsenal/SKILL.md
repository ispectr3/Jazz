---
name: torchattacks-arsenal
description: >-
  15 adversarial attacks from TorchAttacks library. FGSM, PGD, C&W,
  AutoAttack, SquareAttack, DeepFool, BIM, RFGSM, EOTPGD, FFGSM,
  TPGD, VNIFGSM, SPSA, UAP for PyTorch model evaluation.
domain: ai-security
subdomain: ml-security
tags: [torchattacks, adversarial, pytorch, autoattack, ml]
mitre_attack: [T1574.002]
nist_csf: [DE.CM-04]
mitre_atlas: [AML.T0012]
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Description
15 adversarial attacks from TorchAttacks for comprehensive PyTorch model evaluation.

## Attack Categories
- One-step: FGSM, RFGSM, FFGSM
- Iterative: PGD, BIM, TPGD, VNIFGSM
- Optimization: C&W, DeepFool
- Ensemble: AutoAttack
- Black-box: SquareAttack, SPSA
- Universal: UAP
- Expectation over Transformation: EOTPGD

## Capabilities
- 15 attack methods with paper references
- Success rate and parameter reporting
- PyTorch native integration

## Workflow
1. Load PyTorch model
2. Select attack methods
3. Run attacks on test data
4. Compare success rates
5. Generate robustness report
