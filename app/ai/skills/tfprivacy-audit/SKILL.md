---
name: tfprivacy-audit
description: >-
  Differential privacy audit using TensorFlow Privacy. Analyzes epsilon
  and delta budgets across thresholds (0.5 to 32.0), noise multiplier,
  and generates budget usage recommendations.
domain: ai-security
subdomain: privacy
tags: [differential-privacy, tf-privacy, epsilon, delta, audit]
mitre_attack: []
nist_csf: [PR.DS-01, ID.RA-01]
mitre_atlas: [AML.T0024]
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Description
TensorFlow Privacy differential privacy audit. Analyzes privacy budgets across multiple epsilon thresholds.

## Capabilities
- Epsilon audit (0.5 to 32.0)
- Delta and noise multiplier analysis
- Privacy budget usage calculation
- Within-budget/exceeded classification
- Recommendation generation

## Workflow
1. Load model with DP training history
2. Analyze epsilon and delta values
3. Check budget against thresholds
4. Classify as within-budget or exceeded
5. Generate recommendations for budget adjustment
