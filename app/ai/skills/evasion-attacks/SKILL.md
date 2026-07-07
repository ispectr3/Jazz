---
name: evasion-attacks
description: >-
  Técnicas de ataques de evasão para modelos de ML/LLM. Inclui FGSM, PGD,
  adversarial patches, defesas como feature squeezing e adversarial training.
domain: ai-security
subdomain: llm-redteam
tags: [evasion, adversarial, ml-security, fgsm, pgd, llm]
mitre_attack: [T1574.002]
nist_csf: [DE.CM-04]
mitre_atlas: [AML.T0012]
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## When to Use
Ao testar robustez de modelos de ML/LLM contra ataques adversariais. Ativar quando:
- Avaliando defesas de modelos de classificacao
- Testando robustez de LLMs contra entradas adversarial
- Realizando red teaming em pipelines de ML

## Prerequisites
- Conhecimento de PyTorch/TensorFlow
- Acesso ao modelo alvo (white-box ou black-box)
- Ferramentas: CleverHans, Foolbox, ART, TextAttack

## Workflow
1. Identificar tipo de modelo (classificador, LLM, detector)
2. Selecionar tecnica de ataque (FGSM, PGD, C&W, Boundary)
3. Calcular perturbacao minima
4. Aplicar a entrada original
5. Verificar se modelo classifica incorretamente

## Attack Types
| Attack | Type | Required Access |
|--------|------|----------------|
| FGSM | Gradient-based | White-box |
| PGD | Iterative gradient | White-box |
| C&W | Optimization | White-box |
| Boundary | Decision-based | Black-box |
| HopSkipJump | Decision-based | Black-box |
| Adversarial Patch | Physical | Any |

## Defenses
- Feature Squeezing: Reduzir espaco de caracteristicas
- Randomized Smoothing: Media de predicoes com ruido
- Adversarial Training: Treinar com exemplos adversariais
- Ensemble Defense: Multiplos modelos votam

## Tools
| Tool | Description |
|------|-------------|
| CleverHans | Ataques adversariais |
| Foolbox | Ataques PyTorch/TF |
| ART (IBM) | Adversarial robustness |
| TorchAttacks | Ataques PyTorch |
| TextAttack | Ataques NLP |
