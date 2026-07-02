# Ataques de Evasão (Evasion Attacks)

> **CAMADA=IA | DOMINIO=LLM, ML | SEGURANCA=Evasion Attacks, FGSM, ML Security | PILARES=8/8**

**Evasion Attacks** manipulam entradas durante a inferência para fazer um modelo classificar incorretamente uma amostra maliciosa como benigna.

## Mecanismo
1. Seleciona entrada legítima
2. Calcula perturbação mínima imperceptível
3. Adiciona à entrada original
4. Modelo classifica incorretamente
5. Humano não percebe diferença

## Tipos de Ataques
- **Classificadores Lineares (SVM, Regressão Logística):** Solução analítica fechada
- **Redes Neurais (FGSM, PGD, C&W):** Técnicas de gradiente
- **Caixa Preta (Boundary, HopSkipJump):** Busca na fronteira de decisão
- **Física (Adversarial Patches):** Patches/adesivos para mundo real

## Exemplo FGSM
```python
def fgsm_attack(model, image, epsilon, target_label):
    image.requires_grad = True
    output = model(image)
    loss = F.nll_loss(output, target_label)
    model.zero_grad()
    loss.backward()
    sign = image.grad.sign()
    adv_image = image + epsilon * sign
    return torch.clamp(adv_image, 0, 1)
```

## Ataques por Domínio
| Domínio | Técnica |
|---|---|
| Detecção de Malware | Content perturbation, section injection |
| Detecção de Spam | Good word insertion, misspelling |
| Reconhecimento Facial | Adversarial glasses, pixel perturbation |
| Modelos de Linguagem | Synonym substitution, char perturbation |

## Defesas
- **Feature Squeezing:** Reduzir espaço de características
- **Randomized Smoothing:** Média de predições com ruído
- **Adversarial Training:** Treinar com exemplos adversariais
- **Input Gradient Regularization:** Regularizar gradientes
- **Ensemble Defense:** Múltiplos modelos votam

## Ferramentas
| Ferramenta | Descrição |
|---|---|
| CleverHans | Biblioteca de ataques adversariais |
| Foolbox | Ataques robustos em PyTorch/TF |
| ART (IBM) | Framework de adversarial robustness |
| TorchAttacks | Coleção de ataques em PyTorch |
| TextAttack | Ataques em NLP |
