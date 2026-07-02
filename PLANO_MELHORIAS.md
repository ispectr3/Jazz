# PLANO DE MELHORIAS — Jaizz Noir

Baseado na analise de 5 repositorios de referencia:
1. **H-mmer/pentest-agents** — 50 agentes, chain-table, 7-Question Gate, brain.py
2. **capture0x/ai-cyber-agent** — Scanner modular, WAF bypass, CSRF detector
3. **mukul975/Anthropic-Cybersecurity-Skills** — 817 skills, 6 frameworks, agentskills.io
4. **matty69v/Bug-Bounty-Agents** — 43 prompts especializados, Burp MCP

---

## FASE 1 — FUNDACAO (implementado nesta sessao)

### 1.1 Chain Table (A→B Capability Mapping) ✅
- `app/ai/chain_table.py`: 28 mapeamentos de capacidade para proximo bug
- Integrado no `cross_correlate_all()` do claude_bughunter.py
- Severidade agravada automaticamente em cadeias detectadas

### 1.2 7-Question Validation Gate ✅
- `app/ai/validation_gate.py`: 7 perguntas, never-submit list (18 patterns)
- Batch evaluation para triagem em lote

### 1.3 CSRF Detector Adapter ✅
- `app/plugins/csrf_detector.py`: BeautifulSoup form analysis
- Detecta forms POST/PUT/DELETE sem token CSRF
- Sinaliza endpoints API suspeitos em scripts

### 1.4 WAF Bypass Adapter ✅
- `app/plugins/wafbypass_adapter.py`: 7 encoding transforms
- 6 niveis de bypass com tag e keyword alternatives
- Rotation ladder para detection tokens

### 1.5 Knowledge Base Expandida ✅
- `app/ai/knowledge/pentest_lessons.md`: Top 10 erros + 45+ lessons learned
- `app/ai/knowledge/detection_ladder.md`: 7 tiers XSS detection + matrix de exaustao

---

## FASE 2 — FRAMEWORK MAPPING (proximo)

### 2.1 MITRE ATT&CK Mapping
Cada finding deve carregar `mitre_attack` IDs baseado no tipo de vulnerabilidade:

| Classe | ATT&CK ID | Nome |
|--------|-----------|------|
| SQL Injection | T1190 | Exploit Public-Facing Application |
| XSS | T1059.007 | JavaScript |
| SSRF | T1190 | Exploit Public-Facing Application |
| IDOR | T1213 | Data from Information Repositories |
| RCE | T1203 | Exploitation for Client Execution |
| CSRF | T1204.001 | User Execution: Malicious Link |
| Credential Leak | T1552 | Unsecured Credentials |
| Container Escape | T1611 | Escape to Host |

**Implementacao:**
- Adicionar campo `mitre_attack: List[str]` no schema do Finding
- `app/ai/mitre_mapper.py`: mapping table + funcao `classify_mitre(title, description) -> list[str]`
- Dashboard exibir badges ATT&CK nos findings

### 2.2 NIST CSF 2.0 Mapping
| Funcao | Categoria | Findings tipicos |
|--------|-----------|------------------|
| IDENTIFY (ID) | ID.AM | Asset discovery, subdomain enum |
| PROTECT (PR) | PR.AC | Auth bypass, weak ACL |
| DETECT (DE) | DE.CM | WAF bypass, anomaly detection |
| RESPOND (RS) | RS.AN | RCE, data exfiltration |

**Implementacao:**
- `app/ai/nist_mapper.py`
- Campo `nist_csf: List[str]` no Finding

---

## FASE 3 — NOVOS DOMINIOS (proximo)

### 3.1 OT/ICS Security
- Novo adapter: `modbus_adapter.py` — scan de portas 502 (Modbus) e 44818 (Ethernet/IP)
- KB: `knowledge/ot_security.md`

### 3.2 API Security (GraphQL)
- Novo adapter: `graphql_adapter.py` — introspection query, batching attack, depth limit bypass
- KB: `knowledge/graphql_attacks.md`

### 3.3 DevSecOps / CI/CD
- Novo adapter: `devsecops_adapter.py` — .env exposure, CI/CD tokens, hardcoded secrets
- KB: `knowledge/devsecops.md`

### 3.4 Mobile Security
- Novo adapter: `mobile_adapter.py` — Android manifest analysis, iOS plist exposure
- KB: `knowledge/mobile_security.md`

### 3.5 Container Security
- Novo adapter: `container_adapter.py` — Docker socket exposure, K8s dashboard, privileged pods
- KB: `knowledge/container_security.md`

---

## FASE 4 — INTEGRACOES (proximo)

### 4.1 Burp Suite MCP
Seguir pattern do `matty69v/Bug-Bounty-Agents`:
- Criar `app/mcp/burp_server.py` que se conecta ao Burp via SSE
- Jaizz Noir envia requests para Burp, recebe responses analisadas
- Integracao com o adapter do CSRF detector para usar o proxy do Burp

### 4.2 agentskills.io Format
Converter nossos KBs para o formato padrao:
```yaml
---
name: detecting-prompt-injection
description: Técnicas de detecção de prompt injection em LLMs
domain: ai-security
subdomain: llm-redteam
tags: [llm, prompt-injection, red-team, garak]
mitre_attack: [T1190]
nist_csf: [DE.CM-01]
version: "1.0"
---
```

### 4.3 Auto-Module Loading
Seguir pattern do `ai-cyber-agent`:
- `app/plugins/loader.py` — importlib para carregar adapters dinamicamente
- Registrar adapters via decorator `@register_adapter("nome")`
- Scanner API descobre adapters automaticamente

---

## FASE 5 — TESTES CONTRA ALVOS REAIS

### 5.1 Local Vulnerable App
- `tests/vulnerable_app.py` — Flask app com vulnerabilidades intencionais:
  - SQLi em /api/users?id=
  - XSS em /search?q=
  - CSRF em /api/update_email (POST sem token)
  - SSRF em /api/fetch?url=
  - IDOR em /api/profile/{id}
  - Open redirect em /redirect?next=

### 5.2 Test Pipeline
```bash
python3 tests/run_scan.py --target http://localhost:5000 --engines all
python3 tests/run_scan.py --target http://localhost:5000 --engines csrf,wafbypass
python3 tests/validate_findings.py --project-id 1
python3 tests/test_chain.py --project-id 1
```

### 5.3 Public Test Targets (autorizados)
- `testphp.vulnweb.com` — Acunetix test site
- `juice-shop.herokuapp.com` — OWASP Juice Shop

---

## MATRIZ DE PRIORIDADE

| Item | Impacto | Esforco | Prioridade |
|------|---------|---------|------------|
| MITRE ATT&CK mapping | Alto | Baixo | **FASE 2** |
| Chain table | Alto | Baixo | ✅ Feito |
| 7-Question Gate | Alto | Baixo | ✅ Feito |
| CSRF Detector | Medio | Baixo | ✅ Feito |
| WAF Bypass | Medio | Medio | ✅ Feito |
| GraphQL Adapter | Alto | Medio | FASE 3 |
| OT/ICS Adapter | Medio | Alto | FASE 3 |
| Burp MCP | Alto | Alto | FASE 4 |
| agentskills.io format | Medio | Medio | FASE 4 |
| Auto-module loading | Medio | Baixo | FASE 4 |
