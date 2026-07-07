# Jaizz Noir — Suíte de Pentest com IA

<p align="center">
  <img src="app/static/bg.png" alt="Jaizz Noir" width="120" style="border-radius:50%;border:3px solid #c02626;">
</p>

<p align="center">
  <em>Automação de pentest multi-agente com busca RAG de CVEs, streaming em tempo real e análise de exploração com LLM.</em>
</p>

---

## Visão Geral

Jaizz Noir é uma plataforma de pentest open-source que orquestra **8 agentes de IA especializados** para automatizar reconhecimento, detecção de vulnerabilidades, exploração e geração de relatórios. O sistema utiliza um pipeline de 10 fases, cada uma alimentada por decisões baseadas em LLM, para descobrir e analisar falhas de segurança em aplicações web e infraestrutura de rede.

**Diferencial:** Diferente de scanners estáticos, o Jaizz Noir usa IA agentiva para selecionar ferramentas, validar achados, encadear vulnerabilidades e adaptar sua abordagem com base em resultados em tempo real — simulando o fluxo de trabalho de um pentester sênior.

---

## Arquitetura

```
┌─────────────────────────────────────────────────────────┐
│                    PIPELINE (10 fases)                   │
├──────────┬──────────┬──────────┬──────────┬─────────────┤
│  Recon   │Fingerprint│   Web   │  Legacy  │Orquestrador │
│  Fase    │  Fase    │  Fase   │ Módulos  │   Fase      │
├──────────┼──────────┼──────────┼──────────┼─────────────┤
│ ZAP MCP  │   CVE    │  Risco  │ Análise  │  Relatório  │
│  Fase    │  Fase    │  Score  │   IA     │   Fase      │
└──────────┴──────────┴──────────┴──────────┴─────────────┘
         │                                               │
         ▼                                               ▼
┌─────────────────────────────────────────────────────────┐
│                    CAMADA DE AGENTES IA                  │
├──────────┬──────────┬──────────┬──────────┬─────────────┤
│Pentester │ Searcher │  Coder   │ Installer│  Enricher   │
│ Agente   │  Agente  │  Agente  │  Agente  │   Agente    │
├──────────┼──────────┼──────────┼──────────┼─────────────┤
│ Adviser  │Reflector │ Planner  │Router (8 │ Roteamento  │
│  Agente  │  Agente  │  Agente  │providers)│  de Modelos │
└──────────┴──────────┴──────────┴──────────┴─────────────┘
         │                                               │
         ▼                                               ▼
┌─────────────────────────────────────────────────────────┐
│                  VALIDAÇÃO E FUNDAMENTAÇÃO               │
├──────────┬──────────┬──────────┬──────────┬─────────────┤
│Grounded  │  Chain   │  Portão  │ Validador│ Monitor de  │
│Pipeline  │  Table   │ 7 Perg.  │ de Escopo│ Execução    │
└──────────┴──────────┴──────────┴──────────┴─────────────┘
```

### Fases do Pipeline

| Fase | Descrição | Grupo Paralelo |
|------|-----------|---------------|
| **Recon** | Resolução DNS, enumeração de domínios/subdomínios | 0 |
| **Fingerprint** | Análise de cabeçalhos HTTP, detecção de tecnologias (~20 assinaturas) | 0 |
| **Web** | Web scraping, robots.txt, análise de headers de segurança | 2 |
| **Legacy Modules** | Executa ferramentas OSINT/Infra/Web (Maryam, Naabu, Nuclei, etc.) | 0 |
| **Orquestrador** | Seleção de ferramentas com IA + execução + análise LLM | 1 |
| **ZAP MCP** | Spider + scan ativo do OWASP ZAP via REST API | 0 |
| **CVE** | Consulta de CVEs por tecnologia + versão (ChromaDB RAG + BNVD/NVD) | 1 |
| **Risco** | Calcula scores por categoria (headers, transporte, CVE, etc.) | 2 |
| **Análise IA** | Análise final com LLM, mapeamento NIST CSF, recomendações | 0 |
| **Relatório** | Gera relatórios HTML, JSON, Markdown | 0 |

### Papéis dos Agentes

| Agente | Modelo | Provedor | Função |
|--------|--------|----------|--------|
| **Pentester** | deepseek-v4-pro | free-gateway | Explora vulnerabilidades, executa cadeias de ataque |
| **Searcher** | deepseek-chat | free-gateway | OSINT/recon, dados CVE, pesquisa de exploits |
| **Coder** | deepseek-chat | free-gateway | Escreve PoCs e scripts de automação |
| **Installer** | llama-3.1-8b-instant | groq | Configura infraestrutura de teste |
| **Enricher** | llama-3.1-8b-instant | groq | Correlaciona achados, mapeia MITRE ATT&CK |
| **Adviser** | deepseek-v4-pro | free-gateway | Orientação estratégica, detecta becos sem saída |
| **Reflector** | deepseek-chat | free-gateway | Revisor de qualidade, checa alucinações |
| **Planner** | deepseek-v4-pro | free-gateway | Decompõe objetivos em passos acionáveis |

### Provedores

8 provedores de LLM com failover automático:

- **Groq** — llama-3.1, mixtral (inferência rápida)
- **OpenAI** — GPT-4o, GPT-4o-mini
- **DeepSeek** — deepseek-chat, deepseek-reasoner
- **NVIDIA NIM** — Nemotron, Llama, DeepSeek via API NVIDIA
- **Gemini** — gemini-2.0-flash (Google)
- **Free Gateway** — gateway comunitário (sem necessidade de API key)
- **Ollama** — LLMs locais (Qwen, Llama, etc.)
- **Fallback** — retorna resposta segura quando nenhum provedor disponível

---

## Funcionalidades

### Core
- **Pipeline de 10 fases** — recon automatizado → exploração → relatório
- **8 agentes de IA especializados** — prompts específicos por função e roteamento de modelos
- **Streaming em tempo real** — eventos WebSocket para saída de terminal ao vivo
- **Busca RAG de CVEs** — ChromaDB com 140+ descrições de tecnologias
- **Seleção de ferramentas** — LLM decide quais ferramentas executar baseado no contexto do alvo

### Validação e Segurança
- **Grounded Pipeline** — validação multi-estágio com regras específicas por fonte
- **Chain Table** — 28 mapeamentos de capacidade para encadeamento de vulnerabilidades
- **Portão de 7 Perguntas** — validação pré-envio com 18 padrões de nunca-enviar
- **Validador de Escopo** — whitelist/blacklist de alvos, bloqueio de ações proibidas
- **Monitor de Execução** — detecção de loops, limite de taxa, auto-intervenção

### Observabilidade
- **Integração Langfuse** — rastreamento de custos LLM, monitoramento de latência
- **Tracing SQLite** — histórico completo de chamadas LLM com contagem de tokens
- **Summarizer QA** — gerenciamento de contexto para pipelines longos
- **Dashboard em tempo real** — terminal ao vivo via WebSocket

### Relatórios
- **Relatórios HTML** — barras de severidade, scores de risco, guia de exploração
- **Relatórios JSON** — dados estruturados legíveis por máquina
- **Relatórios Markdown** — formato de texto limpo para documentação
- **Mapeamento NIST CSF** — alinha achados com o framework de cibersegurança

---

## Início Rápido

```bash
# Clone o repositório
git clone https://github.com/seuusuario/jaizz-noir.git
cd jaizz-noir

# Instale dependências
pip3 install -r requirements.txt

# Configure o ambiente
cp .env.example .env
# Edite .env com suas chaves de API (pelo menos um provedor)

# Execute o servidor
python3 wsgi.py
```

Abra `http://localhost:5000` no seu navegador.

### Variáveis de Ambiente

| Variável | Obrigatório | Padrão | Descrição |
|----------|-------------|--------|-----------|
| `GROQ_API_KEY` | Não | — | Chave da API Groq |
| `OPENAI_API_KEY` | Não | — | Chave da API OpenAI |
| `DEEPSEEK_API_KEY` | Não | — | Chave da API DeepSeek |
| `NVIDIA_API_KEY` | Não | — | Chave da API NVIDIA NIM |
| `GEMINI_API_KEY` | Não | — | Chave da API Google Gemini |
| `FREE_API_KEY` | Não | — | Chave do gateway gratuito |
| `LANGFUSE_SECRET_KEY` | Não | — | Chave Langfuse para observabilidade |
| `LANGFUSE_PUBLIC_KEY` | Não | — | Chave pública Langfuse |
| `LANGFUSE_HOST` | Não | cloud.langfuse.com | URL do host Langfuse |

Pelo menos uma chave de API é necessária para funcionalidade LLM. Sem nenhuma, o FallbackClient retorna respostas seguras padrão.

---

## Endpoints da API

### Scanner
| Método | Endpoint | Descrição |
|--------|----------|-----------|
| GET | `/api/engines` | Lista motores de scan disponíveis (46) |
| POST | `/api/scan` | Dispara motores de scan individuais |
| POST | `/api/pipeline` | Inicia pipeline completo (assíncrono) |
| POST | `/api/fullscan` | Inicia scan completo via Celery |

### Pipeline & Flows
| Método | Endpoint | Descrição |
|--------|----------|-----------|
| GET | `/api/flows` | Lista execuções do pipeline |
| GET | `/api/flows/<id>` | Detalhes do pipeline + dados de resultado |
| GET | `/api/flows/<id>/tasks` | Tarefas do pipeline |
| WS | `/api/flows/<id>/ws` | WebSocket para eventos em tempo real |
| GET | `/api/flows/<id>/context` | Contexto QA do pipeline |
| POST | `/api/flows/<id>/summarize` | Resume iteração do pipeline |

### Findings
| Método | Endpoint | Descrição |
|--------|----------|-----------|
| GET | `/api/findings/stats` | Estatísticas de distribuição de severidade |
| GET | `/api/findings/grouped` | Findings agrupados por fonte |
| GET | `/api/findings/<id>` | Detalhes do finding |

### Traces
| Método | Endpoint | Descrição |
|--------|----------|-----------|
| GET | `/api/traces` | Histórico de chamadas LLM |
| GET | `/api/traces/stats` | Estatísticas de uso LLM |

### Projetos
| Método | Endpoint | Descrição |
|--------|----------|-----------|
| GET | `/api/projects` | Lista projetos |
| POST | `/api/projects` | Cria projeto |
| GET | `/api/projects/<id>` | Detalhes do projeto |

---

## Estrutura do Projeto

```
jaizz-noir/
├── app/
│   ├── __init__.py          # Factory do Flask
│   ├── extensions.py        # SQLAlchemy, JWT, Celery, Sock
│   ├── ai/                  # Núcleo de IA
│   │   ├── agents.py        # 8 agentes especializados + roteador
│   │   ├── llm.py           # Chat LLM unificado + tracing
│   │   ├── client.py        # 8 implementações de provedores
│   │   ├── tracer.py        # Tracing SQLite + Langfuse
│   │   ├── events.py        # Barramento de eventos + stream manager
│   │   ├── classifier.py    # Seleção de ferramentas (LLM + regras)
│   │   ├── grounded_agent.py # Pipeline de validação
│   │   ├── cve_rag.py       # Busca vetorial ChromaDB
│   │   ├── cve_database.py  # Consulta CVE + fallback RAG
│   │   ├── chain_table.py   # 28 cadeias de vulnerabilidade
│   │   ├── validation_gate.py # Portão de 7 Perguntas
│   │   ├── scope_validator.py # Controle de escopo
│   │   ├── execution_monitor.py # Detecção de loops + limites
│   │   ├── summarizer.py    # Gerenciamento de pares QA
│   │   ├── nist_csf_mapper.py # Alinhamento NIST CSF
│   │   └── knowledge/       # Base de conhecimento
│   ├── pipeline/            # Fases do pipeline
│   │   ├── engine.py        # PipelineContext + executor
│   │   ├── phases.py        # Recon, Fingerprint
│   │   ├── phase_orchestrator.py # Orquestração com IA
│   │   ├── phase_web_and_risk.py # Web + scoring de risco
│   │   ├── phase_ai_and_report.py # Análise IA + relatórios
│   │   ├── phase_zap_mcp.py # Integração OWASP ZAP
│   │   └── phase_legacy_modules.py # Executores de ferramentas legadas
│   ├── plugins/             # Adaptadores de ferramentas (nmap, sqlmap, etc.)
│   ├── models/              # Modelos ORM
│   ├── api/                 # Endpoints REST
│   ├── templates/           # Dashboard HTML
│   └── static/              # Assets estáticos
├── config.py                # Configuração da aplicação
├── wsgi.py                  # Ponto de entrada
├── celery_worker.py         # Worker Celery
└── requirements.txt         # Dependências
```

---

## Deploy

### Opção 1: Render

1. Faça push para o GitHub
2. Crie um **Web Service** no Render
3. Conecte seu repositório
4. Configure:
   - **Runtime**: Python 3
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn wsgi:app`
5. Adicione variáveis de ambiente do `.env`
6. Deploy

### Opção 2: Railway

1. Faça push para o GitHub
2. Crie um novo projeto no Railway
3. Conecte seu repositório
4. Railway detecta Python automaticamente
5. Adicione variáveis de ambiente

### Opção 3: Docker

```bash
docker build -t jaizz-noir .
docker run -p 5000:5000 --env-file .env jaizz-noir
```

---

## Licença

Licença MIT — veja `LICENSE` para detalhes.

---

## Aviso de Segurança

Jaizz Noir é projetado para **testes de segurança autorizados apenas**. Usuários devem garantir permissão explícita para testar qualquer alvo. O validador de escopo pode restringir testes a alvos aprovados. Os mantenedores não assumem responsabilidade por uso indevido.
