# Jaizz Noir — AI-Powered Penetration Testing Suite

<p align="center">
  <img src="app/static/bg.png" alt="Jaizz Noir" width="120" style="border-radius:50%;border:3px solid #c02626;">
</p>

<p align="center">
  <em>Multi-agent pentest automation with RAG-based CVE lookup, real-time streaming, and LLM-powered exploitation analysis.</em>
</p>

---

## Overview

Jaizz Noir is an open-source penetration testing platform that orchestrates **8 specialized AI agents** to automate reconnaissance, vulnerability detection, exploitation, and reporting. The system uses a pipeline of 10 phases, each powered by LLM-driven decision-making, to discover and analyze security flaws in web applications and network infrastructure.

**Key differentiator:** Unlike static scanners, Jaizz Noir uses agentic AI to select tools, validate findings, chain vulnerabilities, and adapt its approach based on real-time results — mimicking the workflow of a senior penetration tester.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    PIPELINE (10 phases)                  │
├──────────┬──────────┬──────────┬──────────┬─────────────┤
│  Recon   │Fingerprint│   Web   │  Legacy  │Orchestrator │
│  Phase   │  Phase   │  Phase  │ Modules  │   Phase     │
├──────────┼──────────┼──────────┼──────────┼─────────────┤
│ ZAP MCP  │   CVE    │  Risk   │    AI    │   Report    │
│  Phase   │  Phase   │  Score  │ Analysis │   Phase     │
└──────────┴──────────┴──────────┴──────────┴─────────────┘
         │                                               │
         ▼                                               ▼
┌─────────────────────────────────────────────────────────┐
│                    AI AGENT LAYER                        │
├──────────┬──────────┬──────────┬──────────┬─────────────┤
│Pentester │ Searcher │  Coder   │ Installer│  Enricher   │
│ Agent    │  Agent   │  Agent   │  Agent   │   Agent     │
├──────────┼──────────┼──────────┼──────────┼─────────────┤
│ Adviser  │Reflector │ Planner  │Router (8 │  Model      │
│  Agent   │  Agent   │  Agent   │providers)│  Routing    │
└──────────┴──────────┴──────────┴──────────┴─────────────┘
         │                                               │
         ▼                                               ▼
┌─────────────────────────────────────────────────────────┐
│                  VALIDATION & GROUNDING                  │
├──────────┬──────────┬──────────┬──────────┬─────────────┤
│Grounded  │  Chain   │  7-Quest │ Scope    │ Execution   │
│Pipeline  │  Table   │  Gate    │Validator │  Monitor    │
└──────────┴──────────┴──────────┴──────────┴─────────────┘
```

### Pipeline Phases

| Phase | Description | Parallel Group |
|-------|-------------|---------------|
| **Recon** | DNS resolution, domain/subdomain enumeration | 0 |
| **Fingerprint** | HTTP header analysis, technology detection (~20 signatures) | 0 |
| **Web** | Web scraping, robots.txt, security headers analysis | 2 |
| **Legacy Modules** | Runs OSINT/Infra/Web tools (Maryam, Naabu, Nuclei, etc.) | 0 |
| **Orchestrator** | AI-driven tool selection + tool execution + LLM analysis | 1 |
| **ZAP MCP** | OWASP ZAP spider + active scan via REST API | 0 |
| **CVE** | CVE lookup by technology + version (ChromaDB RAG + BNVD/NVD) | 1 |
| **Risk Score** | Calculates scores per category (headers, transport, CVE, etc.) | 2 |
| **AI Analysis** | Final LLM analysis with NIST CSF mapping, recommendations | 0 |
| **Report** | Generates HTML, JSON, Markdown reports | 0 |

### Agent Roles

| Agent | Model | Provider | Role |
|-------|-------|----------|------|
| **Pentester** | deepseek-v4-pro | free-gateway | Exploits vulnerabilities, executes attack chains |
| **Searcher** | deepseek-chat | free-gateway | OSINT/recon, CVE data, exploit research |
| **Coder** | deepseek-chat | free-gateway | Writes PoC exploits and automation scripts |
| **Installer** | llama-3.1-8b-instant | groq | Sets up testing infrastructure |
| **Enricher** | llama-3.1-8b-instant | groq | Correlates findings, maps to MITRE ATT&CK |
| **Adviser** | deepseek-v4-pro | free-gateway | Strategic guidance, detects dead ends |
| **Reflector** | deepseek-chat | free-gateway | QA reviewer, checks for hallucinations |
| **Planner** | deepseek-v4-pro | free-gateway | Decomposes goals into actionable steps |

### Providers

8 LLM providers with automatic failover:

- **Groq** — llama-3.1, mixtral (fast inference)
- **OpenAI** — GPT-4o, GPT-4o-mini
- **DeepSeek** — deepseek-chat, deepseek-reasoner
- **NVIDIA NIM** — Nemotron, Llama, DeepSeek via NVIDIA API
- **Gemini** — gemini-2.0-flash (Google)
- **Free Gateway** — community API gateway (no API key needed)
- **Ollama** — local LLMs (Qwen, Llama, etc.)
- **Fallback** — returns safe default when no provider is available

---

## Features

### Core
- **10-phase pipeline** — automated recon → exploitation → reporting
- **8 specialized AI agents** — each with role-specific prompts and model routing
- **Real-time streaming** — WebSocket events for live terminal output
- **RAG CVE lookup** — ChromaDB vector store with 140+ tech descriptions
- **Tool selection** — LLM decides which tools to run based on target context

### Validation & Safety
- **Grounded Pipeline** — multi-stage validation with source-specific rules
- **Chain Table** — 28 capability mappings for vulnerability chaining
- **7-Question Gate** — pre-submission validation with 18 never-submit patterns
- **Scope Validator** — target whitelist/blacklist, forbidden action blocking
- **Execution Monitor** — loop detection, rate limiting, auto-intervention

### Observability
- **Langfuse integration** — LLM cost tracking, latency monitoring, prompt debugging
- **SQLite tracing** — full LLM call history with token counts
- **Summarizer QA** — context management for long-running pipelines
- **Real-time dashboard** — WebSocket-powered live terminal

### Reporting
- **HTML reports** — severity bars, risk scores, exploitation guide
- **JSON reports** — machine-readable structured data
- **Markdown reports** — clean text format for documentation
- **NIST CSF mapping** — aligns findings with cybersecurity framework

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/jaizz-noir.git
cd jaizz-noir

# Install dependencies
pip3 install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your API keys (at least one provider)

# Run the server
python3 wsgi.py
```

Open `http://localhost:5000` in your browser.

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GROQ_API_KEY` | No | — | Groq API key for fast inference |
| `OPENAI_API_KEY` | No | — | OpenAI API key |
| `DEEPSEEK_API_KEY` | No | — | DeepSeek API key |
| `NVIDIA_API_KEY` | No | — | NVIDIA NIM API key |
| `GEMINI_API_KEY` | No | — | Google Gemini API key |
| `FREE_API_KEY` | No | — | Free gateway API key |
| `LANGFUSE_SECRET_KEY` | No | — | Langfuse observability |
| `LANGFUSE_PUBLIC_KEY` | No | — | Langfuse public key |
| `LANGFUSE_HOST` | No | cloud.langfuse.com | Langfuse host URL |

At least one API key is required for LLM functionality. Without any, the FallbackClient returns safe default responses.

---

## API Endpoints

### Scanner
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/engines` | List available scan engines (46) |
| POST | `/api/scan` | Dispatch individual scan engines |
| POST | `/api/pipeline` | Start full pipeline scan (async, returns immediately) |
| POST | `/api/fullscan` | Start full scan via Celery |

### Pipeline & Flows
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/flows` | List pipeline runs |
| GET | `/api/flows/<id>` | Get pipeline details + result data |
| GET | `/api/flows/<id>/tasks` | Get pipeline tasks |
| WS | `/api/flows/<id>/ws` | WebSocket for real-time pipeline events |
| GET | `/api/flows/<id>/context` | Get QA context for pipeline |
| POST | `/api/flows/<id>/summarize` | Summarize pipeline iteration |

### Findings
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/findings/stats` | Severity distribution statistics |
| GET | `/api/findings/grouped` | Findings grouped by plugin source |
| GET | `/api/findings/<id>` | Finding details |

### Traces
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/traces` | LLM call history |
| GET | `/api/traces/stats` | LLM usage statistics |

### Projects
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/projects` | List projects |
| POST | `/api/projects` | Create project |
| GET | `/api/projects/<id>` | Project details |

---

## Project Structure

```
jaizz-noir/
├── app/
│   ├── __init__.py          # Flask app factory
│   ├── extensions.py        # SQLAlchemy, JWT, Celery, Sock
│   ├── ai/                  # AI core
│   │   ├── agents.py        # 8 specialized agents + router
│   │   ├── llm.py           # Unified LLM chat + tracing
│   │   ├── client.py        # 8 provider implementations
│   │   ├── tracer.py        # SQLite + Langfuse tracing
│   │   ├── events.py        # Event bus + stream manager
│   │   ├── classifier.py    # Tool selection (LLM + rules)
│   │   ├── grounded_agent.py # Validation pipeline
│   │   ├── cve_rag.py       # ChromaDB vector search
│   │   ├── cve_database.py  # CVE query + RAG fallback
│   │   ├── chain_table.py   # 28 vulnerability chains
│   │   ├── validation_gate.py # 7-Question Gate
│   │   ├── scope_validator.py # Target scope enforcement
│   │   ├── execution_monitor.py # Loop detection + limits
│   │   ├── summarizer.py    # QA pair management
│   │   ├── nist_csf_mapper.py # NIST CSF alignment
│   │   └── knowledge/       # Knowledge base
│   ├── pipeline/            # Pipeline phases
│   │   ├── engine.py        # PipelineContext + executor
│   │   ├── phases.py        # Recon, Fingerprint
│   │   ├── phase_orchestrator.py # AI orchestration
│   │   ├── phase_web_and_risk.py # Web + risk scoring
│   │   ├── phase_ai_and_report.py # AI analysis + reports
│   │   ├── phase_zap_mcp.py # OWASP ZAP integration
│   │   └── phase_legacy_modules.py # Legacy tool runners
│   ├── plugins/             # Tool adapters (nmap, sqlmap, etc.)
│   ├── models/              # ORM models
│   ├── api/                 # REST endpoints
│   ├── templates/           # Dashboard HTML
│   └── static/              # Static assets
├── config.py                # Application config
├── wsgi.py                  # Entry point
├── celery_worker.py         # Celery worker
└── requirements.txt         # Dependencies
```

---

## Deployment

### Option 1: Render

1. Push to GitHub
2. Create a new **Web Service** on Render
3. Connect your repository
4. Set:
   - **Runtime**: Python 3
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn wsgi:app`
5. Add environment variables from `.env`
6. Deploy

### Option 2: Railway

1. Push to GitHub
2. Create a new project on Railway
3. Connect your repository
4. Railway auto-detects Python; no additional config needed
5. Add environment variables

### Option 3: Docker

```bash
docker build -t jaizz-noir .
docker run -p 5000:5000 --env-file .env jaizz-noir
```

---

## License

MIT License — see `LICENSE` for details.

---

## Security Notice

Jaizz Noir is designed for **authorized security testing only**. Users must ensure they have explicit permission to test any target. The scope validator can restrict testing to approved targets. The maintainers assume no liability for misuse.
