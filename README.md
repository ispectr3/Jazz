# Jaizz Noir — AI-Powered Penetration Testing Suite

<p align="center">
  <img src="app/static/bg.png" alt="Jaizz Noir" width="120" style="border-radius:50%;border:3px solid #c02626;">
</p>

<p align="center">
  <em>Multi-agent pentest automation with RAG-based CVE lookup, real-time streaming, and LLM-powered exploitation analysis.</em>
  <br>
  <a href="README.en.md">🇺🇸 English</a> · <a href="README.pt-br.md">🇧🇷 Português</a>
</p>

---

Jaizz Noir is an open-source penetration testing platform that orchestrates **8 specialized AI agents** across a **10-phase pipeline** to automate reconnaissance, vulnerability detection, exploitation, and reporting.

**Key differentiator:** Unlike static scanners, Jaizz Noir uses agentic AI that selects tools, validates findings, chains vulnerabilities, and adapts its approach in real-time — mimicking the workflow of a senior penetration tester.

## Quick Start

```bash
git clone https://github.com/yourusername/jaizz-noir.git
cd jaizz-noir
pip3 install -r requirements.txt
cp .env.example .env
# Edit .env with at least one API key
python3 wsgi.py
```

Open `http://localhost:5000`.

## Architecture

### Pipeline (10 phases)

| Phase | Description |
|-------|-------------|
| **Recon** | DNS resolution, domain/subdomain enumeration |
| **Fingerprint** | HTTP header analysis, technology detection (~20 signatures) |
| **Web** | Web scraping, robots.txt, security headers |
| **Legacy Modules** | OSINT/Infra/Web tools (Maryam, Naabu, Nuclei, etc.) |
| **Orchestrator** | AI-driven tool selection + execution + LLM analysis |
| **ZAP MCP** | OWASP ZAP spider + active scan |
| **CVE** | ChromaDB RAG + BNVD/NVD CVE lookup by tech version |
| **Risk Score** | Per-category risk scoring (headers, transport, CVE, etc.) |
| **AI Analysis** | Final LLM analysis with NIST CSF mapping |
| **Report** | HTML, JSON, Markdown report generation |

### 8 AI Agents

| Agent | Model | Provider | Role |
|-------|-------|----------|------|
| **Pentester** | deepseek-v4-pro | free-gateway | Exploit execution |
| **Searcher** | deepseek-chat | free-gateway | OSINT/CVE research |
| **Coder** | deepseek-chat | free-gateway | PoC writing |
| **Installer** | llama-3.1-8b-instant | groq | Infrastructure setup |
| **Enricher** | llama-3.1-8b-instant | groq | MITRE ATT&CK mapping |
| **Adviser** | deepseek-v4-pro | free-gateway | Strategic guidance |
| **Reflector** | deepseek-chat | free-gateway | QA review |
| **Planner** | deepseek-v4-pro | free-gateway | Goal decomposition |

### 8 LLM Providers

Groq · OpenAI · DeepSeek · NVIDIA NIM · Gemini · Free Gateway · Ollama · Fallback

### Validation Pipeline

- **GroundedPipeline** — source-specific validation rules (SQLi, Nuclei, CVE IDs, etc.)
- **Chain Table** — 28 capability chains for vulnerability correlation
- **7-Question Gate** — pre-submission validation with 18 never-submit patterns
- **Scope Validator** — target whitelist/blacklist, forbidden action blocking
- **Execution Monitor** — loop detection (same tool >5x), rate limiting, auto-intervention

### Real-time Streaming

- WebSocket endpoint: `/api/flows/<id>/ws`
- Events: `progress`, `phase_start`, `phase_end`, `llm_call`, `tool_call`, `finding`, `error`, `complete`
- Langfuse integration for LLM cost tracking

## Deploy

**Render**: Web Service → Python 3 → `gunicorn wsgi:app`
**Railway**: Auto-detect Python project
**Docker**: `docker build -t jaizz-noir .`

## Documentation

- [🇺🇸 Full English README](README.en.md)
- [🇧🇷 README completo em Português](README.pt-br.md)

## Security Notice

For **authorized security testing only**. The scope validator restricts testing to approved targets. Maintainers assume no liability for misuse.
