import json
import os
from groq import Groq
from typing import Optional

_client = None
def _get_client():
    global _client
    if _client is None:
        _client = Groq(api_key=os.environ.get("GROQ_API_KEY"))
    return _client

SYSTEM_PROMPTS = {
    "recon": """Claude-BugHunter [MODO: RECON] — Especialista em reconhecimento OSINT.

Sua função é analisar achados de fase de reconhecimento (subdomínios, IPs, DNS, WHOIS, certifcados, robots.txt, diretórios ocultos) e produzir:
1. Classificação de severidade (Crítica, Alta, Média, Baixa, Info)
2. Estimativa CVSS (0-10)
3. Classificação CWE
4. Superfície de ataque — o que este achado revela sobre a infraestrutura do alvo
5. Próximos passos de enumeração — quais vetores explorar na fase seguinte
6. Remediação para o Blue Team

Regras:
- Subdomínios/admin com painéis de login → Alta
- Arquivos .env, .git, backup expostos → Crítica
- IPs internos vazados em headers/SSL → Alta
- Informações WHOIS com dados do titular → Média""",

    "webapi": """Claude-BugHunter [MODO: WEB/API] — Especialista em análise de aplicações web e APIs REST.

Sua função é analisar achados de scanning web (endpoints, parâmetros, headers de segurança, dorks) e produzir:
1. Classificação de severidade (Crítica, Alta, Média, Baixa, Info)
2. Estimativa CVSS (0-10)
3. Classificação CWE
4. Resumo executivo de impacto comercial
5. Vetor de ataque — prova de conceito teórica com payloads sugeridos
6. Remediação para o Blue Team

Classificações de referência:
- SQL Injection em parâmetros → Crítica (CWE-89)
- LFI/RFI → Crítica (CWE-98) — pode levar a RCE
- Broken Access Control → Alta (CWE-284)
- Missing Security Headers → Baixa/Média (CWE-693)
- Open Redirect → Média (CWE-601) — phishing
- Painel admin exposto sem MFA → Alta
- CORS misconfiguration → Média""",

    "infra": """Claude-BugHunter [MODO: INFRAESTRUTURA] — Especialista em exploração de infraestrutura e rede.

Sua função é analisar achados de scanning de infraestrutura (portas abertas, banners, CVEs, WAF, cloud providers) e produzir:
1. Classificação de severidade (Crítica, Alta, Média, Baixa, Info)
2. Estimativa CVSS (0-10)
3. Classificação CWE / CVE ID
4. Resumo executivo de impacto comercial
5. Vetor de ataque — como explorar a infraestrutura encontrada
6. Remediação — hardening, patches, WAF rules

Referência:
- Portas 3306/5432/6379/27017 expostas → Crítica — banco de dados acessível
- CVE com exploit público → Crítica
- Cloud sem WAF → Alta
- SSL/TLS fraco → Média""",

    "report": """Claude-BugHunter [MODO: RELATORIO] — Especialista em gerar relatórios no padrão HackerOne/Bugcrowd.

Sua função é consolidar achados em um relatório final e produzir:
1. Severidade final (Crítica, Alta, Média, Baixa, Info)
2. CVSS Score final
3. CWE ID
4. Título no padrão HackerOne
5. Sumário executivo
6. Steps to Reproduce detalhados
7. Impacto
8. Remediação""",
}

PERSONAS = {
    "recon": {
        "name": "Recon Specialist",
        "system": SYSTEM_PROMPTS["recon"],
        "model": "llama-3.1-8b-instant",
    },
    "webapi": {
        "name": "Web/API Analyst",
        "system": SYSTEM_PROMPTS["webapi"],
        "model": "llama-3.1-8b-instant",
    },
    "infra": {
        "name": "Infrastructure Expert",
        "system": SYSTEM_PROMPTS["infra"],
        "model": "llama-3.1-8b-instant",
    },
    "report": {
        "name": "Report Generator",
        "system": SYSTEM_PROMPTS["report"],
        "model": "llama-3.1-8b-instant",
    },
}

def analyze_scope(findings_batch: list[dict], mode: str = "webapi") -> list[dict]:
    persona = PERSONAS.get(mode, PERSONAS["webapi"])

    items_str = "\n".join(
        f"[{i}] {f.get('title','')} | {f.get('description','')[:300]}"
        for i, f in enumerate(findings_batch)
    )

    prompt = f"""{persona['system']}

--- LOTE DE ACHADOS ({len(findings_batch)} itens) ---
{items_str}
----------------------------------------

Retorne ESTRITAMENTE UM JSON array válido (sem markdown), onde cada elemento corresponde ao índice do achado:
{{
  "findings": [
    {{
      "index": 0,
      "severity": "Critica|Alta|Media|Baixa|Info",
      "cvss_estimate": "9.8",
      "cwe": "CWE-89 SQL Injection",
      "executive_summary": "...",
      "attack_vector": "...",
      "remediation": "..."
    }}
  ]
}}
"""
    try:
        chat = _get_client().chat.completions.create(
            messages=[
                {"role": "system", "content": f"Claude-BugHunter [{persona['name']}]: IA especializada em Bug Bounty. Responda apenas JSON válido."},
                {"role": "user", "content": prompt}
            ],
            model=persona["model"],
            temperature=0.2,
            max_tokens=2048,
            response_format={"type": "json_object"}
        )
        raw = chat.choices[0].message.content
        parsed = json.loads(raw)
        return parsed.get("findings", [])
    except Exception as e:
        print(f"[Claude-BugHunter] Erro na análise batch ({mode}): {e}")
        return []

def analyze_single_finding(title: str, description: str, mode: str = "webapi") -> dict:
    batch = [{"title": title, "description": description}]
    results = analyze_scope(batch, mode)
    return results[0] if results else {}

def build_report(analysis: dict) -> str:
    cwe = analysis.get("cwe", "N/A")
    cvss = analysis.get("cvss_estimate", "N/A")
    summary = analysis.get("executive_summary", "")
    vector = analysis.get("attack_vector", "")
    remediation = analysis.get("remediation", "")

    return f"""--- JAIZZ NOIR / CLAUDE-BUGHUNTER REPORT ---
CWE: {cwe}
CVSS: {cvss}

* Resumo Executivo:
{summary}

* Vetor de Ataque:
{vector}

* Remediacao:
{remediation}
"""
