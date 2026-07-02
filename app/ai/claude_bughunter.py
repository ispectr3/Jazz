import json
import os
import random
from groq import Groq
from typing import Optional
from app.ai.knowledge_retriever import get_retriever
from app.ai.chain_table import ChainTable
from app.ai.validation_gate import ValidationGate
from app.ai.mitre_mapper import MitreMapper
from app.ai.anonymizer import get_anonymizer

_client = None
def _get_client():
    global _client
    if _client is None:
        _client = Groq(api_key=os.environ.get("GROQ_API_KEY"))
    return _client

def _anonymized_chat(messages: list[dict], **kwargs) -> str:
    """Wrapper que anonimiza PII antes de enviar ao Groq e restaura no response."""
    anon = get_anonymizer()
    clean_messages = []
    for msg in messages:
        content = msg.get('content', '')
        if msg['role'] == 'user':
            content = anon.anonymize(content)
        clean_messages.append({'role': msg['role'], 'content': content})

    chat = _get_client().chat.completions.create(
        messages=clean_messages,
        **{k: v for k, v in kwargs.items() if k != 'messages'}
    )
    raw = chat.choices[0].message.content
    return anon.restore_response(raw)

REAL_REPORTS_KB = None
def _load_report_kb():
    global REAL_REPORTS_KB
    if REAL_REPORTS_KB is not None:
        return REAL_REPORTS_KB
    kb_path = os.path.join(os.path.dirname(__file__), "reports_knowledge_base.json")
    if os.path.exists(kb_path):
        try:
            with open(kb_path) as f:
                REAL_REPORTS_KB = json.load(f)
        except Exception:
            REAL_REPORTS_KB = {"real_findings": [], "techniques": {}}
    else:
        REAL_REPORTS_KB = {"real_findings": [], "techniques": {}}
    return REAL_REPORTS_KB

def _build_real_examples(query: str = "", plugin_source: str = "") -> str:
    if query:
        retriever = get_retriever()
        return retriever.format_for_prompt(query, top_k=4, plugin_source=plugin_source)
    kb = _load_report_kb()
    findings = kb.get("real_findings", [])
    if not findings:
        return ""
    selected = random.sample(findings, min(4, len(findings)))
    parts = []
    for i, f in enumerate(selected):
        parts.append(f"""--- EXEMPLO REAL #{i+1}: {f['source']} ---
Titulo: {f['title']}
Severidade: {f['severity']} | CWE: {f['cwe']} | CVSS: {f['cvss']}
Descricao: {f['description']}
Analise: 1. Comportamento: {f['description'].split('.')[0]}. 2. Arquitetura: Contexto real de auditoria. 3. Impacto: Consequencia documentada.
Vetor: {f['attack_vector']}
Remediacao: {f['remediation']}
Veredito: Severidade {f['severity']} — confirmado em auditoria real.
""")
    return "\n".join(parts)

TECHNIQUES_REFERENCE = ""
def _build_techniques_ref() -> str:
    kb = _load_report_kb()
    techs = kb.get("techniques", {})
    if not techs:
        return ""
    parts = []
    for category, items in techs.items():
        parts.append(f"  {category}: {', '.join(items)}")
    return "TECNICAS CONHECIDAS (referencia para correlacao):\n" + "\n".join(parts)

FEW_SHOT_EXAMPLES = """
--- EXEMPLO 1: PORTA 80 ABERTA (INFO) ---
Titulo: Porta Aberta: 80/HTTP
Descricao: Porta 80 (HTTP) esta aberta em example.com.
Analise: 1. Comportamento: Porta HTTP padrao. 2. Arquitetura: Servidor web generico. 3. Impacto: Nenhum.
Veredito: Severidade Info.

--- EXEMPLO 2: .ENV EXPOSTO (CRITICA) ---
Titulo: Path Encontrado: /.env
Descricao: Arquivo .env acessivel em dev.example.com/.env (HTTP 200). Contem chaves de API e senhas.
Analise: 1. Comportamento: Configuracao sensivel exposta. 2. Arquitetura: Contem credenciais. 3. Impacto: Comprometimento total.
Veredito: Severidade Critica.

--- EXEMPLO 3: SUPABASE TABLE EXPOSTA (CRITICA) ---
Titulo: Supabase Table Exposed: users
Descricao: Table: users | Columns: id, email, password_hash, role | Row Count: 15420 | Write Permissions: insert: allowed, update: denied, delete: denied
Analise: 1. Comportamento: Tabela de usuarios com dados sensiveis acessivel via API anonima. 2. Arquitetura: Supabase com RLS desabilitado, permitindo INSERT sem autenticacao. 3. Impacto: Vazamento de dados de 15k usuarios e possibilidade de injecao de registros maliciosos.
Veredito: Severidade Critica.

--- EXEMPLO 4: SUPABASE TABLE (SEM DADOS SENSIVEIS, INFO) ---
Titulo: Supabase Table Exposed: blog_posts
Descricao: Table: blog_posts | Columns: id, title, content, created_at | Row Count: 340 | Write Permissions: N/A
Analise: 1. Comportamento: Tabela de conteudo publico (blog). 2. Arquitetura: Dados nao sensiveis, esperados para leitura publica. 3. Impacto: Nenhum — conteudo publico intencional.
Veredito: Severidade Info.

--- EXEMPLO 5: WIX XSS (ALTA) ---
Titulo: [WixCustomElementXSS] Custom Element XSS
Descricao: Module: WixCustomElementXSS | Severity: high | Wix custom element vulnerable to XSS via unsanitized user input in velo code.
Analise: 1. Comportamento: Elemento Velo personalizado sem sanitizacao. 2. Arquitetura: Wix site com codigo Velo que reflete input do usuario sem escapar. 3. Impacto: XSS refletido no contexto do dominio Wix, roubo de sessao, redirecionamento.
Veredito: Severidade Alta.

--- EXEMPLO 6: WIX API KEY LEAK (CRITICA) ---
Titulo: [WixApiKeyLeak] Wix API Key Exposed
Descricao: Module: WixApiKeyLeak | Severity: critical | Wix API key found exposed in client-side JavaScript.
Analise: 1. Comportamento: Chave de API Wix incorporada em JS do lado do cliente. 2. Arquitetura: Chave com permissoes de escrita em API Wix. 3. Impacto: Acesso indevido a API Wix, modificacao de conteudo, acesso a dados de usuarios.
Veredito: Severidade Critica.

--- EXEMPLO 7: WIX IDOR (ALTA) ---
Titulo: [WixIDORDetector] Insecure Direct Object Reference
Descricao: Module: WixIDORDetector | Severity: high | IDOR vulnerability in Wix member endpoint allowing access to other users data via ID manipulation.
Analise: 1. Comportamento: Endpoint de membro Wix sem validacao de propriedade. 2. Arquitetura: ID numerico sequencial, sem autorizacao por usuario logado. 3. Impacto: Acesso a dados privados de outros membros (email, pedidos, dados pessoais).
Veredito: Severidade Alta.

--- EXEMPLO 8: WASM CRYPTOMINER (CRITICA) ---
Titulo: WASM CRYPTOMINER: module.wasm
Descricao: Module URL: https://example.com/module.wasm | Risk: CRITICAL (Score: 85) | Context: General | Type: CRYPTOMINER | Confidence: HIGH | Patterns: monero, xmrig, cryptonight
Analise: 1. Comportamento: Modulo WebAssembly com referencias a cryptomining (monero, xmrig). 2. Arquitetura: WASM baixado em pagina web, executa mineracao no browser da vitima. 3. Impacto: Uso indevido de CPU, degradacao de performance, consumo de energia sem consentimento.
Veredito: Severidade Critica.

--- EXEMPLO 9: WASM WEAK CRYPTO (BAIXA) ---
Titulo: WASM WEAK_CRYPTO: crypto.wasm
Descricao: Module URL: https://example.com/crypto.wasm | Risk: LOW (Score: 10) | Context: General | Type: WEAK_CRYPTO | Algorithms: MD5, SHA1
Analise: 1. Comportamento: Referencia a algoritmos criptograficos fracos em WASM. 2. Arquitetura: Pode ser uso legitimo para compatibilidade. 3. Impacto: Baixo — sem evidencia de uso para seguranca, provavelmente hash interno.
Veredito: Severidade Baixa.

--- EXEMPLO 10: BADWORKER POSTMESSAGE SEM ORIGEM (MEDIA) ---
Titulo: postMessage without origin validation
Descricao: Severity: MEDIUM | CVSS: 5.3 | CWE: CWE-346 | Impact: Cross-origin data leakage, XSS in worker context | Exploitable: True | Status: ACTIVE
Analise: 1. Comportamento: Web Worker usa postMessage sem validar event.origin. 2. Arquitetura: Worker ativo recebendo mensagens de qualquer origem. 3. Impacto: Vazamento de dados entre origens, possivel XSS no contexto do worker.
Veredito: Severidade Media.

--- EXEMPLO 11: BADWORKER DYNAMIC IMPORTSCRIPTS (ALTA) ---
Titulo: Dynamic importScripts without validation
Descricao: Severity: HIGH | CVSS: 7.5 | CWE: CWE-94 | Impact: Arbitrary code execution | Exploitable: True | Status: ACTIVE
Analise: 1. Comportamento: Worker usa importScripts com URL dinamica sem validacao. 2. Arquitetura: Atacante pode injetar URL maliciosa que sera executada como codigo. 3. Impacto: Execucao remota de codigo no contexto do worker, exfiltracao de dados.
Veredito: Severidade Alta.

--- EXEMPLO 12: OSINTGPT ANALISE DE DADOS (VARIAVEL) ---
Titulo: OSINT Analysis - exposed credentials pattern
Descricao: Confidence Score: 0.92 | Source: pastebin dump | Pattern: email:password combinations from target domain
Analise: 1. Comportamento: Credenciais vazadas encontradas em fontes OSINT. 2. Arquitetura: Dados reais de usuarios em circulacao publica. 3. Impacto: Acesso a contas, reuse de senhas em outros servicos.
Veredito: Severidade Alta (se ativas) ou Media (se historicas).

--- EXEMPLO 13: CASCAVEL RCE (CRITICA) ---
Titulo: [RCE Scanner] Remote Code Execution
Descricao: Host: target.com | Port: 8080 | Plugin: RCE Scanner | Description: Command injection detected in parameter "cmd" via POST /api/exec
Analise: 1. Comportamento: Parametro refletido em execucao de comando. 2. Arquitetura: API com chamada de sistema sem sanitizacao. 3. Impacto: Execucao remota de comandos como root, comprometimento total do servidor.
Veredito: Severidade Critica.

--- EXEMPLO 14: CORRELACAO: WIX ANON KEY + SUPABASE TABLE (CRITICA) ---
Titulo: ACHADO CORRELACIONADO: Wix API Key + Supabase Table Exposed
Descricao: Wix API key vazada em JS expoe project-ref Supabase. A mesma instancia Supabase tem tabela "users" com INSERT permitido. Cadeia: Wix Key Leak -> Supabase Auth Bypass -> Data Exfiltration.
Analise: 1. Comportamento: Duas ferramentas encontraram elos da mesma cadeia. 2. Arquitetura: Wix expoe project-ref+anon-key do Supabase via API. 3. Impacto: Atacante obtem chave Supabase de um endpoint Wix e acessa dados diretamente.
Veredito: Severidade Critica — cadeia de ataque completa e automatizavel.
"""

SYSTEM_BASE = """Claude-BugHunter — Especialista em Bug Bounty e Analise de Vulnerabilidades.

## REGRA FUNDAMENTAL: Chain-of-Thought
Para CADA achado, analise passo a passo antes de dar o veredito:
1. **Comportamento do Parametro/Achado** — O que este dado revela?
2. **Arquitetura do Servidor detectada** — Qual servico esta rodando? Ha indicios de tecnologia, versao, configuracao?
3. **Impacto Potencial** — Se explorado, qual o dano?
Apenas APOS estas 3 etapas, de o veredito final de severidade.

## REGRA DE CLASSIFICACAO (Few-Shot)
Use estes exemplos como referencia para classificar:
{FEW_SHOT_EXAMPLES}

## EXEMPLOS DE AUDITORIAS REAIS (public-pentesting-reports)
Estes sao achados REAIS de auditorias publicadas por empresas como Cure53, BishopFox, TrailOfBits e NCC Group. Use-os como referencia de severidade e analise:
{REAL_EXAMPLES}

{ TECHNIQUES_REFERENCE }

## DIRETRIZES GERAIS
- **SOMENTE classifique como Critica/Alta se houver EXPLORACAO REAL viavel.**
- Achados puramente informacionais devem ser **Info**.
- Evite "falso positivo" — nao invente vulnerabilidades onde so ha informacao.
- Seja conservador na severidade: duvida = Baixa ou Info.
- Para CVSS: use a tabela oficial NVD como referencia.
- Para CWE: mapeie para a categoria mais especifica possivel.
"""

PERSONA_MAP = {
    "recon": "Recon Specialist",
    "webapi": "Web/API Analyst",
    "infra": "Infrastructure Expert",
    "supabase": "Supabase Security Auditor",
    "wix": "Wix Platform Security Analyst",
    "wasm": "WebAssembly Malware Analyst",
    "worker": "Web Worker Security Engineer",
    "cascavel": "CTEM Platform Operator",
    "osint": "OSINT Threat Intelligence Analyst",
    "cross": "Attack Chain Correlator",
}

ADAPTER_KEYWORDS = {
    "supabase": ["supabomb", "supabase", "project_ref", "anon_key", "rpc_function", "storage_bucket"],
    "wix": ["specter", "wix", "velo", "tpa", "cors_misconfig", "idor", "ssrf"],
    "wasm": ["wasminator", "wasm", "webassembly", "cryptominer", "trust_score", "risk_level"],
    "worker": ["badworker", "web worker", "postmessage", "importscripts", "blob worker"],
    "cascavel": ["cascavel", "ctem", "profile", "remediation"],
    "osint": ["osintgpt", "osint", "embedding", "confidence score"],
}

def _determine_mode(batch: list[dict]) -> str:
    titles_concat = " ".join(f.get("title", "") for f in batch).lower()
    infra_keywords = ["porta", "ssl", "cve", "waf", "cloud", "tls", "certificado", "ip do dominio", "hostname"]
    recon_keywords = ["subdominio", "dns", "whois", "dmarc", "spf", "mx", "ns", "txt", "soa", "favicon", "wayback"]
    web_keywords = ["path", "pagina web", "header", "painel", "endpoint", "api", "dork", "spider", "login", "admin", "busca"]

    for mode, keywords in ADAPTER_KEYWORDS.items():
        if any(k in titles_concat for k in keywords):
            return mode

    infra_score = sum(1 for k in infra_keywords if k in titles_concat)
    recon_score = sum(1 for k in recon_keywords if k in titles_concat)
    web_score = sum(1 for k in web_keywords if k in titles_concat)
    if infra_score >= web_score and infra_score >= recon_score:
        return "infra"
    if recon_score >= web_score and recon_score >= infra_score:
        return "recon"
    return "webapi"

def _build_mode_instructions(mode: str) -> str:
    instructions = {
        "supabase": """## MODO: SUPABASE SECURITY AUDITOR
Foco em: exposure de tabelas, permissões de escrita (INSERT/UPDATE/DELETE), RPC functions expostas, storage buckets públicos, configuração de autenticação (signup desabilitado? email verification?).
CRITICO: tabela com dados sensiveis (users, auth, tokens, credentials) + INSERT allowed.
ALTO: storage bucket publico com arquivos, RPC function que retorna dados sem auth, signup aberto sem verificacao.
MEDIO: tabela com dados moderadamente sensiveis sem write permissions.
BAIXO: tabela com dados publicos/intencionais (blog, content, categories).
INFO: descoberta de instancia sem dados sensiveis acessiveis.""",
        "wix": """## MODO: WIX PLATFORM SECURITY ANALYST
Foco em: XSS em custom elements, vazamento de API keys, IDOR em endpoints de membro, CORS misconfiguration, SSRF em processamento de imagem, open redirect, vazamento de tokens de editor.
CRITICO: API key leak + endpoint com dados sensiveis.
ALTO: XSS refletido/armazenado, IDOR, SSRF via upload.
MEDIO: CORS misconfig, open redirect, member enumeration.
BAIXO: tech fingerprint, sitemap com paginas ocultas.
INFO: modulo executado sem achados."""
    }
    return instructions.get(mode, "")

def analyze_scope(findings_batch: list[dict], mode: str = None) -> list[dict]:
    if mode is None:
        mode = _determine_mode(findings_batch)
    persona_name = PERSONA_MAP.get(mode, "Bug Bounty Analyst")
    mode_instructions = _build_mode_instructions(mode)

    items_str = "\n".join(
        f"[{i}] ({f.get('plugin_source','?')}) {f.get('title','')} | {f.get('description','')[:400]}"
        for i, f in enumerate(findings_batch)
    )

    query_str = " ".join(
        f"{f.get('title','')} {f.get('description','')[:200]} {f.get('plugin_source','')}"
        for f in findings_batch
    )
    plugin_sources = {f.get("plugin_source", "") for f in findings_batch if f.get("plugin_source")}
    real_examples = _build_real_examples(query_str, plugin_source=next(iter(plugin_sources), ""))
    techniques_ref = _build_techniques_ref()

    mitre_mapper = MitreMapper()
    mitre_section = mitre_mapper.format_for_prompt(findings_batch)

    system_prompt = SYSTEM_BASE.format(
        FEW_SHOT_EXAMPLES=FEW_SHOT_EXAMPLES,
        REAL_EXAMPLES=real_examples,
        TECHNIQUES_REFERENCE=techniques_ref
    )

    prompt = f"""{system_prompt}

{mode_instructions}

{mitre_section}

--- LOTE DE ACHADOS ({len(findings_batch)} itens) ---
{items_str}
----------------------------------------

Analise CADA achado seguindo o Chain-of-Thought (1. Comportamento, 2. Arquitetura, 3. Impacto) e retorne ESTRITAMENTE UM JSON array valido (sem markdown), onde cada elemento corresponde ao indice do achado:
{{
  "findings": [
    {{
      "index": 0,
      "severity": "Critica|Alta|Media|Baixa|Info",
      "cvss_estimate": "9.8",
      "cwe": "CWE-89: SQL Injection",
      "executive_summary": "Resumo executivo curto do impacto real.",
      "attack_vector": "Como um atacante exploraria isto na pratica.",
      "remediation": "Passos claros para correcao.",
      "exploitability": "facil|medio|dificil",
      "chainable": true
    }}
  ]
}}
"""
    try:
        raw = _anonymized_chat(
            messages=[
                {"role": "system", "content": f"Claude-BugHunter [{persona_name}]: IA especializada em Bug Bounty. Siga Chain-of-Thought rigorosamente. Responda apenas JSON valido."},
                {"role": "user", "content": prompt}
            ],
            model="llama-3.1-8b-instant",
            temperature=0.15,
            max_tokens=4096,
            response_format={"type": "json_object"}
        )
        parsed = json.loads(raw)
        return parsed.get("findings", [])
    except Exception as e:
        print(f"[Claude-BugHunter] Erro na analise batch ({mode}): {e}")
        return []

def cross_correlate_all(project_id: int, all_findings: list[dict]) -> list[dict]:
    from app.models.base import Finding
    from app import create_app
    app = create_app()

    chains = []
    with app.app_context():
        titles = [f.get("title", "") for f in all_findings]
        descriptions = [f.get("description", "") for f in all_findings]
        plugins = set(f.get("plugin_source", "") for f in all_findings)

        if len(plugins) < 2:
            return chains

        combined = "\n".join(
            f"[{i}] ({f.get('plugin_source','?')}) {f.get('title','')}: {f.get('description','')[:200]}"
            for i, f in enumerate(all_findings)
        )

        cross_query = " ".join(f"{f.get('title','')} {f.get('description','')[:150]}" for f in all_findings)
        real_examples = _build_real_examples(cross_query, plugin_source="CrossCorrelator")
        techniques_ref = _build_techniques_ref()

        chain_table = ChainTable()
        chain_prompt = chain_table.format_chain_prompt(all_findings)

        prompt = f"""{SYSTEM_BASE.format(FEW_SHOT_EXAMPLES=FEW_SHOT_EXAMPLES, REAL_EXAMPLES=real_examples, TECHNIQUES_REFERENCE=techniques_ref)}

## MODO: CROSS-CORRELATION — ATAQUE ENCADEADO
Voce recebeu achados de MULTIPLAS ferramentas de seguranca no mesmo alvo.
Sua tarefa: identificar se ha **cadeias de ataque** onde um achado de uma ferramenta
habilita ou potencializa a exploracao de outro achado de ferramenta diferente.

### EXEMPLO DE CORRELACAO:
- Ferramenta A (Wix API Scanner) descobre chave de API Wix vazada com project-ref do Supabase.
- Ferramenta B (Supabomb) descobre tabela "users" com INSERT allowed na mesma instancia Supabase.
- **CORRELACAO**: Wix Key Leak + Supabase Table Exposure = Critico. Um atacante obtem a chave Wix, extrai o project-ref do Supabase, e insere registros maliciosos na tabela users.

### CHAIN TABLE (Capability-to-Next-Bug mappings):
{chain_prompt}

### DIRETRIZES:
- So reporte correlacoes com LOGICA REAL de exploracao.
- Nao force correlacao onde nao existe.
- Cada correlacao precisa ter: ferramentas envolvidas, descricao da cadeia, severidade agravada.

--- ACHADOS DO PROJETO ({len(all_findings)} itens, {len(plugins)} ferramentas: {', '.join(plugins)}) ---
{combined}
----------------------------------------

Retorne ESTRITAMENTE UM JSON array valido:
{{
  "chains": [
    {{
      "title": "Titulo da cadeia de ataque",
      "description": "Descricao detalhada de como os achados se conectam",
      "severity": "Critica|Alta|Media",
      "involved_indices": [0, 3, 7],
      "involved_plugins": ["Supabomb", "SPECTER"],
      "attack_scenario": "Passo a passo do ataque real usando estes achados",
      "remediation": "Correcao necessaria para quebrar a cadeia"
    }}
  ]
}}
"""
        try:
            raw = _anonymized_chat(
                messages=[
                    {"role": "system", "content": "Claude-BugHunter [Cross-Correlator]: Identifique cadeias de ataque entre achados de ferramentas diferentes. Responda apenas JSON valido."},
                    {"role": "user", "content": prompt}
                ],
                model="llama-3.1-8b-instant",
                temperature=0.1,
                max_tokens=4096,
                response_format={"type": "json_object"}
            )
            parsed = json.loads(raw)
            chains = parsed.get("chains", [])

            for chain in chains:
                base = {"project_id": project_id, "plugin_source": "CrossCorrelator"}
                desc = (
                    f"{chain.get('description', '')}\n\n"
                    f"Ferramentas envolvidas: {', '.join(chain.get('involved_plugins', []))}\n\n"
                    f"Cenario de ataque:\n{chain.get('attack_scenario', 'N/A')}\n\n"
                    f"Remediacao:\n{chain.get('remediation', 'N/A')}"
                )
                existing = Finding.query.filter_by(
                    project_id=project_id,
                    plugin_source="CrossCorrelator",
                    title=chain.get("title", "")
                ).first()
                if not existing:
                    new_finding = Finding(
                        project_id=project_id,
                        plugin_source="CrossCorrelator",
                        title=f"[CADEIA] {chain.get('title', 'Attack Chain')}",
                        description=desc,
                        severity=chain.get("severity", "Critica"),
                        raw_data=chain
                    )
                    from app.extensions import db
                    db.session.add(new_finding)
            from app.extensions import db
            db.session.commit()
        except Exception as e:
            print(f"[CrossCorrelator] Erro: {e}")

    return chains


def analyze_single_finding(title: str, description: str, mode: str = None) -> dict:
    batch = [{"title": title, "description": description}]
    results = analyze_scope(batch, mode)
    return results[0] if results else {}

def build_report(analysis: dict) -> str:
    cwe = analysis.get("cwe", "N/A")
    cvss = analysis.get("cvss_estimate", "N/A")
    summary = analysis.get("executive_summary", "")
    vector = analysis.get("attack_vector", "")
    remediation = analysis.get("remediation", "")
    exploitability = analysis.get("exploitability", "N/A")
    chainable = analysis.get("chainable", False)

    chainable_tag = " [ENCADEAVEL]" if chainable else ""

    return f"""--- JAIZZ NOIR / CLAUDE-BUGHUNTER REPORT ---
CWE: {cwe}
CVSS: {cvss}
Exploitability: {exploitability}{chainable_tag}

* Resumo Executivo:
{summary}

* Vetor de Ataque:
{vector}

* Remediacao:
{remediation}
"""


def build_cross_report(chains: list[dict]) -> str:
    if not chains:
        return ""
    parts = []
    for i, chain in enumerate(chains):
        parts.append(f"""=== CADEIA DE ATAQUE #{i+1}: {chain.get('title', 'N/A')} ===
Severidade: {chain.get('severity', 'N/A')}
Ferramentas: {', '.join(chain.get('involved_plugins', []))}

{chain.get('description', 'N/A')}

Cenario de ataque:
{chain.get('attack_scenario', 'N/A')}

Remediacao:
{chain.get('remediation', 'N/A')}
""")
    return "\n\n".join(parts)
