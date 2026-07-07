from app.extensions import celery_app, db
from app.models.base import Finding
import os
from app.ai.anonymizer import get_anonymizer


def _get_groq_client():
    from groq import Groq
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        return None
    return Groq(api_key=api_key)

FEW_SHOT_EXAMPLES = """
--- EXEMPLO INFO: PORTA 80 ABERTA ---
Titulo: Porta Aberta: 80/HTTP
Descricao: Porta 80 (HTTP) esta aberta.
Chain-of-Thought:
1. Comportamento: Porta HTTP padrao.
2. Arquitetura: Servidor web comum.
3. Impacto: Nenhum, esperado.
-> Severidade: Info

--- EXEMPLO CRITICA: .ENV EXPOSTO ---
Titulo: Path Encontrado: /.env
Descricao: Arquivo .env acessivel, contem chaves de API.
Chain-of-Thought:
1. Comportamento: Arquivo de configuracao exposto.
2. Arquitetura: Contem credenciais de banco, API keys.
3. Impacto: Comprometimento total do ambiente.
-> Severidade: Critica

--- EXEMPLO MEDIA: SPF AUSENTE ---
Titulo: SPF Ausente: dominio.com
Descricao: Registro SPF nao encontrado.
Chain-of-Thought:
1. Comportamento: Sem politica SPF no DNS.
2. Arquitetura: Email sem protecao contra spoofing.
3. Impacto: Phishing, engenharia social.
-> Severidade: Media

--- EXEMPLO ALTA: PAINEL ADMIN ---
Titulo: Painel Admin: admin.dominio.com
Descricao: Painel de login administrativo encontrado.
Chain-of-Thought:
1. Comportamento: Formulario de login admin.
2. Arquitetura: Provavelmente sem MFA.
3. Impacto: Acesso administrativo ao sistema.
-> Severidade: Alta

--- EXEMPLO INFO: REGISTRO DNS ---
Titulo: DNS TXT: 20 registros
Descricao: Registros TXT para dominio.com.
Chain-of-Thought:
1. Comportamento: Registro DNS padrao.
2. Arquitetura: Configuracao de email.
3. Impacto: Nenhum, configuracao valida.
-> Severidade: Info
"""

@celery_app.task(name='ai_tasks.analyze_finding')
def analyze_finding_task(finding_id: int):
    from app import create_app
    app = create_app()

    with app.app_context():
        finding = Finding.query.get(finding_id)
        if not finding:
            return "Finding not found"

        print(f"[{finding.plugin_source}] Iniciando analise NeuralCore AI do Finding #{finding_id}...")

        raw_evidence = str(finding.raw_data)[:2000]
        
        prompt = f"""Claude-BugHunter — Hacker Senior de Bug Bounty.

## REGRA: Chain-of-Thought OBRIGATORIO
Para cada achado, analise passo a passo:
1. Comportamento — O que este dado revela?
2. Arquitetura — Qual servico/tecnologia esta envolvida?
3. Impacto — Se explorado, qual o dano real?
Apenas depois destas 3 etapas, de o veredito.

## EXEMPLOS DE CLASSIFICACAO (Few-Shot)
{FEW_SHOT_EXAMPLES}

## DIRETRIZES
- Nao invente vulnerabilidades onde so ha informacao.
- Portas HTTP/HTTPS padrao, registros DNS, WHOIS = Info.
- .env, .git, backup expostos, banco de dados publico = Critica.
- Painel admin sem MFA, CVE com exploit = Alta.
- SPF ausente, SSL fraco, headers faltando = Media/Baixa.
- Se em duvida, seja conservador: Baixa ou Info.

--- DADOS DO ACHADO ---
Scanner: {finding.plugin_source}
Titulo: {finding.title}
Descricao: {finding.description}
Evidencia: {raw_evidence}
----------------------------------------

Retorne APENAS UM JSON valido (sem markdown):
{{
  "severity": "Critica|Alta|Media|Baixa|Info",
  "cvss_estimate": "8.5",
  "cwe": "CWE-89 SQL Injection",
  "executive_summary": "Resumo do impacto comercial real.",
  "attack_vector": "Como explorar na pratica.",
  "remediation": "Passos para corrigir."
}}
"""

        try:
            anon = get_anonymizer()
            safe_prompt = anon.anonymize(prompt)
            groq = _get_groq_client()
            if not groq:
                raise RuntimeError("GROQ_API_KEY not configured")
            chat_completion = groq.chat.completions.create(
                messages=[
                    {
                        "role": "system",
                        "content": "Claude-BugHunter: IA especializada em Bug Bounty. Siga Chain-of-Thought rigorosamente. Responda apenas JSON valido."
                    },
                    {
                        "role": "user",
                        "content": safe_prompt,
                    }
                ],
                model="llama-3.1-8b-instant",
                temperature=0.15,
                max_tokens=2048,
                response_format={"type": "json_object"}
            )
            
            import json
            ai_response = anon.restore_response(chat_completion.choices[0].message.content)
            try:
                parsed_json = json.loads(ai_response)
                formatted_report = f"""--- JAIZZ NOIR / CLAUDE-BUGHUNTER REPORT ---
CWE: {parsed_json.get('cwe', 'N/A')}
CVSS: {parsed_json.get('cvss_estimate', 'N/A')}

* Resumo Executivo:
{parsed_json.get('executive_summary', '')}

* Vetor de Ataque:
{parsed_json.get('attack_vector', '')}

* Remediacao:
{parsed_json.get('remediation', '')}
"""
                new_severity = parsed_json.get('severity', finding.severity)
                
            except Exception as json_err:
                formatted_report = f"--- ANALISE IA (GROQ) ---\n{ai_response}"
                new_severity = "Desconhecida"
            
            finding.description = f"{finding.description}\n\n{formatted_report}"
            
            valid_severities = ["Critica", "Alta", "Media", "Baixa", "Info"]
            new_severity_clean = str(new_severity).strip().title()
            if new_severity_clean == "Critica": new_severity_clean = "Critica"
            if new_severity_clean == "Media": new_severity_clean = "Media"
            
            if new_severity_clean in valid_severities:
                finding.severity = new_severity_clean
                
            db.session.commit()
            print(f"[{finding.plugin_source}] Analise NeuralCore AI concluida para Finding #{finding_id}.")
            return f"Success: {finding_id}"

        except Exception as e:
            print(f"[{finding.plugin_source}] Erro na analise NeuralCore AI: {e}")
            return f"Error: {e}"
