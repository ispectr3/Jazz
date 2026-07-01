from app.extensions import celery_app, db
from app.models.base import Finding
import os
from groq import Groq

client = Groq()

@celery_app.task(name='ai_tasks.analyze_finding')
def analyze_finding_task(finding_id: int):
    from app import create_app
    app = create_app()

    with app.app_context():
        finding = Finding.query.get(finding_id)
        if not finding:
            return "Finding not found"

        print(f"[{finding.plugin_source}] Iniciando análise NeuralCore AI do Finding #{finding_id}...")
        
        # Constrói o prompt de cibersegurança usando os dados do Finding
        raw_evidence = str(finding.raw_data)[:2000] # Limita a 2000 caracteres para não estourar o limite de tokens
        
        prompt = f"""
Você é um Hacker Sênior de Bug Bounty e Especialista de Red Team operando a ferramenta de CTI 'Jaizz Noir'.
Seu conhecimento base inclui as dezenas de matrizes de ataque e heurísticas do repositório 'Claude-BugHunter'.

Sua missão é triar os dados crus de um scanner (como OSINT ou Dorking) e escrever um relatório impecável de Bug Bounty identificando a vulnerabilidade exata.

--- DADOS DA VULNERABILIDADE BRUTA ---
Scanner Origem: {finding.plugin_source}
Título: {finding.title}
Descrição Original: {finding.description}
Evidência Bruta (Payload/JSON): {raw_evidence}
----------------------------------------

Sua saída deve SER EXATAMENTE E APENAS UM JSON VÁLIDO (sem markdown ou texto extra ao redor) contendo as seguintes chaves:
{{
  "severity": "<Critica, Alta, Media, Baixa, ou Info>",
  "cvss_estimate": "<Sua estimativa de Score CVSS ex: 8.5>",
  "cwe": "<Ex: CWE-89 SQL Injection>",
  "executive_summary": "<1 parágrafo incisivo resumindo o impacto comercial do bug>",
  "attack_vector": "<Como um atacante do mundo real exploraria isso (PoC teorica)>",
  "remediation": "<1 a 2 passos práticos para o Blue Team corrigir a falha>"
}}
"""

        try:
            chat_completion = client.chat.completions.create(
                messages=[
                    {
                        "role": "system",
                        "content": "Você é uma IA especializada em Bug Bounty. Você responde ESTRITAMENTE em JSON limpo e validável."
                    },
                    {
                        "role": "user",
                        "content": prompt,
                    }
                ],
                model="llama-3.1-8b-instant",
                temperature=0.3,
                max_tokens=1024,
                response_format={"type": "json_object"}
            )
            
            import json
            ai_response = chat_completion.choices[0].message.content
            try:
                parsed_json = json.loads(ai_response)
                # Formata a string bonita para o BD
                formatted_report = f"""--- JAIZZ NOIR - BUG HUNTER REPORT ---
CWE: {parsed_json.get('cwe', 'N/A')}
Estimativa CVSS: {parsed_json.get('cvss_estimate', 'N/A')}

* Resumo Executivo: 
{parsed_json.get('executive_summary', '')}

* Vetor de Ataque / Exploração:
{parsed_json.get('attack_vector', '')}

* Remediação Recomendada:
{parsed_json.get('remediation', '')}
"""
                new_severity = parsed_json.get('severity', finding.severity)
                
            except Exception as json_err:
                # Se falhar o parse JSON, salva o texto cru
                formatted_report = f"--- ANÁLISE IA (GROQ) ---\n{ai_response}"
                new_severity = "Desconhecida"
            
            # Anexa a resposta da IA na descrição do Finding original
            finding.description = f"{finding.description}\n\n{formatted_report}"
            
            # Atualiza a severidade se foi inferida algo novo válido
            valid_severities = ["Crítica", "Alta", "Média", "Baixa", "Info"]
            # Normalizar para title case ex: 'Alta'
            new_severity_clean = str(new_severity).strip().title()
            # Tratamento especial para remover acentos caso o modelo retorne 'Critica' sem acento
            if new_severity_clean == "Critica": new_severity_clean = "Crítica"
            if new_severity_clean == "Media": new_severity_clean = "Média"
            
            if new_severity_clean in valid_severities:
                finding.severity = new_severity_clean
                
            db.session.commit()
            print(f"[{finding.plugin_source}] Análise NeuralCore AI concluída para o Finding #{finding_id}.")
            return f"Success: {finding_id}"

        except Exception as e:
            print(f"[{finding.plugin_source}] Erro na análise NeuralCore AI: {e}")
            return f"Error: {e}"
