"""
chain_table.py — A→B Capability Chain Mappings

Baseado no chain-table.md do pentest-agents (H-mmer).
Mapeia capacidades confirmadas para o PRÓXIMO bug mais provavel,
permitindo construcao automatizada de cadeias de ataque.

Uso:
    chain = ChainTable()
    next_bugs = chain.suggest_next("idor", confirmed_findings)
    chains = chain.build_chains(all_findings)
"""

CAPABILITY_CHAINS = [
    {
        "from": "open_redirect",
        "to": "oauth_token_theft",
        "description": "Open redirect permite roubo de token OAuth via redirect_uri confuso",
        "severity_boost": "Alta",
        "chain_required": True,
    },
    {
        "from": "open_redirect",
        "to": "phishing_page",
        "description": "Redirect validado em dominio confiavel viabiliza phishing direcionado",
        "severity_boost": "Media",
        "chain_required": False,
    },
    {
        "from": "xss",
        "to": "csrf_token_theft",
        "description": "XSS permite ler csrf_token de cookie/localStorage e fazer requests autenticados",
        "severity_boost": "Critica",
        "chain_required": True,
    },
    {
        "from": "xss",
        "to": "session_hijacking",
        "description": "XSS permite exfiltrar cookie de sessao via fetch para atacante",
        "severity_boost": "Critica",
        "chain_required": True,
    },
    {
        "from": "xss",
        "to": "keylogger",
        "description": "XSS persistente permite capturar teclas do usuario em pagina legitima",
        "severity_boost": "Alta",
        "chain_required": False,
    },
    {
        "from": "idor",
        "to": "account_takeover",
        "description": "IDOR em endpoint de perfil -> alterar email/senha de outro usuario",
        "severity_boost": "Critica",
        "chain_required": True,
    },
    {
        "from": "idor",
        "to": "data_exfiltration",
        "description": "IDOR em listagem -> exportar dados de multiplos usuarios",
        "severity_boost": "Alta",
        "chain_required": False,
    },
    {
        "from": "idor",
        "to": "privilege_escalation",
        "description": "IDOR em parametro de role/grupo -> escalar para admin",
        "severity_boost": "Critica",
        "chain_required": True,
    },
    {
        "from": "ssrf",
        "to": "cloud_metadata_exposure",
        "description": "SSRF -> http://169.254.169.254/latest/meta-data/ -> credenciais cloud",
        "severity_boost": "Critica",
        "chain_required": True,
    },
    {
        "from": "ssrf",
        "to": "internal_service_scan",
        "description": "SSRF permite escanear servicos internos (Redis, Elasticsearch, DB)",
        "severity_boost": "Alta",
        "chain_required": False,
    },
    {
        "from": "ssrf",
        "to": "rce_internal",
        "description": "SSRF -> painel interno sem auth -> RCE",
        "severity_boost": "Critica",
        "chain_required": True,
    },
    {
        "from": "sqli",
        "to": "data_exfiltration",
        "description": "SQLi permite dump completo do banco de dados",
        "severity_boost": "Critica",
        "chain_required": False,
    },
    {
        "from": "sqli",
        "to": "rce_database",
        "description": "SQLi em banco com xp_cmdshell/ INTO OUTFILE -> execucao de comandos",
        "severity_boost": "Critica",
        "chain_required": True,
    },
    {
        "from": "rce",
        "to": "pivoting",
        "description": "RCE permite pivotear para rede interna a partir do host comprometido",
        "severity_boost": "Critica",
        "chain_required": False,
    },
    {
        "from": "rce",
        "to": "persistence",
        "description": "RCE permite instalar backdoor/cron job para persistencia",
        "severity_boost": "Critica",
        "chain_required": False,
    },
    {
        "from": "api_key_leak",
        "to": "data_exfiltration",
        "description": "Chave de API vazada permite acessar dados do servico diretamente",
        "severity_boost": "Critica",
        "chain_required": True,
    },
    {
        "from": "api_key_leak",
        "to": "account_takeover",
        "description": "Chave de API com permissoes de escrita permite modificar configs",
        "severity_boost": "Critica",
        "chain_required": True,
    },
    {
        "from": "cors_misconfig",
        "to": "data_exfiltration",
        "description": "CORS permissivo + pagina legitima -> exfiltrar dados de API via browser",
        "severity_boost": "Alta",
        "chain_required": True,
    },
    {
        "from": "cors_misconfig",
        "to": "xss",
        "description": "CORS permissivo permite bypassar CSP para injecao de script",
        "severity_boost": "Alta",
        "chain_required": True,
    },
    {
        "from": "subdomain_takeover",
        "to": "phishing_page",
        "description": "Subdominio expirado -> registrar em servico externo ->钓鱼",
        "severity_boost": "Alta",
        "chain_required": False,
    },
    {
        "from": "subdomain_takeover",
        "to": "session_hijacking",
        "description": "Subdominio com cookie sem __Host- prefix -> roubo de sessao",
        "severity_boost": "Critica",
        "chain_required": True,
    },
    {
        "from": "csrf",
        "to": "account_takeover",
        "description": "CSRF em troca de email/senha -> takeover de conta",
        "severity_boost": "Critica",
        "chain_required": True,
    },
    {
        "from": "csrf",
        "to": "idor",
        "description": "CSRF + endpoint sem checks de propriedade -> acao em recurso de outro user",
        "severity_boost": "Alta",
        "chain_required": True,
    },
    {
        "from": "ssti",
        "to": "rce",
        "description": "Server-Side Template Injection -> execucao remota de codigo",
        "severity_boost": "Critica",
        "chain_required": True,
    },
    {
        "from": "xxe",
        "to": "ssrf",
        "description": "XXE out-of-band -> SSRF para rede interna",
        "severity_boost": "Alta",
        "chain_required": True,
    },
    {
        "from": "xxe",
        "to": "rce",
        "description": "XXE com expect:// ou php:// -> RCE",
        "severity_boost": "Critica",
        "chain_required": True,
    },
    {
        "from": "exposed_storage",
        "to": "data_exfiltration",
        "description": "Storage bucket publico -> download de todos os arquivos",
        "severity_boost": "Critica",
        "chain_required": False,
    },
    {
        "from": "exposed_storage",
        "to": "rce",
        "description": "Storage bucket com upload publico -> webshell -> RCE",
        "severity_boost": "Critica",
        "chain_required": True,
    },
]


VULN_CLASS_ALIASES = {
    "xss": ["xss", "cross-site scripting", "cross_site_scripting"],
    "sqli": ["sqli", "sql injection", "sql_injection"],
    "rce": ["rce", "command injection", "remote code execution", "code_execution"],
    "ssrf": ["ssrf", "server-side request forgery"],
    "idor": ["idor", "bola", "insecure direct object reference"],
    "csrf": ["csrf", "cross-site request forgery", "xsrf"],
    "open_redirect": ["open redirect", "open_redirect", "url redirect"],
    "ssti": ["ssti", "template injection", "server-side template injection"],
    "xxe": ["xxe", "xml external entity"],
    "api_key_leak": ["api key", "api_key", "secret leak", "credential leak"],
    "cors_misconfig": ["cors", "cross-origin", "cors_misconfig"],
    "subdomain_takeover": ["subdomain takeover", "subdomain_takeover"],
    "exposed_storage": ["storage bucket", "s3 bucket", "supabase storage"],
}

SEVERITY_ORDER = {"Info": 0, "Baixa": 1, "Media": 2, "Alta": 3, "Critica": 4}


class ChainTable:
    def __init__(self):
        self.chains = CAPABILITY_CHAINS
        self.aliases = VULN_CLASS_ALIASES

    def _classify_finding(self, title: str, description: str) -> str:
        text = f"{title} {description}".lower()
        for klass, keywords in self.aliases.items():
            if any(k in text for k in keywords):
                return klass
        return ""

    def suggest_next(self, finding_title: str, finding_desc: str, severity: str = "Info") -> list[dict]:
        vuln_class = self._classify_finding(finding_title, finding_desc)
        if not vuln_class:
            return []

        suggestions = []
        for chain in self.chains:
            if chain["from"] == vuln_class:
                boost_level = SEVERITY_ORDER.get(chain["severity_boost"], 0)
                current_level = SEVERITY_ORDER.get(severity, 0)
                if boost_level >= current_level:
                    suggestions.append({
                        "from_class": vuln_class,
                        "to_class": chain["to"],
                        "description": chain["description"],
                        "severity_if_chained": chain["severity_boost"],
                        "chain_required": chain["chain_required"],
                    })
        return suggestions

    def build_chains(self, findings: list[dict]) -> list[dict]:
        classified = {}
        for i, f in enumerate(findings):
            vc = self._classify_finding(
                f.get("title", ""),
                f.get("description", ""),
            )
            if vc:
                classified.setdefault(vc, []).append(i)

        chains_found = []
        for vc, indices in classified.items():
            for chain in self.chains:
                if chain["from"] == vc and chain["to"] in classified:
                    to_indices = classified[chain["to"]]
                    chains_found.append({
                        "from_class": chain["from"],
                        "to_class": chain["to"],
                        "from_indices": indices,
                        "to_indices": to_indices,
                        "description": chain["description"],
                        "severity_if_chained": chain["severity_boost"],
                        "chain_required": chain["chain_required"],
                    })
        return chains_found

    def format_chain_prompt(self, findings: list[dict]) -> str:
        chains = self.build_chains(findings)
        if not chains:
            segments = []
            for f in findings:
                suggestions = self.suggest_next(
                    f.get("title", ""),
                    f.get("description", ""),
                    f.get("severity", "Info"),
                )
                if suggestions:
                    for s in suggestions[:2]:
                        segments.append(
                            f"- **{s['from_class']}** -> **{s['to_class']}**: {s['description']}"
                        )
            if not segments:
                return ""
            return (
                "### CADEIAS DE ATAQUE POTENCIAIS (Chain Table)\n"
                "Baseado nos achados, estas capacidades podem ser encadeadas:\n"
                + "\n".join(segments)
            )

        segments = ["### CADEIAS DE ATAQUE DETECTADAS (Chain Table)"]
        for c in chains:
            tag = " [OBRIGATORIO]" if c["chain_required"] else ""
            segments.append(
                f"- **{c['from_class']}** (indices {c['from_indices']}) -> "
                f"**{c['to_class']}** (indices {c['to_indices']}){tag}\n"
                f"  {c['description']}\n"
                f"  Severidade agravada: {c['severity_if_chained']}"
            )
        return "\n".join(segments)
