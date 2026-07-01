import json
from app.plugins.base import ScannerAdapter

class RobotsAdapter(ScannerAdapter):
    @property
    def name(self) -> str:
        return "RobotsAnalyzer"

    def validate_input(self, raw_data: str) -> bool:
        try:
            data = json.loads(raw_data)
            return "target" in data and "encontrado" in data
        except Exception:
            return False

    def normalize(self, raw_data: str, project_id: int) -> list:
        data = json.loads(raw_data)
        findings = []
        base = {"project_id": project_id, "plugin_source": self.name}
        domain = data.get("target", "")

        if not data.get("encontrado"):
            findings.append({**base,
                "title": f"robots.txt: Nao encontrado em {domain}",
                "description": f"O arquivo robots.txt nao foi encontrado ou retornou status {data.get('codigo_http')}. Isso pode indicar redirecionamento ou bloqueio.\nURL: {data.get('robots_url')}",
                "severity": "Info",
                "raw_data": data})
            return findings

        findings.append({**base,
            "title": f"robots.txt: Encontrado em {domain}",
            "description": f"robots.txt presente com {len(data.get('disallows', []))} disallows e {len(data.get('sitemaps', []))} sitemaps.",
            "severity": "Info",
            "raw_data": data})

        for path in data.get("disallows", []):
            findings.append({**base,
                "title": f"Disallow Exposto: {domain}{path}",
                "description": f"Caminho bloqueado em robots.txt que pode conter informacoes sensiveis ou paineis administrativos.\nPath: {domain}{path}",
                "severity": "Media",
                "raw_data": {"path": path, "tipo": "disallow", "dominio": domain}})

        for sitemap in data.get("sitemaps", []):
            findings.append({**base,
                "title": f"Sitemap: {sitemap}",
                "description": f"Sitemap XML encontrado, pode revelar paginas nao indexadas.\nURL: {sitemap}",
                "severity": "Info",
                "raw_data": {"sitemap": sitemap, "tipo": "sitemap"}})

        for caminho in data.get("caminhos_ocultos", []):
            if caminho.get("provavelmente_excluido"):
                path = caminho["path"]
                findings.append({**base,
                    "title": f"Path Sugerido: {domain}{path}",
                    "description": f"Path comum de admin/configuracao nao bloqueado por robots.txt. Provavelmente acessivel.\nPath: {domain}{path}",
                    "severity": "Media",
                    "raw_data": {"path": path, "tipo": "caminho_sugerido", "dominio": domain}})

        raw = data.get("raw", "")
        matches = []
        for keyword in ["admin", "login", "password", "backup", "internal", "private"]:
            import re
            for m in re.finditer(rf'[^\n]*{keyword}[^\n]*', raw, re.IGNORECASE):
                matches.append(m.group().strip())
        if matches:
            findings.append({**base,
                "title": f"Termos Sensiveis no robots.txt: {domain}",
                "description": f"Palavras-chave sensiveis encontradas no robots.txt: {', '.join(matches[:5])}",
                "severity": "Media",
                "raw_data": {"termos": matches[:10]}})

        return findings
