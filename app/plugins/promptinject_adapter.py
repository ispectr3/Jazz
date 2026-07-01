import json
from app.plugins.base import ScannerAdapter

class PromptInjectAdapter(ScannerAdapter):
    @property
    def name(self) -> str:
        return "PromptInjector"

    def validate_input(self, raw_data: str) -> bool:
        try:
            data = json.loads(raw_data)
            return "total_tests" in data and "results" in data
        except Exception:
            return False

    def normalize(self, raw_data: str, project_id: int) -> list:
        data = json.loads(raw_data)
        findings = []
        base = {"project_id": project_id, "plugin_source": self.name}
        target = data.get("target", "unknown")

        for r in data.get("results", []):
            test_name = r.get("test", "Unknown")
            preview = r.get("response_preview", "")[:100]
            indicators = r.get("indicators", [])
            success = r.get("success", False)
            error = r.get("error", "")

            if success:
                findings.append({**base,
                    "title": f"Prompt Injection: {test_name} - VULNERAVEL",
                    "description": (
                        f"Teste de injecao de prompt bem-sucedido contra {target}.\n"
                        f"Test: {test_name}\n"
                        f"Indicadores de quebra: {', '.join(indicators)}\n"
                        f"Resposta: {preview}"
                    ),
                    "severity": "Alta",
                    "raw_data": r})
            elif not error:
                findings.append({**base,
                    "title": f"Prompt Injection: {test_name} - OK",
                    "description": (
                        f"Modelo resistiu ao ataque de injecao de prompt.\n"
                        f"Test: {test_name}\n"
                        f"Resposta: {preview}"
                    ),
                    "severity": "Info",
                    "raw_data": r})
            else:
                findings.append({**base,
                    "title": f"Prompt Injection: {test_name} - Erro",
                    "description": f"Erro ao testar injecao de prompt: {error}",
                    "severity": "Info",
                    "raw_data": r})

        summary = {
            "total_tests": data.get("total_tests", 0),
            "successful_injections": data.get("successful_injections", 0),
            "target": target,
        }
        findings.append({**base,
            "title": f"Prompt Injection Scan: {target}",
            "description": (
                f"Scanner de injecao de prompt concluido.\n"
                f"Total de testes: {summary['total_tests']}\n"
                f"Injecoes bem-sucedidas: {summary['successful_injections']}\n"
                f"Alvo: {target}"
            ),
            "severity": "Info",
            "raw_data": summary})

        return findings
