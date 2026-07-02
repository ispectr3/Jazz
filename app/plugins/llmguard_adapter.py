"""
LLM Guard (ProtectAI) — The Security Toolkit for LLM Interactions
=============================================================================
Repositorio: https://github.com/protectai/llm-guard
Instalacao:  pip install llm-guard
Docs:        https://protectai.github.io/llm-guard/
Estrelas:    3.1k | Licenca: MIT | Ativo: Sim

POSICIONAMENTO:
  LLM Guard eh um gateway de seguranca em tempo real para interacoes com LLMs.
  Diferente do Garak/PyRIT (que ATACAM), o LLM Guard DEFENDE — sanitizando
  inputs e outputs antes/depois de chegar no modelo.

CAPACIDADES - INPUT SCANNERS (15):
  Anonymize, BanCode, BanCompetitors, BanSubstrings, BanTopics, Code,
  Gibberish, InvisibleText, Language, PromptInjection, Regex, Secrets,
  Sentiment, TokenLimit, Toxicity

CAPACIDADES - OUTPUT SCANNERS (21):
  BanCode, BanCompetitors, BanSubstrings, BanTopics, Bias, Code,
  Deanonymize, JSON, Language, LanguageSame, MaliciousURLs, NoRefusal,
  ReadingTime, FactualConsistency, Gibberish, Regex, Relevance, Sensitive,
  Sentiment, Toxicity, URLReachability

RELACAO COM OUTRAS FERRAMENTAS:
  - Rebuff:  Antecessor (arquivado) — funcionalidades migradas para LLM Guard
  - Garak:   Ataca LLMs → LLM Guard protege LLMs
  - PyRIT:   Red teaming → LLM Guard bloqueia ataques em tempo real
=============================================================================
"""
import json
from app.plugins.base import ScannerAdapter
from app.plugins.loader import register


@register()
class LLMGuardAdapter(ScannerAdapter):
    @property
    def name(self) -> str:
        return "LLMGuard"

    def validate_input(self, raw_data: str) -> bool:
        try:
            data = json.loads(raw_data)
            return "tool" in data and "scanners" in data
        except Exception:
            return False

    def normalize(self, raw_data: str, project_id: int) -> list:
        data = json.loads(raw_data)
        findings = []
        base = {"project_id": project_id, "plugin_source": self.name}
        for scan_type, scanners in data.get("scanners", {}).items():
            for scanner_name, result in scanners.items():
                risk = result.get("risk", "low")
                blocked = result.get("blocked", False)
                if blocked or risk in ("high", "critical"):
                    severity = "Alta" if blocked else "Media"
                elif risk == "medium":
                    severity = "Media"
                else:
                    severity = "Info"
                findings.append({**base,
                    "title": f"LLM Guard: {scanner_name} ({scan_type})",
                    "description": (
                        f"Scanner: {scanner_name}\n"
                        f"Tipo: {scan_type}\n"
                        f"Risco: {risk}\n"
                        f"Bloqueado: {'Sim' if blocked else 'Nao'}\n"
                        f"Acao: {result.get('action', 'pass')}\n"
                        f"Prompt: {data.get('prompt', 'N/A')[:100]}"
                    ),
                    "severity": severity,
                    "raw_data": result})
        return findings
