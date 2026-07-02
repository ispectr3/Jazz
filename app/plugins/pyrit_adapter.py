"""
PyRIT (Microsoft) — Python Risk Identification Tool for generative AI
=============================================================================
Repositorio: https://github.com/microsoft/PyRIT
Instalacao:  pip install pyrit
Docs:        https://microsoft.github.io/PyRIT/
Estrelas:    4k | Licenca: MIT | Ativo: Sim (v0.14.0, Jun/2026)

POSICIONAMENTO:
  PyRIT eh o framework oficial de red teaming da Microsoft para IA generativa.
  Diferente do Garak (que faz probes isoladas), o PyRIT orquestra ataques
  multi-turno com conversores (base64, rot13, ascii) e scorers automaticos.

CAPACIDADES:
  - Orchestrators: RedTeamingOrchestrator, XAIOrchestrator, SkeletonKey, etc.
  - Converters: base64, rot13, unicode, ascii, leetspeak
  - Targets: Azure OpenAI, OpenAI, HuggingFace, endpoint custom
  - Scorers: SelfAskCategoryScorer, SelfAskTrueFalseScorer, etc.
  - Multi-turno: Ataques com varias interacoes para engenharia social
  - Score automático: Classifica sucesso do ataque sem intervencao manual

RELACAO COM OUTRAS FERRAMENTAS:
  - Garak:  Probes individuais → PyRIT orquestra multi-turno
  - HarmBench: Benchmarks → PyRIT executa ataques reais
  - LLM Guard: Defesa → PyRIT ataca/testa a defesa
  - PromptBench: Avaliacao academica → PyRIT red teaming pratico
=============================================================================
"""
import json
from app.plugins.base import ScannerAdapter
from app.plugins.loader import register


@register()
class PyRITAdapter(ScannerAdapter):
    @property
    def name(self) -> str:
        return "PyRIT"

    def validate_input(self, raw_data: str) -> bool:
        try:
            data = json.loads(raw_data)
            return "tool" in data and "orchestrators" in data
        except Exception:
            return False

    def normalize(self, raw_data: str, project_id: int) -> list:
        data = json.loads(raw_data)
        findings = []
        base = {"project_id": project_id, "plugin_source": self.name}
        for orch in data.get("orchestrators", []):
            success = orch.get("success", False)
            findings.append({**base,
                "title": f"PyRIT: {orch['name']} — {'VULNERAVEL' if success else 'RESISTENTE'}",
                "description": (
                    f"Orchestrator: {orch['name']}\n"
                    f"Turns: {orch.get('turns', 1)}\n"
                    f"Objetivo: {orch.get('objective', 'N/A')}\n"
                    f"Tecnica: {orch.get('technique', 'N/A')}\n"
                    f"Status: {'Ataque bem-sucedido' if success else 'Modelo resistiu'}\n"
                    f"Converters disponiveis: {', '.join(data.get('converters', []))}\n"
                    f"Scorers disponiveis: {', '.join(data.get('scorers', []))}"
                ),
                "severity": "Critica" if success else "Info",
                "raw_data": orch})
        return findings
