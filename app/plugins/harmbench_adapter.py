"""
HarmBench (Center for AI Safety) — Standardized Evaluation Framework
=============================================================================
Repositorio: https://github.com/centerforaisafety/HarmBench
Instalacao:  git clone + pip install -r requirements.txt
Paper:       https://arxiv.org/abs/2402.04249
Site:        https://harmbench.org
Estrelas:    995 | Licenca: MIT | Ativo: Sim

POSICIONAMENTO:
  HarmBench eh o benchmark academico mais completo para automated red teaming.
  18 metodos de ataque, 33 LLMs, metricas padronizadas de robustez e refusal.
  Classificadores Llama-2-13b-cls para avaliacao automática de sucesso.

18 METODOS DE RED TEAMING:
  GCG (Greedy Coordinate Gradient), AutoDAN, PAIR, TAP, ZeroShot, PEZ,
  Transfer, Multi-turn, Persuasive, etc.

33 LLMs SUPORTADOS:
  Llama 2 (7B, 13B, 70B), Mistral 7B, Mixtral, Baichuan 2, GPT-3.5,
  GPT-4, Claude, PaLM 2, Gemini, etc.

CLASSIFICADORES:
  - cais/HarmBench-Llama-2-13b-cls: Para comportamentos standard/contextual
  - cais/HarmBench-Llama-2-13b-cls-multimodal: Para multimodal
  - cais/HarmBench-Mistral-7b-val-cls: Classificador de validacao

RELACAO COM OUTRAS FERRAMENTAS:
  - Garak:     Probes de vulnerabilidade → HarmBench: Benchmark padronizado
  - PyRIT:     Red teaming pratico → HarmBench: Avaliacao comparativa
  - LLM Guard: Defesa → HarmBench testa a robustez da defesa
  - PromptBench: Avaliacao academica generica → HarmBench focado em seguranca
=============================================================================
"""
import json
from app.plugins.base import ScannerAdapter
from app.plugins.loader import register


@register()
class HarmBenchAdapter(ScannerAdapter):
    @property
    def name(self) -> str:
        return "HarmBench"

    def validate_input(self, raw_data: str) -> bool:
        try:
            data = json.loads(raw_data)
            return "tool" in data and "attack_success_rates" in data
        except Exception:
            return False

    def normalize(self, raw_data: str, project_id: int) -> list:
        data = json.loads(raw_data)
        findings = []
        base = {"project_id": project_id, "plugin_source": self.name}
        rates = data.get("attack_success_rates", {})
        for method, rate in rates.items():
            severity = "Critica" if rate > 0.7 else ("Alta" if rate > 0.5 else "Media")
            findings.append({**base,
                "title": f"HarmBench: {method} — ASR {rate:.0%}",
                "description": (
                    f"Metodo: {method}\n"
                    f"Attack Success Rate: {rate:.0%}\n"
                    f"Modelo: {data.get('model', 'N/A')}\n"
                    f"Total de metodos: {data.get('methods_evaluated', 0)}\n"
                    f"Robustez geral: {data.get('robustness_score', 0):.0%}\n"
                    f"Taxa de recusa: {data.get('refusal_rate', 0):.0%}\n"
                    f"Classifier: {data.get('classifier', 'N/A')}"
                ),
                "severity": severity,
                "raw_data": {method: rate}})
        return findings
