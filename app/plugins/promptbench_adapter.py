"""
PromptBench (Microsoft) — Unified Evaluation Framework for LLMs [ARCHIVED]
=============================================================================
Repositorio: https://github.com/microsoftarchive/promptbench
Instalacao:  pip install promptbench
Paper:       https://arxiv.org/abs/2312.07910
Estrelas:    2.8k | Licenca: MIT | ARQUIVADO: Mar/2026

POSICIONAMENTO:
  PromptBench eh um framework unificado para avaliacao de LLMs com suporte
  a ataques adversariais, prompt engineering, datasets multimodais, e
  avaliacao dinamica (DyVal).

ATRIBUTOS:
  - 4 niveis de ataque: character (DeepWordBug, TextBugger), word-level
    (TextFooler, BertAttack), sentence-level (CheckList, StressTest),
    semantic (human-crafted)
  - Datasets: MMLU, BBH, GSM8K, SQuAD V2, GLUE, Math, CSQA, BigBench Hard
  - Modelos: GPT-3.5/4, PaLM 2, Gemini, Llama 2, Vicuna, FLAN-T5, phi
  - Prompt engineering: COT, EmotionPrompt, ExpertPrompt, DyVal, PromptEval
  - Multimodal: VQAv2, NoCaps, MMMU, MathVista

RELACAO COM OUTRAS FERRAMENTAS:
  - HarmBench: Benchmark de seguranca → PromptBench: Benchmark geral
  - Garak: Probes especificas → PromptBench: Ataques adversariais textos
  - PyRIT: Red teaming orquestrado → PromptBench: Ataques em dataset
  - TextAttack: Usado internamente pelo PromptBench para ataques texto
=============================================================================
"""
import json
from app.plugins.base import ScannerAdapter
from app.plugins.loader import register


@register()
class PromptBenchAdapter(ScannerAdapter):
    @property
    def name(self) -> str:
        return "PromptBench"

    def validate_input(self, raw_data: str) -> bool:
        try:
            data = json.loads(raw_data)
            return "tool" in data and "accuracy_baseline" in data
        except Exception:
            return False

    def normalize(self, raw_data: str, project_id: int) -> list:
        data = json.loads(raw_data)
        findings = []
        base = {"project_id": project_id, "plugin_source": self.name}
        baseline = data.get("accuracy_baseline", 0)
        attacked = data.get("accuracy_under_attack", 0)
        degradation = data.get("degradation", 0)
        findings.append({**base,
            "title": f"PromptBench: Degradacao de {degradation:.0%} sob ataque {data.get('attack','all')}",
            "description": (
                f"Modelo: {data.get('model', 'N/A')}\n"
                f"Ataque: {data.get('attack', 'all')}\n"
                f"Datasets: {', '.join(data.get('datasets_tested', []))}\n"
                f"Acuracia baseline: {baseline:.0%}\n"
                f"Acuracia sob ataque: {attacked:.0%}\n"
                f"Degradacao: {degradation:.0%}\n"
                f"Tipos de ataque: {', '.join(data.get('attack_types', []))}"
            ),
            "severity": "Critica" if degradation > 0.5 else ("Alta" if degradation > 0.3 else "Media"),
            "raw_data": data})
        return findings
