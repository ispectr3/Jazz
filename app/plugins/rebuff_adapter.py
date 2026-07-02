"""
Rebuff (ProtectAI) — Self-hardening Prompt Injection Detector [ARCHIVED]
=============================================================================
Repositorio: https://github.com/protectai/rebuff
Instalacao:  pip install rebuff
Estrelas:    1.5k | Licenca: Apache-2.0 | ARQUIVADO: Mai/2025

POSICIONAMENTO:
  Rebuff foi o pioneiro em deteccao de prompt injection com auto-aprendizado.
  Suas funcionalidades foram migradas para o LLM Guard (mesmo mantenedor).

ARQUITETURA - 4 CAMADAS DE DEFESA:
  1. Heuristicas: Filtra padroes maliciosos conhecidos antes do LLM
  2. LLM-based detection: LLM dedicado analisa o prompt
  3. VectorDB (Pinecone/Chroma): Embeddings de ataques anteriores
  4. Canary tokens: Detecta vazamento de tokens canarios na resposta

RELACAO COM OUTRAS FERRAMENTAS:
  - LLM Guard:  Sucessor ativo — usar LLM Guard no lugar
  - Garak:      Ataca com probes → Rebuff detecta as probes
  - PromptInjector: Testa injecao → Rebuff bloqueia
=============================================================================
"""
import json
from app.plugins.base import ScannerAdapter
from app.plugins.loader import register


@register()
class RebuffAdapter(ScannerAdapter):
    @property
    def name(self) -> str:
        return "Rebuff"

    def validate_input(self, raw_data: str) -> bool:
        try:
            data = json.loads(raw_data)
            return "tool" in data and "layers" in data
        except Exception:
            return False

    def normalize(self, raw_data: str, project_id: int) -> list:
        data = json.loads(raw_data)
        findings = []
        base = {"project_id": project_id, "plugin_source": self.name}
        layers = data.get("layers", {})
        detected = data.get("injection_detected", False)
        if detected:
            findings.append({**base,
                "title": "Rebuff: Injection detectada por multiplas camadas",
                "description": (
                    "ATENCAO: Repositorio arquivado (05/2025). Migrar para LLM Guard.\n\n"
                    f"Heuristicas: score {layers.get('heuristics',{}).get('score',0)}\n"
                    f"LLM detection: score {layers.get('llm_detection',{}).get('score',0)}\n"
                    f"VectorDB: {layers.get('vectordb',{}).get('similar_attacks',0)} ataques similares\n"
                    f"Canary tokens: {'vazados' if layers.get('canary_tokens',{}).get('leaked') else 'seguros'}"
                ),
                "severity": "Alta",
                "raw_data": data})
        for layer_name, layer_data in layers.items():
            findings.append({**base,
                "title": f"Rebuff: Camada {layer_name}",
                "description": (
                    f"Camada: {layer_name}\n"
                    f"Detectou: {layer_data.get('detected', False)}\n"
                    f"Score: {layer_data.get('score', 0)}"
                ),
                "severity": "Info",
                "raw_data": layer_data})
        return findings
