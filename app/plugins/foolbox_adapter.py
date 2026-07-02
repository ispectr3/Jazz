import json
import os
from app.plugins.base import ScannerAdapter
from app.plugins.loader import register

@register()
class FoolboxAdapter(ScannerAdapter):
    @property
    def name(self) -> str:
        return "Foolbox"

    def run_attack_simulation(self, model_framework: str = "dummy", attack_type: str = "fgsm") -> str:
        results = {
            "tool": "Foolbox",
            "framework": model_framework,
            "attack": attack_type,
            "simulation": True,
            "scenarios": []
        }
        attacks_info = {
            "fgsm": {
                "epsilon": 0.05,
                "success_rate": 0.73,
                "avg_confidence": 0.31,
                "description": "Fast Gradient Sign Method — perturbacao baseada no sinal do gradiente"
            },
            "pgd": {
                "epsilon": 0.03,
                "steps": 40,
                "success_rate": 0.89,
                "avg_confidence": 0.15,
                "description": "Projected Gradient Descent — iterativo com projecao no espaco valido"
            },
            "deepfool": {
                "epsilon": 0.02,
                "success_rate": 0.94,
                "avg_confidence": 0.08,
                "description": "DeepFool — perturbacao minima para cruzar fronteira de decisao"
            },
            "boundary": {
                "queries_avg": 3500,
                "success_rate": 0.67,
                "avg_confidence": 0.22,
                "description": "Boundary Attack — busca na fronteira de decisao (caixa preta)"
            },
            "carlini_wagner": {
                "confidence": 0.5,
                "success_rate": 0.82,
                "avg_confidence": 0.11,
                "description": "Carlini & Wagner — otimizacao L2 com margem de confianca"
            }
        }
        if attack_type == "all":
            selected = list(attacks_info.values())
        elif attack_type in attacks_info:
            selected = [attacks_info[attack_type]]
        else:
            selected = [attacks_info["fgsm"]]
        for info in selected:
            results["scenarios"].append({
                "attack": attack_type if attack_type != "all" else "fgsm",
                "framework": model_framework,
                **info
            })
        return json.dumps(results, indent=2)

    def validate_input(self, raw_data: str) -> bool:
        try:
            data = json.loads(raw_data)
            return "tool" in data and "scenarios" in data
        except Exception:
            return False

    def normalize(self, raw_data: str, project_id: int) -> list:
        data = json.loads(raw_data)
        findings = []
        base = {"project_id": project_id, "plugin_source": self.name}
        for scenario in data.get("scenarios", []):
            attack = scenario.get("attack", "unknown")
            sr = scenario.get("success_rate", 0)
            severity = "Alta" if sr > 0.8 else "Media"
            findings.append({**base,
                "title": f"Foolbox: {attack.upper()} — taxa de sucesso {sr:.0%}",
                "description": (
                    f"Ataque: {attack}\n"
                    f"Framework: {scenario.get('framework','N/A')}\n"
                    f"Taxa de sucesso: {sr:.0%}\n"
                    f"Confianca media: {scenario.get('avg_confidence',0):.0%}\n"
                    f"Descricao: {scenario.get('description','')}\n"
                    f"Parametros adicionais: epsilon={scenario.get('epsilon','N/A')}, "
                    f"queries_avg={scenario.get('queries_avg','N/A')}"
                ),
                "severity": severity,
                "raw_data": scenario})
        return findings
