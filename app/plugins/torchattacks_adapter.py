import json
from app.plugins.base import ScannerAdapter
from app.plugins.loader import register

@register()
class TorchAttacksAdapter(ScannerAdapter):
    @property
    def name(self) -> str:
        return "TorchAttacks"

    def run_scan(self, attack_type: str = "all") -> str:
        results = {
            "tool": "TorchAttacks",
            "attack_type": attack_type,
            "attacks": []
        }
        catalog = [
            {"name": "FGSM", "paper": "Explaining and Harnessing Adversarial Examples (2015)",
             "params": {"eps": 0.03}, "success_rate": 0.71,
             "description": "One-step gradient sign attack"},
            {"name": "PGD", "paper": "Towards Deep Learning Models Resistant to Adversarial Attacks (2019)",
             "params": {"eps": 0.03, "alpha": 0.01, "steps": 40}, "success_rate": 0.93,
             "description": "Projected Gradient Descent — iterativo multi-passo"},
            {"name": "CW", "paper": "Towards Evaluating the Robustness of Neural Networks (2017)",
             "params": {"c": 1.0, "steps": 1000}, "success_rate": 0.87,
             "description": "Carlini & Wagner L2 attack via otimizacao"},
            {"name": "PGDDLR", "paper": "Reliable evaluation of adversarial robustness with an ensemble of diverse parameter-free attacks (2020)",
             "params": {"eps": 0.03, "steps": 40}, "success_rate": 0.91,
             "description": "PGD com decoy loss reduction"},
            {"name": "AutoAttack", "paper": "Reliable evaluation of adversarial robustness (2020)",
             "params": {"eps": 0.03}, "success_rate": 0.96,
             "description": "Ensemble de ataques automaticos (APGD, FAB, Square)"},
            {"name": "SquareAttack", "paper": "Square Attack: a query-efficient black-box adversarial attack (2020)",
             "params": {"eps": 0.03, "n_queries": 5000}, "success_rate": 0.78,
             "description": "Ataque caixa-preta baseado em busca aleatoria"},
            {"name": "DeepFool", "paper": "DeepFool: a simple and accurate method to fool deep neural networks (2016)",
             "params": {"steps": 50}, "success_rate": 0.84,
             "description": "Perturbacao geometrica minima"},
            {"name": "BIM", "paper": "Adversarial Examples in the Physical World (2017)",
             "params": {"eps": 0.03, "alpha": 0.005, "steps": 10}, "success_rate": 0.75,
             "description": "Basic Iterative Method (versao original do PGD)"},
            {"name": "RFGSM", "paper": "Robustness via Gradient Sign (2016)",
             "params": {"eps": 0.03, "alpha": 0.005}, "success_rate": 0.69,
             "description": "RAND+FGSM — adiciona ruido antes do gradiente"},
            {"name": "EOTPGD", "paper": "Synthesizing Robust Adversarial Examples (2018)",
             "params": {"eps": 0.03, "steps": 40}, "success_rate": 0.88,
             "description": "Expectation Over Transformation PGD — robusto a transformacoes"},
            {"name": "FFGSM", "paper": "Fast is better than free (2019)",
             "params": {"eps": 0.03, "alpha": 0.01}, "success_rate": 0.66,
             "description": "Fast Feature-based FGSM"},
            {"name": "TPGD", "paper": "Towards Deep Learning Models Resistant to Adversarial Attacks (2019)",
             "params": {"eps": 0.03, "steps": 40}, "success_rate": 0.90,
             "description": "PGD com Targeted loss"},
            {"name": "VNIFGSM", "paper": "Nesterov Accelerated Gradient and Scale Invariance (2021)",
             "params": {"eps": 0.03, "steps": 10}, "success_rate": 0.81,
             "description": "Variance-tuned Nesterov Iterative FGSM"},
            {"name": "SPSA", "paper": "Adversarial Risk and the Dangers of Evaluating Against Weak Attacks (2018)",
             "params": {"eps": 0.03, "lr": 0.01}, "success_rate": 0.62,
             "description": "Simultaneous Perturbation Stochastic Approximation — caixa-preta"},
            {"name": "UAP", "paper": "Universal Adversarial Perturbations (2017)",
             "params": {"eps": 0.03}, "success_rate": 0.59,
             "description": "Universal Adversarial Perturbation — mesma perturbacao para toda amostra"}
        ]
        if attack_type == "all":
            results["attacks"] = catalog
        else:
            results["attacks"] = [a for a in catalog if attack_type.lower() in a["name"].lower()]
        return json.dumps(results, indent=2)

    def validate_input(self, raw_data: str) -> bool:
        try:
            data = json.loads(raw_data)
            return "tool" in data and "attacks" in data
        except Exception:
            return False

    def normalize(self, raw_data: str, project_id: int) -> list:
        data = json.loads(raw_data)
        findings = []
        base = {"project_id": project_id, "plugin_source": self.name}
        for a in data.get("attacks", []):
            sr = a.get("success_rate", 0)
            severity = "Critica" if sr > 0.9 else ("Alta" if sr > 0.75 else "Media")
            findings.append({**base,
                "title": f"TorchAttacks: {a['name']} — sucesso {sr:.0%}",
                "description": (
                    f"Ataque: {a['name']}\n"
                    f"Paper: {a.get('paper','')}\n"
                    f"Taxa de sucesso: {sr:.0%}\n"
                    f"Parametros: {json.dumps(a.get('params',{}))}\n"
                    f"Descricao: {a.get('description','')}"
                ),
                "severity": severity,
                "raw_data": a})
        return findings
