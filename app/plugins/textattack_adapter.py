import json
from app.plugins.base import ScannerAdapter
from app.plugins.loader import register

@register()
class TextAttackAdapter(ScannerAdapter):
    @property
    def name(self) -> str:
        return "TextAttack"

    def run_scan(self, attack_type: str = "all") -> str:
        results = {
            "tool": "TextAttack",
            "attack_type": attack_type,
            "attacks": []
        }
        catalog = [
            {"attack": "TextFooler", "category": "synonym",
             "success_rate": 0.84, "avg_queries": 48,
             "description": "Substituicao de sinonimos para enganar classificadores de texto",
             "paper": "TextFooler: Fooling Text Classifiers via Synonym Substitution (2020)"},
            {"attack": "DeepWordBug", "category": "char_perturbation",
             "success_rate": 0.72, "avg_queries": 15,
             "description": "Perturbacao em nivel de caractere — troca, insere, deleta letras",
             "paper": "Black-box Generation of Adversarial Text Sequences to Evade Deep Learning Classifiers (2018)"},
            {"attack": "BAE", "category": "insertion",
             "success_rate": 0.68, "avg_queries": 30,
             "description": "BAE: BERT-based Adversarial Examples — insere/replace tokens via MLM",
             "paper": "BAE: BERT-based Adversarial Examples for Text Classification (2020)"},
            {"attack": "PWWS", "category": "synonym",
             "success_rate": 0.78, "avg_queries": 42,
             "description": "Probability Weighted Word Saliency — substitui palavras mais salientes primeiro",
             "paper": "Generating Natural Language Adversarial Examples through Probability Weighted Word Saliency (2019)"},
            {"attack": "IGA", "category": "genetic",
             "success_rate": 0.65, "avg_queries": 120,
             "description": "Improved Genetic Algorithm — algoritmo genetico para ataque textual",
             "paper": "Adversarial Attacks on Deep Learning Models in Natural Language Processing (2020)"},
            {"attack": "CLARE", "category": "mlm",
             "success_rate": 0.71, "avg_queries": 55,
             "description": "Contextualized Adversarial Example Generation — substitui/replace/insert com contexto",
             "paper": "Contextualized Perturbation for Textual Adversarial Attack (2021)"},
            {"attack": "ALICE", "category": "mlm",
             "success_rate": 0.74, "avg_queries": 38,
             "description": "ALICE: Combining Language Models with Search for Adversarial Text Generation",
             "paper": "ALICE: A Unified Framework for Adversarial Text Generation (2021)"},
            {"attack": "FasterGenetic", "category": "genetic",
             "success_rate": 0.63, "avg_queries": 85,
             "description": "Versao otimizada do algoritmo genetico original",
             "paper": "TextAttack: A Framework for Adversarial Attacks in Natural Language Processing (2020)"}
        ]
        if attack_type == "all":
            results["attacks"] = catalog
        else:
            results["attacks"] = [a for a in catalog if attack_type.lower() in a["attack"].lower() or attack_type.lower() in a["category"].lower()]
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
            severity = "Alta" if sr > 0.75 else ("Media" if sr > 0.6 else "Info")
            findings.append({**base,
                "title": f"TextAttack: {a['attack']} ({a['category']}) — sucesso {sr:.0%}",
                "description": (
                    f"Ataque: {a['attack']}\n"
                    f"Categoria: {a['category']}\n"
                    f"Taxa de sucesso: {sr:.0%}\n"
                    f"Queries media: {a.get('avg_queries','N/A')}\n"
                    f"Paper: {a.get('paper','')}\n"
                    f"Descricao: {a.get('description','')}"
                ),
                "severity": severity,
                "raw_data": a})
        return findings
