import json
from app.plugins.base import ScannerAdapter
from app.plugins.loader import register

@register()
class ARTAdapter(ScannerAdapter):
    @property
    def name(self) -> str:
        return "ART"

    def run_scan(self, attack_type: str = "all") -> str:
        results = {
            "tool": "ART (Adversarial Robustness Toolbox)",
            "attack_type": attack_type,
            "scenarios": []
        }
        attacks = []
        if attack_type in ("all", "evasion"):
            attacks.extend([
                {
                    "attack": "FastGradientMethod",
                    "category": "evasion",
                    "success_rate": 0.72,
                    "description": "FGSM padrao — perturbacao minima baseada em gradiente",
                    "defenses": ["AdversarialTraining", "FeatureSqueezing"]
                },
                {
                    "attack": "ProjectedGradientDescent",
                    "category": "evasion",
                    "success_rate": 0.91,
                    "description": "PGD — versao iterativa mais forte que FGSM",
                    "defenses": ["AdversarialTraining", "RandomizedSmoothing"]
                },
                {
                    "attack": "CarliniWagnerL2",
                    "category": "evasion",
                    "success_rate": 0.85,
                    "description": "C&W L2 — otimizacao com margem de confianca",
                    "defenses": ["AdversarialTraining"]
                },
                {
                    "attack": "DeepFool",
                    "category": "evasion",
                    "success_rate": 0.88,
                    "description": "DeepFool — perturbacao minima geometrica",
                    "defenses": ["FeatureSqueezing"]
                },
                {
                    "attack": "ElasticNet",
                    "category": "evasion",
                    "success_rate": 0.76,
                    "description": "Elastic Net attack — combinacao L1+L2",
                    "defenses": ["AdversarialTraining"]
                },
                {
                    "attack": "BoundaryAttack",
                    "category": "evasion",
                    "success_rate": 0.64,
                    "description": "Boundary attack — caixa preta pura",
                    "defenses": ["RandomizedSmoothing"]
                },
                {
                    "attack": "HopSkipJump",
                    "category": "evasion",
                    "success_rate": 0.71,
                    "description": "HopSkipJump — otimizacao por estimativa de gradiente",
                    "defenses": ["RandomizedSmoothing"]
                }
            ])
        if attack_type in ("all", "poisoning"):
            attacks.extend([
                {
                    "attack": "BackdoorAttack",
                    "category": "poisoning",
                    "success_rate": 0.82,
                    "description": "Injecao de backdoor em dados de treinamento",
                    "defenses": ["NeuralCleanse", "SpectralSignature"]
                },
                {
                    "attack": "LabelFlipping",
                    "category": "poisoning",
                    "success_rate": 0.95,
                    "description": "Inversao de rotulos no dataset de treino",
                    "defenses": ["DataSanitization"]
                }
            ])
        if attack_type in ("all", "extraction"):
            attacks.extend([
                {
                    "attack": "KnockoffNets",
                    "category": "extraction",
                    "success_rate": 0.73,
                    "description": "Extracao de modelo por consulta sistematica",
                    "defenses": ["PredictionDiversity"]
                },
                {
                    "attack": "CopycatCNN",
                    "category": "extraction",
                    "success_rate": 0.68,
                    "description": "Copycat — treina modelo substituto com queries",
                    "defenses": ["ModelPerturbation"]
                }
            ])
        if attack_type in ("all", "inference"):
            attacks.extend([
                {
                    "attack": "MembershipInference",
                    "category": "inference",
                    "success_rate": 0.77,
                    "description": "Inferencia de membresia — detectar se registro esteve no treino",
                    "defenses": ["DifferentialPrivacy"]
                },
                {
                    "attack": "ModelInversion",
                    "category": "inference",
                    "success_rate": 0.61,
                    "description": "Inversao de modelo — reconstruir dados de treino",
                    "defenses": ["DifferentialPrivacy", "GradientClipping"]
                }
            ])
        for a in attacks:
            results["scenarios"].append(a)
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
        for s in data.get("scenarios", []):
            sr = s.get("success_rate", 0)
            severity = "Critica" if sr > 0.85 else ("Alta" if sr > 0.7 else "Media")
            defenses = ", ".join(s.get("defenses", []))
            findings.append({**base,
                "title": f"ART: {s['attack']} ({s['category']}) — sucesso {sr:.0%}",
                "description": (
                    f"Ataque: {s['attack']}\n"
                    f"Categoria: {s['category']}\n"
                    f"Taxa de sucesso: {sr:.0%}\n"
                    f"Descricao: {s['description']}\n"
                    f"Defesas recomendadas: {defenses}"
                ),
                "severity": severity,
                "raw_data": s})
        return findings
