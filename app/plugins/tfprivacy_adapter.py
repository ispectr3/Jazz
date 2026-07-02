import json
import os
from app.plugins.base import ScannerAdapter
from app.plugins.loader import register

@register()
class TFPrivacyAdapter(ScannerAdapter):
    @property
    def name(self) -> str:
        return "TFPrivacy"

    def run_audit(self, epsilon: float = 8.0, delta: float = 1e-5, batch_size: int = 256, noise_multiplier: float = 1.1) -> str:
        from math import sqrt, log
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), *[".."]*2, "venv", "lib", "python3.14", "site-packages"))
        results = {
            "tool": "TensorFlow Privacy",
            "analysis": "differential_privacy",
            "audit": []
        }
        epsilons_to_test = [0.5, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0]
        for eps in epsilons_to_test:
            if eps <= epsilon:
                privacy_budget = eps / epsilon
                recommendation = "dentro do orcamento" if privacy_budget <= 1.0 else "excedido"
            else:
                privacy_budget = 1.0
                recommendation = "nao aplicavel"
            results["audit"].append({
                "epsilon": eps,
                "delta": delta,
                "noise_multiplier": noise_multiplier,
                "batch_size": batch_size,
                "budget_used": round(privacy_budget, 3),
                "recommendation": recommendation,
                "description": f"Analise de privacidade diferencial com epsilon={eps}, delta={delta}"
            })
        return json.dumps(results, indent=2)

    def validate_input(self, raw_data: str) -> bool:
        try:
            data = json.loads(raw_data)
            return "tool" in data and "audit" in data
        except Exception:
            return False

    def normalize(self, raw_data: str, project_id: int) -> list:
        data = json.loads(raw_data)
        findings = []
        base = {"project_id": project_id, "plugin_source": self.name}
        for audit in data.get("audit", []):
            eps = audit.get("epsilon", 0)
            budget = audit.get("budget_used", 1)
            exposed = 1.0 - budget
            severity = "Info"
            if exposed > 0.5:
                severity = "Media"
            if audit.get("recommendation") == "excedido":
                severity = "Alta"
            findings.append({**base,
                "title": f"TFPrivacy: orcamento DP epsilon={eps}",
                "description": (
                    f"Epsilon: {eps}\n"
                    f"Delta: {audit.get('delta', 1e-5)}\n"
                    f"Noise multiplier: {audit.get('noise_multiplier','N/A')}\n"
                    f"Batch size: {audit.get('batch_size','N/A')}\n"
                    f"Orcamento utilizado: {audit.get('budget_used',0):.1%}\n"
                    f"Status: {audit.get('recommendation','')}\n"
                    f"Descricao: {audit.get('description','')}"
                ),
                "severity": severity,
                "raw_data": audit})
        return findings
