import json
import subprocess
import tempfile
import os
from app.plugins.base import ScannerAdapter
from app.plugins.loader import register

@register()
class GarakAdapter(ScannerAdapter):
    @property
    def name(self) -> str:
        return "Garak"

    def run_scan(self, model_type: str, model_name: str, probes: list = None) -> str:
        target = f"--model-type {model_type} --model-name {model_name}"
        probe_arg = ""
        if probes:
            probe_arg = " ".join(f"--probes {p}" for p in probes)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            fname = f.name
        try:
            result = subprocess.run(
                f"garak {target} {probe_arg} --report-output {fname} 2>&1",
                shell=True, capture_output=True, text=True, timeout=300
            )
            if os.path.exists(fname):
                with open(fname) as f:
                    return f.read()
            return json.dumps({"model": model_name, "error": result.stderr[:500]})
        except subprocess.TimeoutExpired:
            return json.dumps({"model": model_name, "error": "timeout"})
        finally:
            if os.path.exists(fname):
                os.unlink(fname)

    def validate_input(self, raw_data: str) -> bool:
        try:
            data = json.loads(raw_data)
            if "error" in data:
                return False
            return "model" in data
        except Exception:
            return False

    def normalize(self, raw_data: str, project_id: int) -> list:
        data = json.loads(raw_data)
        findings = []
        base = {"project_id": project_id, "plugin_source": self.name}
        model = data.get("model", "unknown")
        for probe_name, probe_data in data.get("probes", {}).items():
            for hit in probe_data.get("hits", []):
                findings.append({**base,
                    "title": f"Garak: {hit.get('probe_category','Unknown')}",
                    "description": (
                        f"Modelo: {model}\n"
                        f"Probe: {probe_name}\n"
                        f"Tipo: {hit.get('probe_category','')}\n"
                        f"Payload: {hit.get('payload','')[:200]}\n"
                        f"Resposta: {hit.get('response','')[:200]}"
                    ),
                    "severity": "Critica" if hit.get("severity") == "HIGH" else "Alta",
                    "raw_data": hit})
        return findings
