import json
import os
import subprocess
from app.plugins.base import ScannerAdapter
from app.plugins.loader import register


@register()
class WasminatorAdapter(ScannerAdapter):
    @property
    def name(self) -> str:
        return "Wasminator"

    def validate_input(self, raw_data: str) -> bool:
        try:
            data = json.loads(raw_data)
            return "findings" in data or "modules" in data or "riskScore" in data
        except Exception:
            return False

    def normalize(self, raw_data: str, project_id: int) -> list:
        data = json.loads(raw_data)
        findings = []
        base = {"project_id": project_id, "plugin_source": self.name}

        target = data.get("target", "unknown")
        risk_score = data.get("riskScore", 0)
        summary = data.get("summary", {})

        for f in data.get("findings", []):
            severity = self._map_severity(f.get("severity", "MEDIUM"))
            module = f.get("module", "unknown")

            findings.append({**base,
                "title": f"WASM {f.get('type', 'Issue')}: {module}",
                "description": (
                    f"Module: {module}\n"
                    f"Type: {f.get('type', 'N/A')}\n"
                    f"Confidence: {f.get('confidence', 'MEDIUM')}\n"
                    f"Details: {f.get('details', '')}\n"
                    f"CVE: {f.get('cve', 'N/A')}"
                ),
                "severity": severity,
                "raw_data": f})

        for m in data.get("modules", []):
            url = m.get("url", "unknown")
            risk = m.get("riskLevel", "SAFE")
            trust = m.get("trustScore", 0)
            context = ", ".join(m.get("context", []))
            m_findings = m.get("findings", [])

            if m_findings:
                for mf in m_findings:
                    sev = self._map_severity(mf.get("severity", "MEDIUM"))
                    findings.append({**base,
                        "title": f"WASM Module Issue: {mf.get('type', 'Issue')}",
                        "description": (
                            f"Module URL: {url}\n"
                            f"Risk: {risk} (Score: {trust})\n"
                            f"Context: {context}\n"
                            f"Details: {mf.get('details', '')}"
                        ),
                        "severity": sev,
                        "raw_data": {**mf, "module_url": url}})

            findings.append({**base,
                "title": f"WASM Module: {url.split('/')[-1]}",
                "description": (
                    f"URL: {url}\n"
                    f"Size: {m.get('size', 0)} bytes\n"
                    f"Risk: {risk} (Trust Score: {trust})\n"
                    f"Context: {context}"
                ),
                "severity": "Info",
                "raw_data": m})

        findings.append({**base,
            "title": f"Wasminator Scan Summary: {target}",
            "description": (
                f"Target: {target}\n"
                f"Risk Score: {risk_score}/100\n"
                f"Critical: {summary.get('critical', 0)}\n"
                f"High: {summary.get('high', 0)}\n"
                f"Medium: {summary.get('medium', 0)}\n"
                f"Low: {summary.get('low', 0)}\n"
                f"Modules: {data.get('modules', [])}"
            ),
            "severity": "Info",
            "raw_data": summary})

        return findings

    def _map_severity(self, sev: str) -> str:
        mapping = {
            "CRITICAL": "Crítica", "HIGH": "Alta", "MEDIUM": "Média",
            "LOW": "Baixa", "SAFE": "Info",
        }
        return mapping.get(sev.upper(), "Média")

    def run_scan(self, target_url: str) -> str:
        tool_dir = os.path.join(os.getcwd(), '.tools', 'wasminator')
        cmd = ["node", "wasminator.js", "scan", target_url, "--format", "json"]
        result = subprocess.run(cmd, cwd=tool_dir, capture_output=True, text=True, timeout=120000)
        return result.stdout
