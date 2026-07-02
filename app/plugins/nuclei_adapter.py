import subprocess, json, os
from datetime import datetime
from app.plugins.base import ScannerAdapter
from app.plugins.loader import register

TEMPLATE_DIR = os.path.expanduser("~/nuclei-templates")

SEVERITY_MAP = {
    "critical": "Critica",
    "high": "Alta",
    "medium": "Media",
    "low": "Baixa",
    "info": "Info",
}

@register()
class NucleiAdapter(ScannerAdapter):
    @property
    def name(self) -> str:
        return "Nuclei"

    def validate_input(self, raw_data: str) -> bool:
        return bool(raw_data.strip())

    def normalize(self, target: str, project_id: int) -> list[dict]:
        findings = []
        raw_findings = self._run_nuclei(target)
        for nf in raw_findings:
            info = nf.get("info", {})
            sev = SEVERITY_MAP.get(nf.get("severity", "").lower(), "Info")
            template_id = nf.get("template-id", "unknown")
            name = info.get("name", f"Nuclei Finding: {template_id}")
            description = info.get("description", "")
            tags = ", ".join(info.get("tags", []))
            remediation = info.get("remediation", "")
            severity_str = nf.get("severity", "info")
            matched_at = nf.get("matched-at", target)
            extracted_results = nf.get("extracted-results", [])

            desc_parts = [f"Template: {template_id}"]
            if description:
                desc_parts.append(f"Descricao: {description}")
            if tags:
                desc_parts.append(f"Tags: {tags}")
            if remediation:
                desc_parts.append(f"Remediacao: {remediation}")
            if extracted_results:
                desc_parts.append(f"Evidencias: {'; '.join(extracted_results[:3])}")
            desc_parts.append(f"Alvo: {matched_at}")

            findings.append({
                "project_id": project_id,
                "plugin_source": self.name,
                "title": f"[Nuclei] {name} ({severity_str.upper()})",
                "description": "\n".join(desc_parts),
                "severity": sev,
                "raw_data": nf,
            })

        if not raw_findings:
            findings.append({
                "project_id": project_id,
                "plugin_source": self.name,
                "title": f"Nuclei Scan: {target}",
                "description": f"Nuclei concluiu a varredura em {target} sem encontrar vulnerabilidades conhecidas nos templates testados.",
                "severity": "Info",
                "raw_data": {"target": target, "templates_loaded": "cve,exposure,misconfig,tech"}
            })

        return findings

    def _run_nuclei(self, target: str) -> list[dict]:
        try:
            url = target if target.startswith("http://") or target.startswith("https://") else f"https://{target}"
            r = subprocess.run(
                [
                    "nuclei", "-u", url,
                    "-j", "-silent",
                    "-c", "15", "-rl", "50",
                    "-timeout", "8", "-retries", "1",
                    "-tags", "cve,exposure,misconfig,config,default-login,tech,vulnerabilities,iot,cnvd,osint",
                ],
                capture_output=True, text=True, timeout=180
            )
            results = []
            for line in r.stdout.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            return results
        except subprocess.TimeoutExpired:
            print(f"[Nuclei] Timeout ao escanear {target}")
            return []
        except Exception as e:
            print(f"[Nuclei] Erro ao escanear {target}: {e}")
            return []
