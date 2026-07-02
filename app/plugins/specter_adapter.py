import json
import os
import subprocess
import importlib
import pkgutil
from app.plugins.base import ScannerAdapter
from app.plugins.loader import register


@register()
class SPECTERAdapter(ScannerAdapter):
    @property
    def name(self) -> str:
        return "SPECTER"

    def validate_input(self, raw_data: str) -> bool:
        try:
            data = json.loads(raw_data)
            return isinstance(data, list) or "scanner" in str(data).lower()
        except Exception:
            return False

    def normalize(self, raw_data: str, project_id: int) -> list:
        data = json.loads(raw_data)
        findings = []
        base = {"project_id": project_id, "plugin_source": self.name}

        if isinstance(data, list):
            for item in data:
                finding = self._parse_finding(item, base)
                if finding:
                    findings.append(finding)
        elif isinstance(data, dict):
            if "results" in data:
                for item in data["results"]:
                    finding = self._parse_finding(item, base)
                    if finding:
                        findings.append(finding)
            else:
                finding = self._parse_finding(data, base)
                if finding:
                    findings.append(finding)

        return findings

    def _parse_finding(self, item: dict, base: dict) -> dict:
        title = item.get("title") or item.get("name") or "Unknown Issue"
        description = item.get("description") or item.get("details") or ""
        severity_raw = item.get("severity", "Média")
        severity = self._map_severity(severity_raw)
        module = item.get("module") or item.get("source") or ""

        if module:
            title = f"[{module}] {title}"

        return {**base,
            "title": title,
            "description": description,
            "severity": severity,
            "raw_data": item}

    def _map_severity(self, sev: str) -> str:
        mapping = {
            "critical": "Crítica", "high": "Alta", "medium": "Média",
            "low": "Baixa", "info": "Info",
            "critico": "Crítica", "alto": "Alta", "medio": "Média", "baixo": "Baixa"
        }
        return mapping.get(sev.strip().lower(), "Média")

    def run_scan(self, target: str) -> str:
        tool_dir = os.path.join(os.getcwd(), '.tools', 'SPECTER')
        modules_path = os.path.join(tool_dir, "modules")
        sys_path_backup = list(__import__("sys").path)

        try:
            __import__("sys").path.insert(0, tool_dir)
            modules = []
            for _, name, _ in pkgutil.iter_modules([modules_path]):
                mod = importlib.import_module(f"modules.{name}")
                for attr in dir(mod):
                    obj = getattr(mod, attr)
                    if isinstance(obj, type) and hasattr(obj, "run"):
                        if getattr(obj, "__module__", "").startswith("modules."):
                            modules.append(obj)

            from core.scanner import Scanner
            scanner = Scanner(target)
            results = []
            for mod_cls in modules:
                try:
                    result = scanner.run_module(mod_cls)
                    if result:
                        results.append(result)
                except Exception:
                    pass

            return json.dumps(results, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})
        finally:
            __import__("sys").path = sys_path_backup
