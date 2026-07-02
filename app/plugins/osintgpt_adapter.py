import json
import os
from app.plugins.base import ScannerAdapter
from app.plugins.loader import register


@register()
class OsintGptAdapter(ScannerAdapter):
    @property
    def name(self) -> str:
        return "OsintGPT"

    def validate_input(self, raw_data: str) -> bool:
        try:
            data = json.loads(raw_data)
            return any(k in data for k in ["results", "analysis", "findings", "embeddings"])
        except Exception:
            return False

    def normalize(self, raw_data: str, project_id: int) -> list:
        data = json.loads(raw_data)
        findings = []
        base = {"project_id": project_id, "plugin_source": self.name}

        results = data.get("results", data.get("analysis", data.get("findings", [data])))
        if isinstance(results, dict):
            results = [results]

        for item in results:
            if isinstance(item, dict):
                findings.append(self._parse_item(item, base))

        return findings

    def _parse_item(self, item: dict, base: dict) -> dict:
        title = item.get("title") or item.get("query") or item.get("topic", "OSINT Analysis")
        description = item.get("description") or item.get("summary") or item.get("result", "")
        severity_raw = item.get("severity", "Info")
        sev_map = {"critical": "Crítica", "high": "Alta", "medium": "Média",
                    "low": "Baixa", "info": "Info"}
        severity = sev_map.get(severity_raw.lower(), "Info")

        if "score" in item or "confidence" in item:
            score = item.get("score") or item.get("confidence", 0)
            description += f"\nConfidence Score: {score}"

        if "source" in item:
            description += f"\nSource: {item['source']}"

        return {**base,
            "title": title,
            "description": description,
            "severity": severity,
            "raw_data": item}
