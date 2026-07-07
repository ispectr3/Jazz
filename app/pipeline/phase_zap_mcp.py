import json
import os
import shutil
import subprocess
import time
import urllib.request
import urllib.error
from .engine import PipelinePhase


ZAP_CMD = (
    shutil.which("zap.sh")
    or shutil.which("zap")
    or (os.path.exists("/Applications/ZAP.app/Contents/Java/zap.sh") and "/Applications/ZAP.app/Contents/Java/zap.sh")
    or ""
)
ZAP_PORT = int(os.environ.get("ZAP_PORT", "8081"))
ZAP_API_KEY = os.environ.get("ZAP_API_KEY", "")
ZAP_BASE = f"http://127.0.0.1:{ZAP_PORT}"


class ZAPMCPPhase(PipelinePhase):
    name = "zap_mcp"
    description = "OWASP ZAP: scan ativo via REST API, spider + ascan, coleta de alerts"

    async def run(self, ctx):
        if not self._zap_available():
            self._add_fallback_guide(ctx)
            return ctx

        base_url = f"https://{ctx.target}"

        self._start_zap_headless()

        if not self._wait_for_zap():
            self._add_fallback_guide(ctx)
            return ctx

        spider_id = self._start_spider(base_url)
        if spider_id:
            self._wait_for_scan("spider", spider_id)

        ascan_id = self._start_active_scan(base_url)
        if ascan_id:
            self._wait_for_scan("ascan", ascan_id)

        alerts = self._get_alerts(base_url)
        if alerts:
            self._add_zap_findings(ctx, alerts)

        self._add_zap_guide(ctx, alerts)

        return ctx

    def _zap_available(self) -> bool:
        if ZAP_CMD:
            return True
        try:
            req = urllib.request.Request(f"{ZAP_BASE}/JSON/core/view/version/", method="GET")
            resp = urllib.request.urlopen(req, timeout=3)
            return resp.status == 200
        except Exception:
            return False

    def _start_zap_headless(self):
        if not ZAP_CMD:
            return

        try:
            req = urllib.request.Request(f"{ZAP_BASE}/JSON/core/view/version/", method="GET")
            urllib.request.urlopen(req, timeout=2)
            return
        except Exception:
            pass

        try:
            subprocess.Popen(
                [ZAP_CMD, "-daemon", "-host", "127.0.0.1", "-port", str(ZAP_PORT),
                 "-config", f"api.key={ZAP_API_KEY or 'changeme'}",
                 "-config", "api.disablekey=true" if not ZAP_API_KEY else "",
                 "-config", "spider.maxDuration=5",
                 "-config", "ascan.maxDuration=10"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except Exception:
            pass

    def _wait_for_zap(self, timeout: int = 60) -> bool:
        for _ in range(timeout):
            try:
                req = urllib.request.Request(
                    f"{ZAP_BASE}/JSON/core/view/version/",
                    headers={"X-ZAP-API-Key": ZAP_API_KEY} if ZAP_API_KEY else {},
                )
                urllib.request.urlopen(req, timeout=2)
                return True
            except Exception:
                time.sleep(1)
        return False

    def _api_call(self, path: str, max_retries: int = 2) -> dict | None:
        url = f"{ZAP_BASE}/JSON/{path}"
        if ZAP_API_KEY:
            sep = "&" if "?" in path else "?apikey="
            url += f"{sep}{ZAP_API_KEY}"
        for _ in range(max_retries):
            try:
                req = urllib.request.Request(url, method="GET")
                resp = urllib.request.urlopen(req, timeout=30)
                return json.loads(resp.read().decode())
            except Exception:
                time.sleep(2)
        return None

    def _start_spider(self, url: str) -> str | None:
        data = self._api_call(f"spider/action/scan/?url={urllib.request.quote(url, safe='')}")
        if data and "scan" in data:
            return data["scan"]
        return None

    def _start_active_scan(self, url: str) -> str | None:
        data = self._api_call(f"ascan/action/scan/?url={urllib.request.quote(url, safe='')}&recurse=true")
        if data and "scan" in data:
            return data["scan"]
        return None

    def _wait_for_scan(self, scan_type: str, scan_id: str, timeout: int = 300):
        endpoint = {
            "spider": f"spider/view/status/?scanId={scan_id}",
            "ascan": f"ascan/view/status/?scanId={scan_id}",
        }.get(scan_type)

        if not endpoint:
            return

        for _ in range(timeout // 2):
            data = self._api_call(endpoint)
            if data:
                status = data.get("status", "0")
                if status == "100":
                    return
            time.sleep(2)

    def _get_alerts(self, url: str) -> list[dict]:
        data = self._api_call(
            f"alert/view/alerts/?baseurl={urllib.request.quote(url, safe='')}&start=0&count=100"
        )
        if data and "alerts" in data:
            return data["alerts"]
        return []

    def _add_zap_findings(self, ctx, alerts: list[dict]):
        project_id = ctx.project_id
        base = {"project_id": project_id, "plugin_source": "ZAP"}
        findings = []

        for alert in alerts:
            risk_map = {
                "0": "Info", "1": "Baixa", "2": "Media",
                "3": "Alta", "High": "Alta", "Medium": "Media",
                "Low": "Baixa", "Informational": "Info",
            }
            risk = alert.get("risk", "0")
            severity = risk_map.get(str(risk), risk_map.get(risk, "Media"))

            findings.append({**base,
                "title": f"ZAP: {alert.get('alert', 'Alert')}",
                "description": (
                    f"URL: {alert.get('url', '')}\n"
                    f"Param: {alert.get('param', 'N/A')}\n"
                    f"Solution: {alert.get('solution', 'N/A')[:200]}"
                ),
                "severity": severity,
                "raw_data": alert,
            })

        if findings:
            ctx.modules_findings["ZAP"] = findings

    def _add_zap_guide(self, ctx, alerts: list[dict]):
        guide = getattr(ctx, "exploitation_guide", [])
        if not isinstance(guide, list):
            guide = []

        total_alerts = len(alerts)
        high = sum(1 for a in alerts if str(a.get("risk", "0")) in ("3", "High"))

        guide.append({
            "finding": f"OWASP ZAP Scan: {total_alerts} alerts ({high} high)",
            "type": "web",
            "curl_command": f"zap.sh -daemon -port 8081",
            "payload": "",
            "exploit_steps": [
                f"ZAP encontrou {total_alerts} alerts em {ctx.target}",
                f"{high} de alta severidade — revisar com urgencia",
                "Conecte no ZAP UI: http://127.0.0.1:8081/zap/",
                "Use o Repeater manual para confirmar cada alerta",
            ],
            "references": [
                "https://www.zaproxy.org/docs/",
                "https://github.com/zaproxy/zaproxy",
            ],
        })

        ctx.exploitation_guide = guide

    def _add_fallback_guide(self, ctx):
        guide = getattr(ctx, "exploitation_guide", [])
        if not isinstance(guide, list):
            guide = []

        guide.append({
            "finding": "OWASP ZAP (nao disponivel)",
            "type": "web",
            "curl_command": "brew install --cask zap",
            "payload": "",
            "exploit_steps": [
                "ZAP nao encontrado no PATH",
                "Instale: brew install --cask zap",
                "Rode: /Applications/ZAP.app/Contents/Java/zap.sh -daemon -port 8081",
                "Ou use via UI: open -a ZAP",
            ],
            "references": ["https://www.zaproxy.org/download/"],
        })

        ctx.exploitation_guide = guide
