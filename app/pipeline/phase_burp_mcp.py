import json
import os
import shutil
import subprocess
import urllib.request
import urllib.error
from .engine import PipelinePhase


BURP_JAR = shutil.which("burpsuite") or os.environ.get("BURP_JAR", "")
BURP_REST_URL = os.environ.get("BURP_REST_URL", "http://127.0.0.1:1337")
BURP_API_KEY = os.environ.get("BURP_API_KEY", "")


class BurpMCPPhase(PipelinePhase):
    name = "burp_mcp"
    description = "Burp Suite MCP: scan ativo via REST API, analise de trafego, scanner de vulnerabilidades"

    async def run(self, ctx):
        if not self._burp_available():
            self._add_fallback_guide(ctx)
            return ctx

        base_url = f"https://{ctx.target}"

        self._start_burp_headless()

        scan_id = self._start_scan(base_url)
        if not scan_id:
            return ctx

        issues = self._wait_and_get_issues(scan_id)
        if issues:
            self._add_burp_findings(ctx, issues)

        self._add_burp_guide(ctx, issues)

        return ctx

    def _burp_available(self) -> bool:
        if BURP_JAR:
            return True
        try:
            req = urllib.request.Request(f"{BURP_REST_URL}/health", method="GET")
            resp = urllib.request.urlopen(req, timeout=3)
            return resp.status == 200
        except Exception:
            return False

    def _start_burp_headless(self):
        if not BURP_JAR or not os.path.exists(BURP_JAR):
            return

        try:
            req = urllib.request.Request(f"{BURP_REST_URL}/health", method="GET")
            urllib.request.urlopen(req, timeout=2)
            return
        except Exception:
            pass

        try:
            subprocess.Popen(
                ["java", "-jar", BURP_JAR, "--rest-api", "--port=1337"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except Exception:
            pass

    def _start_scan(self, url: str) -> str | None:
        try:
            payload = json.dumps({
                "urls": [url],
                "scope": {"include": [{"rule": f".*{url.replace('https://', '').replace('http://', '')}.*"}]},
                "scan_configurations": [{"name": "Crawl and Audit"}],
            }).encode()
            headers = {"Content-Type": "application/json"}
            if BURP_API_KEY:
                headers["Authorization"] = f"Bearer {BURP_API_KEY}"

            req = urllib.request.Request(
                f"{BURP_REST_URL}/v0.1/scan",
                data=payload, headers=headers, method="POST",
            )
            resp = urllib.request.urlopen(req, timeout=30)
            data = json.loads(resp.read().decode())
            return data.get("scan_id")
        except Exception:
            return None

    def _wait_and_get_issues(self, scan_id: str) -> list[dict]:
        import time

        max_wait = 300
        poll_interval = 10

        for _ in range(max_wait // poll_interval):
            try:
                req = urllib.request.Request(
                    f"{BURP_REST_URL}/v0.1/scan/{scan_id}",
                    headers={"Authorization": f"Bearer {BURP_API_KEY}"} if BURP_API_KEY else {},
                )
                resp = urllib.request.urlopen(req, timeout=10)
                data = json.loads(resp.read().decode())
                status = data.get("status", "")

                if status == "succeeded":
                    return self._get_issues(scan_id)
                elif status in ("failed", "cancelled"):
                    return []
            except Exception:
                pass
            time.sleep(poll_interval)

        return []

    def _get_issues(self, scan_id: str) -> list[dict]:
        try:
            req = urllib.request.Request(
                f"{BURP_REST_URL}/v0.1/scan/{scan_id}/issues",
                headers={"Authorization": f"Bearer {BURP_API_KEY}"} if BURP_API_KEY else {},
            )
            resp = urllib.request.urlopen(req, timeout=15)
            return json.loads(resp.read().decode())
        except Exception:
            return []

    def _add_burp_findings(self, ctx, issues: list[dict]):
        project_id = ctx.project_id
        base = {"project_id": project_id, "plugin_source": "BurpSuite"}
        findings = []

        for issue in issues:
            severity_map = {
                "high": "Alta", "medium": "Media", "low": "Baixa",
                "information": "Info", "false positive": "Info",
            }
            severity = severity_map.get(
                issue.get("severity", "").lower(), "Media"
            )

            findings.append({**base,
                "title": f"Burp: {issue.get('name', 'Issue')}",
                "description": (
                    f"{issue.get('description', '')}\n"
                    f"Path: {issue.get('path', 'N/A')}\n"
                    f"Confidence: {issue.get('confidence', 'N/A')}"
                ),
                "severity": severity,
                "raw_data": issue,
            })

        if findings:
            ctx.modules_findings["BurpSuite"] = findings

    def _add_burp_guide(self, ctx, issues: list[dict]):
        guide = getattr(ctx, "exploitation_guide", [])
        if not isinstance(guide, list):
            guide = []

        base_url = f"https://{ctx.target}"

        guide.append({
            "finding": "Burp Suite Manual Testing",
            "type": "web",
            "curl_command": f"burpsuite {base_url}",
            "payload": "",
            "exploit_steps": [
                "Configure o navegador com proxy Burp (127.0.0.1:8080)",
                "Intercepte requisicoes e envie ao Repeater",
                "Use o Intruder para brute-force de parametros",
                "Analise respostas no Repeater/Decoder",
                "Use o Scanner para varredura automatica",
            ],
            "references": ["https://portswigger.net/burp/documentation"],
        })

        ctx.exploitation_guide = guide

    def _add_fallback_guide(self, ctx):
        guide = getattr(ctx, "exploitation_guide", [])
        if not isinstance(guide, list):
            guide = []

        base_url = f"https://{ctx.target}"
        guide.append({
            "finding": "Burp Suite (nao disponivel)",
            "type": "web",
            "curl_command": f"curl -v {base_url}/",
            "payload": "",
            "exploit_steps": [
                "Burp Suite nao encontrado no PATH",
                "Instale: brew install --cask burp-suite",
                "Alternativa: use ZAP (zaproxy) ou OWASP ZAP",
                "Proxy manual: mitmproxy ou Charles Proxy",
            ],
            "references": ["https://portswigger.net/burp/communitydownload"],
        })

        ctx.exploitation_guide = guide
