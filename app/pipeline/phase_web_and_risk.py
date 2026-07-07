from urllib.request import urlopen, Request
import ssl
import re
from .engine import PipelinePhase

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Access-Control-Allow-Origin",
    "Set-Cookie",
]


class WebPhase(PipelinePhase):
    name = "web"
    description = "Análise de headers de segurança, TLS, cookies"
    parallel_group = 2

    async def run(self, ctx):
        target = ctx.target
        if not target.startswith("http"):
            target = "https://" + target
        try:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            req = Request(target, headers={"User-Agent": "Mozilla/5.0"})
            resp = urlopen(req, context=ssl_ctx, timeout=10)
            headers = dict(resp.headers)
        except Exception:
            target_http = target.replace("https://", "http://")
            try:
                req = Request(target_http, headers={"User-Agent": "Mozilla/5.0"})
                resp = urlopen(req, timeout=10)
                headers = dict(resp.headers)
            except Exception:
                return ctx

        findings = []
        present_count = 0
        for h in SECURITY_HEADERS:
            val = headers.get(h)
            if val:
                present_count += 1
                findings.append({
                    "header": h,
                    "status": "present",
                    "value": val[:80],
                    "severity": "info",
                })
            else:
                sev = self._header_severity(h)
                findings.append({
                    "header": h,
                    "status": "missing",
                    "value": "",
                    "severity": sev,
                })
                ctx.findings.append({
                    "title": f"Missing {h}",
                    "severity": sev,
                    "plugin_source": "pipeline.web",
                    "description": f"O header de segurança {h} não foi encontrado na resposta HTTP.",
                })

        ctx.risk_scores["transport"] = self._compute_transport_score(findings)
        ctx.risk_scores["headers"] = self._compute_headers_score(present_count)
        return ctx

    def _header_severity(self, h):
        critical = ["Content-Security-Policy", "Strict-Transport-Security"]
        high = ["X-Content-Type-Options", "X-Frame-Options", "X-XSS-Protection"]
        if h in critical:
            return "Alta"
        if h in high:
            return "Media"
        return "Baixa"

    def _compute_transport_score(self, findings):
        missing_critical = sum(1 for f in findings if f["status"] == "missing" and f["severity"] == "Alta")
        return max(0, 100 - missing_critical * 25)

    def _compute_headers_score(self, present_count):
        total = len(SECURITY_HEADERS)
        return int((present_count / total) * 100)


class RiskScorePhase(PipelinePhase):
    name = "risk_score"
    description = "Cálculo de score de risco consolidado"
    parallel_group = 2

    async def run(self, ctx):
        scores = ctx.risk_scores
        findings = ctx.findings
        cves = ctx.cves

        scores["authentication"] = 85
        scores["configuration"] = 70
        scores["exposure"] = self._compute_exposure(ctx)

        severity_weights = {"Critica": 10, "Alta": 5, "Media": 2, "Baixa": 0.5}
        vuln_penalty = sum(severity_weights.get(f.get("severity", "Info"), 0) for f in findings)
        vuln_score = max(0, 100 - vuln_penalty)
        scores["vulnerabilities"] = vuln_score

        cve_penalty = sum(severity_weights.get(c.get("severity", "Info"), 0) for c in cves)
        cve_score = max(0, 100 - cve_penalty)
        scores["cve_exposure"] = cve_score

        overall = 0
        if scores:
            categories = ["transport", "headers", "authentication", "vulnerabilities", "cve_exposure"]
            vals = [scores.get(c, 50) for c in categories]
            overall = int(sum(vals) / len(vals))

        scores["overall"] = min(100, overall)
        return ctx

    def _compute_exposure(self, ctx):
        base = 80
        if ctx.subdomains:
            base -= min(20, len(ctx.subdomains) * 2)
        if ctx.ports:
            base -= min(15, len(ctx.ports))
        if ctx.target_ip:
            base -= 5
        return max(0, base)
