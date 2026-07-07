import socket
import ssl
import json
import re
from urllib.request import urlopen, Request
from urllib.parse import urlparse

from .engine import PipelinePhase, Pipeline, PipelineContext


class ReconPhase(PipelinePhase):
    name = "recon"
    description = "Reconhecimento: DNS, IP, portas, tecnologias"
    parallel_group = 0

    async def run(self, ctx: PipelineContext) -> PipelineContext:
        target = ctx.target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
        ctx.target = target
        try:
            ctx.target_ip = socket.gethostbyname(target)
        except Exception:
            ctx.target_ip = target
        ctx.domains = [target]
        return ctx


class FingerprintPhase(PipelinePhase):
    name = "fingerprint"
    description = "Detecção de tecnologias via headers + responses"
    parallel_group = 0

    async def run(self, ctx: PipelineContext) -> PipelineContext:
        target = ctx.target
        if not target.startswith("http"):
            target = "https://" + target
        try:
            req = Request(target, headers={"User-Agent": "Mozilla/5.0"})
            resp = urlopen(req, timeout=10)
            headers = dict(resp.headers)
            body = resp.read().decode("utf-8", errors="ignore")[:50000]
            ctx.technologies = self._fingerprint(headers, body)
        except Exception:
            try:
                target_http = target.replace("https://", "http://")
                req = Request(target_http, headers={"User-Agent": "Mozilla/5.0"})
                resp = urlopen(req, timeout=10)
                headers = dict(resp.headers)
                body = resp.read().decode("utf-8", errors="ignore")[:50000]
                ctx.technologies = self._fingerprint(headers, body)
            except Exception:
                pass
        return ctx

    def _fingerprint(self, headers: dict, body: str) -> list:
        techs = []
        server = headers.get("Server", "")
        x_powered = headers.get("X-Powered-By", "")
        set_cookie = headers.get("Set-Cookie", "")

        if "cloudflare" in server.lower() or "cloudflare" in headers.get("CF-Ray", "").lower():
            techs.append({"name": "Cloudflare", "category": "CDN", "version": ""})
        if "nginx" in server.lower():
            v = re.search(r"nginx/([\d.]+)", server)
            techs.append({"name": "Nginx", "category": "Web Server", "version": v.group(1) if v else ""})
        if "apache" in server.lower():
            v = re.search(r"Apache(?:/([\d.]+))?", server)
            techs.append({"name": "Apache", "category": "Web Server", "version": v.group(1) if v else ""})
        if "PHP" in x_powered or "php" in server.lower():
            v = re.search(r"PHP/([\d.]+)", x_powered + " " + server)
            techs.append({"name": "PHP", "category": "Language", "version": v.group(1) if v else ""})
        if "ASP" in x_powered or "ASP" in server or ".asp" in body.lower():
            techs.append({"name": "ASP.NET", "category": "Language", "version": ""})
        if "express" in server.lower() or "express" in x_powered.lower():
            techs.append({"name": "Express", "category": "Framework", "version": ""})
        if "python" in server.lower() or "gunicorn" in server.lower():
            techs.append({"name": "Python", "category": "Language", "version": ""})
        if "react" in body.lower() or "reactjs" in body.lower() or "react.js" in body.lower():
            techs.append({"name": "React", "category": "Frontend", "version": ""})
        if "django" in server.lower() or "csrftoken" in set_cookie.lower():
            techs.append({"name": "Django", "category": "Framework", "version": ""})
        if "wordpress" in body.lower() or "wp-content" in body.lower() or "wp-includes" in body.lower():
            techs.append({"name": "WordPress", "category": "CMS", "version": ""})
        if "laravel" in body.lower() or "laravel_session" in set_cookie.lower():
            techs.append({"name": "Laravel", "category": "Framework", "version": ""})
        if "drupal" in body.lower() or "drupal" in server.lower():
            techs.append({"name": "Drupal", "category": "CMS", "version": ""})
        if "jquery" in body.lower():
            v = re.search(r"jquery[.-]?([\d.]+)", body.lower())
            techs.append({"name": "jQuery", "category": "Library", "version": v.group(1) if v else ""})
        if "bootstrap" in body.lower():
            v = re.search(r"bootstrap[.-]?([\d.]+)", body.lower())
            techs.append({"name": "Bootstrap", "category": "Frontend", "version": v.group(1) if v else ""})
        if "cloudflare" not in [t["name"] for t in techs]:
            for h, v in headers.items():
                if "x-cache" in h.lower() and ("cloud" in v.lower() or "cdn" in v.lower()):
                    techs.append({"name": h.split("-")[-1].title() + " CDN", "category": "CDN", "version": ""})
                    break
        google_ana = re.search(r"googletagmanager\.com|google-analytics\.com|gtag\(", body)
        if google_ana:
            techs.append({"name": "Google Analytics", "category": "Analytics", "version": ""})
        if "node" in server.lower() or "node.js" in server.lower():
            techs.append({"name": "Node.js", "category": "Runtime", "version": ""})
        return techs


class CVEPhase(PipelinePhase):
    name = "cve"
    description = "Busca de CVEs via BNVD + NVD + cache local"
    parallel_group = 1

    async def run(self, ctx: PipelineContext) -> PipelineContext:
        from app.ai.cve_database import query_cves as query_cve_db

        all_cves = []
        seen = set()

        for tech in ctx.technologies:
            name = tech.get("name", "")
            version = tech.get("version", "")
            cves = query_cve_db(name, version)
            for c in cves:
                cid = c.get("id", "")
                if cid and cid not in seen:
                    seen.add(cid)
                    all_cves.append({
                        "id": cid,
                        "description": c.get("description", "")[:200],
                        "score": c.get("score"),
                        "severity": self._score_to_severity(c.get("score")),
                        "tech": name,
                        "version": version,
                    })

        ctx.cves = all_cves[:20]
        return ctx

    def _score_to_severity(self, score):
        if score is None:
            return "Info"
        if score >= 9.0:
            return "Critica"
        if score >= 7.0:
            return "Alta"
        if score >= 4.0:
            return "Media"
        return "Baixa"
