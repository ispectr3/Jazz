import json
import os
import re
import shutil
import subprocess
import urllib.request
from app.plugins.base import ScannerAdapter
from app.plugins.loader import register


WHATWEB_BIN = shutil.which("whatweb")


TECH_SIGNATURES = [
    # ========== CDN / Edge ==========
    {"name": "Cloudflare", "category": "CDN", "headers": {"server": "cloudflare", "cf-ray": ""}},
    {"name": "Cloudflare", "category": "CDN", "cookies": ["__cfduid"]},
    {"name": "Cloudfront", "category": "CDN", "headers": {"server": "cloudfront", "x-amz-cf-id": ""}},
    {"name": "Fastly", "category": "CDN", "headers": {"via": "fastly", "x-fastly-request-id": ""}},
    {"name": "Akamai", "category": "CDN", "headers": {"server": "akamai", "x-akamai": ""}},
    {"name": "KeyCDN", "category": "CDN", "headers": {"server": "keycdn"}},
    {"name": "BunnyCDN", "category": "CDN", "headers": {"server": "bunnycdn|bunny"}},
    {"name": "StackPath", "category": "CDN", "headers": {"server": "stackpath"}},
    {"name": "Imperva", "category": "CDN", "headers": {"server": "imperva|incapsula"}},
    {"name": "Sucuri", "category": "CDN", "headers": {"x-sucuri-id": "", "x-sucuri-cache": ""}},
    {"name": "CDN77", "category": "CDN", "headers": {"server": "cdn77"}},
    # ========== Web Servers ==========
    {"name": "Nginx", "category": "Web Server", "headers": {"server": "nginx"}},
    {"name": "Apache", "category": "Web Server", "headers": {"server": "apache"}},
    {"name": "IIS", "category": "Web Server", "headers": {"server": "iis|microsoft-iis", "x-powered-by": "asp.net"}},
    {"name": "Tomcat", "category": "Web Server", "headers": {"server": "tomcat"}},
    {"name": "Caddy", "category": "Web Server", "headers": {"server": "caddy"}},
    {"name": "OpenResty", "category": "Web Server", "headers": {"server": "openresty"}},
    {"name": "LiteSpeed", "category": "Web Server", "headers": {"server": "litespeed"}},
    {"name": "Traefik", "category": "Web Server", "headers": {"server": "traefik"}},
    {"name": "Envoy", "category": "Web Server", "headers": {"server": "envoy"}},
    {"name": "HAProxy", "category": "Web Server", "headers": {"server": "haproxy"}},
    {"name": "Varnish", "category": "Web Server", "headers": {"server": "varnish", "via": "varnish"}},
    # ========== Languages / Runtimes ==========
    {"name": "PHP", "category": "Language", "headers": {"x-powered-by": "php", "server": "php"}},
    {"name": "ASP.NET", "category": "Language", "headers": {"x-powered-by": "asp.net", "server": "asp.net"}},
    {"name": "Python", "category": "Language", "headers": {"server": "python|gunicorn|uwsgi"}},
    {"name": "Ruby", "category": "Language", "headers": {"server": "phusion|passenger|unicorn"}},
    {"name": "Node.js", "category": "Runtime", "headers": {"server": "node.js|nodejs"}},
    {"name": "Java", "category": "Language", "headers": {"server": "java|jetty|tomcat|jboss|wildfly"}},
    {"name": "Go", "category": "Language", "headers": {"server": "go|golang"}},
    {"name": "Rust", "category": "Language", "headers": {"server": "rust|actix"}},
    {"name": ".NET", "category": "Language", "headers": {"x-powered-by": "express|dotnet|.net"}},
    {"name": "Perl", "category": "Language", "headers": {"server": "perl"}},
    # ========== Frameworks ==========
    {"name": "Express", "category": "Framework", "headers": {"x-powered-by": "express"}},
    {"name": "Django", "category": "Framework", "cookies": ["csrftoken", "django"]},
    {"name": "Django", "category": "Framework", "headers": {"server": "wsgi|gunicorn"}},
    {"name": "Flask", "category": "Framework", "cookies": ["session"], "headers": {"server": "werkzeug"}},
    {"name": "Laravel", "category": "Framework", "cookies": ["laravel_session"]},
    {"name": "Symfony", "category": "Framework", "cookies": ["symfony"]},
    {"name": "Rails", "category": "Framework", "headers": {"server": "passenger"}, "cookies": ["_session"]},
    {"name": "Spring Boot", "category": "Framework", "headers": {"server": "spring|tomcat"}},
    {"name": "Next.js", "category": "Framework", "html": ["next.js", "__next", "_next/static"]},
    {"name": "Nuxt.js", "category": "Framework", "html": ["nuxt"]},
    {"name": "Gatsby", "category": "Framework", "html": ["gatsby"]},
    {"name": "FastAPI", "category": "Framework", "headers": {"server": "uvicorn|fastapi"}},
    {"name": "Koa", "category": "Framework", "headers": {"x-powered-by": "koa"}},
    {"name": "SvelteKit", "category": "Framework", "html": ["sveltekit"]},
    # ========== CMS ==========
    {"name": "WordPress", "category": "CMS", "html": ["wp-content", "wp-includes", "wp-json", "wordpress", "xmlrpc"]},
    {"name": "Drupal", "category": "CMS", "html": ["drupal", "drupal.js"]},
    {"name": "Joomla", "category": "CMS", "html": ["joomla", "com_content", "com_user"]},
    {"name": "Magento", "category": "CMS", "cookies": ["mage", "mage_cache"], "html": ["mage"]},
    {"name": "Shopify", "category": "CMS", "headers": {"x-shopid": "", "x-shopify-stage": ""}},
    {"name": "Wix", "category": "CMS", "html": ["wix", "wix.com"]},
    {"name": "Squarespace", "category": "CMS", "html": ["squarespace"]},
    {"name": "Ghost", "category": "CMS", "html": ["ghost"]},
    {"name": "Confluence", "category": "CMS", "html": ["confluence"]},
    {"name": "HubSpot", "category": "CMS", "html": ["hs-analytics", "hubspot"]},
    {"name": "Webflow", "category": "CMS", "html": ["webflow"]},
    {"name": "TYPO3", "category": "CMS", "html": ["typo3"]},
    {"name": "Umbraco", "category": "CMS", "html": ["umbraco"]},
    {"name": "Duda", "category": "CMS", "html": ["duda"]},
    {"name": "Weebly", "category": "CMS", "html": ["weebly"]},
    # ========== Frontend / UI ==========
    {"name": "React", "category": "Frontend", "html": ["react", "reactjs", "react.js", "__react", "reactroot"]},
    {"name": "Angular", "category": "Frontend", "html": ["angular", "ng-", "ng_"]},
    {"name": "Vue.js", "category": "Frontend", "html": ["vue.js", "vuejs", "v-app", "v-bind", "v-model"]},
    {"name": "Svelte", "category": "Frontend", "html": ["svelte"]},
    {"name": "jQuery", "category": "Library", "html": ["jquery"]},
    {"name": "Bootstrap", "category": "Frontend", "html": ["bootstrap"]},
    {"name": "Tailwind CSS", "category": "Frontend", "html": ["tailwind"]},
    {"name": "Material UI", "category": "Frontend", "html": ["mui", "material-ui"]},
    {"name": "Font Awesome", "category": "Library", "html": ["font-awesome", "fontawesome", "fa-"]},
    {"name": "Alpine.js", "category": "Frontend", "html": ["alpinejs", "x-data"]},
    {"name": "HTMX", "category": "Frontend", "html": ["htmx"]},
    {"name": "GSAP", "category": "Library", "html": ["gsap", "tweenmax"]},
    {"name": "D3.js", "category": "Library", "html": ["d3.js"]},
    {"name": "Chart.js", "category": "Library", "html": ["chart.js"]},
    {"name": "Three.js", "category": "Library", "html": ["three.js"]},
    # ========== Analytics / Monitoring ==========
    {"name": "Google Analytics", "category": "Analytics", "html": ["google-analytics", "gtag", "ga.js", "analytics.js"]},
    {"name": "Facebook Pixel", "category": "Analytics", "html": ["facebook.com/tr", "fbq"]},
    {"name": "Hotjar", "category": "Analytics", "html": ["hotjar"]},
    {"name": "Intercom", "category": "Analytics", "html": ["intercom"]},
    {"name": "TikTok Pixel", "category": "Analytics", "html": ["tiktok.com/analytics", "ttq"]},
    {"name": "LinkedIn Insight", "category": "Analytics", "html": ["linkedin.com/insight"]},
    {"name": "Mixpanel", "category": "Analytics", "html": ["mixpanel"]},
    {"name": "Amplitude", "category": "Analytics", "html": ["amplitude"]},
    {"name": "Segment", "category": "Analytics", "html": ["segment.com", "cdn.segment"]},
    {"name": "Sentry", "category": "Monitoring", "html": ["sentry"]},
    {"name": "Datadog", "category": "Monitoring", "html": ["datadog"]},
    {"name": "New Relic", "category": "Monitoring", "html": ["newrelic", "nr-"]},
    {"name": "OpenTelemetry", "category": "Monitoring", "html": ["opentelemetry", "otel"]},
    # ========== Payment ==========
    {"name": "Stripe", "category": "Payment", "html": ["stripe", "pk_live", "pk_test"]},
    {"name": "PayPal", "category": "Payment", "html": ["paypal"]},
    {"name": "Mercado Pago", "category": "Payment", "html": ["mercadopago"]},
    {"name": "PagSeguro", "category": "Payment", "html": ["pagseguro"]},
    {"name": "Pix", "category": "Payment", "html": ["pix", "brcode"]},
    {"name": "PicPay", "category": "Payment", "html": ["picpay"]},
    {"name": "Asaas", "category": "Payment", "html": ["asaas"]},
    # ========== Security ==========
    {"name": "Recaptcha", "category": "Security", "html": ["recaptcha", "g-recaptcha"]},
    {"name": "hCaptcha", "category": "Security", "html": ["hcaptcha"]},
    {"name": "Turnstile", "category": "Security", "html": ["challenges.cloudflare.com/turnstile", "turnstile"]},
    {"name": "ModSecurity", "category": "Security", "headers": {"server": "modsecurity"}},
    # ========== Database ==========
    {"name": "ElasticSearch", "category": "Database", "headers": {"server": "elasticsearch"}},
    {"name": "MongoDB", "category": "Database", "headers": {"server": "mongodb"}},
    {"name": "Redis", "category": "Database", "headers": {"server": "redis"}},
    {"name": "MySQL", "category": "Database", "headers": {"server": "mysql"}},
    {"name": "MariaDB", "category": "Database", "headers": {"server": "mariadb"}},
    {"name": "PostgreSQL", "category": "Database", "headers": {"server": "postgresql"}},
    {"name": "SQLite", "category": "Database", "html": ["sqlite"]},
    {"name": "Firebase", "category": "Database", "headers": {"x-firebase": ""}, "html": ["firebase"]},
    {"name": "Supabase", "category": "Database", "headers": {"x-supabase": ""}, "html": ["supabase"]},
    {"name": "Cassandra", "category": "Database", "html": ["cassandra"]},
    # ========== API ==========
    {"name": "GraphQL", "category": "API", "html": ["graphql"]},
    {"name": "REST API", "category": "API", "headers": {"content-type": "application/json"}},
    {"name": "Swagger", "category": "API", "html": ["swagger", "openapi"]},
    {"name": "REST API", "category": "API", "headers": {"content-type": "application/hal+json"}},
    # ========== Infrastructure ==========
    {"name": "Docker", "category": "Infrastructure", "headers": {"server": "docker"}},
    {"name": "Kubernetes", "category": "Infrastructure", "headers": {"server": "kube|kubernetes"}},
    {"name": "Istio", "category": "Infrastructure", "headers": {"server": "istio"}},
    {"name": "Kong", "category": "Infrastructure", "headers": {"server": "kong"}},
    # ========== Hosting / Cloud ==========
    {"name": "Heroku", "category": "Hosting", "headers": {"via": "heroku"}},
    {"name": "GitHub Pages", "category": "Hosting", "headers": {"server": "github.com"}},
    {"name": "Netlify", "category": "Hosting", "headers": {"server": "netlify"}},
    {"name": "Vercel", "category": "Hosting", "headers": {"server": "vercel"}},
    {"name": "AWS", "category": "Cloud", "headers": {"x-amz": "", "server": "amazon|aws|ecs|elb"}},
    {"name": "Azure", "category": "Cloud", "headers": {"x-azure": "", "server": "azure|azurewebsites"}},
    {"name": "GCP", "category": "Cloud", "headers": {"via": "google", "server": "gws|google|gae"}},
    {"name": "DigitalOcean", "category": "Cloud", "headers": {"server": "digitalocean"}},
    {"name": "Linode", "category": "Cloud", "headers": {"server": "linode"}},
    {"name": "OVH", "category": "Cloud", "headers": {"server": "ovh"}},
    {"name": "Cloudflare Pages", "category": "Cloud", "headers": {"server": "cloudflare-pages"}},
]


@register()
class WhatWebAdapter(ScannerAdapter):
    @property
    def name(self):
        return "WhatWeb"

    def validate_input(self, raw_data: str) -> bool:
        if not raw_data.strip():
            return False
        try:
            data = json.loads(raw_data)
            return bool(data.get("url"))
        except (json.JSONDecodeError, TypeError):
            return raw_data.startswith("http")

    def normalize(self, raw_data: str, project_id: int = 0) -> list[dict]:
        data = json.loads(raw_data) if isinstance(raw_data, str) else raw_data
        base = {"project_id": project_id, "plugin_source": self.name}
        findings = []

        url = data.get("url", "")
        if not url:
            return findings

        if WHATWEB_BIN:
            cli_result = self._run_whatweb_cli(url)
            if cli_result:
                parsed = self._parse_cli_output(cli_result, url, base)
                findings.extend(parsed)
                if findings:
                    return findings

        http_result = self._fetch_url(url)
        if http_result:
            parsed = self._fingerprint_http(http_result, url, base)
            findings.extend(parsed)

        if not findings:
            findings.append({**base,
                "title": "WhatWeb: Nenhuma tecnologia detectada",
                "description": f"Sem fingerprints para {url}",
                "severity": "Info",
                "raw_data": {"url": url},
            })

        return findings

    def run_scan(self, url: str) -> str:
        input_data = {"url": url}
        if self.validate_input(json.dumps(input_data)):
            findings = self.normalize(json.dumps(input_data))
            return json.dumps({"findings": findings, "count": len(findings)})
        return json.dumps({"error": "URL invalida", "count": 0})

    def _run_whatweb_cli(self, url: str) -> str | None:
        try:
            result = subprocess.run(
                [WHATWEB_BIN, "--no-errors", "--color=never", url],
                capture_output=True, text=True, timeout=30000,
            )
            return result.stdout if result.returncode == 0 else None
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None

    def _parse_cli_output(self, output: str, url: str, base: dict) -> list[dict]:
        findings = []
        for line in output.split("\n"):
            if "[" in line and "]" in line:
                parts = re.findall(r"\[([^\]]+)\]", line)
                for p in parts:
                    p = p.strip()
                    if p and p not in ("200", "OK") and not p.startswith("http"):
                        findings.append({**base,
                            "title": f"WhatWeb: {p}",
                            "description": f"Tecnologia detectada via whatweb CLI em {url}",
                            "severity": "Info",
                            "raw_data": {"url": url, "tech": p},
                        })
        return findings

    def _fetch_url(self, url: str) -> dict | None:
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            )
            resp = urllib.request.urlopen(req, timeout=15)
            headers = dict(resp.headers)
            body = resp.read().decode("utf-8", errors="ignore")[:100000]
            cookies = resp.headers.get_all("Set-Cookie") if hasattr(resp.headers, "get_all") else []
            return {"headers": headers, "body": body, "cookies": cookies, "status": resp.status}
        except Exception:
            return None

    def _fingerprint_http(self, http_data: dict, url: str, base: dict) -> list[dict]:
        findings = []
        headers = {k.lower(): v.lower() for k, v in http_data.get("headers", {}).items()}
        body = http_data.get("body", "").lower()
        set_cookie = http_data.get("headers", {}).get("Set-Cookie", "")
        server = headers.get("server", "")
        x_powered = headers.get("x-powered-by", "")
        detected = set()

        for sig in TECH_SIGNATURES:
            name = sig["name"]
            if name in detected:
                continue

            match = False

            if "headers" in sig:
                for hdr, pattern in sig["headers"].items():
                    hdr_val = headers.get(hdr, "")
                    if pattern:
                        if re.search(pattern, hdr_val):
                            match = True
                            break
                    elif hdr_val:
                        match = True
                        break

            if not match and "cookies" in sig:
                for c in sig["cookies"]:
                    if c.lower() in set_cookie.lower() or c.lower() in body[:5000]:
                        match = True
                        break

            if not match and "html" in sig:
                for h in sig["html"]:
                    if h in body:
                        match = True
                        break

            if match:
                version = ""
                if name == "Nginx":
                    v = re.search(r"nginx/([\d.]+)", server)
                    version = v.group(1) if v else ""
                elif name == "Apache":
                    v = re.search(r"apache/([\d.]+)", server)
                    version = v.group(1) if v else ""
                elif name == "IIS":
                    v = re.search(r"microsoft-iis/([\d.]+)", server)
                    version = v.group(1) if v else ""
                elif name == "PHP":
                    v = re.search(r"php/([\d.]+)", x_powered + " " + server)
                    version = v.group(1) if v else ""
                elif name == "jQuery":
                    v = re.search(r"jquery[.-]?([\d.]+)", body)
                    version = v.group(1) if v else ""
                elif name == "Bootstrap":
                    v = re.search(r"bootstrap[.-]?([\d.]+)", body)
                    version = v.group(1) if v else ""
                elif name == "React":
                    v = re.search(r"react[.-]?([\d.]+)", body)
                    version = v.group(1) if v else ""
                elif name == "Angular":
                    v = re.search(r"angular[.-]?([\d.]+)", body)
                    version = v.group(1) if v else ""
                elif name == "Vue.js":
                    v = re.search(r"vue[.-]?([\d.]+)", body)
                    version = v.group(1) if v else ""
                elif name == "Drupal":
                    v = re.search(r"drupal[.-]?([\d.]+)", body)
                    version = v.group(1) if v else ""
                elif name == "WordPress":
                    v = re.search(r"wordpress[.-]?([\d.]+)", body)
                    version = v.group(1) if v else ""
                elif name == "Django":
                    v = re.search(r"django[.-]?([\d.]+)", body)
                    version = v.group(1) if v else ""
                elif name == "nginx":
                    v = re.search(r"nginx/([\d.]+)", server)
                    version = v.group(1) if v else ""
                elif name == "Tomcat":
                    v = re.search(r"tomcat/([\d.]+)", server)
                    version = v.group(1) if v else ""
                elif name == "OpenResty":
                    v = re.search(r"openresty/([\d.]+)", server)
                    version = v.group(1) if v else ""
                elif name == "LiteSpeed":
                    v = re.search(r"litespeed/([\d.]+)", server)
                    version = v.group(1) if v else ""
                elif name == "Node.js":
                    v = re.search(r"node[.-]?([\d.]+)", server)
                    version = v.group(1) if v else ""
                elif name == "Go":
                    v = re.search(r"go[.-]?([\d.]+)", server)
                    version = v.group(1) if v else ""

                findings.append({**base,
                    "title": f"Tecnologia: {name}",
                    "description": f"{name} ({sig['category']}) detectado em {url}" + (f" v{version}" if version else ""),
                    "severity": "Info",
                    "raw_data": {"url": url, "tech": name, "category": sig["category"], "version": version},
                })
                detected.add(name)

        return findings
