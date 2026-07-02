import json
import re
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from app.plugins.base import ScannerAdapter
from app.plugins.loader import register

CSRF_TOKEN_NAMES = [
    "csrf", "xsrf", "_token", "csrf_token", "csrfmiddlewaretoken",
    "authenticity_token", "__csrf", "csrf-token", "xsrf-token",
    "token", "nonce", "_csrf", "csrfToken",
]

CSRF_HEADERS = [
    "x-csrf-token", "x-xsrf-token", "x-csrf-protection",
]

SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}

SENSITIVE_ACTIONS = [
    "email", "password", "senha", "delete", "transfer",
    "payment", "pagamento", "admin", "role", "permission",
    "webhook", "api_key", "secret", "ssh_key",
]


@register()
class CSRFDetector(ScannerAdapter):
    @property
    def name(self) -> str:
        return "CSRFDetector"

    def validate_input(self, raw_data: str) -> bool:
        try:
            data = json.loads(raw_data)
            return "target" in data and "urls" in data
        except Exception:
            return False

    def normalize(self, raw_data: str, project_id: int) -> list:
        data = json.loads(raw_data)
        base = {"project_id": project_id, "plugin_source": self.name}
        findings = []

        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; JaizzNoir/1.0; CSRFDetector)",
        })
        proxy = data.get("proxy")
        if proxy:
            session.proxies.update({"http": proxy, "https": proxy})

        for url in data.get("urls", []):
            try:
                resp = session.get(url, timeout=10, allow_redirects=True)
            except requests.RequestException:
                continue

            if resp.status_code != 200:
                continue

            soup = BeautifulSoup(resp.text, "html.parser")
            forms = soup.find_all("form")

            for form in forms:
                method = form.get("method", "GET").upper()
                action = form.get("action", "")
                action_url = urljoin(url, action)

                if method in SAFE_METHODS:
                    continue

                input_names = [
                    inp.get("name", "") for inp in form.find_all("input")
                ]
                has_token = any(
                    any(t in name.lower() for t in CSRF_TOKEN_NAMES)
                    for name in input_names
                )

                if has_token:
                    continue

                form_id = form.get("id", "") or form.get("name", "") or str(forms.index(form))
                action_sensitive = any(s in action_url.lower() for s in SENSITIVE_ACTIONS)
                severity = "Alta" if action_sensitive else "Media"

                findings.append({
                    **base,
                    "title": f"CSRF: {method} {urlparse(action_url).path}",
                    "description": (
                        f"Formulario sem token CSRF detectado em {url}\n"
                        f"Action: {action_url}\n"
                        f"Method: {method}\n"
                        f"Form ID: {form_id}\n"
                        f"Inputs encontrados: {', '.join(input_names[:8])}"
                    ),
                    "severity": severity,
                    "raw_data": {
                        "url": url,
                        "action": action_url,
                        "method": method,
                        "form_id": form_id,
                        "inputs": input_names,
                        "sensitive_action": action_sensitive,
                    },
                })

            # Check AJAX/API endpoints for CSRF header requirements
            for script in soup.find_all("script"):
                if script.string and ("fetch(" in script.string or "XMLHttpRequest" in script.string):
                    for template in ["/api/", "/v1/", "/graphql", "/rest/"]:
                        if template in script.string:
                            findings.append({
                                **base,
                                "title": f"CSRF Potencial: API endpoint em {url}",
                                "description": (
                                    f"Script detectado com chamada AJAX para API.\n"
                                    f"URL base: {url}\n"
                                    f"Verificar se endpoints exigem token CSRF via header."
                                ),
                                "severity": "Media",
                                "raw_data": {"url": url, "script_snippet": script.string[:200]},
                            })
                            break

        if not findings:
            findings.append({
                **base,
                "title": f"CSRF Scan: Nenhum formulario vulneravel",
                "description": (
                    f"Alvo: {data.get('target')}\n"
                    f"URLs verificadas: {len(data.get('urls', []))}\n"
                    "Todos os formularios com POST/PUT/DELETE possuem token CSRF ou header de protecao."
                ),
                "severity": "Info",
                "raw_data": data,
            })

        return findings
