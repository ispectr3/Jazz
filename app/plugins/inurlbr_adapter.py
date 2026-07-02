import re
from urllib.parse import urlparse, unquote, urljoin
import requests
from bs4 import BeautifulSoup

from app.plugins.base import ScannerAdapter
from app.plugins.loader import register

DORK_PATTERNS = [
    (r"(?i)(select|union|insert|drop|exec|declare)", "SQL Injection"),
    (r"(?i)(file=|path=|dir=|download=|include=)", "LFI/RFI"),
    (r"(?i)(redirect=|url=|link=|return=|next=)", "Open Redirect"),
    (r"(?i)(id=|pid=|uid=|cod=|cat=|page=|subgroupid=|prodid=)", "Parametro Numerico"),
    (r"(?i)(admin|login|signin|cpanel|painel|dashboard)", "Painel Admin"),
    (r"(?i)(wp-admin|wp-content|wp-includes|wordpress)", "WordPress"),
    (r"(?i)(password|senha|passwd|credential|auth)", "Credencial Exposta"),
    (r"(?i)(backup|dump|sql|db|database|bd|banco)", "Exposicao de Dados"),
    (r"(?i)(\.env|\.git|\.svn|config\.|settings\.|\.bak)", "Arquivo Sensivel"),
    (r"(?i)(api|rest|graphql|v1|v2|endpoint)", "API Endpoint"),
    (r"(?i)(search|busca|q=|query=|s=)", "Busca Exposta"),
    (r"(?i)(upload|filemanager|media|asset)", "Upload/Assets"),
    (r"(?i)(\.php|\.asp|\.jsp|\.cgi|\.pl|\.aspx)", "Endpoint Dinamico"),
]

CRAWL_PATHS = [
    "/", "/admin/", "/login/", "/wp-admin/", "/wp-login.php",
    "/api/", "/api/v1/", "/graphql", "/rest/",
    "/.env", "/.git/", "/.svn/", "/backup/", "/dump/",
    "/config/", "/config.php", "/config.json", "/settings/",
    "/phpinfo.php", "/info.php", "/server-status",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/uploads/", "/files/", "/assets/", "/media/",
    "/search/", "/busca/", "/q/",
    "/redirect/", "/link/", "/url/",
    "/download/", "/file/", "/include/",
    "/cgi-bin/", "/cgi-bin/test.cgi",
    "/mysql/", "/phpmyadmin/", "/adminer.php",
    "/.htaccess", "/.htpasswd",
    "/ws/", "/webservice/", "/soap/",
    "/test/", "/dev/", "/staging/", "/beta/",
    "/sitemap", "/feed/", "/rss/",
    "/users/", "/user/", "/profile/",
    "/register/", "/cadastro/", "/signup/",
    "/password/", "/reset/", "/recover/",
    "/oauth/", "/auth/", "/token/",
    "/logs/", "/log/", "/debug/",
    "/error/", "/errors/", "/exception/",
    "/docs/", "/documentation/", "/swagger/",
    "/health", "/healthz", "/healthcheck",
    "/metrics", "/prometheus", "/status",
]


@register()
class InurlbrAdapter(ScannerAdapter):
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; JaizzNoir/1.0; +https://jaizznoir.local)",
            "Accept": "text/html,application/json,*/*",
        })
        self.session.timeout = (5, 5)

    @property
    def name(self) -> str:
        return "INURLBR Dorking Scanner"

    def validate_input(self, raw_data: str) -> bool:
        return bool(raw_data and len(raw_data.strip()) > 0)

    def _classify_url(self, url: str) -> str:
        parsed = urlparse(url)
        path = unquote(parsed.path + "?" + parsed.query)
        for pattern, label in DORK_PATTERNS:
            if re.search(pattern, path):
                return label
        return "Pagina Web"

    def _spider_links(self, base_url: str, html: str, domain: str) -> list:
        found = []
        try:
            soup = BeautifulSoup(html, "html.parser")
            for tag in soup.find_all(["a", "link", "script", "iframe", "form"]):
                href = tag.get("href") or tag.get("src") or tag.get("action")
                if not href:
                    continue
                full = urljoin(base_url, href)
                parsed = urlparse(full)
                if domain in parsed.netloc and parsed.path not in ("", "/"):
                    path = parsed.path.split("?")[0].rstrip("/")
                    if path and len(path) > 1:
                        found.append(full)
        except Exception:
            pass
        return found

    def normalize(self, raw_data: str, project_id: int) -> list:
        target = raw_data.strip().lower()
        target = target.removeprefix("https://").removeprefix("http://").removeprefix("www.")
        target = target.split("/")[0].split(":")[0]

        findings = []
        discovered = set()
        base_url = f"https://{target}"

        for path in CRAWL_PATHS:
            url = f"{base_url}{path}"
            try:
                r = self.session.get(url, timeout=5, allow_redirects=True)
                if r.status_code in (200, 201, 204, 301, 302, 307, 308, 401, 403, 405):
                    cat = self._classify_url(url)

                    sev = "Info"
                    if cat == "Arquivo Sensivel":
                        sev = "Critica"
                    elif cat == "Credencial Exposta":
                        sev = "Alta"
                    elif cat == "Exposicao de Dados":
                        sev = "Alta"
                    elif cat == "Painel Admin":
                        sev = "Media"
                    elif cat == "API Endpoint":
                        sev = "Media"
                    elif cat == "SQL Injection":
                        sev = "Alta"
                    elif cat == "LFI/RFI":
                        sev = "Alta"

                    if r.status_code in (401, 403):
                        sev_map = {"Info": "Media", "Media": "Alta", "Alta": "Critica", "Critica": "Critica"}
                        if sev in sev_map:
                            sev = sev_map[sev]

                    key = f"{path}|{r.status_code}"
                    if key not in discovered:
                        discovered.add(key)
                        findings.append({
                            "project_id": project_id,
                            "plugin_source": self.name,
                            "title": f"{cat}: {target}{path[:40]} ({r.status_code})",
                            "description": (
                                f"URL encontrada via dorking/spider.\n"
                                f"Classificacao: {cat}\n"
                                f"URL: {url}\n"
                                f"HTTP Status: {r.status_code}\n"
                                f"Tamanho: {len(r.content)} bytes"
                            ),
                            "severity": sev,
                            "raw_data": {
                                "url": url,
                                "categoria": cat,
                                "status": r.status_code,
                                "size": len(r.content),
                                "content_type": r.headers.get("content-type", ""),
                            },
                        })

                    if r.status_code == 200 and "text/html" in r.headers.get("content-type", ""):
                        spidered = self._spider_links(url, r.text, target)
                        for su in spidered:
                            if su not in discovered:
                                discovered.add(su)
                                sp = urlparse(su).path
                                scat = self._classify_url(su)
                                sev2 = "Info"
                                if scat == "API Endpoint":
                                    sev2 = "Media"
                                findings.append({
                                    "project_id": project_id,
                                    "plugin_source": self.name,
                                    "title": f"{scat}: {target}{sp[:40]} (spider)",
                                    "description": (
                                        f"URL descoberta via spider.\n"
                                        f"Classificacao: {scat}\n"
                                        f"URL: {su}\n"
                                        f"Origem: {url}"
                                    ),
                                    "severity": sev2,
                                    "raw_data": {
                                        "url": su,
                                        "categoria": scat,
                                        "origin": url,
                                        "source": "spider",
                                    },
                                })

            except Exception:
                pass

        return findings
