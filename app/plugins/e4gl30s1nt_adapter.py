import socket, json
import requests
import dns.resolver
import dns.exception

from app.plugins.base import ScannerAdapter
from app.plugins.loader import register

COMMON_PORTS = [
    (22, "SSH"), (80, "HTTP"), (443, "HTTPS"),
    (8080, "HTTP-Proxy"), (8443, "HTTPS-Alt"),
    (3306, "MySQL"), (5432, "PostgreSQL"),
    (6379, "Redis"), (27017, "MongoDB"),
    (9200, "Elasticsearch"),
]

LEAK_PATHS = [
    "/.git/", "/.env", "/backup/", "/admin/", "/wp-admin/",
    "/config.json", "/phpinfo.php", "/info.php", "/.svn/",
    "/.DS_Store", "/crossdomain.xml", "/.htaccess",
]

TAKEOVER_SIGNATURES = {
    "s3.amazonaws.com": ["The specified bucket does not exist", "NoSuchBucket"],
    "github.io": ["There isn't a GitHub Pages site here"],
    "herokuapp.com": ["No such app", "Heroku | No such app"],
    "azurewebsites.net": ["404 Not Found", "The web page you requested was not found"],
    "cloudfront.net": ["ERROR: The request could not be satisfied", "BadRequest"],
    "netlify.app": ["Not Found - Request ID:"],
}


@register()
class E4gl30s1ntAdapter(ScannerAdapter):
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; JaizzNoir/1.0; +https://jaizznoir.local)",
            "Accept": "text/html,application/json,*/*",
        })
        self.session.timeout = (8, 8)

    @property
    def name(self) -> str:
        return "E4GL30S1NT OSINT Scanner"

    def validate_input(self, raw_data: str) -> bool:
        return bool(raw_data and len(raw_data.strip()) > 0)

    def normalize(self, raw_data: str, project_id: int) -> list:
        target = raw_data.strip().lower()
        target = target.removeprefix("https://").removeprefix("http://").removeprefix("www.")
        target = target.split("/")[0].split(":")[0]

        findings = []
        findings += self._subdomain_scan(target, project_id)
        findings += self._dns_scan(target, project_id)
        findings += self._http_scan(target, project_id)
        findings += self._port_scan(target, project_id)
        findings += self._leaked_paths(target, project_id)
        findings += self._takeover_scan(target, project_id)
        findings += self._cve_lookup(target, project_id)
        return findings

    def _resolve_ip(self, hostname: str):
        try:
            return socket.getaddrinfo(hostname, 443, socket.AF_INET)[0][4][0]
        except Exception:
            return None

    def _subdomain_scan(self, domain: str, pid: int) -> list:
        findings = []
        try:
            r = self.session.get(
                f"https://crt.sh/?q=%25.{domain}&output=json",
                timeout=15,
                headers={"Accept": "application/json"},
            )
            if r.status_code == 200:
                entries = r.json()
                seen = set()
                subdomains = []
                for entry in entries:
                    name = entry.get("name_value", "")
                    for n in name.split("\n"):
                        n = n.strip().lower()
                        if n.endswith(f".{domain}") and n not in seen and n != f"*.{domain}":
                            seen.add(n)
                            subdomains.append(n)

                if subdomains:
                    findings.append({
                        "project_id": pid,
                        "plugin_source": self.name,
                        "title": f"Subdominios: {len(subdomains)} encontrados (crt.sh)",
                        "description": f"Subdominios descobertos via Certificate Transparency:\n" + "\n".join(f"  - {s}" for s in subdomains[:20]),
                        "severity": "Info",
                        "raw_data": {"type": "subdomains", "source": "crt.sh", "subdomains": subdomains[:50], "total": len(subdomains)},
                    })

                    for sub in subdomains[:10]:
                        try:
                            ip = socket.getaddrinfo(sub, 80, socket.AF_INET)[0][4][0]
                            url = f"https://{sub}"
                            try:
                                sr = self.session.get(url, timeout=5)
                                findings.append({
                                    "project_id": pid,
                                    "plugin_source": self.name,
                                    "title": f"Subdominio Ativo: {sub}",
                                    "description": f"{sub} -> {ip} (HTTP {sr.status_code})",
                                    "severity": "Info",
                                    "raw_data": {"type": "subdomain", "subdomain": sub, "ip": ip, "status": sr.status_code},
                                })
                            except requests.exceptions.SSLError:
                                try:
                                    sr = self.session.get(f"http://{sub}", timeout=5)
                                    findings.append({
                                        "project_id": pid,
                                        "plugin_source": self.name,
                                        "title": f"Subdominio Ativo: {sub}",
                                        "description": f"{sub} -> {ip} (HTTP {sr.status_code}, sem SSL)",
                                        "severity": "Info",
                                        "raw_data": {"type": "subdomain", "subdomain": sub, "ip": ip, "status": sr.status_code},
                                    })
                                except Exception:
                                    pass
                            except Exception:
                                pass
                        except Exception:
                            pass
        except Exception:
            pass
        return findings

    def _dns_scan(self, domain: str, pid: int) -> list:
        findings = []
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5

        for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
            try:
                answers = resolver.resolve(domain, rtype)
                data = [str(a) for a in answers]
                findings.append({
                    "project_id": pid,
                    "plugin_source": self.name,
                    "title": f"DNS {rtype}: {len(data)} registros",
                    "description": f"Registros {rtype} para {domain}: {', '.join(data[:8])}",
                    "severity": "Info",
                    "raw_data": {"type": "dns", "rtype": rtype, "records": data},
                })
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                pass
            except Exception:
                pass

        ip = self._resolve_ip(domain)
        if ip:
            findings.append({
                "project_id": pid,
                "plugin_source": self.name,
                "title": f"IP do Dominio: {ip}",
                "description": f"Endereco IP resolvido para {domain}: {ip}",
                "severity": "Info",
                "raw_data": {"type": "ip", "domain": domain, "ip": ip},
            })
        return findings

    def _http_scan(self, domain: str, pid: int) -> list:
        findings = []
        try:
            r = self.session.get(f"https://{domain}", timeout=8)
            h = {k.lower(): v for k, v in r.headers.items()}
            techs = []
            if "x-powered-by" in h:
                techs.append(h["x-powered-by"])
            if "server" in h:
                techs.append(h["server"])
            if techs:
                findings.append({
                    "project_id": pid,
                    "plugin_source": self.name,
                    "title": f"Tecnologias Identificadas: {domain}",
                    "description": f"Tecnologias: {', '.join(techs)}",
                    "severity": "Info",
                    "raw_data": {"type": "technology", "domain": domain, "technologies": techs},
                })
        except Exception:
            pass
        return findings

    def _port_scan(self, domain: str, pid: int) -> list:
        findings = []
        for port, svc in COMMON_PORTS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((domain, port))
                sock.close()
                if result == 0:
                    sev = "Alta" if port in (3306, 5432, 6379, 27017, 9200) else ("Media" if port in (22, 8080, 8443) else "Info")
                    findings.append({
                        "project_id": pid,
                        "plugin_source": self.name,
                        "title": f"Porta Aberta: {port}/{svc}",
                        "description": f"Porta {port} ({svc}) esta aberta em {domain}.",
                        "severity": sev,
                        "raw_data": {"type": "port", "port": port, "service": svc, "domain": domain},
                    })
            except Exception:
                pass
        return findings

    def _leaked_paths(self, domain: str, pid: int) -> list:
        findings = []
        for path in LEAK_PATHS:
            try:
                r = self.session.get(f"https://{domain}{path}", timeout=5)
                if r.status_code in (200, 201, 204, 301, 302, 401, 403):
                    sev = "Info"
                    if path in ("/.git/", "/.env", "/backup/"):
                        sev = "Critica"
                    elif path in ("/wp-admin/", "/admin/"):
                        sev = "Media"
                    elif path in ("/phpinfo.php", "/info.php", "/config.json"):
                        sev = "Alta"

                    findings.append({
                        "project_id": pid,
                        "plugin_source": self.name,
                        "title": f"Caminho Exposto: {path} ({r.status_code})",
                        "description": f"Caminho {path} retornou HTTP {r.status_code} em {domain}.\nURL: https://{domain}{path}",
                        "severity": sev,
                        "raw_data": {"type": "leaked_path", "path": path, "status": r.status_code, "url": f"https://{domain}{path}"},
                    })
            except Exception:
                pass
        return findings

    def _takeover_scan(self, domain: str, pid: int) -> list:
        findings = []
        try:
            seen = set()
            r = self.session.get(
                f"https://crt.sh/?q=%25.{domain}&output=json",
                timeout=15,
                headers={"Accept": "application/json"},
            )
            if r.status_code == 200:
                for entry in r.json():
                    name = entry.get("name_value", "")
                    for n in name.split("\n"):
                        n = n.strip().lower()
                        if n.endswith(f".{domain}") and n not in seen and n != f"*.{domain}":
                            seen.add(n)

            targets = list(seen)[:20]
            targets.insert(0, domain)
        except Exception:
            targets = [domain]

        for sub in targets:
            try:
                cname = None
                try:
                    answers = dns.resolver.resolve(sub, "CNAME")
                    cname = str(answers[0]).rstrip(".")
                except Exception:
                    pass
                if not cname:
                    continue
                r = self.session.get(f"https://{sub}", timeout=8)
                body = r.text
                for service, signatures in TAKEOVER_SIGNATURES.items():
                    for sig in signatures:
                        if sig.lower() in body.lower():
                            findings.append({
                                "project_id": pid,
                                "plugin_source": self.name,
                                "title": f"Subdomain Takeover: {sub} -> {service}",
                                "description": f"{sub} aponta para {service} (CNAME: {cname}) mas retorna recurso inexistente. Subdominio pode ser reivindicado.",
                                "severity": "Critica",
                                "raw_data": {"type": "takeover", "domain": sub, "service": service, "signature": sig, "cname": cname},
                            })
                            break
            except Exception:
                pass
        return findings

    def _cve_lookup(self, domain: str, pid: int) -> list:
        findings = []
        try:
            r = self.session.get(f"https://{domain}", timeout=8)
            h = {k.lower(): v for k, v in r.headers.items()}
            server = h.get("server", "") or h.get("x-powered-by", "")
            if not server:
                return findings
            version_words = server.lower().split()
            for word in version_words[:3]:
                if any(c.isdigit() for c in word):
                    clean = word.strip(",/;")
                    try:
                        nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={clean}&resultsPerPage=5"
                        nr = self.session.get(nvd_url, timeout=10)
                        if nr.status_code == 200:
                            nvd = nr.json()
                            vulns = nvd.get("vulnerabilities", [])
                            if vulns:
                                cve_list = []
                                for v in vulns[:5]:
                                    cve_id = v.get("cve", {}).get("id", "")
                                    severity = v.get("cve", {}).get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
                                    cve_list.append(f"{cve_id} ({severity})")
                                findings.append({
                                    "project_id": pid,
                                    "plugin_source": self.name,
                                    "title": f"NVD: {len(vulns)} CVEs para {server.strip()}",
                                    "description": f"CVEs encontradas para {server.strip()}:\n" + "\n".join(f"  - {c}" for c in cve_list),
                                    "severity": "Alta" if any("CRITICAL" in c for c in cve_list) else "Media",
                                    "raw_data": {"type": "cve", "domain": domain, "server": server.strip(), "cves": cve_list, "source": "NVD"},
                                })
                                break
                    except Exception:
                        pass
        except Exception:
            pass
        return findings
