import socket, ssl, json
from datetime import datetime
from urllib.parse import urljoin
from bs4 import BeautifulSoup
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

SENSITIVE_PORTS = {3306, 5432, 6379, 27017, 9200}

SECURITY_HEADERS = [
    "content-security-policy", "strict-transport-security",
    "x-frame-options", "x-content-type-options",
    "referrer-policy", "permissions-policy",
]

SUBDOMAIN_KEYWORDS = ["admin", "dev", "api", "vpn", "internal", "backup", "staging", "test", "homolog", "beta", "prod", "homologacao"]

TECH_PATTERNS = {
    "nginx": ["nginx", "x-nginx-"],
    "apache": ["apache", "apache/"],
    "cloudflare": ["cloudflare", "cf-ray"],
    "iis": ["iis", "microsoft-iis"],
    "node.js": ["node.js", "express"],
    "gunicorn": ["gunicorn"],
    "php": ["php/", "x-powered-by: php"],
    "wordpress": ["wordpress", "wp-", "wp-content"],
    "django": ["django", "wsgi"],
    "rails": ["rails", "passenger"],
    "java": ["apache-tomcat", "jboss", "jetty", "spring"],
    "aws": ["aws", "amazon", "x-amz-"],
}

TAKEOVER_SIGNATURES = {
    "s3.amazonaws.com": ["The specified bucket does not exist", "NoSuchBucket"],
    "github.io": ["There isn't a GitHub Pages site here"],
    "herokuapp.com": ["No such app", "Heroku | No such app"],
    "azurewebsites.net": ["404 Not Found", "The web page you requested was not found"],
    "cloudfront.net": ["ERROR: The request could not be satisfied", "BadRequest"],
    "shopify.com": ["Sorry, this shop is currently unavailable"],
    "surge.sh": ["project not found"],
    "netlify.app": ["Not Found - Request ID:"],
    "pantheon.io": ["The gods are angry"],
    "wordpress.com": ["Doesn't look like anything to us"],
    "ghost.io": ["The thing you were looking for is no longer here"],
    "fly.io": ["Page not found"],
    "unbounce.com": ["The page you were looking for doesn't exist"],
}


@register()
class MrHolmesAdapter(ScannerAdapter):
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; JaizzNoir/1.0; +https://jaizznoir.local)",
            "Accept": "text/html,application/json,*/*",
        })
        self.session.timeout = (8, 8)

    @property
    def name(self) -> str:
        return "Mr.Holmes Pentest Recon"

    def validate_input(self, raw_data: str) -> bool:
        return bool(raw_data and len(raw_data.strip()) > 0)

    def normalize(self, raw_data: str, project_id: int) -> list:
        target = raw_data.strip().lower()
        target = target.removeprefix("https://").removeprefix("http://").removeprefix("www.")
        target = target.split("/")[0].split(":")[0]

        findings = []
        findings += self._dns_scan(target, project_id)
        findings += self._http_scan(target, project_id)
        findings += self._subdomain_scan(target, project_id)
        findings += self._port_scan(target, project_id)
        findings += self._ssl_scan(target, project_id)
        findings += self._ssl_deep_scan(target, project_id)
        findings += self._takeover_scan(target, project_id)
        findings += self._cve_lookup(target, project_id)
        return findings

    def _resolve_ip(self, hostname: str):
        try:
            return socket.getaddrinfo(hostname, 443, socket.AF_INET)[0][4][0]
        except Exception:
            try:
                return socket.getaddrinfo(hostname, 80, socket.AF_INET)[0][4][0]
            except Exception:
                return None

    def _dns_scan(self, domain: str, pid: int) -> list:
        findings = []
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5

        for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
            try:
                answers = resolver.resolve(domain, rtype)
                data = [str(a) for a in answers]
                findings.append({
                    "project_id": pid,
                    "plugin_source": self.name,
                    "title": f"DNS {rtype}: {len(data)} registros",
                    "description": f"Registros {rtype} para {domain}: {', '.join(data[:8])}",
                    "severity": "Info",
                    "raw_data": {"domain": domain, "type": rtype, "records": data},
                })
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                pass
            except Exception:
                pass
        return findings

    def _http_scan(self, domain: str, pid: int) -> list:
        findings = []
        url = f"https://{domain}"

        try:
            r = self.session.get(url, timeout=8)
            h = {k.lower(): v for k, v in r.headers.items()}

            missing = [hdr for hdr in SECURITY_HEADERS if hdr not in h]
            if missing:
                sev = "Alta" if len(missing) >= 4 else "Media"
                findings.append({
                    "project_id": pid,
                    "plugin_source": self.name,
                    "title": f"Security Headers Ausentes: {domain} ({len(missing)})",
                    "description": f"Headers ausentes: {', '.join(missing)}.\nURL: {url}\nServer: {h.get('server', 'N/A')}",
                    "severity": sev,
                    "raw_data": {"domain": domain, "missing_headers": missing, "server": h.get("server")},
                })

            techs_found = []
            full_response = (str(r.headers) + r.text[:2000]).lower()
            for tech_name, patterns in TECH_PATTERNS.items():
                for p in patterns:
                    if p in full_response:
                        techs_found.append(tech_name)
                        break
            if techs_found:
                findings.append({
                    "project_id": pid,
                    "plugin_source": self.name,
                    "title": f"Tecnologias Detectadas: {domain}",
                    "description": f"Tecnologias identificadas em {url}: {', '.join(set(techs_found))}",
                    "severity": "Info",
                    "raw_data": {"domain": domain, "technologies": list(set(techs_found)), "url": url},
                })

            interesting_paths = [
                "/robots.txt", "/sitemap.xml", "/.well-known/",
                "/crossdomain.xml", "/clientaccesspolicy.xml",
            ]
            for path in interesting_paths:
                try:
                    pr = self.session.get(f"{url}{path}", timeout=5)
                    if pr.status_code == 200:
                        findings.append({
                            "project_id": pid,
                            "plugin_source": self.name,
                            "title": f"Path Encontrado: {path}",
                            "description": f"{path} acessivel em {url} (HTTP {pr.status_code})",
                            "severity": "Info",
                            "raw_data": {"domain": domain, "path": path, "status": pr.status_code},
                        })
                except Exception:
                    pass

        except requests.exceptions.SSLError:
            try:
                r = self.session.get(f"http://{domain}", timeout=8)
                findings.append({
                    "project_id": pid,
                    "plugin_source": self.name,
                    "title": f"HTTP Sem SSL: {domain}",
                    "description": f"{domain} nao redireciona para HTTPS (HTTP {r.status_code})",
                    "severity": "Alta",
                    "raw_data": {"domain": domain, "redirect": False},
                })
            except Exception:
                pass
        except Exception:
            pass

        return findings

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
                        "title": f"Subdominios: {len(subdomains)} encontrados",
                        "description": f"Subdominios via Certificate Transparency:\n" + "\n".join(f"  - {s}" for s in subdomains[:20]),
                        "severity": "Media" if len(subdomains) > 20 else "Info",
                        "raw_data": {"domain": domain, "subdomains": subdomains[:50], "total": len(subdomains), "source": "crt.sh"},
                    })

                    interesting = [s for s in subdomains if any(k in s for k in SUBDOMAIN_KEYWORDS)]
                    if interesting:
                        findings.append({
                            "project_id": pid,
                            "plugin_source": self.name,
                            "title": f"Subdominios Sensiveis: {len(interesting)}",
                            "description": f"Subdominios potencialmente sensiveis:\n" + "\n".join(f"  - {s}" for s in interesting[:10]),
                            "severity": "Alta",
                            "raw_data": {"domain": domain, "sensitive_subdomains": interesting[:20], "source": "crt.sh"},
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
                    sev = "Alta" if port in SENSITIVE_PORTS else ("Media" if port in (22, 8080, 8443) else "Info")
                    findings.append({
                        "project_id": pid,
                        "plugin_source": self.name,
                        "title": f"Porta Aberta: {port}/{svc}",
                        "description": f"Porta {port} ({svc}) aberta em {domain}.",
                        "severity": sev,
                        "raw_data": {"domain": domain, "port": port, "service": svc},
                    })
            except Exception:
                pass
        return findings

    def _ssl_scan(self, domain: str, pid: int) -> list:
        findings = []
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    expires = cert.get("notAfter", "")
                    try:
                        exp_date = datetime.strptime(expires, "%b %d %H:%M:%S %Y %Z")
                        days_left = (exp_date - datetime.utcnow()).days
                        if days_left < 0:
                            sev, msg = "Critica", f"Certificado expirado ha {abs(days_left)} dias!"
                        elif days_left < 15:
                            sev, msg = "Alta", f"Certificado expira em {days_left} dias!"
                        elif days_left < 60:
                            sev, msg = "Media", f"Certificado expira em {days_left} dias."
                        else:
                            sev, msg = "Info", f"Certificado valido por {days_left} dias."
                        findings.append({
                            "project_id": pid,
                            "plugin_source": self.name,
                            "title": f"SSL: {domain} ({days_left}d)",
                            "description": f"{msg}\nEmissor: {issuer.get('organizationName', 'N/A')}",
                            "severity": sev,
                            "raw_data": {"domain": domain, "expires": expires, "days_left": days_left, "issuer": issuer},
                        })
                    except ValueError:
                        pass
        except (ssl.SSLError, ConnectionRefusedError, socket.timeout, OSError):
            pass
        return findings

    def _ssl_deep_scan(self, domain: str, pid: int) -> list:
        findings = []

        for proto_name, proto_version in [
            ("TLS 1.0", ssl.PROTOCOL_TLSv1),
            ("TLS 1.1", ssl.PROTOCOL_TLSv1_1),
            ("TLS 1.2", ssl.PROTOCOL_TLSv1_2),
        ]:
            try:
                ctx = ssl.SSLContext(proto_version)
                with socket.create_connection((domain, 443), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                        if proto_name in ("TLS 1.0", "TLS 1.1"):
                            findings.append({
                                "project_id": pid,
                                "plugin_source": self.name,
                                "title": f"SSL: {proto_name} Suportado",
                                "description": f"{domain} aceita conexoes {proto_name}, que e um protocolo obsoleto e inseguro.",
                                "severity": "Alta",
                                "raw_data": {"domain": domain, "protocol": proto_name, "deprecated": True},
                            })
            except (ssl.SSLError, ConnectionRefusedError, socket.timeout, OSError):
                pass

        try:
            ctx = ssl.create_default_context()
            ctx.set_ciphers("ALL:!COMPLEMENTOFDEFAULT:!eNULL:!aNULL")
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cipher = ssock.cipher()
                    if cipher and cipher[0]:
                        weak_ciphers = ["rc4", "des", "3des", "md5", "export", "null", "anon", "seed"]
                        cipher_name = cipher[0].lower()
                        if any(w in cipher_name for w in weak_ciphers):
                            findings.append({
                                "project_id": pid,
                                "plugin_source": self.name,
                                "title": f"SSL: Cipher Fraco Detectado ({cipher[0]})",
                                "description": f"Cipher {cipher[0]} negociado com {domain}. Ciphers fracos sao vulneraveis a ataques como POODLE, BEAST, CRIME.",
                                "severity": "Alta",
                                "raw_data": {"domain": domain, "cipher": cipher[0], "weak": True},
                            })
        except Exception:
            pass

        return findings

    def _takeover_scan(self, domain: str, pid: int) -> list:
        findings = []
        targets = [domain]

        try:
            r = self.session.get(
                f"https://crt.sh/?q=%25.{domain}&output=json",
                timeout=15,
                headers={"Accept": "application/json"},
            )
            if r.status_code == 200:
                seen = set()
                for entry in r.json():
                    name = entry.get("name_value", "")
                    for n in name.split("\n"):
                        n = n.strip().lower()
                        if n.endswith(f".{domain}") and n not in seen and n != f"*.{domain}":
                            seen.add(n)
                targets = list(seen)[:20]
                targets.insert(0, domain)
        except Exception:
            pass

        for sub in targets:
            try:
                cname = None
                try:
                    answers = dns.resolver.resolve(sub, "CNAME")
                    cname = str(answers[0]).rstrip(".")
                except Exception:
                    pass

                r = self.session.get(f"https://{sub}", timeout=8)
                body = r.text

                for service, signatures in TAKEOVER_SIGNATURES.items():
                    if not cname and not any(s in sub for s in [".s3.", ".github.", "heroku", "azure", "cloudfront",
                                                                  "netlify", "shopify", "surge", "pantheon", "ghost",
                                                                  "fly.io", "unbounce"]):
                        continue
                    for sig in signatures:
                        if sig.lower() in body.lower():
                            findings.append({
                                "project_id": pid,
                                "plugin_source": self.name,
                                "title": f"Subdomain Takeover: {sub} -> {service}",
                                "description": (
                                    f"{sub} aponta para {service} mas o recurso nao existe.\n"
                                    f"CNAME: {cname or 'N/A'}\n"
                                    f"Assinatura: '{sig}' na resposta.\n"
                                    f"Isso permite que um atacante reivindique o subdominio."
                                ),
                                "severity": "Critica",
                                "raw_data": {"domain": sub, "service": service, "signature": sig, "cname": cname},
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
                                    "description": f"CVEs encontradas para {server.strip()}:\n" + "\n".join(f"  - {c}" for c in cve_list) + f"\nFonte: NVD (nvd.nist.gov)",
                                    "severity": "Alta" if any("CRITICAL" in c for c in cve_list) else "Media",
                                    "raw_data": {"domain": domain, "server": server.strip(), "cves": cve_list, "source": "NVD"},
                                })
                                break
                    except Exception:
                        pass
        except Exception:
            pass
        return findings
