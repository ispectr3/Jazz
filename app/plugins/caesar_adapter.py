import socket, ssl, hashlib, json, os, ipaddress, re
from datetime import datetime
from urllib.parse import urlparse
import requests
import dns.resolver
import dns.exception

from app.plugins.base import ScannerAdapter

SHODAN_KEY = os.getenv("SHODAN_API_KEY", "")

COMMON_PORTS = [
    (22, "SSH"), (80, "HTTP"), (443, "HTTPS"),
    (8080, "HTTP-Proxy"), (8443, "HTTPS-Alt"),
    (3306, "MySQL"), (5432, "PostgreSQL"),
    (6379, "Redis"), (27017, "MongoDB"),
    (9200, "Elasticsearch"),
]

SENSITIVE_PORTS = {3306, 5432, 6379, 27017, 9200}

LEAK_PATHS = [
    "/backup/", "/.git/", "/.env", "/admin/",
    "/wp-admin/", "/logs/", "/.htaccess",
    "/config.json", "/config.php", "/info.php",
    "/phpinfo.php", "/.svn/", "/.DS_Store",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
]

CLOUD_RANGES = {
    "CLOUDFLARE": ["104.16.0.0/12", "172.64.0.0/13", "131.0.72.0/22"],
    "AWS": ["54.0.0.0/8", "52.0.0.0/8", "13.0.0.0/8", "35.0.0.0/8"],
    "GCP": ["34.0.0.0/8", "35.192.0.0/12", "35.196.0.0/12"],
    "AZURE": ["20.0.0.0/8", "40.0.0.0/8", "52.240.0.0/12"],
    "ORACLE": ["129.146.0.0/16", "140.238.0.0/16"],
}

SKIP_MODULES = {
    "cpf", "cnpj", "cep", "geoint", "phone", "namint",
    "whatsmyname", "ip", "dns", "whois", "subdomain",
    "leaklooker", "abuseipdb", "portscan", "http",
    "cve", "filephish", "ssl", "dorks", "gitfive",
    "ghunt", "mosint", "scam", "emailval", "hash",
    "exif", "hibp", "registrobr", "wayback", "encoder",
    "regex", "timestamp", "favicon", "ela", "crypto",
    "blacklist", "emailverify", "virustotal", "urlscan",
    "malwarebazaar", "tor", "telegram", "linkedin",
    "shodan", "bgp", "cloudrange", "waf", "mac",
    "password", "speed", "graph",
}


class CaesarAdapter(ScannerAdapter):
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; JaizzNoir/1.0; +https://jaizznoir.local)",
            "Accept": "text/html,application/json,*/*",
        })
        self.session.timeout = (8, 8)

    @property
    def name(self) -> str:
        return "CaesarOSINT"

    def validate_input(self, raw_data: str) -> bool:
        return bool(raw_data and len(raw_data.strip()) > 0)

    def normalize(self, raw_data: str, project_id: int) -> list:
        target = raw_data.strip()
        target = target.lower().removeprefix("https://").removeprefix("http://").removeprefix("www.")
        target = target.split("/")[0].split(":")[0]

        findings = []

        resolvable = self._resolve(target)

        if resolvable:
            findings += self._check_http_security(target, project_id)
            findings += self._check_ssl_cert(target, project_id)
            findings += self._check_waf(target, project_id)
            findings += self._check_cloud(target, project_id)
            findings += self._check_portscan(target, project_id)
            findings += self._check_leaked_paths(target, project_id)
            findings += self._check_favicon(target, project_id)
            findings += self._check_dns_records(target, project_id)
            findings += self._check_email_auth(target, project_id)
            try:
                findings += self._check_subdomains(target, project_id)
            except Exception:
                pass
            try:
                findings += self._check_wayback(target, project_id)
            except Exception:
                pass
            if SHODAN_KEY:
                try:
                    findings += self._check_shodan(target, project_id)
                except Exception:
                    pass

        try:
            findings += self._check_whois(target, project_id)
        except Exception:
            pass

        try:
            findings += self._check_tor(target, project_id)
        except Exception:
            pass

        return findings

    def _resolve(self, hostname: str):
        try:
            return socket.getaddrinfo(hostname, 443, socket.AF_INET)
        except Exception:
            return None

    def _resolve_ip(self, hostname: str):
        try:
            return socket.getaddrinfo(hostname, 443, socket.AF_INET)[0][4][0]
        except Exception:
            return None

    def _check_http_security(self, domain: str, pid: int) -> list:
        findings = []
        try:
            r = self.session.get(f"https://{domain}", timeout=8)
            headers = r.headers
            hdr_lower = {k.lower(): v for k, v in headers.items()}

            sev = "Info"
            issues = []

            if "content-security-policy" not in hdr_lower:
                issues.append("CSP")
            if "strict-transport-security" not in hdr_lower:
                issues.append("HSTS")
            if "x-frame-options" not in hdr_lower:
                issues.append("X-Frame-Options")
            if "x-content-type-options" not in hdr_lower:
                issues.append("X-Content-Type-Options")
            if "referrer-policy" not in hdr_lower and "referer-policy" not in hdr_lower:
                issues.append("Referrer-Policy")

            if issues:
                if "content-security-policy" in issues or "strict-transport-security" in issues:
                    sev = "Media"
                if len(issues) >= 4:
                    sev = "Alta"

                findings.append({
                    "project_id": pid,
                    "plugin_source": self.name,
                    "title": f"Security Headers ausentes: {domain}",
                    "description": (
                        f"Headers de seguranca faltando ({len(issues)}): {', '.join(issues)}.\n"
                        f"URL: https://{domain}\n"
                        f"Server: {headers.get('Server', 'N/A')}"
                    ),
                    "severity": sev,
                    "raw_data": {"url": f"https://{domain}", "missing_headers": issues, "server": headers.get("Server")},
                })

            if "server" in hdr_lower:
                findings.append({
                    "project_id": pid,
                    "plugin_source": self.name,
                    "title": f"Server Header: {hdr_lower['server']}",
                    "description": f"Servidor expoe o header Server: {hdr_lower['server']} em https://{domain}",
                    "severity": "Info",
                    "raw_data": {"url": f"https://{domain}", "server": hdr_lower["server"]},
                })

        except requests.exceptions.SSLError:
            findings.append({
                "project_id": pid,
                "plugin_source": self.name,
                "title": f"SSL Invalido: {domain}",
                "description": f"Dominio {domain} nao possui certificado SSL valido.",
                "severity": "Alta",
                "raw_data": {"domain": domain, "ssl_error": "invalid"},
            })
        except Exception as e:
            pass

        return findings

    def _check_ssl_cert(self, domain: str, pid: int) -> list:
        findings = []
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    expires = cert.get("notAfter", "")
                    sans = cert.get("subjectAltName", [])

                    try:
                        exp_date = datetime.strptime(expires, "%b %d %H:%M:%S %Y %Z")
                        days_left = (exp_date - datetime.utcnow()).days

                        if days_left < 0:
                            sev = "Critica"
                            msg = f"Certificado expirado ha {abs(days_left)} dias!"
                        elif days_left < 15:
                            sev = "Alta"
                            msg = f"Certificado expira em {days_left} dias!"
                        elif days_left < 60:
                            sev = "Media"
                            msg = f"Certificado expira em {days_left} dias."
                        else:
                            sev = "Info"
                            msg = f"Certificado valido por {days_left} dias."

                        findings.append({
                            "project_id": pid,
                            "plugin_source": self.name,
                            "title": f"SSL: {domain} ({days_left}d restantes)",
                            "description": (
                                f"{msg}\n"
                                f"Emissor: {issuer.get('organizationName', 'N/A')}\n"
                                f"Validade: {exp_date.strftime('%d/%m/%Y')}\n"
                                f"SANs: {len(sans)} dominios"
                            ),
                            "severity": sev,
                            "raw_data": {"domain": domain, "expires": expires, "days_left": days_left, "issuer": issuer},
                        })
                    except ValueError:
                        pass
        except Exception:
            pass

        return findings

    def _check_waf(self, domain: str, pid: int) -> list:
        findings = []
        try:
            r = self.session.get(f"https://{domain}", timeout=8)
            h = {k.lower(): v for k, v in r.headers.items()}

            waf_signatures = {
                "Cloudflare": ["cf-ray", "cf-cache-status", "__cfduid"],
                "AWS WAF": ["x-amz-cf-id", "x-amzn-requestid"],
                "CloudFront": ["x-amz-cf-pop"],
                "Akamai": ["x-akamai-transformed"],
                "F5 BIG-IP": ["x-asm-version", "x-asm-data"],
                "Sucuri": ["x-sucuri-id", "x-sucuri-cache"],
                "ModSecurity": ["x-mod-security"],
                "Imperva": ["x-iinfo", "x-cdn"],
            }

            detected = []
            for name, sigs in waf_signatures.items():
                for s in sigs:
                    if s in h:
                        detected.append(name)
                        break

            if detected:
                findings.append({
                    "project_id": pid,
                    "plugin_source": self.name,
                    "title": f"WAF Detectado: {', '.join(set(detected))}",
                    "description": f"WAF detectado em https://{domain}: {', '.join(set(detected))}",
                    "severity": "Info",
                    "raw_data": {"domain": domain, "wafs": list(set(detected))},
                })
        except Exception:
            pass

        return findings

    def _check_cloud(self, domain: str, pid: int) -> list:
        findings = []
        try:
            ip = self._resolve_ip(domain)
            if not ip:
                return findings
            ip_obj = ipaddress.ip_address(ip)
            provider = None
            for prov, cidrs in CLOUD_RANGES.items():
                for cidr in cidrs:
                    if ipaddress.ip_address(ip) in ipaddress.ip_network(cidr):
                        provider = prov
                        break
                if provider:
                    break
            if provider:
                findings.append({
                    "project_id": pid,
                    "plugin_source": self.name,
                    "title": f"Cloud: {provider}",
                    "description": f"O IP {ip} pertence a {provider}.",
                    "severity": "Info",
                    "raw_data": {"domain": domain, "ip": ip, "cloud": provider},
                })
        except Exception:
            pass

        return findings

    def _check_portscan(self, domain: str, pid: int) -> list:
        findings = []
        for port, svc in COMMON_PORTS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((domain, port))
                sock.close()
                if result == 0:
                    sev = "Info"
                    if port in SENSITIVE_PORTS:
                        sev = "Alta"
                    elif port in (22, 8080, 8443):
                        sev = "Media"

                    findings.append({
                        "project_id": pid,
                        "plugin_source": self.name,
                        "title": f"Porta Aberta: {port}/{svc}",
                        "description": f"Porta {port} ({svc}) esta aberta em {domain}.",
                        "severity": sev,
                        "raw_data": {"domain": domain, "port": port, "service": svc},
                    })
            except Exception:
                pass
        return findings

    def _check_leaked_paths(self, domain: str, pid: int) -> list:
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
                    elif path in ("/phpinfo.php", "/info.php", "/config.json", "/config.php"):
                        sev = "Alta"

                    findings.append({
                        "project_id": pid,
                        "plugin_source": self.name,
                        "title": f"Path Exposto: {path} ({r.status_code})",
                        "description": (
                            f"Caminho {path} retornou HTTP {r.status_code} em {domain}.\n"
                            f"URL: https://{domain}{path}"
                        ),
                        "severity": sev,
                        "raw_data": {"domain": domain, "path": path, "status": r.status_code},
                    })
            except Exception:
                pass
        return findings

    def _check_favicon(self, domain: str, pid: int) -> list:
        findings = []
        for fav_path in ("/favicon.ico", "/favicon.png", "/apple-touch-icon.png"):
            try:
                r = self.session.get(f"https://{domain}{fav_path}", timeout=5)
                if r.status_code == 200 and len(r.content) > 100:
                    import mmh3
                    import base64
                    b64 = base64.b64encode(r.content).decode()
                    mmh = mmh3.hash(b64)
                    findings.append({
                        "project_id": pid,
                        "plugin_source": self.name,
                        "title": f"Favicon Hash: {mmh}",
                        "description": f"Favicon hash (mmh3): {mmh} | Path: {fav_path}",
                        "severity": "Info",
                        "raw_data": {"domain": domain, "favicon_path": fav_path, "hash": mmh},
                    })
                    break
            except Exception:
                pass
        return findings

    def _check_dns_records(self, domain: str, pid: int) -> list:
        findings = []
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5

        for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
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

    def _check_email_auth(self, domain: str, pid: int) -> list:
        findings = []
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5

        spf_record = None
        try:
            answers = resolver.resolve(domain, "TXT")
            for a in answers:
                txt = str(a)
                if txt.startswith("v=spf1"):
                    spf_record = txt
                    break
        except Exception:
            pass

        dmarc_record = None
        try:
            answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
            dmarc_record = str(answers[0])
        except Exception:
            pass

        if not spf_record:
            findings.append({
                "project_id": pid,
                "plugin_source": self.name,
                "title": f"SPF Ausente: {domain}",
                "description": f"Registro SPF nao encontrado para {domain}. Isto pode permitir falsificacao de email (spoofing).",
                "severity": "Media",
                "raw_data": {"domain": domain, "spf": None, "dmarc": dmarc_record},
            })
        else:
            spf_softfail = "~all" in spf_record
            spf_hardfail = "-all" in spf_record
            if not spf_hardfail and not spf_softfail:
                findings.append({
                    "project_id": pid,
                    "plugin_source": self.name,
                    "title": f"SPF Sem Hard Fail: {domain}",
                    "description": f"SPF configurado mas sem mecanismo de rejeicao explicito (~all ou -all): {spf_record[:100]}",
                    "severity": "Info",
                    "raw_data": {"domain": domain, "spf": spf_record, "dmarc": dmarc_record},
                })
            else:
                findings.append({
                    "project_id": pid,
                    "plugin_source": self.name,
                    "title": f"SPF Configurado: {domain}",
                    "description": f"SPF presente: {spf_record[:100]}",
                    "severity": "Info",
                    "raw_data": {"domain": domain, "spf": spf_record, "dmarc": dmarc_record},
                })

        if not dmarc_record:
            findings.append({
                "project_id": pid,
                "plugin_source": self.name,
                "title": f"DMARC Ausente: {domain}",
                "description": f"Registro DMARC nao encontrado para {domain}. Isso permite que emails falsificados nao sejam rejeitados.",
                "severity": "Media",
                "raw_data": {"domain": domain, "spf": spf_record, "dmarc": None},
            })
        else:
            findings.append({
                "project_id": pid,
                "plugin_source": self.name,
                "title": f"DMARC Configurado: {domain}",
                "description": f"DMARC presente: {dmarc_record[:100]}",
                "severity": "Info",
                "raw_data": {"domain": domain, "spf": spf_record, "dmarc": dmarc_record},
            })

        return findings

    def _check_subdomains(self, domain: str, pid: int) -> list:
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
                        "description": f"Subdominios encontrados via Certificate Transparency:\n" + "\n".join(f"  - {s}" for s in subdomains[:20]),
                        "severity": "Media" if len(subdomains) > 20 else "Info",
                        "raw_data": {"domain": domain, "subdomains": subdomains[:50], "total": len(subdomains), "source": "crt.sh"},
                    })

                    interesting = [s for s in subdomains if any(k in s for k in ("admin", "dev", "api", "vpn", "internal", "backup", "staging", "test", "homolog", "beta"))]
                    if interesting:
                        findings.append({
                            "project_id": pid,
                            "plugin_source": self.name,
                            "title": f"Subdominios Sensiveis: {len(interesting)} encontrados",
                            "description": "Subdominios com nomes potencialmente sensiveis:\n" + "\n".join(f"  - {s}" for s in interesting[:10]),
                            "severity": "Alta",
                            "raw_data": {"domain": domain, "sensitive_subdomains": interesting[:20]},
                        })
        except Exception:
            pass

        return findings

    def _check_wayback(self, domain: str, pid: int) -> list:
        findings = []
        try:
            r = self.session.get(
                f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit=100&fl=original,statuscode,timestamp",
                timeout=15,
            )
            if r.status_code == 200:
                rows = r.json()
                if len(rows) > 1:
                    urls = set()
                    for row in rows[1:]:
                        if len(row) >= 3:
                            urls.add(row[0])

                    findings.append({
                        "project_id": pid,
                        "plugin_source": self.name,
                        "title": f"Wayback: {len(urls)} URLs arquivadas",
                        "description": f"Foram encontradas {len(urls)} URLs arquivadas para {domain} no Wayback Machine.",
                        "severity": "Info",
                        "raw_data": {"domain": domain, "total_urls": len(urls), "urls": list(urls)[:30]},
                    })

                    suspicious = [u for u in urls if any(k in u.lower() for k in (".env", ".git", "backup", "admin", "api/", "wp-admin", "config", "database", "sql", "password", "token", "secret", "credentials"))]
                    if suspicious:
                        findings.append({
                            "project_id": pid,
                            "plugin_source": self.name,
                            "title": f"Wayback: {len(suspicious)} URLs suspeitas arquivadas",
                            "description": (
                                "URLs com palavras-chave sensiveis encontradas no Wayback Machine:\n"
                                + "\n".join(f"  - {u}" for u in suspicious[:15])
                            ),
                            "severity": "Alta",
                            "raw_data": {"domain": domain, "suspicious_urls": suspicious[:20]},
                        })
        except Exception:
            pass

        return findings

    def _check_whois(self, domain: str, pid: int) -> list:
        findings = []
        try:
            import whois
            w = whois.whois(domain)
            if w.get("domain_name"):
                findings.append({
                    "project_id": pid,
                    "plugin_source": self.name,
                    "title": f"WHOIS: {domain}",
                    "description": (
                        f"Registrar: {w.get('registrar', 'N/A')}\n"
                        f"Criacao: {w.get('creation_date', 'N/A')}\n"
                        f"Expiracao: {w.get('expiration_date', 'N/A')}\n"
                        f"Nameservers: {', '.join(str(n) for n in (w.get('name_servers') or [])[:4])}"
                    ),
                    "severity": "Info",
                    "raw_data": {
                        "domain": domain,
                        "registrar": str(w.get("registrar", "")),
                        "creation": str(w.get("creation_date", "")),
                        "expiration": str(w.get("expiration_date", "")),
                    },
                })
        except Exception:
            pass

        return findings

    def _check_tor(self, domain: str, pid: int) -> list:
        findings = []
        try:
            ip = self._resolve_ip(domain)
            if not ip:
                return findings

            r = self.session.get(
                f"https://check.torproject.org/torbulkexitlist",
                timeout=10,
            )
            if r.status_code == 200:
                exit_nodes = r.text.splitlines()
                if ip in exit_nodes:
                    findings.append({
                        "project_id": pid,
                        "plugin_source": self.name,
                        "title": f"Tor Exit Node: {ip}",
                        "description": f"O IP {ip} do dominio {domain} consta como node de saida da rede Tor.",
                        "severity": "Media",
                        "raw_data": {"domain": domain, "ip": ip, "tor_exit": True},
                    })
        except Exception:
            pass

        return findings

    def _check_shodan(self, domain: str, pid: int) -> list:
        findings = []
        import shodan
        api = shodan.Shodan(SHODAN_KEY)
        ip = self._resolve_ip(domain)
        if not ip:
            return findings
        try:
            info = api.host(ip)
            if info:
                vulns = info.get("vulns", [])
                ports = info.get("ports", [])
                if vulns:
                    findings.append({
                        "project_id": pid,
                        "plugin_source": self.name,
                        "title": f"Shodan: {len(vulns)} vulnerabilidades em {ip}",
                        "description": f"CVEs encontradas no Shodan para {ip}: {', '.join(vulns[:10])}\nPortas abertas: {ports}",
                        "severity": "Critica" if any(v.startswith("CVE-2024") for v in vulns) else "Alta",
                        "raw_data": {"domain": domain, "ip": ip, "vulns": vulns, "ports": ports},
                    })
                if ports:
                    findings.append({
                        "project_id": pid,
                        "plugin_source": self.name,
                        "title": f"Shodan: {len(ports)} portas abertas",
                        "description": f"Portas detectadas pelo Shodan para {ip}: {ports}",
                        "severity": "Media",
                        "raw_data": {"domain": domain, "ip": ip, "ports": ports},
                    })
        except shodan.APIError as e:
            if "internal error" in str(e).lower():
                pass
        except Exception:
            pass

        return findings
