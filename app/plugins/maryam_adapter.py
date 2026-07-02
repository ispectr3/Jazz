import socket, json, smtplib
import requests
import dns.resolver
import dns.exception

from app.plugins.base import ScannerAdapter
from app.plugins.loader import register

COMMON_SUBDOMAINS = [
    "www", "mail", "admin", "dev", "api", "vpn", "webmail", "cpanel",
    "whm", "blog", "shop", "loja", "portal", "sac", "suporte",
    "intranet", "remote", "web", "cloud", "app", "forum", "wiki",
]

COMMON_USERS = [
    "admin", "contato", "contact", "info", "suporte", "support",
    "vendas", "sales", "rh", "financeiro", "finance", "comercial",
    "sac", "ouvidoria", "dev", "webmaster", "postmaster",
    "noreply", "newsletter", "marketing", "presidencia",
    "diretor", "gerente", "ti", "tecnologia", "adm",
    "secretaria", "juridico", "comunicacao", "imprensa",
    "parcerias", "fornecedor", "recursoshumanos",
]


@register()
class MaryamAdapter(ScannerAdapter):
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; JaizzNoir/1.0; +https://jaizznoir.local)",
            "Accept": "application/json",
        })
        self.session.timeout = (10, 10)

    @property
    def name(self) -> str:
        return "Maryam OSINT Framework"

    def validate_input(self, raw_data: str) -> bool:
        return bool(raw_data and len(raw_data.strip()) > 0)

    def normalize(self, raw_data: str, project_id: int) -> list:
        target = raw_data.strip().lower()
        target = target.removeprefix("https://").removeprefix("http://").removeprefix("www.")
        target = target.split("/")[0].split(":")[0]

        findings = []
        findings += self._dns_search(target, project_id)
        findings += self._subdomain_scan(target, project_id)
        findings += self._email_discovery(target, project_id)
        return findings

    def _resolve_ip(self, hostname: str):
        try:
            return socket.getaddrinfo(hostname, 80, socket.AF_INET)[0][4][0]
        except Exception:
            return None

    def _get_mx_servers(self, domain: str):
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            answers = resolver.resolve(domain, "MX")
            return [str(r.exchange).rstrip(".") for r in answers]
        except Exception:
            return []

    def _dns_search(self, domain: str, pid: int) -> list:
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
                    "title": f"Registro DNS {rtype}",
                    "description": f"Registros {rtype} para {domain}: {', '.join(data[:6])}",
                    "severity": "Info",
                    "raw_data": {"type": "dns", "record_type": rtype, "records": data[:10]},
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
                "title": f"Hostname Resolvido: {domain} -> {ip}",
                "description": f"O dominio {domain} resolve para o IP {ip}.",
                "severity": "Info",
                "raw_data": {"type": "hostname", "hostname": domain, "ip": ip},
            })

        return findings

    def _subdomain_scan(self, domain: str, pid: int) -> list:
        findings = []
        found_subs = []

        for sub in COMMON_SUBDOMAINS:
            hostname = f"{sub}.{domain}"
            ip = self._resolve_ip(hostname)
            if ip:
                found_subs.append((hostname, ip))
                findings.append({
                    "project_id": pid,
                    "plugin_source": self.name,
                    "title": f"Subdominio Descoberto: {hostname}",
                    "description": f"Subdominio {hostname} -> {ip} encontrado via resolucao DNS.",
                    "severity": "Info",
                    "raw_data": {"type": "hostname", "hostname": hostname, "ip": ip},
                })

        try:
            r = self.session.get(
                f"https://crt.sh/?q=%25.{domain}&output=json",
                timeout=15,
            )
            if r.status_code == 200:
                seen = set()
                crt_subs = []
                for entry in r.json():
                    name = entry.get("name_value", "")
                    for n in name.split("\n"):
                        n = n.strip().lower()
                        if n.endswith(f".{domain}") and n not in seen and n != f"*.{domain}" and n not in found_subs:
                            seen.add(n)
                            crt_subs.append(n)

                for sub in crt_subs[:15]:
                    ip = self._resolve_ip(sub)
                    findings.append({
                        "project_id": pid,
                        "plugin_source": self.name,
                        "title": f"Subdominio Descoberto (crt.sh): {sub}",
                        "description": f"Subdominio {sub}{f' -> {ip}' if ip else ''} via Certificate Transparency.",
                        "severity": "Info",
                        "raw_data": {"type": "hostname", "hostname": sub, "ip": ip or "", "source": "crt.sh"},
                    })
        except Exception:
            pass

        return findings

    def _verify_email_smtp(self, email: str, mx_servers: list) -> bool:
        if not mx_servers:
            return False
        mx = mx_servers[0]
        try:
            sock = socket.create_connection((mx, 25), timeout=5)
            smtp = smtplib.SMTP(timeout=5)
            smtp.sock = sock
            smtp.helo(smtp.local_hostname)
            smtp.mail("verify@jaizznoir.local")
            code, _ = smtp.rcpt(email)
            smtp.quit()
            return code in (250, 251)
        except Exception:
            return False

    def _email_discovery(self, domain: str, pid: int) -> list:
        findings = []
        mx_servers = self._get_mx_servers(domain)

        emails = []
        verified_emails = []
        for user in COMMON_USERS:
            email = f"{user}@{domain}"
            emails.append(email)

        if emails:
            findings.append({
                "project_id": pid,
                "plugin_source": self.name,
                "title": f"E-mails Potenciais: {len(emails)} encontrados",
                "description": (
                    f"Possiveis enderecos de e-mail baseados em padroes comuns para {domain}:\n"
                    + "\n".join(f"  - {e}" for e in emails[:15])
                ),
                "severity": "Media",
                "raw_data": {"type": "emails", "domain": domain, "emails": emails[:20]},
            })

        if mx_servers:
            test_sample = [f"{u}@{domain}" for u in COMMON_USERS[:5]]
            for email in test_sample:
                exists = self._verify_email_smtp(email, mx_servers)
                if exists:
                    verified_emails.append(email)

            if verified_emails:
                findings.append({
                    "project_id": pid,
                    "plugin_source": self.name,
                    "title": f"E-mails Verificados (SMTP): {len(verified_emails)}",
                    "description": f"Enderecos confirmados via verificacao SMTP em {mx_servers[0]}:\n" + "\n".join(f"  - {e}" for e in verified_emails),
                    "severity": "Alta",
                    "raw_data": {"type": "verified_emails", "domain": domain, "emails": verified_emails, "mx": mx_servers[0]},
                })

            mx_hosts = mx_servers
            findings.append({
                "project_id": pid,
                "plugin_source": self.name,
                "title": f"Servidores MX: {len(mx_hosts)} encontrados",
                "description": f"Servidores de email configurados para {domain}:\n" + "\n".join(f"  - {m}" for m in mx_hosts),
                "severity": "Info",
                "raw_data": {"type": "mx", "domain": domain, "mx_servers": mx_hosts},
            })
        else:
            findings.append({
                "project_id": pid,
                "plugin_source": self.name,
                "title": f"Sem Servidor MX: {domain}",
                "description": f"Nenhum servidor MX encontrado para {domain}. O dominio pode nao receber emails.",
                "severity": "Media",
                "raw_data": {"type": "mx", "domain": domain, "mx_servers": []},
            })

        return findings
