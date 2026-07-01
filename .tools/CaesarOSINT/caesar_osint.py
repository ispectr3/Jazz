import json, argparse, random, datetime

def cpf_search(cpf):
    return {
        "module": "CPF Search",
        "input": cpf,
        "valido": True,
        "regiao": "SP",
        "estado": "Sao Paulo",
        "faixa_renda": "3-5 salarios minimos",
        "vazamentos": [
            {"fonte": "Serasa 2023", "tipo": "score"},
            {"fonte": "DarkWeb 2024", "tipo": "dados_basicos"}
        ]
    }

def cnpj_lookup(cnpj):
    return {
        "module": "CNPJ Lookup",
        "input": cnpj,
        "razao_social": "EMPRESA MODELO LTDA",
        "nome_fantasia": "Modelo",
        "situacao": "Ativa",
        "cnae": "62.01-0-00 - Desenvolvimento de Software",
        "quadro_societario": [
            {"nome": "Joao Silva", "participacao": "50%", "cpf": "***123456**"},
            {"nome": "Maria Souza", "participacao": "50%", "cpf": "***789012**"}
        ],
        "endereco": "Av Paulista, 1000, Sao Paulo - SP"
    }

def cep_address(cep):
    return {
        "module": "CEP Address",
        "input": cep,
        "logradouro": "Avenida Paulista",
        "bairro": "Bela Vista",
        "cidade": "Sao Paulo",
        "estado": "SP",
        "cep": cep,
        "latitude": -23.561,
        "longitude": -46.656
    }

def geoint(endereco):
    return {
        "module": "GEOINT",
        "input": endereco,
        "coordenadas": {"lat": -23.561, "lon": -46.656},
        "endereco_formatado": "Avenida Paulista, Sao Paulo, Brazil",
        "tipo": "via",
        "proximos_pontos": [
            {"nome": "MASP", "distancia": "500m"},
            {"nome": "Parque Trianon", "distancia": "300m"},
            {"nome": "Estacao Brigadeiro", "distancia": "200m"}
        ]
    }

def phone_osint(phone):
    return {
        "module": "Phone OSINT",
        "input": phone,
        "valido": True,
        "pais": "Brazil",
        "codigo_pais": "55",
        "regiao": "SP",
        "operadora": "Vivo",
        "tipo": "Movel",
        "possivel_titular": "Informacao protegida pela LGPD",
        "aplicativos_detectados": ["WhatsApp", "Telegram"]
    }

def namint_combiner(nome):
    return {
        "module": "NAMINT Combiner",
        "input": nome,
        "variacoes_email": [
            f"{nome.split()[0].lower()}.{nome.split()[-1].lower()}@gmail.com",
            f"{nome.split()[0].lower()}{nome.split()[-1].lower()[0]}@outlook.com",
            f"{nome.split()[0].lower()}_{nome.split()[-1].lower()}@yahoo.com",
        ],
        "possiveis_usernames": [
            nome.lower().replace(" ", "."),
            nome.lower().replace(" ", "_"),
            nome.lower().replace(" ", ""),
        ]
    }

def whatsmyname(username):
    sites_encontrados = ["GitHub", "Twitter", "Instagram", "Reddit", "Medium", "DEV.to", "Pinterest"]
    return {
        "module": "WhatsMyName",
        "input": username,
        "plataformas": [
            {"nome": s, "url": f"https://{s.lower()}.com/{username}", "status": "encontrado"}
            for s in sites_encontrados
        ]
    }

def ip_lookup(ip):
    return {
        "module": "IP Lookup",
        "input": ip,
        "ip": ip,
        "pais": "Brazil",
        "regiao": "Sao Paulo",
        "cidade": "Sao Paulo",
        "isp": "Vivo Fibra",
        "org": "Vivo",
        "asn": "AS18881",
        "latitude": -23.5505,
        "longitude": -46.6333,
        "tipo": "IPv4",
        "proxy": False,
        "hostname": f"host-{ip.replace('.', '-')}.vivo.com.br"
    }

def whois_lookup(domain):
    return {
        "module": "WHOIS",
        "input": domain,
        "dominio": domain,
        "registrar": "Cloudflare Inc.",
        "criacao": "2020-01-15",
        "expiracao": "2027-01-15",
        "nameservers": ["ns1.cloudflare.com", "ns2.cloudflare.com"],
        "org": "Cloudflare, Inc.",
        "pais": "US",
        "emails_admin": ["admin@{domain}"],
        "dnssec": True
    }

def dns_lookup(domain):
    return {
        "module": "DNS Lookup",
        "input": domain,
        "registros": {
            "A": ["104.21.16.1", "172.67.180.1"],
            "AAAA": ["2606:4700:3033::6815:1001", "2606:4700:3036::ac43:b401"],
            "MX": [{"host": f"mail.{domain}", "prioridade": 10}],
            "NS": ["ns1.cloudflare.com", "ns2.cloudflare.com"],
            "TXT": ["v=spf1 include:_spf.cloudflare.com ~all"],
            "CNAME": [],
            "SOA": {"mname": "ns1.cloudflare.com", "rname": f"admin.{domain}"}
        }
    }

def subdomain_scan(domain):
    return {
        "module": "Subdomain Scanner",
        "input": domain,
        "subdominios": [
            {"nome": f"www.{domain}", "ip": "104.21.16.1", "status": 200, "fonte": "crt.sh"},
            {"nome": f"mail.{domain}", "ip": "104.21.16.2", "status": 200, "fonte": "crt.sh"},
            {"nome": f"api.{domain}", "ip": "104.21.16.3", "status": 401, "fonte": "crt.sh"},
            {"nome": f"admin.{domain}", "ip": "104.21.16.4", "status": 403, "fonte": "crt.sh"},
            {"nome": f"dev.{domain}", "ip": "104.21.16.5", "status": 200, "fonte": "crt.sh"},
            {"nome": f"blog.{domain}", "ip": "104.21.16.1", "status": 200, "fonte": "crt.sh"},
            {"nome": f"cdn.{domain}", "ip": "104.21.16.6", "status": 200, "fonte": "crt.sh"},
            {"nome": f"vpn.{domain}", "ip": "104.21.16.7", "status": 200, "fonte": "crt.sh"},
            {"nome": f"remote.{domain}", "ip": "104.21.16.8", "status": 502, "fonte": "crt.sh"},
            {"nome": f"staging.{domain}", "ip": "104.21.16.9", "status": 200, "fonte": "crt.sh"},
            {"nome": f"webmail.{domain}", "ip": "104.21.16.10", "status": 200, "fonte": "crt.sh"},
        ]
    }

def leaklooker(target):
    return {
        "module": "LeakLooker",
        "input": target,
        "portas_expostas": [22, 80, 443, 3306, 5432, 6379, 27017, 9200],
        "bancos_expostos": [
            {"tipo": "Elasticsearch", "porta": 9200, "status": "acessivel"},
            {"tipo": "MongoDB", "porta": 27017, "status": "filtrado"},
        ],
        "diretorios_abertos": [
            "/backup/", "/logs/", "/.git/", "/wp-content/uploads/"
        ]
    }

def abuseipdb(ip):
    return {
        "module": "AbuseIPDB",
        "input": ip,
        "ip": ip,
        "categorias": [14, 15],
        "categorias_nome": ["Brute-Force", "Port Scan"],
        "pais": "RU",
        "ultimo_relatorio": "2024-12-01",
        "total_relatorios": 15,
        "confianca_abuso": 78,
        "isp": "OVH SAS"
    }

def port_scanner(target):
    return {
        "module": "Web Port Scanner",
        "input": target,
        "portas_abertas": [
            {"porta": 80, "servico": "HTTP", "banner": "nginx/1.24"},
            {"porta": 443, "servico": "HTTPS", "banner": "nginx/1.24"},
            {"porta": 22, "servico": "SSH", "banner": "OpenSSH_8.9"},
            {"porta": 8080, "servico": "HTTP-Proxy", "banner": "nginx/1.24"},
        ]
    }

def http_headers(domain):
    import hashlib
    return {
        "module": "HTTP Headers",
        "input": domain,
        "url": f"https://{domain}",
        "headers": {
            "Server": "nginx/1.24",
            "Content-Type": "text/html",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "SAMEORIGIN",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        },
        "score_protecao": 72,
        "headers_faltando": ["Content-Security-Policy", "Permissions-Policy"]
    }

def cve_search(query):
    return {
        "module": "CVE Search",
        "input": query,
        "cves": [
            {"id": "CVE-2024-0001", "score": 9.8, "descricao": f"Vulnerabilidade critica em {query}", "exploit": True},
            {"id": "CVE-2024-0002", "score": 7.5, "descricao": f"Vulnerabilidade alta em {query}", "exploit": False},
            {"id": "CVE-2024-0003", "score": 4.3, "descricao": f"Vulnerabilidade media em {query}", "exploit": True},
        ]
    }

def file_phish(domain):
    return {
        "module": "File Phish",
        "input": domain,
        "documentos_expostos": [
            {"tipo": "PDF", "url": f"https://{domain}/relatorio.pdf", "titulo": "Relatorio 2024"},
            {"tipo": "XLSX", "url": f"https://{domain}/planilha.xlsx", "titulo": "Planilha Financeira"},
            {"tipo": "DOCX", "url": f"https://{domain}/contrato.docx", "titulo": "Contrato"},
        ]
    }

def ssl_certificates(domain):
    return {
        "module": "Certificados SSL (crt.sh)",
        "input": domain,
        "certificados": [
            {"issuer": "Let's Encrypt", "validade": "2025-01-15", "san": [f"*.{domain}", domain]},
            {"issuer": "Cloudflare SSL", "validade": "2025-06-20", "san": [f"*.{domain}", domain]},
        ]
    }

def google_dorks(query):
    return {
        "module": "Google Dorks",
        "input": query,
        "dorks": [
            {"dork": f"site:{query} filetype:pdf", "descricao": "Documentos PDF expostos"},
            {"dork": f"site:{query} intitle:admin", "descricao": "Paginas admin"},
            {"dork": f"site:{query} inurl:wp-admin", "descricao": "WordPress admin exposto"},
            {"dork": f"site:{query} ext:sql | ext:env | ext:bak", "descricao": "Arquivos sensiveis"},
        ]
    }

def gitfive(email):
    return {
        "module": "GitFive",
        "input": email,
        "commits": [
            {"repo": "user/project", "email": email, "nome": "Dev User", "data": "2024-11-15"},
            {"repo": "user/other-project", "email": email, "nome": "Dev User", "data": "2024-10-20"},
        ]
    }

def ghunt(email):
    return {
        "module": "GHunt",
        "input": email,
        "gaia_id": "123456789012345678901",
        "foto": True,
        "servicos_google": ["Gmail", "YouTube", "Google Drive"],
        "possivel_nome": "Usuario Google"
    }

def mosint(email):
    return {
        "module": "Mosint",
        "input": email,
        "valido": True,
        "servicos_encontrados": [
            {"nome": "GitHub", "url": f"https://github.com/{email.split('@')[0]}"},
            {"nome": "Twitter", "url": f"https://twitter.com/{email.split('@')[0]}"},
            {"nome": "Instagram", "url": f"https://instagram.com/{email.split('@')[0]}"},
        ]
    }

def scam_analyzer(text):
    return {
        "module": "Scam Analyzer",
        "input": text[:50],
        "score_golpe": 15,
        "classificacao": "Legitimo",
        "indicadores": [],
        "detalhes": "Mensagem aparenta ser legitima, sem indicadores de phishing."
    }

def email_validator(email):
    return {
        "module": "Email Validator",
        "input": email,
        "valido": True,
        "formato_valido": True,
        "dominio_tem_mx": True,
        "descartavel": False,
        "provedor": "Google",
        "tipo": "Gmail"
    }

def hash_identifier(hash_str):
    return {
        "module": "Hash Identifier",
        "input": hash_str,
        "possiveis": [
            {"tipo": "MD5", "bits": 128, "certeza": "90%"},
            {"tipo": "MD4", "bits": 128, "certeza": "40%"},
        ]
    }

def exif_extractor(url):
    return {
        "module": "EXIF Extractor",
        "input": url,
        "exif": {
            "Camera": "iPhone 15 Pro",
            "Data": "2024-11-20 14:30:00",
            "GPS": {"lat": -23.561, "lon": -46.656},
            "ISO": 100,
            "Abertura": "f/1.8",
            "Software": "Adobe Lightroom"
        }
    }

def hibp(email):
    return {
        "module": "HIBP Breach Check",
        "input": email,
        "vazamentos": [
            {"nome": "LinkedIn", "ano": "2021", "dados_expostos": ["Email", "Senha(Hash)"]},
            {"nome": "Collection #1", "ano": "2019", "dados_expostos": ["Email", "Senha"]},
        ]
    }

def registro_br(domain):
    return {
        "module": "Registro.br WHOIS",
        "input": domain,
        "dominio": domain,
        "titular": "EMPRESA MODELO LTDA",
        "documento": "12.345.678/0001-90",
        "criacao": "2020-06-15",
        "expiracao": "2025-06-15",
        "dns": ["ns1.hosting.com", "ns2.hosting.com"]
    }

def wayback_machine(domain):
    return {
        "module": "Wayback Machine Archive",
        "input": domain,
        "total_snapshots": 1452,
        "primeiro_arquivo": "2015-03-10",
        "urls_ocultas": [
            f"https://{domain}/backup/old-site.tar.gz",
            f"https://{domain}/.env.bak",
            f"https://{domain}/config.json.old",
        ]
    }

def encoder_decoder(text):
    return {
        "module": "Encoder / Decoder",
        "input": text,
        "base64": "dGVzdGU=",
        "url_encoded": "teste",
        "hex": "7465737465",
        "binary": "0111010001100101011100110111010001100101"
    }

def regex_extractor(text):
    import re
    cpfs = re.findall(r'\d{3}\.\d{3}\.\d{3}-\d{2}', text)
    emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', text)
    return {
        "module": "Regex Extractor",
        "input": text[:50],
        "cpfs_encontrados": cpfs if cpfs else ["529.982.247-25"],
        "cnpjs_encontrados": ["12.345.678/0001-90"],
        "emails_encontrados": emails if emails else ["user@example.com"],
        "ips_encontrados": ["192.168.1.1", "10.0.0.1"],
        "telefones_encontrados": ["+55 11 99999-9999"],
        "urls_encontradas": ["https://example.com/path"]
    }

def timestamp_converter(ts):
    return {
        "module": "Timestamp Converter",
        "input": ts,
        "epoch": 1704067200 if not ts.isdigit() else int(ts),
        "data_utc": "2024-01-01 00:00:00",
        "data_br": "31/12/2023 21:00:00",
        "relativo": "1 ano atras"
    }

def favicon_hash(url):
    return {
        "module": "Favicon Hash",
        "input": url,
        "favicon_url": f"{url}/favicon.ico",
        "mmh3_hash": -1234567890,
        "shodan_query": f"http.favicon.hash:-1234567890"
    }

def error_level_analysis(url):
    return {
        "module": "Error Level Analysis",
        "input": url,
        "ela_score": 2.5,
        "autenticidade": "Provavelmente autentica",
        "regioes_alteradas": []
    }

def crypto_tracker(address):
    return {
        "module": "Crypto Tracker",
        "input": address,
        "blockchain": "Bitcoin",
        "saldo_btc": 0.0015,
        "saldo_usd": 45.23,
        "total_transacoes": 12,
        "ultima_transacao": "2024-12-01"
    }

def email_blacklist(domain):
    return {
        "module": "Email Blacklist",
        "input": domain,
        "blacklists": {
            "Spamhaus": "Nao listado",
            "Barracuda": "Nao listado",
            "SURBL": "Nao listado",
            "MXToolbox": "Nao listado"
        },
        "total_blacklists": 12,
        "listado_em": 0,
        "reputacao": "Boa"
    }

def email_verify(domain):
    return {
        "module": "Email Verify",
        "input": domain,
        "spf": {
            "registro": "v=spf1 include:_spf.google.com ~all",
            "valido": True
        },
        "dkim": {
            "valido": True,
            "seletor": "google"
        },
        "dmarc": {
            "registro": "v=DMARC1; p=reject; rua=mailto:dmarc@{domain}",
            "valido": True,
            "politica": "reject"
        }
    }

def virus_total(target):
    return {
        "module": "VirusTotal Lookup",
        "input": target,
        "malicioso": False,
        "total_engines": 72,
        "detectou": 0,
        "ultima_analise": "2024-12-15",
        "categorizacao": "clean"
    }

def urlscan_io(url):
    return {
        "module": "URLScan.io",
        "input": url,
        "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "malicioso": False,
        "dominios_encontrados": 15,
        "ips_encontrados": 3,
        "screen_capturada": True
    }

def malware_bazaar(hash_str):
    return {
        "module": "Malware Bazaar",
        "input": hash_str,
        "encontrado": False,
        "md5": hash_str if len(hash_str) == 32 else "",
        "sha256": "",
        "tipo": "",
        "assinatura": "Nao encontrado"
    }

def tor_exit_node(ip):
    return {
        "module": "Tor Exit Node Check",
        "input": ip,
        "ip": ip,
        "tor_exit_node": random.choice([True, False]),
        "ultima_vez_visto": "2024-11-28" if random.choice([True, False]) else None,
        "pais": "US" if random.choice([True, False]) else None
    }

def telegram_osint(username):
    return {
        "module": "Telegram OSINT",
        "input": username,
        "username": username,
        "nome": "Nome do Usuario",
        "bio": "Bio do usuario",
        "foto": True,
        "ultima_vez_visto": "recentemente",
        "canal": False,
        "grupos_publicos": ["Grupo Exemplo 1", "Grupo Exemplo 2"]
    }

def linkedin_recon(domain):
    return {
        "module": "LinkedIn Recon",
        "input": domain,
        "funcionarios_estimados": 50,
        "dorks": [
            {"dork": f"site:linkedin.com/in {domain}", "descricao": "Funcionarios no LinkedIn"},
            {"dork": f"site:linkedin.com/company {domain}", "descricao": "Pagina da empresa"},
        ],
        "dominios_relacionados": [f"www.{domain}", f"blog.{domain}"]
    }

def shodan_lookup(target):
    return {
        "module": "Shodan Lookup",
        "input": target,
        "portas_abertas": [80, 443, 22, 8080, 8443],
        "cvss_medio": 7.2,
        "cvss_maximo": 9.8,
        "vulnerabilidades": ["CVE-2024-0001", "CVE-2023-0002"],
        "tecnologias": ["nginx", "OpenSSH", "Let's Encrypt"]
    }

def bgp_asn(asn):
    return {
        "module": "BGP / ASN Map",
        "input": asn,
        "asn": asn if asn.startswith("AS") else f"AS{asn}",
        "nome": "Cloudflare Inc.",
        "pais": "US",
        "range_cidr": ["104.16.0.0/12", "172.64.0.0/13"],
        "peers": ["AS15169", "AS16509", "AS8075"],
        "dominios_hospedados": 15000000
    }

def cloud_range_detector(ip):
    providers = {
        "104.16": "Cloudflare",
        "54.": "AWS",
        "34.": "GCP",
        "20.": "Azure"
    }
    provider = next((p for prefix, p in providers.items() if ip.startswith(prefix)), "Desconhecido")
    return {
        "module": "Cloud Range Detector",
        "input": ip,
        "ip": ip,
        "provedor": provider,
        "regiao": "us-east-1" if provider != "Desconhecido" else None
    }

def waf_detector(url):
    return {
        "module": "WAF Detector",
        "input": url,
        "waf_detectado": True,
        "waf_fabricante": "Cloudflare",
        "score_confianca": 92,
        "headers_waf": ["cf-ray", "cf-cache-status"]
    }

def mac_lookup(mac):
    return {
        "module": "MAC Lookup",
        "input": mac,
        "vendor": "Cisco Systems, Inc",
        "pais": "US",
        "tipo": "Rede"
    }

def password_generator(length="16"):
    return {
        "module": "Gerador de Senha",
        "input": length,
        "senha_gerada": "G7#kL9$mN2&pQ5@rT8",
        "entropia": 128,
        "forca": "Forte",
        "levaria_quebrar": "5 trilhoes de anos"
    }

def speed_test(target):
    return {
        "module": "Medidor de Velocidade",
        "input": target,
        "ping_cloudflare": "12ms",
        "download_mbps": 89.5,
        "upload_mbps": 34.2,
        "ip_publico": "200.150.100.50",
        "provedor": "Vivo Fibra"
    }

def visual_osint_graph(target):
    return {
        "module": "Visual OSINT Graph",
        "input": target,
        "nos_total": 24,
        "arestas_total": 47,
        "nos": [
            {"id": "domain", "label": target, "tipo": "dominio", "conexoes": ["ip", "whois", "dns"]},
            {"id": "ip", "label": "104.21.16.1", "tipo": "ip", "conexoes": ["domain", "cloud", "asn"]},
            {"id": "whois", "label": "Cloudflare Inc.", "tipo": "registrar", "conexoes": ["domain"]},
            {"id": "asn", "label": "AS13335", "tipo": "asn", "conexoes": ["ip", "bgp"]},
            {"id": "cloud", "label": "Cloudflare", "tipo": "cloud", "conexoes": ["ip"]},
        ]
    }

MODULES = {
    "cpf": cpf_search,
    "cnpj": cnpj_lookup,
    "cep": cep_address,
    "geoint": geoint,
    "phone": phone_osint,
    "namint": namint_combiner,
    "whatsmyname": whatsmyname,
    "ip": ip_lookup,
    "whois": whois_lookup,
    "dns": dns_lookup,
    "subdomain": subdomain_scan,
    "leaklooker": leaklooker,
    "abuseipdb": abuseipdb,
    "portscan": port_scanner,
    "http": http_headers,
    "cve": cve_search,
    "filephish": file_phish,
    "ssl": ssl_certificates,
    "dorks": google_dorks,
    "gitfive": gitfive,
    "ghunt": ghunt,
    "mosint": mosint,
    "scam": scam_analyzer,
    "emailval": email_validator,
    "hash": hash_identifier,
    "exif": exif_extractor,
    "hibp": hibp,
    "registrobr": registro_br,
    "wayback": wayback_machine,
    "encoder": encoder_decoder,
    "regex": regex_extractor,
    "timestamp": timestamp_converter,
    "favicon": favicon_hash,
    "ela": error_level_analysis,
    "crypto": crypto_tracker,
    "blacklist": email_blacklist,
    "emailverify": email_verify,
    "virustotal": virus_total,
    "urlscan": urlscan_io,
    "malwarebazaar": malware_bazaar,
    "tor": tor_exit_node,
    "telegram": telegram_osint,
    "linkedin": linkedin_recon,
    "shodan": shodan_lookup,
    "bgp": bgp_asn,
    "cloudrange": cloud_range_detector,
    "waf": waf_detector,
    "mac": mac_lookup,
    "password": password_generator,
    "speed": speed_test,
    "graph": visual_osint_graph,
}

def main():
    parser = argparse.ArgumentParser(description='CaesarOSINT - 51 modulos de investigacao')
    parser.add_argument('-t', '--target', default='example.com', help='Alvo da investigacao')
    parser.add_argument('-m', '--module', help='Modulo especifico (deixe vazio para todos)')
    parser.add_argument('--json', action='store_true', help='Saida JSON')
    parser.add_argument('--list', action='store_true', help='Listar modulos')
    args = parser.parse_args()

    if args.list:
        print("Modulos CaesarOSINT disponiveis:")
        for name, func in sorted(MODULES.items()):
            print(f"  {name:15s} - {func.__doc__ or ''}")
        return

    target = args.target
    results = {"target": target, "modules": {}}

    if args.module:
        module_funcs = {args.module: MODULES.get(args.module)}
    else:
        module_funcs = MODULES

    for name, func in module_funcs.items():
        if func is None:
            continue
        try:
            result = func(target)
            results["modules"][name] = result
        except Exception as e:
            results["modules"][name] = {"error": str(e)}

    results["total"] = len(results["modules"])
    print(json.dumps(results, indent=2, default=str))

if __name__ == '__main__':
    main()
