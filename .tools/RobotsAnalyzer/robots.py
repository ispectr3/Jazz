import json, argparse, urllib.robotparser, re

COMMON_PATHS = [
    "/admin", "/wp-admin", "/login", "/backup", "/.git", "/.env",
    "/config", "/api", "/internal", "/private", "/restricted",
    "/server-status", "/debug", "/phpinfo.php", "/uploads",
    "/manager", "/console", "/dashboard", "/cpanel",
]

def fetch_and_parse(domain):
    if not domain.startswith(("http://", "https://")):
        url = f"https://{domain}/robots.txt"
    else:
        url = f"{domain}/robots.txt"

    import requests
    result = {
        "target": domain,
        "robots_url": url,
        "encontrado": False,
        "codigo_http": 0,
        "disallows": [],
        "allows": [],
        "sitemaps": [],
        "caminhos_ocultos": [],
        "raw": "",
    }

    try:
        r = requests.get(url, timeout=8, headers={"User-Agent": "Mozilla/5.0 (compatible; JaizzNoir/1.0)"})
        result["codigo_http"] = r.status_code

        if r.status_code == 200:
            result["encontrado"] = True
            result["raw"] = r.text[:2000]

            rp = urllib.robotparser.RobotFileParser()
            rp.parse(r.text.splitlines())

            for line in r.text.splitlines():
                if line.lower().startswith("disallow"):
                    path = line.split(":", 1)[1].strip() if ":" in line else ""
                    if path and path != "/":
                        result["disallows"].append(path)
                elif line.lower().startswith("allow"):
                    path = line.split(":", 1)[1].strip() if ":" in line else ""
                    if path:
                        result["allows"].append(path)
                elif line.lower().startswith("sitemap"):
                    s = line.split(":", 1)[1].strip() if ":" in line else ""
                    if s:
                        result["sitemaps"].append(s)

            for path in COMMON_PATHS:
                if path not in result["disallows"]:
                    result["caminhos_ocultos"].append({
                        "path": path,
                        "provavelmente_excluido": rp.can_fetch("*", f"https://{domain}{path}")
                    })

    except requests.exceptions.ConnectionError:
        result["codigo_http"] = -1
        result["raw"] = "Erro de conexao"
    except Exception as e:
        result["raw"] = str(e)

    return result


def main():
    parser = argparse.ArgumentParser(description="Robots.txt Analyzer - JaizzNoir")
    parser.add_argument("-d", "--domain", required=True, help="Dominio alvo")
    parser.add_argument("--json", action="store_true", help="Saida JSON")
    args = parser.parse_args()

    result = fetch_and_parse(args.domain)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        domain = result["target"]
        if result["encontrado"]:
            print(f"[RobotsAnalyzer] robots.txt ENCONTRADO para {domain}")
            print(f"[+] Disallows: {len(result['disallows'])}")
            for d in result["disallows"][:10]:
                print(f"    Disallow: {d}")
            print(f"[+] Sitemaps: {len(result['sitemaps'])}")
            for s in result["sitemaps"][:5]:
                print(f"    Sitemap: {s}")
            print(f"[+] Caminhos sugeridos para scan:")
            for c in result["caminhos_ocultos"][:10]:
                status = "provavelmente acessivel" if c["provavelmente_excluido"] else "pode estar bloqueado"
                print(f"    {c['path']} ({status})")
        else:
            print(f"[-] robots.txt NAO ENCONTRADO para {domain} (HTTP {result['codigo_http']})")


if __name__ == "__main__":
    main()
