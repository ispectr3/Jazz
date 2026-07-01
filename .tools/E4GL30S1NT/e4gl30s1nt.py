import json, argparse

def main():
    parser = argparse.ArgumentParser(description='E4GL30S1NT Mock - OSINT Scanner')
    parser.add_argument('-d', '--domain', help='Domain alvo')
    parser.add_argument('--api', action='store_true', help='Saida JSON')
    args, _ = parser.parse_known_args()

    if args.api:
        output = {
            "domain": args.domain,
            "ips": [f"192.168.{i}.{j}" for i in range(1,3) for j in range(1,3)],
            "subdomains": [f"{s}.{args.domain}" for s in ["mail","dev","admin","beta","cdn","api","vpn","ns1","ns2"]],
            "emails": [f"{u}@{args.domain}" for u in ["contact","admin","webmaster","support","info","billing","abuse","security"]],
            "technologies": ["nginx 1.24", "PHP 8.2", "MySQL 8.0", "Cloudflare", "Let's Encrypt"],
            "asn_org": "Cloudflare Inc.",
            "ports_open": [22, 80, 443, 8080, 8443],
            "vulnerabilities": [
                {"type": "Missing Security Headers", "endpoint": f"https://{args.domain}/"},
                {"type": "Directory Listing Enabled", "endpoint": f"https://{args.domain}/assets/"},
                {"type": "SSL Certificate Expiring Soon", "endpoint": f"https://{args.domain}/"}
            ]
        }
        print(json.dumps(output, indent=2))
    else:
        print(f"[E4GL30S1NT] Scanning target: {args.domain}")
        print(f"[+] Subdomains found: 9")
        print(f"[+] Emails found: 8")
        print(f"[+] Open ports: 5")

if __name__ == '__main__':
    main()
