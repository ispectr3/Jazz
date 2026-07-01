import json, argparse

def main():
    parser = argparse.ArgumentParser(description='Mr.Holmes Mock - Pentest Recon Suite')
    parser.add_argument('-d', '--domain', help='Domain alvo')
    parser.add_argument('--json', action='store_true', help='Saida JSON')
    parser.add_argument('--quiet', action='store_true')
    parser.add_argument('--dns', action='store_true', help='DNS recon')
    parser.add_argument('--subdomains', action='store_true')
    args, _ = parser.parse_known_args()

    output = {
        "target": args.domain,
        "dns": {
            "a_records": [f"203.0.113.{i}" for i in range(1,5)],
            "mx_records": [f"mail{i}.{args.domain}" for i in range(1,4)],
            "ns_records": [f"ns{i}.{args.domain}" for i in range(1,3)],
            "txt_records": ["v=spf1 include:_spf.google.com ~all"],
            "soa": f"ns1.{args.domain}. admin.{args.domain}. 2024010101"
        },
        "subdomains": [
            {"name": f"www.{args.domain}", "ip": "203.0.113.1", "status": 200},
            {"name": f"mail.{args.domain}", "ip": "203.0.113.2", "status": 200},
            {"name": f"admin.{args.domain}", "ip": "203.0.113.3", "status": 403},
            {"name": f"dev.{args.domain}", "ip": "203.0.113.4", "status": 200},
            {"name": f"blog.{args.domain}", "ip": "203.0.113.1", "status": 301},
            {"name": f"api.{args.domain}", "ip": "203.0.113.5", "status": 401},
            {"name": f"cdn.{args.domain}", "ip": "203.0.113.6", "status": 200},
            {"name": f"vpn.{args.domain}", "ip": "203.0.113.7", "status": 200},
            {"name": f"staging.{args.domain}", "ip": "203.0.113.8", "status": 200},
            {"name": f"webmail.{args.domain}", "ip": "203.0.113.9", "status": 200},
            {"name": f"remote.{args.domain}", "ip": "203.0.113.10", "status": 200},
            {"name": f"support.{args.domain}", "ip": "203.0.113.11", "status": 200}
        ],
        "http_scan": {
            "status_codes": {200: 8, 301: 1, 401: 1, 403: 1, 404: 12},
            "technologies": ["Cloudflare", "Nginx", "PHP", "MySQL"],
            "security_headers": {"missing": ["X-Content-Type-Options", "Strict-Transport-Security"]}
        }
    }

    if args.json:
        print(json.dumps(output, indent=2))
    else:
        print(f"[Mr.Holmes] Recon on {args.domain}")
        print(f"[+] DNS records: {len(output['dns'])} types")
        print(f"[+] Subdomains: {len(output['subdomains'])}")

if __name__ == '__main__':
    main()
