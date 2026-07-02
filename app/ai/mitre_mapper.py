"""
mitre_mapper.py — MITRE ATT&CK v19.1 Mapping Engine

Mapeia findings do Jaizz Noir para tecnicas MITRE ATT&CK Enterprise.
Baseado no padrao do Anthropic-Cybersecurity-Skills (mukul975).

Uso:
    mapper = MitreMapper()
    techniques = mapper.classify("SQL Injection", "Error-based via id param")
    # -> [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "TA0001"}]
"""

import re

ATTACK_MAPPINGS = [
    # Initial Access (TA0001)
    {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "TA0001",
        "tactic_name": "Initial Access",
        "keywords": ["sqli", "sql injection", "rce", "ssrf", "lfi", "command injection", "ssti",
                      "log4shell", "jndi", "heartbleed", "path traversal"],
    },
    {
        "id": "T1133",
        "name": "External Remote Services",
        "tactic": "TA0001",
        "tactic_name": "Initial Access",
        "keywords": ["vpn", "rdp", "ssh exposure", "remote access", "docker api", "docker socket",
                      "k8s api", "redis unauth", "mongodb unauth", "elasticsearch exposed"],
    },
    {
        "id": "T1195",
        "name": "Supply Chain Compromise",
        "tactic": "TA0001",
        "tactic_name": "Initial Access",
        "keywords": ["dependency confusion", "supply chain", "malicious package", "npm hijack",
                      "pypi hijack"],
    },
    {
        "id": "T1566",
        "name": "Phishing",
        "tactic": "TA0001",
        "tactic_name": "Initial Access",
        "keywords": ["phishing", "social engineering", "coerced auth"],
    },
    {
        "id": "T1078.001",
        "name": "Default Accounts",
        "tactic": "TA0001",
        "tactic_name": "Initial Access",
        "keywords": ["default credential", "default password", "password policy", "weak password"],
    },
    {
        "id": "T1199",
        "name": "Trusted Relationship",
        "tactic": "TA0001",
        "tactic_name": "Initial Access",
        "keywords": ["oauth misconfig", "oauth redirect", "oidc poisoning", "saml bypass",
                      "saml signature wrapping", "jwt none algorithm", "jwt key confusion"],
    },
    {
        "id": "T1091",
        "name": "Replication Through Removable Media",
        "tactic": "TA0001",
        "tactic_name": "Initial Access",
        "keywords": ["bluetooth", "blueborne", "wireless attack", "rogue ap"],
    },
    # Execution (TA0002)
    {
        "id": "T1059.007",
        "name": "Command and Scripting Interpreter: JavaScript",
        "tactic": "TA0002",
        "tactic_name": "Execution",
        "keywords": ["xss", "cross-site scripting", "javascript", "dom-based", "mutation xss",
                      "polyglot xss"],
    },
    {
        "id": "T1203",
        "name": "Exploitation for Client Execution",
        "tactic": "TA0002",
        "tactic_name": "Execution",
        "keywords": ["rce", "remote code execution", "deserialization", "java deserialize",
                      "php deserialize", "python pickle"],
    },
    {
        "id": "T1059.008",
        "name": "Network Device CLI",
        "tactic": "TA0002",
        "tactic_name": "Execution",
        "keywords": ["command injection", "os command", "blind rce", "dns callback"],
    },
    # Persistence (TA0003)
    {
        "id": "T1525",
        "name": "Implant Internal Image",
        "tactic": "TA0003",
        "tactic_name": "Persistence",
        "keywords": ["backdoor", "webshell", "persistence", "cron", "fast webshell", "wp admin"],
    },
    {
        "id": "T1098",
        "name": "Account Manipulation",
        "tactic": "TA0003",
        "tactic_name": "Persistence",
        "keywords": ["account takeover", "ato", "privilege escalation", "mass assignment",
                      "isadmin bypass", "role escalation"],
    },
    {
        "id": "T1505.003",
        "name": "Web Shell",
        "tactic": "TA0003",
        "tactic_name": "Persistence",
        "keywords": ["webshell", "w shell", "file upload", "put method", "webdav"],
    },
    # Privilege Escalation (TA0004)
    {
        "id": "T1611",
        "name": "Escape to Host",
        "tactic": "TA0004",
        "tactic_name": "Privilege Escalation",
        "keywords": ["container escape", "docker escape", "privileged pod", "container escape"],
    },
    {
        "id": "T1548",
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "TA0004",
        "tactic_name": "Privilege Escalation",
        "keywords": ["sudo bypass", "suid", "capability abuse"],
    },
    # Defense Evasion (TA0005)
    {
        "id": "T1550",
        "name": "Use Alternate Authentication Material",
        "tactic": "TA0005",
        "tactic_name": "Defense Evasion",
        "keywords": ["pass-the-hash", "pass-the-ticket", "silver ticket", "golden ticket"],
    },
    {
        "id": "T1027",
        "name": "Obfuscated Files or Information",
        "tactic": "TA0005",
        "tactic_name": "Defense Evasion",
        "keywords": ["encoding bypass", "double encoding", "unicode obfuscation", "base64",
                      "waf bypass", "chunked transfer encoding"],
    },
    {
        "id": "T1562.001",
        "name": "Disable or Modify Tools",
        "tactic": "TA0005",
        "tactic_name": "Defense Evasion",
        "keywords": ["rate limit bypass", "ip rotation", "header spoofing", "waf detection"],
    },
    # Credential Access (TA0006)
    {
        "id": "T1552",
        "name": "Unsecured Credentials",
        "tactic": "TA0006",
        "tactic_name": "Credential Access",
        "keywords": ["api key", "secret leak", "credential leak", "password", ".env", "token leak",
                      "aws key", "gcp key", "azure key", "secrets scraper"],
    },
    {
        "id": "T1539",
        "name": "Steal Web Session Cookie",
        "tactic": "TA0006",
        "tactic_name": "Credential Access",
        "keywords": ["session hijacking", "cookie theft", "session token", "session fixation",
                      "cookie flags"],
    },
    {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "TA0006",
        "tactic_name": "Credential Access",
        "keywords": ["brute force", "ssh brute", "ftp brute", "password spray", "credential stuffing",
                      "smtp enum", "vrfy", "expn"],
    },
    {
        "id": "T1555",
        "name": "Credentials from Password Stores",
        "tactic": "TA0006",
        "tactic_name": "Credential Access",
        "keywords": ["password manager", "keychain", "credential dump"],
    },
    {
        "id": "T1528",
        "name": "Steal Application Access Token",
        "tactic": "TA0006",
        "tactic_name": "Credential Access",
        "keywords": ["jwt leak", "oauth token", "access token", "jwks poisoning"],
    },
    # Discovery (TA0007)
    {
        "id": "T1082",
        "name": "System Information Discovery",
        "tactic": "TA0007",
        "tactic_name": "Discovery",
        "keywords": ["osint", "recon", "fingerprint", "dns recon", "subdomain", "shodan",
                      "wayback", "whois", "tech fingerprint", "dns deep", "traceroute",
                      "network mapper", "subdomain hunter"],
    },
    {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "TA0007",
        "tactic_name": "Discovery",
        "keywords": ["port scan", "service discovery", "nmap", "naabu", "dir bruteforce",
                      "admin finder", "api enum"],
    },
    {
        "id": "T1217",
        "name": "Exploitation for Credential Access",
        "tactic": "TA0007",
        "tactic_name": "Discovery",
        "keywords": ["param miner", "js analyzer", "git dumper", "info disclosure"],
    },
    # Lateral Movement (TA0008)
    {
        "id": "T1021",
        "name": "Remote Services",
        "tactic": "TA0008",
        "tactic_name": "Lateral Movement",
        "keywords": ["lateral movement", "pivoting", "pivot", "smb", "ssh", "winrm"],
    },
    {
        "id": "T1210",
        "name": "Exploitation of Remote Services",
        "tactic": "TA0008",
        "tactic_name": "Lateral Movement",
        "keywords": ["smb exploit", "eternal blue", "ms17-010"],
    },
    # Collection (TA0009)
    {
        "id": "T1213",
        "name": "Data from Information Repositories",
        "tactic": "TA0009",
        "tactic_name": "Collection",
        "keywords": ["idor", "bola", "data exposure", "information disclosure", "directory listing",
                      "s3 bucket", "cloud enum", "elasticsearch index"],
    },
    # Exfiltration (TA0010)
    {
        "id": "T1048",
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "TA0010",
        "tactic_name": "Exfiltration",
        "keywords": ["data exfiltration", "data leak", "exfil", "dns exfil"],
    },
    {
        "id": "T1537",
        "name": "Transfer Data to Cloud Account",
        "tactic": "TA0010",
        "tactic_name": "Exfiltration",
        "keywords": ["s3 bucket exfil", "cloud storage leak", "public bucket"],
    },
    # Command and Control (TA0011)
    {
        "id": "T1071.001",
        "name": "Web Protocols",
        "tactic": "TA0011",
        "tactic_name": "Command and Control",
        "keywords": ["c2", "beaconing", "callbacks", "cobalt strike", "sliver", "empire"],
    },
    {
        "id": "T1573",
        "name": "Encrypted Channel",
        "tactic": "TA0011",
        "tactic_name": "Command and Control",
        "keywords": ["tls fingerprint", "ssl check", "https tunnel"],
    },
    # Impact (TA0040)
    {
        "id": "T1485",
        "name": "Data Destruction",
        "tactic": "TA0040",
        "tactic_name": "Impact",
        "keywords": ["ransomware", "data destruction", "wiper", "cryptominer", "wasm miner"],
    },
    {
        "id": "T1498",
        "name": "Network Denial of Service",
        "tactic": "TA0040",
        "tactic_name": "Impact",
        "keywords": ["dos", "ddos", "graphql dos", "http2 rapid reset", "hpack bomb",
                      "graphql ast bomb", "race condition", "toctou"],
    },
    {
        "id": "T1496",
        "name": "Resource Hijacking",
        "tactic": "TA0040",
        "tactic_name": "Impact",
        "keywords": ["cryptominer", "wasm miner", "crypto mining", "resource hijack"],
    },
    # Additional specific techniques from Cascavel
    {
        "id": "T1557.001",
        "name": "LLMNR/NBT-NS Poisoning and SMB Capture",
        "tactic": "TA0006",
        "tactic_name": "Credential Access",
        "keywords": ["smb capture", "responder", "llmnr", "net-ntlm"],
    },
    {
        "id": "T1204.001",
        "name": "User Execution: Malicious Link",
        "tactic": "TA0002",
        "tactic_name": "Execution",
        "keywords": ["csrf", "cross-site request forgery", "xsrf", "clickjacking",
                      "open redirect", "url redirect"],
    },
    {
        "id": "T1574.002",
        "name": "DLL Side-Loading",
        "tactic": "TA0005",
        "tactic_name": "Defense Evasion",
        "keywords": ["dll hijack", "dll sideload", "binary planting"],
    },
    {
        "id": "T1547",
        "name": "Boot or Logon Autostart Execution",
        "tactic": "TA0003",
        "tactic_name": "Persistence",
        "keywords": ["auto-start", "registry run", "launchd", "startup folder"],
    },
    {
        "id": "T1499",
        "name": "Endpoint Denial of Service",
        "tactic": "TA0040",
        "tactic_name": "Impact",
        "keywords": ["fuzzing", "fuzz engine", "http fuzzing"],
    },
    {
        "id": "T1600",
        "name": "Weaken Encryption",
        "tactic": "TA0005",
        "tactic_name": "Defense Evasion",
        "keywords": ["ssl weak cipher", "tls downgrade", "https downgrade", "http3 downgrade"],
    },
    {
        "id": "T1583",
        "name": "Acquire Infrastructure",
        "tactic": "TA0042",
        "tactic_name": "Resource Development",
        "keywords": ["domain registration", "subdomain takeover", "cname dangling",
                      "dns zone transfer"],
    },
    {
        "id": "T1580",
        "name": "Cloud Infrastructure Discovery",
        "tactic": "TA0007",
        "tactic_name": "Discovery",
        "keywords": ["cloud metadata", "imds", "aws metadata", "gcp metadata", "azure imds",
                      "cloud enum", "cloud storage", "s3", "gcs", "azure blob"],
    },
    {
        "id": "T1613",
        "name": "Container and Resource Discovery",
        "tactic": "TA0007",
        "tactic_name": "Discovery",
        "keywords": ["docker", "k8s", "kubernetes", "kubelet", "etcd", "container discovery"],
    },
    {
        "id": "T1526",
        "name": "Cloud Service Discovery",
        "tactic": "TA0007",
        "tactic_name": "Discovery",
        "keywords": ["cloud service", "saas discovery", "api enumeration", "api versioning"],
    },
    {
        "id": "T1546",
        "name": "Event Triggered Execution",
        "tactic": "TA0003",
        "tactic_name": "Persistence",
        "keywords": ["prototype pollution", "proto pollution", "constructor pollution"],
    },
    {
        "id": "T1192",
        "name": "Spearphishing Link",
        "tactic": "TA0001",
        "tactic_name": "Initial Access",
        "keywords": ["phishing simulation", "email spoof", "spf", "dkim", "dmarc"],
    },
]


class MitreMapper:
    def __init__(self):
        self.mappings = ATTACK_MAPPINGS

    def classify(self, title: str, description: str) -> list[dict]:
        text = f"{title} {description}".lower()
        matched = []
        seen_ids = set()
        for m in self.mappings:
            if any(k in text for k in m["keywords"]):
                if m["id"] not in seen_ids:
                    seen_ids.add(m["id"])
                    matched.append({
                        "id": m["id"],
                        "name": m["name"],
                        "tactic": m["tactic"],
                        "tactic_name": m["tactic_name"],
                    })
        return matched

    def enrich_finding(self, finding: dict) -> dict:
        techniques = self.classify(
            finding.get("title", ""),
            finding.get("description", ""),
        )
        if techniques:
            finding["mitre_attack"] = techniques
        return finding

    def enrich_batch(self, findings: list[dict]) -> list[dict]:
        return [self.enrich_finding(f) for f in findings]

    def format_for_prompt(self, findings: list[dict]) -> str:
        enriched = self.enrich_batch(findings)
        parts = ["### MITRE ATT&CK Mappings"]
        for f in enriched:
            techs = f.get("mitre_attack", [])
            if techs:
                tech_str = "; ".join(f"{t['id']} {t['name']} ({t['tactic_name']})" for t in techs)
                parts.append(f"- {f.get('title', '?')}: {tech_str}")
        if len(parts) == 1:
            return ""
        return "\n".join(parts)
