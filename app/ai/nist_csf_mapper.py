import re

CSF_MAPPINGS = [
    {
        "function": "Govern",
        "function_id": "GV",
        "category": "Organizational Context",
        "category_id": "GV.OC",
        "keywords": ["policy", "compliance", "regulatory", "gdpr", "lgpd", "sox", "pci"],
    },
    {
        "function": "Govern",
        "function_id": "GV",
        "category": "Risk Management Strategy",
        "category_id": "GV.RM",
        "keywords": ["risk assessment", "risk score", "risk management", "risk exposure"],
    },
    {
        "function": "Govern",
        "function_id": "GV",
        "category": "Roles and Responsibilities",
        "category_id": "GV.RR",
        "keywords": ["access control", "privilege", "permission", "role"],
    },
    {
        "function": "Identify",
        "function_id": "ID",
        "category": "Asset Management",
        "category_id": "ID.AM",
        "keywords": ["asset", "inventory", "porta aberta", "open port", "host", "domain",
                      "subdomain", "dns", "service discovery", "technology", "fingerprint"],
    },
    {
        "function": "Identify",
        "function_id": "ID",
        "category": "Risk Assessment",
        "category_id": "ID.RA",
        "keywords": ["vulnerability", "cve", "cvss", "cwe", "severity", "finding",
                      "vulnerabilidade", "weakness", "exposure"],
    },
    {
        "function": "Identify",
        "function_id": "ID",
        "category": "Improvement",
        "category_id": "ID.IM",
        "keywords": ["missing", "ausente", "falta", "not implemented", "nao implementado"],
    },
    {
        "function": "Protect",
        "function_id": "PR",
        "category": "Identity Management and Access Control",
        "category_id": "PR.AA",
        "keywords": ["authentication", "login", "password", "jwt", "oauth", "saml",
                      "mfa", "2fa", "session", "token", "credential", "default password",
                      "weak password", "brute force", "brute-force"],
    },
    {
        "function": "Protect",
        "function_id": "PR",
        "category": "Awareness and Training",
        "category_id": "PR.AT",
        "keywords": ["training", "awareness", "phishing", "social engineering"],
    },
    {
        "function": "Protect",
        "function_id": "PR",
        "category": "Data Security",
        "category_id": "PR.DS",
        "keywords": ["encryption", "tls", "ssl", "https", "hsts", "cipher", "certificate",
                      "data leak", "data exposure", "information disclosure", "directory listing",
                      "information disclosure", "sqli", "sql injection", "xss",
                      "cross-site scripting", "injection", "lfi", "rfi"],
    },
    {
        "function": "Protect",
        "function_id": "PR",
        "category": "Platform Security",
        "category_id": "PR.PS",
        "keywords": ["security header", "csp", "content-security-policy", "x-frame-options",
                      "x-content-type-options", "x-xss-protection", "referrer-policy",
                      "permissions-policy", "cors", "access-control", "cookie",
                      "secure flag", "httponly", "samesite"],
    },
    {
        "function": "Protect",
        "function_id": "PR",
        "category": "Technology Infrastructure Resilience",
        "category_id": "PR.IR",
        "keywords": ["backup", "redundancy", "failover", "disaster recovery", "cdn",
                      "cloudflare", "waf", "firewall", "rate limit", "rate-limiting"],
    },
    {
        "function": "Detect",
        "function_id": "DE",
        "category": "Continuous Monitoring",
        "category_id": "DE.CM",
        "keywords": ["monitoring", "logging", "audit", "scan", "scanner", "detection",
                      "waf bypass", "bypass", "waf detection"],
    },
    {
        "function": "Detect",
        "function_id": "DE",
        "category": "Adverse Event Analysis",
        "category_id": "DE.AE",
        "keywords": ["anomaly", "suspicious", "malicious", "attack vector", "exploit",
                      "payload", "exploitation"],
    },
    {
        "function": "Respond",
        "function_id": "RS",
        "category": "Incident Management",
        "category_id": "RS.MA",
        "keywords": ["incident", "response", "remediation", "mitigation", "patch"],
    },
    {
        "function": "Respond",
        "function_id": "RS",
        "category": "Incident Analysis",
        "category_id": "RS.AN",
        "keywords": ["analysis", "ai_analysis", "ai analysis", "critical finding",
                      "attack chain", "exploitation guide"],
    },
    {
        "function": "Recover",
        "function_id": "RC",
        "category": "Incident Recovery",
        "category_id": "RC.IM",
        "keywords": ["recover", "restore", "rollback", "recovery plan"],
    },
]


def map_finding(title: str, description: str = "") -> list[dict]:
    combined = f"{title} {description}".lower()
    matched = []
    seen = set()

    for mapping in CSF_MAPPINGS:
        for kw in mapping["keywords"]:
            if kw.lower() in combined:
                key = mapping["category_id"]
                if key not in seen:
                    matched.append({
                        "function": mapping["function"],
                        "function_id": mapping["function_id"],
                        "category": mapping["category"],
                        "category_id": mapping["category_id"],
                    })
                    seen.add(key)
                break

    return matched


def map_findings(findings: list[dict]) -> dict:
    result = {}
    for f in findings:
        mappings = map_finding(f.get("title", ""), f.get("description", ""))
        for m in mappings:
            func = m["function"]
            if func not in result:
                result[func] = {
                    "function_id": m["function_id"],
                    "categories": {},
                    "count": 0,
                }
            cat = m["category"]
            if cat not in result[func]["categories"]:
                result[func]["categories"][cat] = {
                    "category_id": m["category_id"],
                    "findings": [],
                }
            result[func]["categories"][cat]["findings"].append(f.get("title", ""))
            result[func]["count"] += 1

    return result
