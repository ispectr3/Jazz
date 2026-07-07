---
name: badworker-static-patterns
description: >-
  Static analysis patterns for web worker security. CWE-94 dynamic importScripts,
  CWE-346 postMessage origin validation, CWE-95 eval usage, CWE-755 JSON.parse
  error handling, CWE-918 SSRF via fetch.
domain: web-application-security
subdomain: web-worker
tags: [worker, static-analysis, cwe, supply-chain, browser-security]
mitre_attack: [T1059.007, T1574.002]
nist_csf: [DE.CM-04]
mitre_atlas: []
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Static Pattern Table
| Pattern | Severity |
|---------|----------|
| Dynamic importScripts | HIGH |
| eval usage | HIGH |
| Function constructor | HIGH |
| Worker creation code | INFO |

## CWE-94: Dynamic importScripts
- CVSS: 7.5 (base) / 9.5 (critical)
- Arbitrary code execution in worker thread
- Detection: Regex with no validation guards

## CWE-346: postMessage without Origin
- CVSS: 5.3 (MEDIUM)
- Cross-origin data leakage
- Detection: self.postMessage > 0 and e.origin === 0

## CWE-95: eval/Function Constructor
- CVSS: 8.1 / 10.0 (critical)
- Remote code execution
- Detection: eval( or new Function(

## CWE-755: JSON.parse without Error Handling
- CVSS: 3.7 (LOW)
- DoS via worker crash
- Detection: JSON.parse( without try/catch

## CWE-918: SSRF via Dynamic fetch
- CVSS: 6.5 (MEDIUM)
- SSRF, internal network scanning
- Detection: fetch( with concatenated URL
