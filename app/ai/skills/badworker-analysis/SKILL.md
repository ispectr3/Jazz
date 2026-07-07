---
name: badworker-analysis
description: >-
  Web Worker security analysis. Static analysis of worker source code
  for importScripts injection, eval, postMessage origin validation,
  SSRF via dynamic fetch, and JSON.parse safety.
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

## Description
Static security analysis of Web Workers including blob, service, and shared workers.

## Capabilities
- importScripts injection detection (CWE-94)
- eval/Function constructor usage (CWE-95)
- postMessage origin validation (CWE-346)
- SSRF via dynamic fetch URL (CWE-918)
- JSON.parse without try/catch (CWE-755)
- Heuristic detection of embedded workers
- PoC generation per vulnerability class
- CVSS scoring and CWE mapping

## Workflow
1. Capture worker source code (blob, file, or inline)
2. Apply static pattern regexes
3. Classify findings by CWE and severity
4. Generate proof-of-concept exploits
5. Calculate security score

## Detection Patterns
- Dynamic importScripts: /importScripts\s*\(/
- eval: /\beval\s*\(/
- postMessage without origin: /self\.postMessage/
- Dynamic fetch: /fetch\s*\([^)]*\+/
