---
name: wasminator-analysis
description: >-
  WebAssembly (WASM) module security scanning. Risk scoring, module
  trust analysis, behavioral context detection, and CVE detection
  in WASM modules.
domain: web-application-security
subdomain: wasm-security
tags: [wasm, webassembly, module-analysis, cve, risk-scoring]
mitre_attack: [T1190]
nist_csf: [ID.RA-01, DE.CM-01]
mitre_atlas: []
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Description
WebAssembly security analysis using Wasminator. Scans WASM modules for vulnerabilities, calculates risk scores, and assesses module trustworthiness.

## Capabilities
- WASM module scanning and analysis
- Module risk scoring (0-100)
- Trust score per module
- Behavioral context analysis
- CVE detection in WASM modules
- Severity mapping (CRITICAL/HIGH/MEDIUM/LOW/SAFE)

## Workflow
1. Identify WASM modules on target page
2. Run Wasminator scanner on each module
3. Parse risk scores and findings
4. Cross-reference CVEs with module metadata
5. Generate trust assessment
