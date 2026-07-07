---
name: runtime-hooks-injection
description: >-
  Browser runtime security hooking. Generates JavaScript hooks for
  Worker, SharedWorker, ServiceWorker, Blob, and createObjectURL
  interception to detect malicious worker activity.
domain: web-application-security
subdomain: browser-security
tags: [runtime, hooks, worker, blob, browser-security, monitoring]
mitre_attack: [T1059.007, T1574.002]
nist_csf: [DE.CM-04, PR.PT-01]
mitre_atlas: []
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Description
Client-side JavaScript hook generation for runtime detection of Web Worker abuse.

## Capabilities
- Hook Worker, SharedWorker, ServiceWorker constructors
- Hook Blob constructor to capture inline worker source
- Hook URL.createObjectURL for blob URL tracking
- Detect crypto mining, data exfiltration, eval abuse
- Worker classification (blob-based vs URL-based)

## Workflow
1. Generate hook JavaScript
2. Inject into target page context
3. Monitor worker creation events
4. Analyze captured worker source code
5. Report suspicious patterns

## Detection Targets
- Crypto miners in blob workers
- Data exfiltration via service workers
- Clickjacking via shared workers
- Supply chain attacks via third-party scripts
- Anti-analysis evasion (self-deleting workers)
