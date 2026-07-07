---
name: runtime-api-hooks
description: >-
  Browser runtime API hooking for security monitoring. Hook Blob, URL,
  Worker, ServiceWorker, SharedWorker constructors to detect malicious
  worker creation, crypto miners, and data exfiltration.
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

## Hook Table

| Hook | Target | Purpose |
|------|--------|---------|
| window.Blob | Blob constructor | Capture inline worker source |
| window.URL.createObjectURL | URL factory | Map blob URLs to source |
| window.Worker | Worker constructor | Detect blob workers |
| navigator.serviceWorker.register | SW registration | Track service workers |
| window.SharedWorker | SharedWorker | Track shared workers |

## Use Cases
### Malicious Worker Detection
- Crypto miners via Blob workers
- Data exfiltration via service workers intercepting fetch/XHR
- Clickjacking via shared workers

### Supply Chain Attack Detection
- Third-party scripts creating hidden workers
- CDN compromise leading to worker injection

### Anti-Analysis Evasion
- Malware creating workers from Blob URLs
- Self-deleting workers
