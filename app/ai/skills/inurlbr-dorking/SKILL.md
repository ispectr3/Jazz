---
name: inurlbr-dorking
description: >-
  Web dorking and crawling scanner. Probes sensitive paths, classifies
  URLs by dork patterns (SQLi, LFI, admin panels, secrets), and spiders
  linked pages for deeper discovery.
domain: web-application-security
subdomain: dorking
tags: [dorking, crawling, sensitive-paths, discovery, recon]
mitre_attack: [T1595]
nist_csf: [ID.AM-01]
mitre_atlas: []
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Description
Web dorking and crawling for sensitive path discovery and URL classification.

## Capabilities
- Crawls 50+ common sensitive paths
- URL classification by 13 dork patterns (SQL injection, LFI/RFI, Open Redirect, Admin Panels, WordPress, Credentials, Data Exposure, Sensitive Files, API endpoints, Search, Upload/Assets, Dynamic Endpoints)
- Spider-based link discovery
- Severity mapping based on category and HTTP status

## Dork Patterns
- SQL injection: /api/users?id=, /search?q=
- LFI/RFI: /index.php?file=, /include=
- Open Redirect: /redirect?next=, /goto?url=
- Admin panels: /admin, /dashboard, /wp-admin
- Credentials: /config, /.env, /backup
- API endpoints: /api, /graphql, /swagger

## Workflow
1. Start with target URL
2. Probe for sensitive paths
3. Spider linked pages
4. Classify findings by dork pattern
5. Prioritize by severity and exploitability
