---
name: whatweb-fingerprinting
description: >-
  Technology fingerprinting using WhatWeb. Detects 100+ technologies
  across CDN, web servers, languages, frameworks, CMS, frontend,
  analytics, and cloud categories.
domain: web-application-security
subdomain: fingerprinting
tags: [whatweb, fingerprinting, technology-detection, recon, cms]
mitre_attack: [T1595]
nist_csf: [ID.AM-01]
mitre_atlas: []
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Description
WhatWeb is a technology fingerprinting engine detecting 100+ technologies across 17 categories.

## Capabilities
- CDN detection (Cloudflare, Akamai, Fastly)
- Web server identification (Nginx, Apache, IIS)
- Language/runtime detection (PHP, Python, Node.js, ASP.NET)
- Framework detection (Django, Laravel, Express, React)
- CMS detection (WordPress, Drupal, Joomla)
- Version extraction for major technologies
- Cookie and header-based fingerprinting

## Workflow
1. Run WhatWeb: `whatweb target --log-json=output.json`
2. Parse JSON output for technology matches
3. Cross-reference versions with CVE database
4. Feed technologies to CVE lookup phase

## Verification
- Technology name matches known technologies
- Version extraction validation
- Category classification
