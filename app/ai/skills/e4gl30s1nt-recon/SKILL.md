---
name: e4gl30s1nt-recon
description: >-
  OSINT reconnaissance scanner. Subdomain discovery via crt.sh with
  probing, DNS enumeration, HTTP fingerprinting, port scanning, path
  discovery, subdomain takeover checks, and NVD CVE lookup.
domain: osint
subdomain: reconnaissance
tags: [osint, subdomain, dns, cve, takeover, reconnaissance]
mitre_attack: [T1595]
nist_csf: [ID.AM-01]
mitre_atlas: []
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Description
OSINT recon scanner inspired by E4GL30S1NT for comprehensive external reconnaissance.

## Capabilities
- Subdomain discovery via crt.sh with active probing
- DNS record enumeration (A, AAAA, MX, NS, TXT)
- HTTP technology fingerprinting via headers
- Port scanning (10 common ports)
- Sensitive path discovery
- Subdomain takeover detection (S3, GitHub Pages, Heroku, Azure, CloudFront, Netlify)
- NVD CVE lookup from server banners

## Workflow
1. Enumerate subdomains via crt.sh
2. Probe discovered subdomains
3. Fingerprint HTTP technologies
4. Scan common ports
5. Check for subdomain takeover
6. Lookup CVEs from banners
