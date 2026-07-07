---
name: maryam-osint
description: >-
  Maryam OSINT framework for reconnaissance. DNS enumeration, subdomain
  discovery (brute-force + crt.sh), and email discovery with SMTP
  verification.
domain: osint
subdomain: reconnaissance
tags: [maryam, osint, dns, subdomain, email, reconnaissance]
mitre_attack: [T1595]
nist_csf: [ID.AM-01]
mitre_atlas: []
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Description
Maryam OSINT framework for automated reconnaissance.

## Capabilities
- DNS record enumeration (A, AAAA, MX, NS, TXT, CNAME)
- Subdomain brute-force (20 common prefixes)
- Certificate Transparency subdomain discovery
- Email discovery from common username patterns (30+ users)
- SMTP-based email verification
- MX server identification

## Workflow
1. Run DNS enumeration on target domain
2. Brute-force common subdomains
3. Discover subdomains via Certificate Transparency
4. Discover email addresses from patterns
5. Verify emails via SMTP
6. Aggregate findings
