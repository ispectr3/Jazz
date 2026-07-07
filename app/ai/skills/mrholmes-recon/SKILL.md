---
name: mrholmes-recon
description: >-
  Automated pentest reconnaissance. DNS scanning, HTTP security headers,
  subdomain discovery, port scanning, SSL/TLS analysis (protocols,
  ciphers), subdomain takeover, and NVD CVE lookup.
domain: osint
subdomain: reconnaissance
tags: [mrholmes, recon, ssl, dns, takeover, cve]
mitre_attack: [T1595]
nist_csf: [ID.AM-01, DE.CM-01]
mitre_atlas: []
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Description
Automated pentest reconnaissance tool integrating multiple scanning techniques.

## Capabilities
- DNS enumeration (A, AAAA, MX, NS, TXT, CNAME, SOA)
- HTTP security headers audit (6 headers)
- Technology fingerprinting (13 patterns)
- Subdomain discovery via Certificate Transparency
- Sensitive subdomain identification
- Port scanning (10 common ports)
- SSL cert expiry analysis
- TLS protocol version testing (1.0/1.1 detection)
- Weak cipher detection (RC4, DES, 3DES, MD5, export, null, anon)
- Subdomain takeover detection (13 cloud services)
- NVD CVE lookup

## Workflow
1. Run DNS enumeration
2. Fingerprint HTTP technologies
3. Discover subdomains
4. Scan ports and services
5. Analyze SSL/TLS configuration
6. Check subdomain takeover
7. Lookup CVEs from banners
