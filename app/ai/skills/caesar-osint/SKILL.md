---
name: caesar-osint
description: >-
  Comprehensive OSINT scanner. HTTP security headers, SSL/TLS, WAF
  detection, cloud provider ID, port scan, favicon hashing, DNS records,
  email auth (SPF/DMARC), crt.sh subdomains, Wayback Machine, WHOIS.
domain: osint
subdomain: reconnaissance
tags: [osint, ssl, dns, waf, cloud, reconnaissance]
mitre_attack: [T1595]
nist_csf: [ID.AM-01]
mitre_atlas: []
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Description
Comprehensive OSINT and reconnaissance scanner covering 15+ intelligence gathering techniques.

## Capabilities
- HTTP security header audit (HSTS, CSP, XFO, etc.)
- SSL cert expiry and weak cipher detection
- WAF fingerprinting (Cloudflare, AWS, Akamai, F5, Sucuri, Imperva, ModSecurity)
- Cloud provider identification (Cloudflare, AWS, GCP, Azure, Oracle)
- Port scanning (common ports)
- Sensitive path discovery
- Favicon mmh3 hashing for Shodan
- DNS record enumeration (A, AAAA, MX, NS, TXT, CNAME)
- SPF/DMARC email authentication audit
- Subdomain discovery via Certificate Transparency
- Wayback Machine URL history extraction
- WHOIS lookups
- Tor exit node detection
- Shodan vulnerability lookup

## Workflow
1. Run all recon modules against target
2. Aggregate findings by category
3. Cross-reference across modules (e.g., WAF + SSL + DNS)
4. Prioritize actionable intel
5. Feed to vulnerability scanning phase
