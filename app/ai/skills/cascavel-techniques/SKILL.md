---
name: cascavel-arsenal
description: >-
  Comprehensive plugin arsenal for web application testing. 100+ techniques
  across injection, server-side, auth, protocol, defense bypass, API, cloud,
  recon, and infrastructure testing.
domain: web-application-security
subdomain: comprehensive
tags: [web-security, injection, ssrf, xss, sqli, recon, cloud]
mitre_attack: [T1190, T1059.007, T1213, T1552, T1611]
nist_csf: [ID.RA-01, DE.CM-01, PR.AC-01]
mitre_atlas: [AML.T0047]
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Injection & Code Execution (7 plugins)
XSS, SQLi, SSTI, RCE, Blind RCE, NoSQL, Log4Shell

## Server-Side Attacks (4 plugins)
SSRF (IMDSv2, DNS rebinding, gopher), XXE, LFI, Path Traversal

## Authentication & Authorization (6 plugins)
JWT (none alg, key confusion), OAuth, CSRF, IDOR, Session Fixation, Password Policy

## Protocol-Level Attacks (4 plugins)
HTTP Smuggling (CL-TE, TE-CL), HTTP/2 Smuggle, WebSocket, gRPC

## Defense Analysis & Bypass (7 plugins)
CORS, CSP Bypass, Clickjacking, Host Header, Cache Poisoning, Rate Limit, WAF Bypass

## API Security (4 plugins)
GraphQL Probe + Injection, API Enum, API Versioning

## Infrastructure (8 plugins)
Docker, K8s, Redis, MongoDB, Elastic, CI/CD, Cloud Metadata, Cloud Enum

## Recon & OSINT (11 plugins)
Subdomain, Subdomain Takeover, DNS Deep, DNS Rebinding, Network Mapper,
Email Harvester, Email Spoof, Shodan, Wayback, WHOIS, Traceroute
