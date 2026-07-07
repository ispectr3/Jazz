---
name: naabu-portscan
description: >-
  Fast port scanning using ProjectDiscovery Naabu. Scans 10 common
  ports with service identification and severity classification for
  exposed sensitive services.
domain: network-security
subdomain: port-scanning
tags: [naabu, port-scan, network, discovery, project-discovery]
mitre_attack: [T1046]
nist_csf: [ID.AM-01]
mitre_atlas: []
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Description
Fast port scanning via ProjectDiscovery Naabu for rapid service discovery.

## Capabilities
- Fast port scanning via Naabu
- 10 common ports (SSH, HTTP, HTTPS, HTTP-Proxy, MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch)
- Sensitive database port alerting
- Severity classification
- Timeout handling

## Ports Scanned
22 (SSH), 80 (HTTP), 443 (HTTPS), 8080 (HTTP-Proxy), 8443 (HTTPS-Alt), 3306 (MySQL), 5432 (PostgreSQL), 6379 (Redis), 27017 (MongoDB), 9200 (Elasticsearch)

## Workflow
1. Run Naabu against target
2. Parse open port results
3. Classify severity (database ports = high)
4. Feed to service-specific scanners
