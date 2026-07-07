---
name: nmap-scanning
description: >-
  Network port scanning and service detection using Nmap. Covers port
  discovery, service version detection, OS fingerprinting, and NSE scripts.
domain: network-security
subdomain: port-scanning
tags: [nmap, port-scan, service-detection, network, reconnaissance]
mitre_attack: [T1046]
nist_csf: [ID.AM-01, DE.CM-01]
mitre_atlas: []
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Description
Nmap is the industry standard network port scanner. This skill covers port discovery, service/version detection, OS fingerprinting using Nmap XML output.

## Capabilities
- Port scanning with configurable ports and flags
- Service version detection (-sV)
- OS fingerprinting
- XML output parsing into structured findings
- Async scan support with customizable flags

## Workflow
1. Run Nmap with service detection: `nmap -sV -oX output.xml target`
2. Parse XML output into findings
3. Classify severity by port and service
4. Cross-reference with CVE database

## Verification
- Valid port numbers (1-65535)
- Valid service-port mappings
- Valid port states (open/filtered/closed)
