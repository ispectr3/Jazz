---
name: ffuf-fuzzing
description: >-
  Web fuzzing using ffuf (Fuzz Faster U Fool). Directory brute-force,
  parameter fuzzing, and subdomain discovery with automatic wordlist
  management.
domain: web-application-security
subdomain: fuzzing
tags: [ffuf, fuzzing, directory-bruteforce, parameter-discovery, web]
mitre_attack: [T1046, T1595]
nist_csf: [ID.AM-01, DE.CM-01]
mitre_atlas: []
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Description
Ffuf is a fast web fuzzer for directory brute-force, parameter discovery, and subdomain enumeration.

## Capabilities
- Directory fuzzing with wordlists
- Parameter fuzzing (POST data)
- Subdomain fuzzing (Host header)
- Automatic wordlist discovery
- Status code and response size filtering

## Workflow
1. Directory fuzz: `ffuf -u target/FUZZ -w wordlist.txt`
2. Parameter fuzz: `ffuf -u target?FUZZ=test -w params.txt`
3. Parse JSON output for valid paths
4. Classify by HTTP status and response size

## Verification
- Valid HTTP status codes (100-599)
- URL presence
- Response size validation
