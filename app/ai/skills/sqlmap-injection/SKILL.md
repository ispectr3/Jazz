---
name: sqlmap-injection
description: >-
  Automated SQL injection detection using sqlmap. Covers boolean-blind,
  time-blind, error-based, union, and stacked query techniques with
  database fingerprinting.
domain: web-application-security
subdomain: sql-injection
tags: [sqlmap, sqli, injection, database, boolean-blind, time-blind]
mitre_attack: [T1190]
nist_csf: [ID.RA-01, PR.AC-01]
mitre_atlas: []
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Description
SQLMap is the leading automated SQL injection tool. Detects and exploits SQL injection vulnerabilities with multiple techniques.

## Capabilities
- 5 injection techniques (boolean, time, error, union, stacked)
- Parameter-level vulnerability reporting
- Database fingerprint (DBMS type/version)
- HTTP method/data/cookie support
- Level and risk configuration

## Workflow
1. Identify injection point (parameter, header, cookie)
2. Run sqlmap: `sqlmap -u "target?id=1" --batch --output-dir=output`
3. Parse JSON output for vulnerable parameters
4. Classify by technique and DBMS

## Verification
- Payload contains SQLi keywords (' , or 1=1, union, select, sleep)
- Technique is valid (1-5 mapping)
- Parameter identified
