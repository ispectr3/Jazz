---
name: jwt-attacks
description: >-
  JWT security testing via jwt_tool. Covers none algorithm, algorithm
  confusion (RS-to-HS), secret brute-force, KID injection, JKU/SSRF,
  and JWK injection attacks.
domain: web-application-security
subdomain: authentication
tags: [jwt, token, authentication, algorithm-confusion, injection]
mitre_attack: [T1190, T1213]
nist_csf: [PR.AC-01, DE.CM-01]
mitre_atlas: []
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Description
JWT (JSON Web Token) security testing covering all major attack vectors using jwt_tool.

## Capabilities
- None algorithm attack (alg:none)
- Algorithm confusion (RS256 to HS256)
- Secret brute-force
- KID injection (path traversal, SQLi)
- JKU injection/SSRF
- JWK injection

## Workflow
1. Capture JWT token from request
2. Test none algorithm: modify alg to "none"
3. Test algorithm confusion: RS256->HS256 with public key
4. Brute-force secret: `jwt_tool token.txt -C -d wordlist.txt`
5. Test KID injection: `kid: "../../../etc/passwd"`
6. Test JKU injection: point to attacker-controlled JWK set

## Verification
- Token accepted with alg:none
- Token verified with wrong algorithm
- Secret cracked
- KID/JKU injection successful
