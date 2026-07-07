---
name: waf-bypass
description: >-
  WAF bypass technique testing with 6 encoding levels. URL encode,
  double URL, HTML entities, hex, Unicode, base64, tab injection,
  tag alternatives, and JS keyword alternatives.
domain: web-application-security
subdomain: waf-bypass
tags: [waf, bypass, encoding, obfuscation, injection, xss, sqli]
mitre_attack: [T1059.007, T1190]
nist_csf: [DE.CM-01]
mitre_atlas: [AML.T0047]
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Description
WAF bypass testing with 6 levels of encoding and obfuscation techniques.

## Capabilities
- 6-level bypass payload generation (URL, double URL, HTML entities, hex, Unicode, base64)
- Tag alternatives (script -> img/svg/body/details/form/math)
- JS keyword alternatives (eval->Function/setTimeout, alert->prompt/confirm)
- Payload reflection detection
- Severity escalation by bypass level

## Techniques
Level 1: URL encoding
Level 2: Double URL encoding
Level 3: HTML entity encoding
Level 4: Hex/Unicode encoding
Level 5: Base64 encoding
Level 6: Combined obfuscation

## Workflow
1. Identify WAF (detect blocking behavior)
2. Start at Level 1 encoding
3. If blocked, escalate to next level
4. Try tag alternatives if encoding fails
5. Try JS keyword alternatives
6. Document which level/technique bypassed WAF
