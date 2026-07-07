---
name: csrf-detection
description: >-
  CSRF (Cross-Site Request Forgery) detection. Analyzes HTML forms
  for missing CSRF tokens, identifies AJAX/API endpoints lacking
  CSRF header protection.
domain: web-application-security
subdomain: csrf
tags: [csrf, cross-site-request-forgery, forms, tokens, api]
mitre_attack: [T1204.001]
nist_csf: [PR.AC-01, DE.CM-01]
mitre_atlas: []
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Description
CSRF detection through HTML form analysis and API endpoint inspection.

## Capabilities
- Form analysis for CSRF token presence
- CSRF token name pattern matching (csrf, _token, authenticity_token)
- Sensitive action detection (password changes, deletions, payments)
- AJAX/API endpoint CSRF header checking
- Proxy support for authenticated scanning

## Workflow
1. Fetch target page with forms
2. Parse HTML for form elements
3. Check each form for CSRF token field
4. Identify sensitive actions (POST/PUT/DELETE without token)
5. Flag API endpoints lacking CSRF headers

## Mitigation
- CSRF tokens on all state-changing operations
- SameSite cookie attribute (Strict/Lax)
- Custom request headers for API endpoints
