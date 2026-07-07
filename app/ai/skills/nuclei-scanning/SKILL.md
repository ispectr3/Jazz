---
name: nuclei-scanning
description: >-
  Template-based vulnerability scanning using ProjectDiscovery Nuclei.
  Covers CVE, exposure, misconfig, default-login, technology, and
  infrastructure templates.
domain: web-application-security
subdomain: vulnerability-scanning
tags: [nuclei, cve, template-based, vulnerability, project-discovery]
mitre_attack: [T1190, T1046]
nist_csf: [ID.RA-01, DE.CM-01]
mitre_atlas: []
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Description
Nuclei is a fast template-based vulnerability scanner. It uses YAML templates to detect CVEs, misconfigurations, exposures, and technology-specific issues.

## Capabilities
- Template-based scanning (CVE, exposure, misconfig, config, default-login, tech)
- JSON-line output parsing
- Severity mapping (critical/high/medium/low/info)
- Multiple template tag selection

## Workflow
1. Select templates by tag: `nuclei -t cves/ -u target -json`
2. Parse JSON-line output
3. Match findings to CVE IDs and severity
4. Generate remediation guidance

## Verification
- Template ID presence
- Matched-at URL validation
- Severity consistency check
