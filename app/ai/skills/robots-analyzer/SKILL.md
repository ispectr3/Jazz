---
name: robots-analyzer
description: >-
  robots.txt analysis for sensitive path discovery. Extracts disallowed
  paths, identifies exposed admin panels, backup directories, sitemaps,
  and hidden paths from robots.txt content.
domain: web-application-security
subdomain: reconnaissance
tags: [robots.txt, discovery, sensitive-paths, sitemap, recon]
mitre_attack: [T1595]
nist_csf: [ID.AM-01]
mitre_atlas: []
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Description
robots.txt analysis for discovering hidden or sensitive paths.

## Capabilities
- robots.txt presence detection
- Disallowed path extraction and classification
- Sitemap discovery
- Hidden path suggestion (paths likely sensitive but not blocked)
- Sensitive keyword scanning in raw content (admin, login, password, backup, internal, private)

## Workflow
1. Fetch /robots.txt from target
2. Parse Disallow, Allow, and Sitemap directives
3. Classify disallowed paths by sensitivity
4. Suggest additional paths not listed
5. Generate sitemap of discovered resources
