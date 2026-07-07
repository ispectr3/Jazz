---
name: supabomb-analysis
description: >-
  Supabase security scanning. Detects exposed credentials, accessible
  tables, RPC functions, public storage buckets, and performs data
  dumping via Supabomb.
domain: cloud-security
subdomain: supabase
tags: [supabase, cloud, database, credentials, storage]
mitre_attack: [T1552, T1213]
nist_csf: [ID.RA-01, PR.AC-01]
mitre_atlas: []
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Description
Supabase project security testing. Scans for exposed credentials, misconfigured access controls, and publicly accessible data.

## Capabilities
- Supabase credential extraction
- Table enumeration and exposure detection
- RPC function discovery
- Public storage bucket identification
- Data dumping capabilities
- Write permission testing

## Workflow
1. Identify Supabase project URL
2. Test for exposed anon/public keys
3. Enumerate accessible tables and schemas
4. Discover exposed RPC functions
5. Check storage bucket permissions
6. Attempt data extraction from public resources
