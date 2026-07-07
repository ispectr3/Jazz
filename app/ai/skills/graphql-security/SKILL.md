---
name: graphql-security
description: >-
  GraphQL API security testing. Introspection queries, dangerous
  operations discovery, batching attacks, depth-based DoS, and alias
  abuse for rate-limit bypass.
domain: web-application-security
subdomain: api-security
tags: [graphql, api, introspection, injection, dos]
mitre_attack: [T1190, T1498]
nist_csf: [ID.RA-01, PR.AC-01]
mitre_atlas: []
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Description
GraphQL API security testing covering introspection, dangerous operations, batching attacks, and depth-based DoS.

## Capabilities
- Introspection query detection
- Dangerous operation discovery (delete, drop, admin mutations)
- Batching attack detection
- Query depth attack (DoS via circular fragments)
- Alias abuse detection (rate-limit bypass)

## Workflow
1. Send introspection query to /graphql endpoint
2. Analyze schema for dangerous mutations
3. Test batching attacks: `[{"query":"..."},{"query":"..."}]`
4. Test depth: deeply nested queries
5. Test alias abuse: multiple aliases for same query

## Verification
- Introspection enabled/disabled
- Dangerous operations found
- Depth limits enforced
- Rate limiting on batched queries
