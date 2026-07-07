---
name: hcxtools-hash
description: >-
  Hash extraction from Wi-Fi captures via hcxtools. Converts PMKID
  and WPA handshakes into Hashcat 22000 format for offline password
  cracking.
domain: wireless-security
subdomain: wifi-audit
tags: [hcxtools, hashcat, pmkid, handshake, cracking, wireless]
mitre_attack: [T1552.004]
nist_csf: [PR.AC-01]
mitre_atlas: []
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Description
Wi-Fi hash extraction via hcxtools for offline password cracking with Hashcat.

## Capabilities
- PMKID hash extraction ($PMKID* format)
- WPA handshake (WPAPSK) extraction
- Hashcat 22000 format support
- PCAP to hash conversion

## Workflow
1. Process PCAP captures from hcxdumptool
2. Extract PMKID hashes
3. Extract WPA handshakes
4. Convert to Hashcat 22000 format
5. Submit for offline cracking
