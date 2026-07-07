---
name: hcxdumptool-wifi
description: >-
  Wi-Fi PMKID and handshake capture using hcxdumptool. Captures PMKID
  and WPA handshakes from wireless networks for offline cracking.
domain: wireless-security
subdomain: wifi-audit
tags: [hcxdumptool, wifi, pmkid, handshake, capture, wireless]
mitre_attack: [T1552.004]
nist_csf: [PR.AC-01]
mitre_atlas: []
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Description
Wi-Fi security auditing via hcxdumptool for PMKID and handshake capture.

## Capabilities
- PMKID capture detection and extraction
- WPA handshake capture detection
- PCAP file path association
- Capture type classification (PMKID vs handshake)

## Workflow
1. Run hcxdumptool to capture wireless traffic
2. Detect PMKID and handshake captures
3. Associate captures with BSSID/ESSID
4. Save captures for offline cracking (via hcxtools + hashcat)
5. Classify capture type
