---
name: wifite2-wireless
description: >-
  Automated Wi-Fi security auditing via Wifite2. Scans for wireless
  networks, identifies BSSID/ESSID/channel/encryption type (WPA/WEP/
  OPEN), and assesses network security posture.
domain: wireless-security
subdomain: wifi-audit
tags: [wifite2, wifi, wireless, wpa, wep, audit]
mitre_attack: [T1552.004]
nist_csf: [PR.AC-01]
mitre_atlas: []
version: "1.0"
author: Jaizz Noir
license: Apache-2.0
---

## Description
Automated Wi-Fi security auditing via Wifite2 for wireless network discovery and assessment.

## Capabilities
- Wireless scan output parsing
- BSSID/ESSID extraction
- Channel identification
- Encryption type detection (WPA, WEP, OPEN)
- Numeric sorting of discovered networks

## Workflow
1. Run Wifite2 scan
2. Parse output for discovered networks
3. Extract BSSID, ESSID, channel, encryption
4. Classify networks by security (WPA=medium, WEP=high, OPEN=critical)
5. Generate wireless security report
