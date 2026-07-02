# Cascavel Plugin Arsenal — Técnicas de Exploração

## Injection & Code Execution (7 plugins)
- **XSS**: Polyglot payloads, DOM-based, mutation XSS, WAF bypass, event handlers
- **SQLi**: Time-based, error-based, union-based, boolean blind, DBMS fingerprint
- **SSTI**: Jinja2, Twig, Mako, Freemarker, multi-engine polyglot payloads
- **RCE**: Command injection, OS detection, chained commands, encoding bypass
- **Blind RCE**: Time-based OOB detection, sleep injection, DNS callback
- **NoSQL**: MongoDB injection ($gt, $ne, $regex), JSON body injection
- **Log4Shell**: 12 headers, 5 WAF bypass payloads, Java fingerprint, OOB tokens

## Server-Side Attacks (4 plugins)
- **SSRF**: IMDSv2, DNS rebinding, gopher://, redirect chain, cloud metadata
- **XXE**: XML entity injection, OOB exfiltration, parameter entities
- **LFI**: Path traversal, null byte, double encoding, wrapper protocols
- **Path Traversal**: Directory traversal, encoding bypass, OS-specific paths

## Authentication & Authorization (6 plugins)
- **JWT**: None algorithm, key confusion (RS→HS), JWKS poisoning, claim analysis
- **OAuth**: PKCE enforcement, state validation, token leakage, redirect URI
- **CSRF**: Token validation, SameSite, origin header check
- **IDOR**: Sequential ID enumeration, UUID prediction, access control bypass
- **Session Fixation**: Cookie flags, session regeneration, pre-auth token
- **Password Policy**: Policy strength, common password testing, lockout

## Protocol-Level Attacks (4 plugins)
- **HTTP Smuggling**: CL-TE, TE-CL, TE-TE, H2.O desync, chunked mutation
- **HTTP/2 Smuggle**: HTTP/2 downgrade, continuation flood, HPACK injection
- **WebSocket**: CSWSH, origin bypass, message injection, upgrade detection
- **gRPC**: Reflection enabled, insecure channel, service enumeration

## Defense Analysis & Bypass (7 plugins)
- **CORS**: Wildcard origin, null origin, subdomain trust, credential exposure
- **CSP Bypass**: Unsafe-inline, unsafe-eval, data: URI, base-uri, *.cdn bypass
- **Clickjacking**: X-Frame-Options, CSP frame-ancestors, transparent overlay
- **Host Header**: Password reset poisoning, cache deception, SSRF via Host
- **Cache Poisoning**: Unkeyed headers, cache key normalization, fat GET
- **Rate Limit**: Brute force feasibility, IP rotation bypass, header spoofing
- **WAF Bypass**: Encoding mutation, chunked TE, case alternation, comment injection

## API Security (4 plugins)
- **GraphQL Probe**: Introspection enabled, field suggestion, type enumeration
- **GraphQL Injection**: Batch query, alias overload, nested depth, SQL in fields
- **API Enum**: Endpoint discovery, version detection, documentation exposure
- **API Versioning**: Deprecated version detection, v1 vs v2 comparison, OpenAPI

## Advanced Web Attacks (6 plugins)
- **Mass Assignment**: Hidden field injection, role escalation, isAdmin bypass
- **Race Condition**: TOCTOU, parallel request race, last-write-wins detection
- **Prototype Pollution**: __proto__, constructor pollution, JSON merge injection
- **Deserialization**: Java/PHP/Python/Ruby serialized objects, magic bytes
- **Open Redirect**: URL parameter manipulation, encoding bypass, scheme tricks
- **CRLF Injection**: Header injection, response splitting, log injection

## Infrastructure Exposure (8 plugins)
- **Docker**: Remote API (2375/2376), registry leak, socket exposure
- **K8s**: API server, etcd, kubelet, dashboard, service accounts
- **Redis**: Unauthenticated access, INFO dump, config get
- **MongoDB**: No-auth access, database listing, collection dump
- **Elastic**: Cluster health, index listing, Kibana dashboard
- **CI/CD**: Jenkins, GitLab CI, GitHub Actions, artifact exposure
- **Cloud Metadata**: AWS IMDS, GCP metadata, Azure IMDS, link-local bypass
- **Cloud Enum**: S3/GCS/Azure blob enumeration, DNS CNAME analysis

## Reconnaissance & OSINT (11 plugins)
- **Subdomain**: Certificate Transparency, DNS brute, zone transfer
- **Subdomain Takeover**: CNAME dangling, fingerprint matching, service detection
- **DNS Deep**: All record types (A/AAAA/MX/TXT/NS/SOA/SRV/CAA/DMARC)
- **DNS Rebinding**: TTL manipulation, private IP rebind, bypass detection
- **Network Mapper**: Live host detection, service enumeration, port profiling
- **Email Harvester**: Web scraping, SMTP VRFY, pattern generation
- **Email Spoof**: SPF, DKIM, DMARC validation, spoofability scoring
- **Shodan**: API-based recon, service fingerprint, CVE mapping
- **Wayback**: URL extraction, parameter discovery from Wayback Machine
- **WHOIS**: WHOIS/RDAP, domain age, registrar risk, privacy, DNSSEC, expiry
- **Traceroute**: Hop analysis, latency profiling, CDN/ISP detection, firewall

## Information Gathering (7 plugins)
- **Tech Fingerprint**: Wappalyzer-style, header/meta/script analysis
- **JS Analyzer**: API key extraction, endpoint discovery, source map detection
- **Param Miner**: Hidden parameter brute force, reflected parameter discovery
- **Info Disclosure**: .env, .git, backup files, debug endpoints, error messages
- **Secrets Scraper**: AWS/GCP/Azure keys, JWT, API tokens, passwords (regex)
- **Git Dumper**: .git directory enumeration, HEAD/config/refs extraction
- **Admin Finder**: Common admin paths, CMS-specific panels, status code analysis

## Web Scanning (7 plugins)
- **Dir Bruteforce**: Path enumeration, wordlist-based, status filtering
- **Nikto**: Nikto binary integration
- **Katana**: Automated deep crawling via Katana
- **HTTP Methods**: OPTIONS, TRACE, PUT, DELETE, PATCH testing
- **WP Scan**: WordPress-specific themes, plugins, user enumeration
- **Nuclei**: Template-based vulnerability scanning
- **Upload Detection**: PUT/PATCH method, WebDAV, extension acceptance

## Cloud & Storage (2 plugins)
- **S3 Bucket**: Public bucket detection, ACL misconfiguration, listing
- **SAML**: Signature wrapping, assertion injection, XML canonicalization

## Analysis & Profiling (6 plugins)
- **SSL**: Certificate validation, TLS version, cipher strength, HSTS
- **Security Headers**: CSP parsing, Information Disclosure detection
- **WAF Detection**: 30+ product fingerprint, bypass recommendations
- **Profiler**: Target profiling, technology stack, risk scoring
- **Nmap Advanced**: Service version, script scanning, OS fingerprint
- **Auto Exploit**: CVE matching, exploit suggestion based on versions

## Brute Force & Auth (6 plugins)
- **SSH Brute**: Paramiko-based, key auth detection
- **FTP Brute**: Anonymous login, credential testing, directory listing
- **SMB/AD**: Share enumeration, null session, AD recon
- **SMTP Enum**: VRFY/EXPN user enumeration, open relay
- **Heartbleed**: CVE-2014-0160, TLS heartbeat memory leak
- **Domain Transfer**: DNS zone transfer (AXFR) testing

## Additional Plugins (coverage expansion)
- **Adversary Simulation**: MITRE ATT&CK attack chain simulation
- **Blockchain/Web3**: RPC endpoints, smart contracts, DeFi vulns, MEV
- **Bluetooth**: BlueBorne, BLE misconfig, replay, KNOB
- **Broker SSRF Relay**: Kafka/RabbitMQ/Redis SSRF via HTTP
- **Cloud Ghosting**: Advanced IMDSv2 evasion
- **Cobalt Strike C2**: Framework detection (CS, Sliver, Empire, MSF)
- **Coerced Auth Web**: Coerced authentication via web vectors
- **Container Escape**: Docker/K8s escape techniques
- **Firmware**: Firmware endpoints, QEMU escapes, debug interfaces
- **Fuzzing Engine**: HTTP fuzzing (params, headers, body, path)
- **GraphQL AST Bomb**: Circular fragments causing O(2^N) DoS
- **HTTP/2 Rapid Reset**: CVE-2023-44487, HPACK bombing
- **HTTP/3 QUIC**: Downgrade attacks, QUIC misconfig
- **ICS/SCADA**: Modbus, DNP3, BACnet, Siemens S7, OPC UA
- **OIDC Poisoning**: OpenID Connect token manipulation
- **Printer Exploit**: PJL, PostScript, LPD vulnerabilities
- **Supply Chain**: Dependency confusion, malicious packages
- **Web3 RPC**: Ethereum RPC exposure, JSON-RPC attack vectors
- **Wireless**: Rogue AP, deauth, WPA2 enterprise attacks
- **Zero Trust Validation**: Validate Zero Trust architecture controls
