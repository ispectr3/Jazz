# Runtime API Hooks (Browser Security)

> **CAMADA=IA | DOMINIO=WEB, Supply Chain | SEGURANCA=Runtime Monitoring, Worker Detection | PILARES=8/8**

## Hook Table

| Hook | Target | Purpose |
|---|---|---|
| `window.Blob` | Blob constructor | Capture inline worker source code |
| `window.URL.createObjectURL` | URL factory | Map blob URLs to captured source |
| `window.Worker` | Worker constructor | Detect regular + blob workers |
| `navigator.serviceWorker.register` | SW registration | Track service workers |
| `window.SharedWorker` | SharedWorker constructor | Track shared workers |

## Use Cases

### 1. Malicious Worker Detection
- Crypto miners running via Blob workers
- Data exfiltration via service workers (intercepting fetch/XHR)
- Clickjacking/UI redressing via shared workers

### 2. Supply Chain Attack Detection
- Third-party scripts creating hidden workers
- Browser extension abuse (workers with elevated permissions)
- CDN compromise leading to worker injection

### 3. Anti-Analysis Evasion
- Malware creating workers from Blob URLs to evade network detection
- Code splitting across workers to bypass static analysis
- Self-deleting workers that exfiltrate and terminate

## Implementation Pattern
```javascript
// Hook Blob to capture inline worker source
const OriginalBlob = window.Blob;
window.Blob = function(...args) {
    const blob = new OriginalBlob(...args);
    // Capture source for analysis
    blob.__capturedSource = args[0];
    return blob;
};

// Hook URL.createObjectURL to track blob→URL mapping
const OriginalCreateObjectURL = window.URL.createObjectURL;
window.URL.createObjectURL = function(blob) {
    const url = OriginalCreateObjectURL.call(this, blob);
    if (blob.__capturedSource) {
        window.__blobSourceMap = window.__blobSourceMap || new Map();
        window.__blobSourceMap.set(url, blob.__capturedSource);
    }
    return url;
};
```

## Cross-References
- **AI Chatbot Exploitation.md:** Workers podem interceptar chamadas de API de chatbots
- **Evasion Attacks.md:** Workers podem ser usados para evadir deteccao
- **Supabomb:** Runtime scanning de aplicacoes web
