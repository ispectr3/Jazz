import json
from app.plugins.base import ScannerAdapter
from app.plugins.loader import register

HOOK_SCRIPT = """
(function() {
    if (window.__runtimeHooksInstalled) return;
    window.__runtimeHooksInstalled = true;
    window.__capturedWorkers = [];
    window.__blobSourceMap = new Map();
    window.__serviceWorkers = [];
    window.__workerActivity = [];

    const OriginalBlob = window.Blob;
    window.Blob = function(...args) {
        const blob = new OriginalBlob(...args);
        try {
            const source = (args[0] || []).join('');
            blob.__capturedSource = source;
            blob.__capturedTime = Date.now();
            if (source.length > 50) {
                window.__workerActivity.push({
                    type: 'blob_created',
                    time: blob.__capturedTime,
                    size: source.length,
                    preview: source.slice(0, 200)
                });
            }
        } catch(e) {}
        return blob;
    };

    const OriginalCreateObjectURL = window.URL.createObjectURL;
    window.URL.createObjectURL = function(blob) {
        const url = OriginalCreateObjectURL.call(this, blob);
        if (blob && blob.__capturedSource) {
            window.__blobSourceMap.set(url, {
                source: blob.__capturedSource,
                time: blob.__capturedTime || Date.now()
            });
        }
        return url;
    };

    const OriginalWorker = window.Worker;
    window.Worker = function(...args) {
        const url = args[0];
        const captured = {
            type: 'worker',
            url: url,
            time: Date.now(),
            blobSource: null
        };
        if (typeof url === 'string' && window.__blobSourceMap.has(url)) {
            const entry = window.__blobSourceMap.get(url);
            captured.blobSource = entry.source.slice(0, 500);
        }
        window.__capturedWorkers.push(captured);
        window.__workerActivity.push({ type: 'worker_created', url: url, time: Date.now() });
        return new OriginalWorker(...args);
    };

    const OriginalSWRegister = navigator.serviceWorker.register.bind(navigator.serviceWorker);
    navigator.serviceWorker.register = function(scriptURL, options) {
        window.__serviceWorkers.push({ scriptURL: scriptURL, scope: options?.scope || '/', time: Date.now() });
        window.__workerActivity.push({ type: 'sw_register', url: scriptURL, time: Date.now() });
        return OriginalSWRegister(scriptURL, options);
    };

    const OriginalSharedWorker = window.SharedWorker;
    window.SharedWorker = function(...args) {
        const url = args[0];
        window.__capturedWorkers.push({ type: 'shared_worker', url: url, time: Date.now() });
        window.__workerActivity.push({ type: 'shared_worker_created', url: url, time: Date.now() });
        return new OriginalSharedWorker(...args);
    };
})();
"""

@register()
class RuntimeHooksAdapter(ScannerAdapter):
    @property
    def name(self) -> str:
        return "RuntimeHooks"

    def generate_hooks(self) -> str:
        return HOOK_SCRIPT

    def run_analysis(self, captured_data: dict) -> str:
        results = {
            "tool": "RuntimeHooks",
            "total_workers": len(captured_data.get("workers", [])),
            "total_sw": len(captured_data.get("serviceWorkers", [])),
            "total_shared": len(captured_data.get("sharedWorkers", [])),
            "blob_workers": sum(1 for w in captured_data.get("workers", []) if w.get("blobSource")),
            "findings": []
        }
        for w in captured_data.get("workers", []):
            source = w.get("blobSource", "")
            suspicious = False
            indicators = []
            if source:
                suspicious_keywords = ["crypto", "mine", "xmrig", "coin", "exfil", "fetch(", "XMLHttpRequest",
                                       "postMessage", "importScripts", "eval(", "atob"]
                for kw in suspicious_keywords:
                    if kw in source.lower():
                        suspicious = True
                        indicators.append(kw)
            results["findings"].append({
                "url": w.get("url", "blob"),
                "has_blob_source": bool(source),
                "suspicious": suspicious,
                "indicators": indicators,
                "source_preview": source[:200] if source else ""
            })
        return json.dumps(results, indent=2)

    def validate_input(self, raw_data: str) -> bool:
        try:
            data = json.loads(raw_data)
            return "tool" in data
        except Exception:
            return False

    def normalize(self, raw_data: str, project_id: int) -> list:
        data = json.loads(raw_data)
        findings = []
        base = {"project_id": project_id, "plugin_source": self.name}
        for f in data.get("findings", []):
            if f.get("suspicious"):
                findings.append({**base,
                    "title": f"RuntimeHooks: Worker suspeito detectado — {f.get('url','blob')[:60]}",
                    "description": (
                        f"URL: {f.get('url','N/A')}\n"
                        f"Blob source: {'Sim' if f.get('has_blob_source') else 'Nao'}\n"
                        f"Indicadores: {', '.join(f.get('indicators',[]))}\n"
                        f"Preview: {f.get('source_preview','')}"
                    ),
                    "severity": "Alta",
                    "raw_data": f})
        if data.get("blob_workers", 0) > 0:
            findings.append({**base,
                "title": f"RuntimeHooks: {data['blob_workers']} blob workers detectados",
                "description": f"Total workers: {data['total_workers']}, Service Workers: {data['total_sw']}, Shared: {data['total_shared']}",
                "severity": "Info",
                "raw_data": {"blob_workers": data["blob_workers"], "total": data["total_workers"]}})
        return findings
