import json
from typing import Dict, List, Optional

from app.ai.client import LLMClient

TOOL_DESCRIPTIONS = {
    "nmap": "Port scan with service/OS detection (-sS -sV -T4 -O -F). Finds open ports and services.",
    "nuclei": "Vulnerability scanner with 1000+ templates for CVEs, misconfigs, exposures.",
    "supabomb": "Supabase instance scanner. Finds exposed tables, buckets, and misconfigurations.",
    "specter": "Wix platform scanner. Detects API keys, misconfigs, and data exposure.",
    "wasminator": "WebAssembly vulnerability scanner. Finds WASM-specific issues.",
    "badworker": "Web Worker security scanner. Detects XSS, data exfiltration in workers.",
    "ffuf": "Web fuzzer for directory, parameter, and subdomain discovery.",
    "sqlmap": "SQL injection scanner. Tests parameters for SQLi via sqlmap.",
    "graphql": "GraphQL API security scanner. Tests introspection, batching, depth attacks.",
    "whatweb": "Technology fingerprinting (140+ signatures: CMS, frameworks, CDN, cloud, analytics, payment, security, infrastructure).",
    "fullscan": "Runs ALL available tools against the target for maximum coverage.",
}

RULE_BASED_DEFAULTS = ["nmap", "nuclei", "badworker", "ffuf", "sqlmap", "whatweb"]


class ToolClassifier:
    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.llm_client = llm_client

    def decide(self, target: str, technologies: List[dict], findings: List[dict]) -> List[str]:
        if self.llm_client:
            try:
                return self._llm_decide(target, technologies, findings)
            except Exception:
                pass

        return self._rule_decide(target, technologies, findings)

    def _llm_decide(self, target: str, technologies: List[dict], findings: List[dict]) -> List[str]:
        from app.ai.agents import SearcherAgent
        tech_names = [t.get("name", "") for t in technologies]
        tech_str = ", ".join(tech_names) if tech_names else "Nenhuma tecnologia detectada"

        prompt = f"""Target: {target}
Technologies detected: {tech_str}

Available tools and what each does:
{json.dumps(TOOL_DESCRIPTIONS, indent=2, ensure_ascii=False)}

Choose which tools to run against this target.
Return ONLY a JSON array of tool names. Example: ["nmap", "whatweb", "nuclei"]
Rules:
- If target is Supabase, include "supabomb"
- If target is Wix, include "specter"
- If target has GraphQL endpoint, include "graphql"
- If target is a WASM file, include "wasminator"
- Always include "nmap", "whatweb" for general targets
- "fullscan" runs everything"""

        agent = SearcherAgent()
        raw = agent.chat(
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            max_tokens=500,
        )

        try:
            tools = json.loads(raw)
            if isinstance(tools, list) and len(tools) > 0:
                valid = set(TOOL_DESCRIPTIONS.keys())
                return [t for t in tools if t in valid] or self._rule_decide(target, technologies, findings)
        except (json.JSONDecodeError, TypeError):
            pass

        return self._rule_decide(target, technologies, findings)

    def _rule_decide(self, target: str, technologies: List[dict], findings: List[dict]) -> List[str]:
        tools = []
        target_lower = target.lower()

        if any(ext in target_lower for ext in [".supabase", "supabase.", "project-ref"]):
            tools.append("supabomb")
        if "wix" in target_lower or "wixsite" in target_lower or "wix.com" in target_lower:
            tools.append("specter")
        if target_lower.endswith(".wasm") or ".wasm" in target_lower:
            tools.append("wasminator")

        has_graphql = any(
            "graphql" in t.get("title", "").lower() or
            t.get("name", "").lower() == "graphql"
            for t in technologies + findings
        )
        if has_graphql or "graphql" in target_lower or "/graphql" in target_lower:
            tools.append("graphql")

        tools.extend(RULE_BASED_DEFAULTS)
        return list(dict.fromkeys(tools))
