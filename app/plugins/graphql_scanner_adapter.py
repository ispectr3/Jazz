import json
import re
import urllib.request
import urllib.error
from app.plugins.base import ScannerAdapter
from app.plugins.loader import register


INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind name description
      fields { name type { name kind } }
    }
    directives { name description locations }
  }
}
"""

BATCHING_PAYLOAD = """{"query":"query{__typename}","variables":{}}"""


@register()
class GraphQLScannerAdapter(ScannerAdapter):
    @property
    def name(self):
        return "GraphQLScanner"

    def validate_input(self, raw_data: str) -> bool:
        if not raw_data.strip():
            return False
        try:
            data = json.loads(raw_data)
            return bool(data.get("endpoint"))
        except (json.JSONDecodeError, TypeError):
            return "/graphql" in raw_data or "/v1/graphql" in raw_data

    def normalize(self, raw_data: str, project_id: int = 0) -> list[dict]:
        data = json.loads(raw_data)
        base = {"project_id": project_id, "plugin_source": self.name}
        findings = []

        endpoint = data.get("endpoint", "")
        if not endpoint:
            return findings

        has_introspection, schema_info = self._check_introspection(endpoint)
        if has_introspection:
            findings.append({**base,
                "title": "GraphQL: Introspection habilitada",
                "description": (
                    f"GraphQL endpoint {endpoint} tem introspection habilitada.\n"
                    f"Isso permite vazar todo o schema da API."
                ),
                "severity": "Alta",
                "raw_data": {"endpoint": endpoint, "schema": schema_info[:1000]},
            })

        if schema_info:
            dangerous_ops = self._find_dangerous_operations(schema_info)
            for op in dangerous_ops:
                findings.append({**base,
                    "title": f"GraphQL: Operacao perigosa — {op['name']}",
                    "description": (
                        f"Tipo: {op['kind']} — {op['name']}\n"
                        f"Risco: {op['risk']}"
                    ),
                    "severity": op["severity"],
                    "raw_data": op,
                })

        batchable = self._check_batching(endpoint)
        if batchable:
            findings.append({**base,
                "title": "GraphQL: Batching attack viavel",
                "description": (
                    f"Endpoint {endpoint} permite queries em lote.\n"
                    f"Possivel ataque de batching para brute-force ou rate-limit bypass."
                ),
                "severity": "Media",
                "raw_data": {"endpoint": endpoint},
            })

        depth_vuln = self._check_query_depth(endpoint)
        if depth_vuln:
            findings.append({**base,
                "title": "GraphQL: Query depth attack viavel",
                "description": (
                    f"Endpoint {endpoint} permite queries profundas.\n"
                    f"Possivel ataque de negacao de servico (DoS) via query complexa."
                ),
                "severity": "Media",
                "raw_data": {"endpoint": endpoint},
            })

        aliases_vuln = self._check_alias_abuse(endpoint)
        if aliases_vuln:
            findings.append({**base,
                "title": "GraphQL: Alias abuse viavel",
                "description": (
                    f"Endpoint {endpoint} aceita alias em queries.\n"
                    f"Possivel ataque de rate-limit bypass via multiplos aliases."
                ),
                "severity": "Baixa",
                "raw_data": {"endpoint": endpoint},
            })

        return findings

    def run_scan(self, endpoint: str) -> str:
        input_data = {"endpoint": endpoint}
        if self.validate_input(json.dumps(input_data)):
            findings = self.normalize(json.dumps(input_data))
            return json.dumps({"findings": findings, "count": len(findings)})
        return json.dumps({"error": "Endpoint GraphQL invalido", "count": 0})

    def _check_introspection(self, endpoint: str) -> tuple[bool, str]:
        try:
            req = urllib.request.Request(
                endpoint,
                data=json.dumps({"query": INTROSPECTION_QUERY}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            resp = urllib.request.urlopen(req, timeout=15)
            body = resp.read().decode()
            data = json.loads(body)
            if data.get("data", {}).get("__schema"):
                schema = json.dumps(data["data"]["__schema"], indent=2)
                return True, schema[:2000]
            return False, ""
        except Exception:
            return False, ""

    def _find_dangerous_operations(self, schema_info: str) -> list[dict]:
        dangerous = []
        patterns = {
            "Mutation": {
                "keywords": ["delete", "drop", "truncate", "exec", "eval",
                             "resetPassword", "updateUser", "setAdmin"],
                "severity": "Alta",
                "risk": "Pode modificar ou destruir dados",
            },
            "Query": {
                "keywords": ["users", "passwords", "tokens", "secrets", "keys",
                             "admin", "config", "internal", "debug"],
                "severity": "Media",
                "risk": "Pode expor dados sensiveis",
            },
        }

        for kind, config in patterns.items():
            for kw in config["keywords"]:
                pattern = rf'\b{re.escape(kw)}\b'
                matches = re.findall(pattern, schema_info, re.IGNORECASE)
                for m in matches:
                    dangerous.append({
                        "name": m,
                        "kind": kind,
                        "severity": config["severity"],
                        "risk": config["risk"],
                    })

        return dangerous

    def _check_batching(self, endpoint: str) -> bool:
        try:
            payload = f"[{BATCHING_PAYLOAD},{BATCHING_PAYLOAD}]"
            req = urllib.request.Request(
                endpoint,
                data=payload.encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            resp = urllib.request.urlopen(req, timeout=10)
            body = resp.read().decode()
            data = json.loads(body)
            return isinstance(data, list) and len(data) == 2
        except Exception:
            return False

    def _check_query_depth(self, endpoint: str) -> bool:
        deep_query = """{"query":"query Deep{__typename"}"""
        for _ in range(10):
            deep_query = deep_query.replace(
                '"}', '{__typename"}'
            )
        try:
            req = urllib.request.Request(
                endpoint,
                data=deep_query.encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            resp = urllib.request.urlopen(req, timeout=10)
            return resp.status == 200
        except Exception:
            return False

    def _check_alias_abuse(self, endpoint: str) -> bool:
        alias_query = '{"query":"query{a1:__typename a2:__typename a3:__typename}"}'
        try:
            req = urllib.request.Request(
                endpoint,
                data=alias_query.encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            resp = urllib.request.urlopen(req, timeout=10)
            body = json.loads(resp.read().decode())
            return len(body.get("data", {})) >= 3
        except Exception:
            return False
