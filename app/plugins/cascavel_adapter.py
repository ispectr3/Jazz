import importlib.util
import json
import os
from pathlib import Path
from typing import Any

from app.plugins.base import ScannerAdapter
from app.plugins.loader import register


CASCABEL_REPO = Path(os.getcwd()) / '.tools' / 'Cascavel'


@register()
class CascavelAdapter(ScannerAdapter):
    CASCABEL_CATEGORIES: dict[str, list[str]] = {}

    def __init__(self, repo_path: str | Path | None = None):
        self.repo_path = Path(repo_path) if repo_path else CASCABEL_REPO
        self._cached_plugins: dict[str, dict[str, Any]] | None = None
        self._discover_and_cache()

    CATEGORY_KEYWORDS: dict[str, list[str]] = {
        'injection': ['xss', 'sqli', 'ssti', 'rce', 'injection', 'nosql', 'log4shell', 'blind_rce', 'cve_2021'],
        'server_side': ['ssrf', 'xxe', 'lfi', 'path_traversal'],
        'auth': ['jwt', 'oauth', 'csrf', 'idor', 'session', 'password', 'saml', 'oidc'],
        'protocol': ['smuggling', 'http2', 'websocket', 'grpc', 'http3', 'crlf'],
        'defense': ['cors', 'csp', 'clickjack', 'host_header', 'cache_poison', 'rate_limit', 'waf'],
        'api': ['graphql', 'api_enum', 'api_versioning', 'graphql_probe'],
        'advanced_web': ['mass_assignment', 'race_condition', 'prototype_pollution', 'deserialization', 'open_redirect'],
        'infra': ['docker', 'k8s', 'redis', 'mongodb', 'elastic', 'cicd', 'cloud_metadata', 'cloud_enum', 'container_escape'],
        'recon': ['subdomain', 'dns', 'network_mapper', 'email', 'shodan', 'wayback', 'whois', 'traceroute', 'osint'],
        'info_gathering': ['tech_fingerprint', 'js_analyzer', 'param_miner', 'info_disclosure', 'secrets', 'git_dumper', 'admin_finder'],
        'web_scan': ['dir_brute', 'nikto', 'katana', 'http_methods', 'wps', 'nuclei'],
        'cloud_storage': ['s3_bucket', 'cloud_storage'],
        'analysis': ['ssl', 'security_headers', 'waf_detec', 'profiler', 'nmap', 'auto_exploit'],
        'bruteforce': ['ssh_brute', 'ftp_brute', 'smb', 'smtp', 'heartbleed', 'domain_transf'],
        'ics_scada': ['ics', 'scada', 'modbus', 'dnp3', 'bacnet', 's7'],
        'blockchain': ['blockchain', 'web3', 'rpc_exposure', 'smart_contract'],
        'wireless': ['bluetooth', 'wifi', 'wireless', 'rogue'],
        'supply_chain': ['supply_chain', 'dependency'],
        'c2_detection': ['cobalt_strike', 'c2'],
        'firmware': ['firmware'],
        'fuzzing': ['fuzzing'],
        'adversary_sim': ['adversary_simulation'],
        'zero_trust': ['zero_trust'],
    }

    def _discover_and_cache(self) -> None:
        self._cached_plugins = {}
        self.CASCABEL_CATEGORIES = {k: [] for k in self.CATEGORY_KEYWORDS}
        plugins_dir = self.repo_path / 'plugins'
        if not plugins_dir.is_dir():
            return
        for f in sorted(plugins_dir.iterdir()):
            if f.name.startswith('__') or f.name == 'schema.py' or not f.name.endswith('.py'):
                continue
            name = f.stem
            self._cached_plugins[name] = {
                'path': str(f),
                'name': name,
                'module': None,
            }
            for cat, keywords in self.CATEGORY_KEYWORDS.items():
                if any(kw in name.lower() for kw in keywords):
                    self.CASCABEL_CATEGORIES[cat].append(name)
        self.CASCABEL_CATEGORIES = {k: v for k, v in self.CASCABEL_CATEGORIES.items() if v}

    @property
    def name(self) -> str:
        return 'Cascavel'

    def validate_input(self, raw_data: str) -> bool:
        if not raw_data.strip():
            return False
        try:
            data = json.loads(raw_data)
            if isinstance(data, list):
                return len(data) > 0
            return bool(data.get('plugin') or data.get('resultados') or data.get('vulns'))
        except (json.JSONDecodeError, TypeError):
            return False

    def normalize(self, raw_data: str, project_id: int = 0) -> list[dict[str, Any]]:
        data = json.loads(raw_data)
        findings = []
        base = {'project_id': project_id, 'plugin_source': self.name}
        items = data if isinstance(data, list) else [data]
        for item in items:
            findings.extend(self._parse_plugin_output(item, base))
        return findings

    def _parse_plugin_output(self, item: dict, base: dict) -> list[dict]:
        findings = []
        plugin = item.get('plugin', 'unknown')
        resultados = item.get('resultados', {})
        tecnicas = item.get('tecnicas', [])

        vulns = []
        if isinstance(resultados, dict):
            vulns = resultados.get('vulns', [])
            if not vulns:
                for key in ('findings', 'issues', 'alerts', 'detections'):
                    if key in resultados and isinstance(resultados[key], list):
                        vulns = resultados[key]
                        break
            docs = resultados.get('docs_expostas', [])
            endpoints = resultados.get('endpoints_ativos', [])
            if docs:
                for d in docs:
                    findings.append({**base,
                        'title': f'[{plugin}] {d.get("tipo", "Doc")} exposed',
                        'description': f'{d.get("path", "?")} — {d.get("severidade", "MEDIO")}',
                        'severity': self._map_sev(d.get('severidade', 'MEDIO')),
                        'raw_data': d})
            if endpoints:
                for ep in endpoints:
                    findings.append({**base,
                        'title': f'[{plugin}] API endpoint: {ep.get("prefix", "?")}',
                        'description': f'Status {ep.get("status", "?")}, methods: {ep.get("methods_allowed", "unknown")}',
                        'severity': 'Info',
                        'raw_data': ep})
        elif isinstance(resultados, list):
            vulns = resultados

        for v in vulns:
            if isinstance(v, dict):
                sev = self._map_sev(v.get('severidade', v.get('severity', 'MEDIO')))
                title = v.get('tipo') or v.get('title') or v.get('name', 'Issue')
                desc = v.get('descricao') or v.get('description') or v.get('details', '')
                endpoint = v.get('endpoint', '')
                label = f'[{plugin}] {title}'
                if endpoint:
                    label += f' @ {endpoint}'
                findings.append({**base,
                    'title': label,
                    'description': desc,
                    'severity': sev,
                    'raw_data': v})

        if not findings and isinstance(resultados, str):
            findings.append({**base,
                'title': f'[{plugin}] {resultados}',
                'description': resultados,
                'severity': 'Info',
                'raw_data': item})

        return findings

    @staticmethod
    def _map_sev(sev: str) -> str:
        return {'CRITICO': 'Crítica', 'ALTO': 'Alta', 'MEDIO': 'Média', 'BAIXO': 'Baixa', 'INFO': 'Info'}.get(
            sev.strip().upper(), 'Média'
        )

    def run_plugin(self, name: str, target: str, ip: str = '',
                   ports: list[int] | None = None, banners: dict | None = None) -> dict[str, Any]:
        info = self._cached_plugins.get(name) if self._cached_plugins else None
        if not info:
            return {'plugin': name, 'erro': 'Plugin não encontrado'}
        spec = importlib.util.spec_from_file_location(name, info['path'])
        if not spec or not spec.loader:
            return {'plugin': name, 'erro': 'Módulo não resolvido'}
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
        except Exception as e:
            return {'plugin': name, 'erro': str(e)}
        if not hasattr(mod, 'run'):
            return {'plugin': name, 'erro': 'Sem função run()'}
        import inspect
        sig = inspect.signature(mod.run)
        has_context = 'context' in sig.parameters
        kwargs = {}
        if has_context:
            kwargs['context'] = {}
        try:
            return mod.run(target, ip, ports or [], banners or {}, **kwargs)
        except TypeError as e:
            return {'plugin': name, 'erro': f'Assinatura: {e}'}

    def run_scan(self, target: str, profile: str = 'full') -> str:
        results = []
        for name in self._cached_plugins or {}:
            results.append(self.run_plugin(name, target))
        return json.dumps(results)

    def run_category(self, target: str, category: str) -> str:
        plugins = self.get_plugins_by_category(category)
        if not plugins:
            return json.dumps({'error': f'Unknown category: {category}'})
        results = [self.run_plugin(name, target) for name in plugins]
        return json.dumps(results)

    def get_plugins(self) -> list[str]:
        return sorted(self._cached_plugins or {})

    def get_categories(self) -> list[str]:
        return list(self.CASCABEL_CATEGORIES.keys())

    def get_plugins_by_category(self, category: str) -> list[str]:
        return self.CASCABEL_CATEGORIES.get(category, [])

    def discover_plugins(self) -> list[str]:
        return self.get_plugins()
