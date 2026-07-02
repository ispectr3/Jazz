import json
import os
import re
import shutil
import subprocess
from typing import Any

from app.plugins.base import ScannerAdapter
from app.plugins.loader import register


JWT_TOOL_BIN = shutil.which('jwt_tool') or shutil.which('jwt-tool') or ''


@register()
class JWTToolAdapter(ScannerAdapter):
    """Wrapper para jwt_tool (ticarpi) — análise de seguranca de JWTs."""

    JWT_TOOL_BIN = JWT_TOOL_BIN

    @property
    def name(self) -> str:
        return 'JWTTool'

    def validate_input(self, raw_data: str) -> bool:
        if not raw_data.strip():
            return False
        try:
            data = json.loads(raw_data)
            return bool(data.get('jwt') or data.get('token'))
        except (json.JSONDecodeError, TypeError):
            return bool(re.search(r'^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', raw_data.strip()))

    def normalize(self, raw_data: str, project_id: int = 0) -> list[dict[str, Any]]:
        try:
            data = json.loads(raw_data)
            token = data.get('jwt') or data.get('token', '')
        except (json.JSONDecodeError, TypeError):
            data = {}
            token = raw_data.strip()

        base = {'project_id': project_id, 'plugin_source': self.name}
        findings = []

        if not token:
            return findings

        attacks = data.get('attacks', ['none', 'weak_alg', 'brute', 'kid', 'jku'])
        wordlist = data.get('wordlist', '')

        for attack in attacks:
            raw = self._run_attack(token, attack, wordlist)
            if raw and 'error' not in raw:
                parsed = self._parse_attack_output(attack, raw, token)
                findings.extend(parsed)

        findings = self._apply_base(findings, base)
        return findings

    def _run_attack(self, token: str, attack: str, wordlist: str = '') -> dict:
        if not self.JWT_TOOL_BIN:
            return {'error': 'jwt_tool não encontrado no PATH'}

        cmd = [self.JWT_TOOL_BIN, token]

        attack_map = {
            'none': ['-X', 'a'],
            'weak_alg': ['-X', 'b'],
            'brute': ['-C', '-d', wordlist or '/usr/share/wordlists/rockyou.txt'],
            'kid': ['-X', 'k'],
            'jku': ['-X', 'j'],
            'jwks': ['-X', 'c'],
        }

        flags = attack_map.get(attack, [])
        if not flags:
            return {'error': f'ataque desconhecido: {attack}'}

        cmd.extend(flags)

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120000,
                env={**os.environ, 'PATH': os.path.dirname(self.JWT_TOOL_BIN) + ':' + os.environ.get('PATH', '')}
            )
            if result.returncode != 0:
                return {'error': result.stderr.strip() or f'Exit code {result.returncode}'}
            return {'attack': attack, 'stdout': result.stdout, 'stderr': result.stderr}
        except subprocess.TimeoutExpired:
            return {'error': 'Timeout 120s'}
        except FileNotFoundError:
            return {'error': 'jwt_tool não encontrado'}

    def _parse_attack_output(self, attack: str, raw: dict, original_token: str) -> list[dict]:
        results = []
        stdout = raw.get('stdout', '')

        vuln_patterns = {
            'none': {
                'title': 'JWT: Algoritmo None aceito',
                'severity': 'Crítica',
                'pattern': r'(algorithm is none|verified.*none|None alg)',
                'desc': 'O servidor aceita tokens JWT com algoritmo "none", permitindo forjar tokens arbitrarios.'
            },
            'weak_alg': {
                'title': 'JWT: Algorithm Confusion (RS256->HS256)',
                'severity': 'Alta',
                'pattern': r'(HMAC.*verified|symmetric.*key|changed.*to.*HS256)',
                'desc': 'O servidor aceita tokens originalmente RS256 como HS256, permitindo usar a chave publica como secret HMAC.'
            },
            'brute': {
                'title': 'JWT: Secret fraca descoberta',
                'severity': 'Crítica',
                'pattern': r'(KEY FOUND|password.*is|secret.*found)',
                'desc': 'A chave secreta do JWT foi descoberta por brute-force.'
            },
            'kid': {
                'title': 'JWT: KID Injection',
                'severity': 'Crítica',
                'pattern': r'(kid.*inject|path.*traversal|SQL.*injection|verified.*kid)',
                'desc': 'O campo kid do header JWT pode ser manipulado para path traversal ou SQL injection.'
            },
            'jku': {
                'title': 'JWT: JKU Injection / SSRF',
                'severity': 'Alta',
                'pattern': r'(JKU.*verified|jku.*accepted|SSRF)',
                'desc': 'O servidor aceita JKU apontando para URLs controladas pelo atacante.'
            },
            'jwks': {
                'title': 'JWT: JWK Injection',
                'severity': 'Crítica',
                'pattern': r'(JWK.*verified|embedded.*key|jwk.*accepted)',
                'desc': 'O servidor aceita JWK embarcado no header do token.'
            },
        }

        info = vuln_patterns.get(attack)
        if info and re.search(info['pattern'], stdout, re.IGNORECASE):
            results.append({
                'title': info['title'],
                'description': f"{info['desc']}\nAtaque: {attack}\nToken original: {original_token[:80]}...",
                'severity': info['severity'],
                'raw_data': {'attack': attack, 'output': stdout[:500], 'token': original_token},
            })

        if not results:
            results.append({
                'title': f'JWT Scan: {attack} — Sem vulnerabilidade detectada',
                'description': f'Ataque {attack} executado sem sucesso. Token possivelmente seguro para este vetor.',
                'severity': 'Info',
                'raw_data': {'attack': attack, 'output': stdout[:300]},
            })

        return results

    def _apply_base(self, findings: list, base: dict) -> list:
        for f in findings:
            f.update({k: v for k, v in base.items() if k not in f})
        return findings

    def run_scan(self, token: str, attacks: list | None = None,
                 wordlist: str = '') -> str:
        input_data = {
            'token': token,
            'attacks': attacks or ['none', 'weak_alg', 'brute', 'kid', 'jku', 'jwks'],
            'wordlist': wordlist,
        }
        if self.validate_input(json.dumps(input_data)):
            findings = self.normalize(json.dumps(input_data))
            return json.dumps({'findings': findings, 'count': len(findings)})
        return json.dumps({'error': 'Token JWT invalido', 'count': 0})
