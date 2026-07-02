import json
import os
import shutil
import subprocess
from typing import Any

from app.plugins.base import ScannerAdapter
from app.plugins.loader import register


FFUF_BIN = shutil.which('ffuf') or ''

WORDLIST_DIRS = [
    '/usr/share/wordlists',
    '/usr/share/seclists/Discovery/Web-Content',
    '/opt/homebrew/share/wordlists',
    os.path.expanduser('~/wordlists'),
]

DEFAULT_WORDLISTS = [
    'common.txt',
    'directory-list-2.3-medium.txt',
    'raft-medium-words.txt',
]


@register()
class FfufAdapter(ScannerAdapter):
    """Wrapper para ffuf (ffuf) — fuzzing web de diretorios, parametros e subdominios."""

    FFUF_BIN = FFUF_BIN

    @property
    def name(self) -> str:
        return 'Ffuf'

    def validate_input(self, raw_data: str) -> bool:
        if not raw_data.strip():
            return False
        try:
            data = json.loads(raw_data)
            return bool(data.get('url'))
        except (json.JSONDecodeError, TypeError):
            return raw_data.startswith('http')

    def normalize(self, raw_data: str, project_id: int = 0) -> list[dict[str, Any]]:
        data = json.loads(raw_data)
        base = {'project_id': project_id, 'plugin_source': self.name}
        findings = []

        url = data.get('url', '')
        wordlist = data.get('wordlist', self._find_wordlist())
        mode = data.get('mode', 'directory')

        if not wordlist:
            findings.append({
                **base,
                'title': 'Ffuf: Wordlist nao encontrada',
                'description': 'Nenhuma wordlist encontrada nos diretorios padrao.',
                'severity': 'Info',
                'raw_data': {'url': url, 'mode': mode},
            })
            return findings

        raw = self._run_ffuf(url, wordlist, mode)
        if not raw or 'error' in raw:
            return findings

        fuzz_results = raw.get('results', [])
        for r in fuzz_results:
            status = r.get('status', 0)
            length = r.get('length', 0)
            words = r.get('words', 0)
            lines = r.get('lines', 0)
            input_val = r.get('input', {}).get('FUZZ', '')

            if not input_val:
                continue

            severity = self._classify_severity(status, length, mode)
            if severity == 'Info' and status < 300:
                continue

            findings.append({
                **base,
                'title': f'Ffuf: {input_val} ({status})',
                'description': (
                    f"URL: {url.replace('FUZZ', input_val)}\n"
                    f"Status: {status} | Tamanho: {length}B\n"
                    f"Modo: {mode}"
                ),
                'severity': severity,
                'raw_data': r,
            })

        if not findings:
            findings.append({
                **base,
                'title': f'Ffuf: Scan {url} — Nada relevante encontrado',
                'description': f'{len(fuzz_results)} resultados, todos filtrados.',
                'severity': 'Info',
                'raw_data': {'url': url, 'total_results': len(fuzz_results)},
            })

        return findings

    def _run_ffuf(self, url: str, wordlist: str, mode: str = 'directory') -> dict | None:
        if not self.FFUF_BIN:
            return {'error': 'ffuf nao encontrado no PATH'}

        cmd = [self.FFUF_BIN, '-u', url, '-w', wordlist, '-o', '-', '-of', 'json']

        if mode == 'parameter':
            cmd.extend(['-X', 'POST', '-d', 'FUZZ=test'])
        elif mode == 'subdomain':
            cmd.extend(['-H', f'Host: FUZZ.{url.replace("https://", "").replace("http://", "").split("/")[0]}'])

        cmd.extend(['-fc', '404', '-fs', '0'])

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300000,
                env={**os.environ, 'PATH': os.path.dirname(self.FFUF_BIN) + ':' + os.environ.get('PATH', '')}
            )
            if result.returncode not in (0, 1):
                return None
            return json.loads(result.stdout) if result.stdout.strip() else None
        except (subprocess.TimeoutExpired, json.JSONDecodeError):
            return None

    def _find_wordlist(self) -> str | None:
        for wl_name in DEFAULT_WORDLISTS:
            for d in WORDLIST_DIRS:
                path = os.path.join(d, wl_name)
                if os.path.isfile(path):
                    return path
        for d in WORDLIST_DIRS:
            if os.path.isdir(d):
                for f in os.listdir(d):
                    if f.endswith('.txt'):
                        return os.path.join(d, f)
        return None

    def _classify_severity(self, status: int, length: int, mode: str) -> str:
        if status == 200:
            return 'Media'
        if status in (201, 202, 204):
            return 'Media'
        if status in (301, 302, 307, 308):
            return 'Baixa'
        if status in (401, 403):
            return 'Info'
        if status in (500, 502, 503):
            return 'Media'
        return 'Info'

    def run_scan(self, url: str, wordlist: str | None = None,
                 mode: str = 'directory') -> str:
        wl = wordlist or self._find_wordlist()
        input_data = {'url': url, 'wordlist': wl, 'mode': mode}
        if self.validate_input(json.dumps(input_data)):
            findings = self.normalize(json.dumps(input_data))
            return json.dumps({'findings': findings, 'count': len(findings)})
        return json.dumps({'error': 'URL invalida'})
