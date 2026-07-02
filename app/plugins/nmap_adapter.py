import json
import os
import subprocess
import tempfile
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from app.plugins.base import ScannerAdapter
from app.plugins.loader import register


@register()
class NmapXMLAdapter(ScannerAdapter):
    """Roda nmap em background (subprocess) e normaliza XML de saida para Findings."""

    NMAP_BIN = shutil.which('nmap') or '/opt/homebrew/bin/nmap'

    @property
    def name(self) -> str:
        return 'Nmap Scanner'

    def validate_input(self, raw_data: str) -> bool:
        if not raw_data.strip():
            return False
        try:
            root = ET.fromstring(raw_data)
            return root.tag == 'nmaprun'
        except (ET.ParseError, TypeError):
            return False

    def normalize(self, raw_data: str, project_id: int = 0) -> list[dict[str, Any]]:
        root = ET.fromstring(raw_data)
        findings = []
        base = {'project_id': project_id, 'plugin_source': self.name}

        for host in root.findall('.//host'):
            status = host.find('.//status')
            if status is None or status.get('state') != 'up':
                continue

            addr = host.find('.//address')
            ip = addr.get('addr') if addr is not None else '?'

            hostname_el = host.find('.//hostname')
            hostname = hostname_el.get('name') if hostname_el is not None else ip

            osmatch = host.find('.//osmatch')
            os_info = osmatch.get('name', '') if osmatch is not None else ''

            for port in host.findall('.//port'):
                state = port.find('.//state')
                if state is None or state.get('state') != 'open':
                    continue

                portid = port.get('portid')
                proto = port.get('protocol', 'tcp')
                svc = port.find('.//service')
                sname = svc.get('name', 'unknown') if svc is not None else 'unknown'
                product = svc.get('product', '') if svc is not None else ''
                version = svc.get('version', '') if svc is not None else ''
                extra = f' {product} {version}'.strip()

                findings.append({**base,
                    'title': f'Porta aberta: {portid}/{proto} — {sname}',
                    'description': f'{hostname}:{portid} ({proto}) | {sname}{extra} | OS: {os_info}',
                    'severity': 'Baixa',
                    'raw_data': {'host': ip, 'port': portid, 'protocol': proto,
                                 'service': sname, 'product': product, 'version': version,
                                 'os': os_info, 'state': state.get('state')}})

            if os_info:
                findings.append({**base,
                    'title': f'OS Detection: {os_info}',
                    'description': f'Host {hostname} — {os_info}',
                    'severity': 'Info',
                    'raw_data': {'host': ip, 'os': os_info}})

        return findings

    def run_scan(self, target: str, flags: str = '-sS -sV -T4 -O -F', sudo: bool = False) -> str:
        if not os.access(self.NMAP_BIN, os.X_OK):
            return json.dumps({'error': f'nmap não encontrado em {self.NMAP_BIN}'})

        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as tmp:
            output_path = tmp.name

        try:
            cmd = [self.NMAP_BIN]
            if sudo:
                cmd = ['sudo'] + cmd
            cmd.extend(flags.split())
            cmd.extend(['-oX', '-', target])

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300000,
                env={**os.environ, 'PATH': os.path.dirname(self.NMAP_BIN) + ':' + os.environ.get('PATH', '')}
            )
            if result.returncode != 0:
                return json.dumps({'error': result.stderr.strip() or f'Exit code {result.returncode}'})
            return result.stdout
        except subprocess.TimeoutExpired:
            return json.dumps({'error': 'Timeout 300s'})
        except FileNotFoundError:
            return json.dumps({'error': 'nmap não encontrado no PATH'})
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)

    def run_scan_async(self, target: str, flags: str = '-sS -sV -T4 -O -F',
                       callback=None, sudo: bool = False) -> subprocess.Popen:
        cmd = [self.NMAP_BIN]
        if sudo:
            cmd = ['sudo'] + cmd
        cmd.extend(flags.split())
        cmd.extend(['-oX', '-', target])
        return subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env={**os.environ, 'PATH': os.path.dirname(self.NMAP_BIN) + ':' + os.environ.get('PATH', '')}
        )
