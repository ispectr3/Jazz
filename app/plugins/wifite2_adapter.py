import re
from app.plugins.base import ScannerAdapter
from app.plugins.loader import register

@register()
class Wifite2Adapter(ScannerAdapter):
    @property
    def name(self) -> str:
        return "Wifite2 Wireless Scanner"

    def validate_input(self, raw_data: str) -> bool:
        return bool(re.search(r'\[\d+\].*\(.*\)', raw_data))

    def normalize(self, raw_data: str, scan_id: int = None) -> list:
        networks = []
        pattern = re.compile(r'\[(\d+)\]\s+(?:.*?\s+)?\(?(\d+)\)?\s+(\S+)\s+(\S+)\s+\[?(\w+(?:\/\w+)?)\]?')

        for line in raw_data.splitlines():
            line = line.strip()
            if not line or '[' not in line:
                continue
            if 'WPA' in line or 'WEP' in line or 'OPEN' in line:
                parts = line.split()
                if len(parts) >= 5:
                    bssid = parts[-4] if ':' in parts[-4] else parts[-5] if len(parts) > 5 and ':' in parts[-5] else None
                    essid = parts[-3] if bssid else None
                    ch = parts[-2] if bssid else None
                    enc = parts[-1] if bssid else None
                    if bssid and not re.match(r'^[0-9a-fA-F:]{17}$', bssid):
                        bssid = None
                    networks.append({
                        "bssid": bssid or "unknown",
                        "essid": essid or "Hidden",
                        "channel": int(ch) if ch and ch.isdigit() else 0,
                        "encryption": enc or "unknown",
                        "scan_id": scan_id
                    })
        return networks
