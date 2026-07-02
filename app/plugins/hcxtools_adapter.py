import re
from app.plugins.base import ScannerAdapter
from app.plugins.loader import register

@register()
class HcxtoolsAdapter(ScannerAdapter):
    @property
    def name(self) -> str:
        return "hcxtools Hash Converter"

    def validate_input(self, raw_data: str) -> bool:
        return bool(re.search(r'\$PMKID\*|\$WPAPSK\*', raw_data))

    def normalize(self, raw_data: str, capture_id: int = None) -> list:
        hashes = []
        for line in raw_data.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith('$PMKID*'):
                hashes.append({
                    "capture_id": capture_id,
                    "hash_format": "22000",
                    "hash_content": line,
                    "type": "PMKID"
                })
            elif line.startswith('$WPAPSK*'):
                hashes.append({
                    "capture_id": capture_id,
                    "hash_format": "22000",
                    "hash_content": line,
                    "type": "Handshake"
                })
        return hashes
