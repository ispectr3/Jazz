import re
from app.plugins.base import ScannerAdapter
from app.plugins.loader import register

@register()
class HcxdumptoolAdapter(ScannerAdapter):
    @property
    def name(self) -> str:
        return "hcxdumptool Capturer"

    def validate_input(self, raw_data: str) -> bool:
        return "PMKID" in raw_data or "handshake" in raw_data.lower() or "captured" in raw_data.lower()

    def normalize(self, raw_data: str, scan_id: int = None, network_id: int = None) -> list:
        captures = []
        pmkid_match = re.search(r'PMKID captured\s*(?::\s*)?(\S+)', raw_data, re.IGNORECASE)
        handshake_match = re.search(r'handshake captured\s*(?::\s*)?(\S+)', raw_data, re.IGNORECASE)
        pcap_match = re.search(r'saved in\s+(\S+\.pcap(?:ng)?)', raw_data, re.IGNORECASE)

        if pmkid_match:
            captures.append({
                "capture_type": "pmkid",
                "hash_value": pmkid_match.group(1),
                "raw_data": raw_data,
                "scan_id": scan_id,
                "network_id": network_id
            })
        if handshake_match:
            captures.append({
                "capture_type": "handshake",
                "hash_value": handshake_match.group(1),
                "raw_data": raw_data,
                "scan_id": scan_id,
                "network_id": network_id
            })
        if pcap_match:
            if not captures:
                captures.append({
                    "capture_type": "raw_pcap",
                    "hash_value": pcap_match.group(1),
                    "raw_data": raw_data,
                    "scan_id": scan_id,
                    "network_id": network_id
                })
            else:
                captures[0]["pcap_path"] = pcap_match.group(1)

        return captures
