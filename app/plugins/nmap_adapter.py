import json
from app.plugins.base import ScannerAdapter
from typing import Dict, Any, List

class NmapJSONAdapter(ScannerAdapter):
    """
    Exemplo de Adapter: Lê um JSON gerado pelo Nmap e normaliza para o modelo 'Finding'.
    """
    
    @property
    def name(self) -> str:
        return "Nmap JSON Importer"

    def validate_input(self, raw_data: str) -> bool:
        try:
            data = json.loads(raw_data)
            # Verifica se possui assinatura típica
            return "nmaprun" in data
        except json.JSONDecodeError:
            return False

    def normalize(self, raw_data: str) -> List[Dict[str, Any]]:
        findings = []
        data = json.loads(raw_data)
        
        # Simulação simplificada de extração de portas abertas
        # Na vida real, a estrutura do Nmap JSON é navegada iterativamente
        if "hosts" in data:
            for host in data.get("hosts", []):
                for port in host.get("ports", []):
                    if port.get("state") == "open":
                        finding = {
                            "plugin_source": self.name,
                            "title": f"Port Open: {port.get('portid')}/{port.get('protocol')}",
                            "description": f"Service: {port.get('service', {}).get('name', 'unknown')}",
                            "severity": "Low", # Padrão para porta aberta, a IA ajusta depois
                            "raw_data": port
                        }
                        findings.append(finding)
                        self.generate_log("SUCCESS", f"Normalized finding for port {port.get('portid')}")
                        
        return findings
