import subprocess, json, re, socket
from datetime import datetime
from app.plugins.base import ScannerAdapter
from app.plugins.loader import register

COMMON_PORTS = [22, 80, 443, 8080, 8443, 3306, 5432, 6379, 27017, 9200]
SENSITIVE_PORTS = {3306, 5432, 6379, 27017, 9200}

@register()
class NaabuAdapter(ScannerAdapter):
    @property
    def name(self) -> str:
        return "Naabu"

    def validate_input(self, raw_data: str) -> bool:
        return bool(raw_data.strip())

    def normalize(self, target: str, project_id: int) -> list[dict]:
        findings = []
        ports_str = ",".join(str(p) for p in COMMON_PORTS)
        try:
            r = subprocess.run(
                ["naabu", "-host", target, "-p", ports_str, "-silent"],
                capture_output=True, text=True, timeout=60
            )
            open_ports = []
            for line in r.stdout.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                if ":" in line:
                    host, port = line.rsplit(":", 1)
                    open_ports.append(int(port))

            for port in open_ports:
                service = self._resolve_service(port)
                severity = "Critica" if port in SENSITIVE_PORTS else "Info"
                desc = self._build_desc(target, port, service, severity)
                findings.append({
                    "project_id": project_id,
                    "plugin_source": self.name,
                    "title": f"Porta Aberta (Naabu): {port}/{service}",
                    "description": desc,
                    "severity": severity,
                    "raw_data": {"target": target, "port": port, "service": service}
                })

            if not open_ports:
                findings.append({
                    "project_id": project_id,
                    "plugin_source": self.name,
                    "title": f"Scan de Portas: {target}",
                    "description": f"Nenhuma porta comum aberta encontrada em {target} entre as {len(COMMON_PORTS)} portas escaneadas via Naabu.",
                    "severity": "Info",
                    "raw_data": {"target": target, "ports_scanned": COMMON_PORTS}
                })

        except subprocess.TimeoutExpired:
            findings.append({
                "project_id": project_id,
                "plugin_source": self.name,
                "title": f"Naabu Timeout: {target}",
                "description": f"Scan de portas via Naabu excedeu o tempo limite para {target}.",
                "severity": "Info",
                "raw_data": {"target": target, "error": "timeout"}
            })
        except Exception as e:
            findings.append({
                "project_id": project_id,
                "plugin_source": self.name,
                "title": f"Naabu Erro: {target}",
                "description": f"Erro ao executar Naabu: {e}",
                "severity": "Info",
                "raw_data": {"target": target, "error": str(e)}
            })

        return findings

    def _resolve_service(self, port: int) -> str:
        services = {
            22: "SSH", 80: "HTTP", 443: "HTTPS", 8080: "HTTP-Proxy",
            8443: "HTTPS-Alt", 3306: "MySQL", 5432: "PostgreSQL",
            6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch",
        }
        return services.get(port, "Desconhecido")

    def _build_desc(self, target: str, port: int, service: str, severity: str) -> str:
        base = f"Porta {port} ({service}) foi detectada como aberta em {target} via Naabu."
        if severity == "Critica":
            base += f" ATENCAO: {service} e um servico de banco de dados exposto na internet."
        return base
