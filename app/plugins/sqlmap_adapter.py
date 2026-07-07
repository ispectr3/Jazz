import json
import os
import shutil
import subprocess
from app.plugins.base import ScannerAdapter
from app.plugins.loader import register


SQLMAP_BIN = shutil.which("sqlmap") or os.path.expanduser("~/.tools/sqlmap/sqlmap.py")
PYTHON_BIN = shutil.which("python3") or shutil.which("python")


@register()
class SQLMapAdapter(ScannerAdapter):
    SQLMAP_BIN = SQLMAP_BIN

    @property
    def name(self):
        return "SQLMap"

    def validate_input(self, raw_data: str) -> bool:
        if not raw_data.strip():
            return False
        try:
            data = json.loads(raw_data)
            return bool(data.get("url")) or bool(data.get("request_file"))
        except (json.JSONDecodeError, TypeError):
            return raw_data.startswith("http")

    def normalize(self, raw_data: str, project_id: int = 0) -> list[dict]:
        data = json.loads(raw_data)
        base = {"project_id": project_id, "plugin_source": self.name}
        findings = []

        url = data.get("url", "")
        method = data.get("method", "GET")
        data_body = data.get("data", "")
        cookie = data.get("cookie", "")
        level = data.get("level", 1)
        risk = data.get("risk", 1)
        params = data.get("params", "")

        raw_output = self._run_sqlmap(url, method, data_body, cookie, level, risk, params)
        if not raw_output:
            findings.append({**base,
                "title": "SQLMap: Scan nao executado",
                "description": f"SQLMap nao disponivel em {SQLMAP_BIN} ou timeout ao escanear {url}",
                "severity": "Info",
                "raw_data": {"url": url},
            })
            return findings

        parsed = self._parse_output(raw_output, url)
        findings.extend(parsed)

        if not findings:
            findings.append({**base,
                "title": f"SQLMap: Nenhuma injecao encontrada em {url}",
                "description": f"Level={level}, Risk={risk}. Nenhum parametro vulneravel a SQL injection.",
                "severity": "Info",
                "raw_data": {"url": url, "level": level, "risk": risk},
            })

        return findings

    def run_scan(self, url: str, method: str = "GET", data: str = "",
                 cookie: str = "", level: int = 1, risk: int = 1,
                 params: str = "") -> str:
        input_data = {
            "url": url, "method": method, "data": data,
            "cookie": cookie, "level": level, "risk": risk, "params": params,
        }
        if self.validate_input(json.dumps(input_data)):
            findings = self.normalize(json.dumps(input_data))
            return json.dumps({"findings": findings, "count": len(findings)})
        return json.dumps({"error": "URL invalida", "count": 0})

    def _run_sqlmap(self, url: str, method: str, data: str, cookie: str,
                    level: int, risk: int, params: str) -> str | None:
        if not os.path.exists(SQLMAP_BIN):
            return None

        cmd = [PYTHON_BIN, SQLMAP_BIN, "-u", url, "--batch", "--output-dir=/tmp/sqlmap_out"]

        if method.upper() == "POST" and data:
            cmd.extend(["--data", data])
        if cookie:
            cmd.extend(["--cookie", cookie])
        if level > 1:
            cmd.extend(["--level", str(level)])
        if risk > 1:
            cmd.extend(["--risk", str(risk)])
        if params:
            cmd.extend(["-p", params])

        cmd.extend(["--flush-session", "--random-agent"])

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300000,
            )
            if result.returncode not in (0, 1):
                return None
            return result.stdout + "\n" + result.stderr
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None

    def _parse_output(self, output: str, url: str) -> list[dict]:
        findings = []
        base = {"plugin_source": self.name}

        if "identified the following injection" in output.lower():
            vuln_sections = output.split("identified the following injection")
            for section in vuln_sections[1:]:
                param = "unknown"
                for line in section.split("\n"):
                    if "Parameter:" in line:
                        param = line.split("Parameter:")[-1].strip().split()[0]
                        break

                techniques = []
                if "boolean-based blind" in section: techniques.append("boolean-based blind")
                if "time-based blind" in section: techniques.append("time-based blind")
                if "error-based" in section: techniques.append("error-based")
                if "union query" in section: techniques.append("union query")
                if "stacked queries" in section: techniques.append("stacked queries")

                findings.append({**base,
                    "title": f"SQL Injection: {param}",
                    "description": (
                        f"Parametro '{param}' vulneravel a SQL injection em {url}\n"
                        f"Tecnicas: {', '.join(techniques) if techniques else 'N/A'}"
                    ),
                    "severity": "Critica",
                    "raw_data": {"url": url, "param": param, "techniques": techniques},
                })

                db_type = ""
                db_version = ""
                for line in section.split("\n"):
                    if "back-end DBMS:" in line:
                        db_type = line.split("back-end DBMS:")[-1].strip()
                    if "banner:" in line.lower():
                        db_version = line.split(":")[-1].strip()

                if db_type:
                    findings.append({**base,
                        "title": f"SQLMap: Fingerprint DB — {db_type}",
                        "description": f"Banco identificado: {db_type} {db_version}",
                        "severity": "Media",
                        "raw_data": {"db_type": db_type, "db_version": db_version},
                    })

        return findings
