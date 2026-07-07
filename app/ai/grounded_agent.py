import json
import re
from typing import Any, Dict, List, Optional


class GroundedFinding:
    def __init__(
        self,
        title: str,
        description: str,
        severity: str,
        source: str,
        source_data: dict,
        cve: Optional[str] = None,
        cvss: Optional[float] = None,
        cwe: Optional[str] = None,
    ):
        self.title = title
        self.description = description
        self.severity = severity
        self.source = source
        self.source_data = source_data
        self.cve = cve
        self.cvss = cvss
        self.cwe = cwe
        self.validated = False
        self.validation_notes = []

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "source": self.source,
            "cve": self.cve,
            "cvss": self.cvss,
            "cwe": self.cwe,
            "validated": self.validated,
            "validation_notes": self.validation_notes,
        }


class Gatherer:
    def __init__(self, ctx):
        self.ctx = ctx

    def collect_from_findings(self) -> List[GroundedFinding]:
        grounded = []
        for mod, mod_findings in self.ctx.modules_findings.items():
            for f in mod_findings:
                grounded.append(GroundedFinding(
                    title=f.get("title", "Unknown"),
                    description=f.get("description", ""),
                    severity=f.get("severity", "Info"),
                    source=mod,
                    source_data=f,
                    cve=f.get("cve"),
                    cvss=f.get("cvss"),
                    cwe=f.get("cwe"),
                ))

        for f in self.ctx.findings:
            if not any(g.title == f.get("title") for g in grounded):
                grounded.append(GroundedFinding(
                    title=f.get("title", "Unknown"),
                    description=f.get("description", ""),
                    severity=f.get("severity", "Info"),
                    source="general",
                    source_data=f,
                    cve=f.get("cve"),
                    cvss=f.get("cvss"),
                    cwe=f.get("cwe"),
                ))

        return grounded

    def collect_from_cves(self) -> List[GroundedFinding]:
        grounded = []
        for cve in self.ctx.cves:
            cve_id = cve.get("id", cve.get("cve_id", ""))
            grounded.append(GroundedFinding(
                title=f"CVE: {cve_id}",
                description=cve.get("description", cve.get("summary", "")),
                severity=cve.get("severity", cve.get("cvss_severity", "Unknown")),
                source="cve_database",
                source_data=cve,
                cve=cve_id,
                cvss=cve.get("cvss", cve.get("cvss_score")),
                cwe=cve.get("cwe", cve.get("cwe_id")),
            ))
        return grounded

    def collect_from_technologies(self) -> List[GroundedFinding]:
        grounded = []
        for t in self.ctx.technologies:
            name = t.get("name", "Unknown")
            version = t.get("version", "")
            cat = t.get("category", "")
            desc = f"Tecnologia: {name}"
            if version:
                desc += f" (versao {version})"
            if cat:
                desc += f" [{cat}]"
            grounded.append(GroundedFinding(
                title=f"Tecnologia: {name}",
                description=desc,
                severity="Info",
                source="whatweb",
                source_data=t,
            ))
        return grounded

    def collect_all(self) -> List[GroundedFinding]:
        seen_titles = set()
        result = []
        for gathering_fn in [
            self.collect_from_findings,
            self.collect_from_cves,
            self.collect_from_technologies,
        ]:
            for g in gathering_fn():
                if g.title not in seen_titles:
                    seen_titles.add(g.title)
                    result.append(g)
        return result


VALID_PORT_RANGES = {
    "http": (80, 80),
    "https": (443, 443),
    "ssh": (22, 22),
    "ftp": (21, 21),
    "mysql": (3306, 3306),
    "postgresql": (5432, 5432),
    "mongodb": (27017, 27017),
    "redis": (6379, 6379),
    "elasticsearch": (9200, 9200),
    "docker": (2375, 2376),
    "kubernetes": (6443, 6443),
    "smtp": (25, 25),
    "dns": (53, 53),
}

KNOWN_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")
KNOWN_TECHNOLOGIES = {
    "nginx", "apache", "cloudflare", "php", "python", "node.js",
    "express", "react", "vue.js", "angular", "django", "laravel",
    "wordpress", "drupal", "joomla", "jquery", "bootstrap",
    "mysql", "postgresql", "mongodb", "redis", "elasticsearch",
    "docker", "kubernetes", "aws", "gcp", "azure", "github",
}


class Validator:
    def validate(self, finding: GroundedFinding) -> GroundedFinding:
        source = finding.source.lower()
        data = finding.source_data

        dispatch = {
            "cve_database": self._validate_cve,
            "nmap": self._validate_nmap,
            "nuclei": self._validate_nuclei,
            "sqlmap": self._validate_sqlmap,
            "ffuf": self._validate_ffuf,
            "whatweb": self._validate_whatweb,
            "supabomb": self._validate_evidence,
            "specter": self._validate_evidence,
            "wasminator": self._validate_evidence,
            "badworker": self._validate_evidence,
            "graphql": self._validate_evidence,
            "general": self._validate_general,
        }
        validator = dispatch.get(source, self._validate_general)
        validator(finding, data)
        return finding

    def _validate_cve(self, finding: GroundedFinding, data: dict):
        cve_id = finding.cve or data.get("id", data.get("cve_id", ""))
        if not cve_id or not KNOWN_CVE_PATTERN.match(str(cve_id)):
            finding.validation_notes.append("CVE ID invalido ou ausente")
            return
        cvss = finding.cvss or data.get("score", data.get("cvss_score"))
        if cvss is not None:
            try:
                score = float(cvss)
                if score < 0 or score > 10:
                    finding.validation_notes.append(f"CVSS {score} fora do intervalo 0-10")
                    return
            except (ValueError, TypeError):
                finding.validation_notes.append(f"CVSS invalido: {cvss}")
                return
        desc = data.get("description", data.get("summary", ""))
        if not desc or len(desc) < 15:
            finding.validation_notes.append("Descricao CVE muito curta ou vazia")
            return
        cve_match = re.search(r"CVE-\d{4}-\d{4,}", desc)
        if not cve_match or cve_match.group() != cve_id:
            finding.validation_notes.append("CVE ID nao corresponde ao texto da descricao")
            return
        finding.validation_notes.append(f"Validado: {cve_id} com CVSS {cvss}")
        finding.validated = True

    def _validate_nmap(self, finding: GroundedFinding, data: dict):
        port = data.get("port")
        if port is None:
            finding.validation_notes.append("Sem numero de porta")
            return
        try:
            port_num = int(port)
            if port_num < 1 or port_num > 65535:
                finding.validation_notes.append(f"Porta {port_num} fora do intervalo valido")
                return
        except (ValueError, TypeError):
            finding.validation_notes.append(f"Porta invalida: {port}")
            return
        service = (data.get("service") or data.get("name") or "").lower()
        if service:
            expected = VALID_PORT_RANGES.get(service)
            if expected and not (expected[0] <= port_num <= expected[1]):
                finding.validation_notes.append(
                    f"Servico {service} na porta {port_num} (esperado: {expected[0]}-{expected[1]})"
                )
                return
        state = data.get("state", "").lower()
        if state and state not in ("open", "filtered", "closed"):
            finding.validation_notes.append(f"Estado de porta invalido: {state}")
            return
        finding.validation_notes.append(f"Porta {port_num} ({service}) real e valida")
        finding.validated = True

    def _validate_nuclei(self, finding: GroundedFinding, data: dict):
        template = data.get("template_id", data.get("template", ""))
        matched = data.get("matched_at", "")
        if matched and template:
            finding.validation_notes.append(f"Template {template} matched em {matched}")
            finding.validated = True
        elif template:
            finding.validation_notes.append(f"Template {template} sem match confirmado")
            finding.validated = True
        else:
            finding.validation_notes.append("Nuclei finding sem template ID ou matched_at")

    def _validate_sqlmap(self, finding: GroundedFinding, data: dict):
        raw = data.get("payload") or data.get("raw_data", "")
        payload = str(raw) if not isinstance(raw, str) else raw
        param = data.get("parameter", data.get("param", ""))
        technique = data.get("technique", "")
        tech_map = {"1": "boolean", "2": "time", "3": "error", "4": "union", "5": "stacked"}
        if technique and technique not in tech_map and technique not in tech_map.values():
            finding.validation_notes.append(f"Tecnica SQLi invalida: {technique}")
            return
        if payload:
            sqli_keywords = ["'", '"', "or 1=1", "union", "select", "sleep(", "pg_sleep"]
            if not any(kw in payload.lower() for kw in sqli_keywords):
                finding.validation_notes.append("Payload nao contem marcadores SQLi classicos")
                return
        if param:
            finding.validation_notes.append(f"SQLi confirmado no parametro {param}")
        elif payload:
            finding.validation_notes.append("SQLi confirmado por payload real")
        else:
            finding.validation_notes.append("SQLi sem payload ou parametro — pode ser falso positivo")
            return
        finding.validated = True

    def _validate_ffuf(self, finding: GroundedFinding, data: dict):
        url = data.get("url", data.get("target", ""))
        status = data.get("status", data.get("status_code"))
        if status is not None:
            try:
                code = int(status)
                if code < 100 or code > 599:
                    finding.validation_notes.append(f"Status code invalido: {code}")
                    return
            except (ValueError, TypeError):
                finding.validation_notes.append(f"Status code invalido: {status}")
                return
        if url and status is not None:
            finding.validation_notes.append(f"Path {url} retorna HTTP {status}")
            finding.validated = True
        elif url:
            finding.validation_notes.append(f"Path {url} descoberto (sem status)")
            finding.validated = True

    def _validate_whatweb(self, finding: GroundedFinding, data: dict):
        name = (data.get("name") or data.get("title", "")).lower()
        raw = data.get("raw_data", {})
        if isinstance(raw, dict):
            version = raw.get("version", "")
            category = raw.get("category", "")
        else:
            version = ""
            category = ""
        if name:
            found = any(tech in name for tech in KNOWN_TECHNOLOGIES)
            if found:
                detail = f"Tecnologia conhecida: {name}"
                if version:
                    detail += f" v{version}"
                if category:
                    detail += f" [{category}]"
                finding.validation_notes.append(detail)
                finding.validated = True
            else:
                if version or category:
                    finding.validation_notes.append(f"Fingerprint: {name} v{version}")
                    finding.validated = True
                else:
                    finding.validation_notes.append(f"Tecnologia desconhecida: {name}")

    def _validate_evidence(self, finding: GroundedFinding, data: dict):
        evidence = data.get("evidence", data.get("raw_data", data.get("details", "")))
        if evidence and len(str(evidence)) > 10:
            finding.validation_notes.append("Evidence confirmada")
            finding.validated = True
        else:
            title = data.get("title", "")
            desc = data.get("description", "")
            if title and desc and len(desc) > 20:
                finding.validation_notes.append("Finding com titulo e descricao")
                finding.validated = True

    def _validate_general(self, finding: GroundedFinding, data: dict):
        title = data.get("title", "")
        desc = data.get("description", "")
        severity = data.get("severity", "")
        if severity not in ("Info", "Baixa", "Media", "Alta", "Critica", "Critical", "High", "Medium", "Low"):
            finding.validation_notes.append(f"Severidade invalida: {severity}")
        if title and desc and len(desc) > 20:
            finding.validation_notes.append("Finding com titulo e descricao validos")
            finding.validated = True
        elif title:
            finding.validation_notes.append("Apenas titulo, sem descricao")


class Presenter:
    def __init__(self, llm_client=None):
        self.llm_client = llm_client

    def format_finding(self, finding: GroundedFinding) -> dict:
        return {
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity,
            "source": finding.source,
            "cve": finding.cve,
            "cvss": finding.cvss,
            "cwe": finding.cwe,
            "validated": finding.validated,
        }

    def format_report(self, findings: List[GroundedFinding]) -> dict:
        validated = [f for f in findings if f.validated]
        unvalidated = [f for f in findings if not f.validated]

        return {
            "total_findings": len(findings),
            "validated_count": len(validated),
            "unvalidated_count": len(unvalidated),
            "hallucination_risk": len(unvalidated) / max(len(findings), 1),
            "validated_findings": [self.format_finding(f) for f in validated],
            "unvalidated_findings": [self.format_finding(f) for f in unvalidated],
        }


class CrossValidator:
    def __init__(self, ctx):
        self.ctx = ctx

    def validate_findings(self, findings: List[GroundedFinding]) -> List[GroundedFinding]:
        tech_names = {t.get("name", "").lower() for t in self.ctx.technologies}
        for f in findings:
            if f.source == "cve_database":
                self._cross_check_cve(f, tech_names)
        return findings

    def _cross_check_cve(self, finding: GroundedFinding, tech_names: set):
        data = finding.source_data
        tech = (data.get("tech") or data.get("vendor") or "").lower()
        if not tech:
            return
        if tech not in tech_names:
            finding.validation_notes.append(
                f"CROSS-CHECK: CVE para {tech} mas tecnologia nao detectada no fingerprint"
            )
            finding.validated = False


class GroundedPipeline:
    def __init__(self, llm_client=None):
        self.gatherer = None
        self.validator = Validator()
        self.presenter = Presenter(llm_client)

    def process(self, ctx) -> dict:
        self.gatherer = Gatherer(ctx)
        raw_findings = self.gatherer.collect_all()

        validated = []
        for f in raw_findings:
            f = self.validator.validate(f)
            validated.append(f)

        cross = CrossValidator(ctx)
        validated = cross.validate_findings(validated)

        report = self.presenter.format_report(validated)

        ctx.grounded_findings = [f.to_dict() for f in validated]
        ctx.hallucination_risk = report["hallucination_risk"]

        return report
