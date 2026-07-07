"""
validation_gate.py — 7-Question Gate Validation

Baseado na metodologia do pentest-agents (H-mmer).
Cada finding deve passar por 7 perguntas antes de ser reportado.
Primeiro NAO = KILL (achar descartado).

Uso:
    gate = ValidationGate()
    result = gate.evaluate(title, description, extra)
    if result.passed:
        print("Finding validated!")
    else:
        print(f"KILLED: {result.reason}")
"""

import re
from dataclasses import dataclass, field
from typing import Optional

NEVER_SUBMIT_PATTERNS = [
    r"(?i)(login|signin|signup|register) page exists",
    r"(?i)port (80|443) (is )?open",
    r"(?i)default (error|page|welcome page)",
    r"(?i)server header.*(apache|nginx|iis)",
    r"(?i)technolog(y|ies) detected",
    r"(?i)ssl certificate issuer",
    r"(?i)dns (record|resolution|lookup)",
    r"(?i)whois lookup",
    r"(?i)subdomain discovered.*no (content|service)",
    r"(?i)csrf token.*present",
    r"(?i)cookie.*httponly.*(true|set)",
    r"(?i)x-content-type-options.*nosniff",
]


@dataclass
class GateResult:
    passed: bool
    gate: int = 0
    question: str = ""
    reason: str = ""
    severity_suggestion: str = ""
    details: dict = field(default_factory=dict)


class ValidationGate:
    def __init__(self):
        self.never_submit = NEVER_SUBMIT_PATTERNS

    def _has_poc(self, description: str, extra: Optional[dict] = None) -> bool:
        has_url = bool(re.search(r"https?://[^\s]+", description))
        has_request = bool(re.search(r"(GET|POST|PUT|DELETE|PATCH)\s+\S+\s+HTTP", description))
        has_payload = bool(re.search(r"(<script|alert\(|confirm\(|prompt\(|fetch\(|' OR |1=1|\.\./|\$\{|sleep\()", description, re.IGNORECASE))
        has_extra = bool(extra and (extra.get("evidence") or extra.get("raw_data")))
        if has_url and (has_request or has_payload):
            return True
        if has_request and has_payload:
            return True
        if has_extra:
            return True
        return False

    def _is_in_scope(self, description: str, title: str) -> bool:
        text = f"{title} {description}".lower()
        out_of_scope = [
            "third.party", "cdn\\.", "googleapis\\.com",
            "cloudflare\\.com", "akamai\\.com",
        ]
        return not any(re.search(p, text) for p in out_of_scope)

    def _needs_auth(self, description: str) -> bool:
        return bool(re.search(r"(admin|authenticated|logged.in|requires auth)", description.lower()))

    def _is_info_only(self, severity: str, description: str) -> bool:
        if severity and severity.lower() == "info":
            return True
        info_signals = [
            "porta aberta", "port open", "service detected",
            "tecnologia detectada", "technology detected",
        ]
        return any(s in description.lower() for s in info_signals)

    def evaluate(
        self,
        title: str,
        description: str,
        severity: str = "",
        plugin_source: str = "",
        extra: Optional[dict] = None,
    ) -> GateResult:
        text = f"{title} {description}"

        # Q1: Tem evidencia HTTP (request + response)?
        if not self._has_poc(description, extra):
            return GateResult(
                passed=False, gate=1,
                question="Q1: Evidencia HTTP real?",
                reason=f"Falta request/response HTTP ou payload concreto: '{title}'",
            )

        # Q2: Bug class comeca com letra maiuscula? (place holder para checagem real)
        if not title or title == "Info":
            return GateResult(
                passed=False, gate=2,
                question="Q2: Achado tem titulo valido?",
                reason="Titulo vazio ou generic 'Info'",
            )

        # Q3: Asset in-scope?
        if not self._is_in_scope(description, title):
            return GateResult(
                passed=False, gate=3,
                question="Q3: Asset in-scope?",
                reason=f"Referencia a servico third-party: '{title}'",
            )

        # Q4: Funciona sem privilegio especial?
        needs_auth = self._needs_auth(description)
        if needs_auth and severity in ("", "Critica", "Alta"):
            return GateResult(
                passed=False, gate=4,
                question="Q4: Accessivel sem privilegio?",
                reason=f"Requer autenticacao mas classificado como {severity}",
                severity_suggestion="Media",
            )

        # Q5: Nao e comportamento documentado?
        doc_signals = [
            "documented", "expected", "intended", "by design",
            "normal behavior", "expected behavior",
        ]
        if any(s in description.lower() for s in doc_signals):
            return GateResult(
                passed=False, gate=5,
                question="Q5: Comportamento documentado/conhecido?",
                reason="Texto sugere comportamento esperado ou documentado",
            )

        # Q6: Impacto provado com dados reais?
        if not self._has_poc(description, extra):
            return GateResult(
                passed=False, gate=6,
                question="Q6: Impacto provado com dados reais?",
                reason="Sem evidencia concreta de impacto, apenas descricao generica",
            )

        # Q7: Esta na never-submit list?
        for pattern in self.never_submit:
            if re.search(pattern, text):
                return GateResult(
                    passed=False, gate=7,
                    question="Q7: Nao esta na never-submit list?",
                    reason=f"Padrao '{pattern}' encontrado — achado informacional sem valor",
                    severity_suggestion="Info",
                )

        # Passed all gates
        return GateResult(
            passed=True,
            question="7-Question Gate: PASS",
            reason="Todas as 7 perguntas validadas",
            severity_suggestion=severity,
        )

    def batch_evaluate(self, findings: list[dict]) -> list[dict]:
        results = []
        for f in findings:
            result = self.evaluate(
                title=f.get("title", ""),
                description=f.get("description", ""),
                severity=f.get("severity", ""),
                plugin_source=f.get("plugin_source", ""),
                extra=f.get("extra"),
            )
            results.append({
                "index": findings.index(f),
                "title": f.get("title", ""),
                "gate_passed": result.passed,
                "gate_question": result.question,
                "reason": result.reason,
                "severity_suggestion": result.severity_suggestion or f.get("severity", "Info"),
            })
        return results

    def format_gate_summary(self, results: list[dict]) -> str:
        passed = sum(1 for r in results if r["gate_passed"])
        killed = sum(1 for r in results if not r["gate_passed"])
        parts = [
            f"=== VALIDATION GATE: {passed} PASS / {killed} KILL ===",
        ]
        for r in results:
            status = "PASS" if r["gate_passed"] else "KILL"
            parts.append(f"  [{status}] {r['title']}")
            if not r["gate_passed"]:
                parts.append(f"         {r['gate_question']}: {r['reason']}")
        return "\n".join(parts)
